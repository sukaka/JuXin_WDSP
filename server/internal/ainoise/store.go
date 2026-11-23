// store.go 降噪簇仓储：指纹 upsert（事件关联幂等，重复扫描不重复计数）、
// 列表/详情/统计、suppress/resolve 状态流转、sweep run 记录。
package ainoise

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// 仓储错误。
var (
	ErrClusterNotFound = errors.New("noise cluster not found")
	ErrClusterState    = errors.New("noise cluster status does not allow this operation")
)

// EventInput 待聚类事件（WAF 安全事件或 WDSP API 运行时事件的统一映射）。
type EventInput struct {
	EventID       uuid.UUID
	Source        string // WAF / API
	ApplicationID *uuid.UUID
	Host          string
	RawURI        string // WAF 为 request_path；API 为 endpoint_key（已归一化）
	RuleID        *int
	DetectorCode  string
	ClientIP      string
	OccurredAt    time.Time
}

// Cluster 降噪簇。
type Cluster struct {
	ID              uuid.UUID  `json:"id"`
	Source          string     `json:"source"`
	FingerprintHash string     `json:"fingerprint_hash"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	Host            string     `json:"host"`
	NormalizedURI   string     `json:"normalized_uri"`
	RuleID          *int       `json:"rule_id"`
	DetectorCode    string     `json:"detector_code"`
	ClientIP        string     `json:"client_ip"`
	EventCount      int        `json:"event_count"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	Status          string     `json:"status"`
	AIVerdict       string     `json:"ai_verdict"`
	AIConfidence    *float64   `json:"ai_confidence"`
	AISummary       string     `json:"ai_summary"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ClusterEvent 簇内事件关联。
type ClusterEvent struct {
	EventID          uuid.UUID `json:"event_id"`
	Source           string    `json:"source"`
	IsRepresentative bool      `json:"is_representative"`
	CreatedAt        time.Time `json:"created_at"`
}

// ListFilter 簇列表筛选。
type ListFilter struct {
	Source   string
	Status   string
	Verdict  string
	Since    *time.Time // last_seen 下界
	Until    *time.Time // last_seen 上界
	Page     int
	PageSize int
}

// Stats 面板统计。
type Stats struct {
	ActiveClusters              int64 `json:"active_clusters"`
	FoldedEvents                int64 `json:"folded_events"`
	LikelyFalsePositiveClusters int64 `json:"likely_false_positive_clusters"`
	SuppressedClusters          int64 `json:"suppressed_clusters"`
}

// SweepRun 一次扫描运行记录。
type SweepRun struct {
	ID              uuid.UUID  `json:"id"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at"`
	ScannedEvents   int        `json:"scanned_events"`
	NewClusters     int        `json:"new_clusters"`
	UpdatedClusters int        `json:"updated_clusters"`
	LLMCalls        int        `json:"llm_calls"`
	TokensUsed      int        `json:"tokens_used"`
	Status          string     `json:"status"` // SUCCESS / FAILED / PARTIAL
	Error           string     `json:"error"`
}

// Evidence 簇证据摘要（LLM 评分输入；全部由数据库事实构成，禁止编造）。
type Evidence struct {
	Cluster          Cluster    `json:"cluster"`
	RepresentativeID *uuid.UUID `json:"representative_event_id"`
	AttackType       string     `json:"attack_type"`
	Severity         string     `json:"severity"`
	Action           string     `json:"action"`
	RuleHits         []string   `json:"rule_hits"` // 如 "rule 942100: SQL Injection Attack"
	EventsPerMinute  float64    `json:"events_per_minute"`
}

// Store 降噪簇仓储契约（SQLStore 生产实现 / MemStore 测试与降级实现）。
type Store interface {
	// UpsertEvent 按指纹聚类事件；created=true 表示新建簇。
	// 同一事件重复扫描幂等（关联已存在时不重复计数）。
	UpsertEvent(ctx context.Context, in EventInput) (created bool, clusterID uuid.UUID, err error)
	List(ctx context.Context, f ListFilter) ([]Cluster, int64, error)
	Get(ctx context.Context, id uuid.UUID) (*Cluster, error)
	ListEvents(ctx context.Context, clusterID uuid.UUID, limit int) ([]ClusterEvent, error)
	// Transition 状态流转：suppress（ACTIVE→SUPPRESSED）、resolve（ACTIVE/SUPPRESSED→RESOLVED）。
	Transition(ctx context.Context, id uuid.UUID, action string) (*Cluster, error)
	Stats(ctx context.Context) (*Stats, error)
	// VerdictCandidates 待 LLM 评分的簇（ACTIVE、超阈值、尚未判定）。
	VerdictCandidates(ctx context.Context, minEvents, limit int) ([]Cluster, error)
	UpdateVerdict(ctx context.Context, id uuid.UUID, verdict string, confidence *float64, summary string) error
	// FalsePositiveCandidates 疑似误报且超阈值的活跃簇（降噪推荐候选）。
	FalsePositiveCandidates(ctx context.Context, minEvents, limit int) ([]Cluster, error)
	// HasOpenRecommendation 同簇是否已有 DRAFT/PENDING_REVIEW 降噪推荐（防重复推荐）。
	HasOpenRecommendation(ctx context.Context, clusterID uuid.UUID) (bool, error)
	Evidence(ctx context.Context, clusterID uuid.UUID) (*Evidence, error)
	RecordSweepRun(ctx context.Context, run *SweepRun) error
	ListSweepRuns(ctx context.Context, page, pageSize int) ([]SweepRun, int64, error)
}

// SQLStore PostgreSQL 实现。
type SQLStore struct {
	db *pgxpool.Pool
}

// NewStore 创建生产仓储。
func NewStore(db *pgxpool.Pool) *SQLStore { return &SQLStore{db: db} }

const clusterColumns = `id, source, fingerprint_hash, application_id, host, normalized_uri, rule_id,
  COALESCE(detector_code,''), COALESCE(host(client_ip),''), event_count, first_seen, last_seen,
  status, ai_verdict, ai_confidence, ai_summary, created_at, updated_at`

func scanCluster(row pgx.Row) (*Cluster, error) {
	var c Cluster
	err := row.Scan(&c.ID, &c.Source, &c.FingerprintHash, &c.ApplicationID, &c.Host, &c.NormalizedURI,
		&c.RuleID, &c.DetectorCode, &c.ClientIP, &c.EventCount, &c.FirstSeen, &c.LastSeen,
		&c.Status, &c.AIVerdict, &c.AIConfidence, &c.AISummary, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpsertEvent 事务内：查簇 → 不存在则新建 → 关联事件（幂等）→ 新关联才计数。
func (s *SQLStore) UpsertEvent(ctx context.Context, in EventInput) (bool, uuid.UUID, error) {
	norm := NormalizeURI(in.RawURI)
	fp := Fingerprint(in.Source, in.Host, norm, in.RuleID, in.DetectorCode, in.ClientIP)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id uuid.UUID
	created := false
	err = tx.QueryRow(ctx,
		`SELECT id FROM ai_noise_clusters WHERE source=$1 AND fingerprint_hash=$2`, in.Source, fp).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, uuid.Nil, err
		}
		created = true
		err = tx.QueryRow(ctx, `
INSERT INTO ai_noise_clusters (source, fingerprint_hash, application_id, host, normalized_uri,
  rule_id, detector_code, client_ip, event_count, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,'')::inet,1,$9,$9) RETURNING id`,
			in.Source, fp, in.ApplicationID, in.Host, norm, in.RuleID, in.DetectorCode, in.ClientIP,
			in.OccurredAt).Scan(&id)
		if err != nil {
			return false, uuid.Nil, fmt.Errorf("insert noise cluster: %w", err)
		}
	}
	// 关联事件：同事件重复扫描 ON CONFLICT 跳过（窗口重叠不重复计数）；
	// 首个关联事件自动成为代表事件。
	tag, err := tx.Exec(ctx, `
INSERT INTO ai_noise_cluster_events (cluster_id, event_id, source, is_representative)
SELECT $1, $2, $3, NOT EXISTS (
  SELECT 1 FROM ai_noise_cluster_events WHERE cluster_id=$1 AND is_representative)
ON CONFLICT (cluster_id, event_id, source) DO NOTHING`, id, in.EventID, in.Source)
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("link noise cluster event: %w", err)
	}
	if tag.RowsAffected() == 1 && !created {
		if _, err = tx.Exec(ctx, `
UPDATE ai_noise_clusters SET event_count=event_count+1, last_seen=GREATEST(last_seen,$2), updated_at=now()
WHERE id=$1`, id, in.OccurredAt); err != nil {
			return false, uuid.Nil, fmt.Errorf("update noise cluster: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return false, uuid.Nil, err
	}
	return created, id, nil
}

// List 分页筛选簇列表（按 last_seen 倒序）。
func (s *SQLStore) List(ctx context.Context, f ListFilter) ([]Cluster, int64, error) {
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if f.Source != "" {
		where += fmt.Sprintf(" AND source = $%d", idx)
		args = append(args, f.Source)
		idx++
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, f.Status)
		idx++
	}
	if f.Verdict != "" {
		where += fmt.Sprintf(" AND ai_verdict = $%d", idx)
		args = append(args, f.Verdict)
		idx++
	}
	if f.Since != nil {
		where += fmt.Sprintf(" AND last_seen >= $%d", idx)
		args = append(args, *f.Since)
		idx++
	}
	if f.Until != nil {
		where += fmt.Sprintf(" AND last_seen < $%d", idx)
		args = append(args, *f.Until)
		idx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_noise_clusters WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	rows, err := s.db.Query(ctx, `SELECT `+clusterColumns+` FROM ai_noise_clusters WHERE `+where+
		` ORDER BY last_seen DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, f.PageSize, (f.Page-1)*f.PageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Cluster{}
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *c)
	}
	return out, total, rows.Err()
}

// Get 簇详情。
func (s *SQLStore) Get(ctx context.Context, id uuid.UUID) (*Cluster, error) {
	c, err := scanCluster(s.db.QueryRow(ctx, `SELECT `+clusterColumns+` FROM ai_noise_clusters WHERE id=$1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClusterNotFound
		}
		return nil, err
	}
	return c, nil
}

// ListEvents 簇内事件（代表事件在前，其余按关联时间）。
func (s *SQLStore) ListEvents(ctx context.Context, clusterID uuid.UUID, limit int) ([]ClusterEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT event_id, source, is_representative, created_at FROM ai_noise_cluster_events
WHERE cluster_id=$1 ORDER BY is_representative DESC, created_at ASC LIMIT $2`, clusterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClusterEvent{}
	for rows.Next() {
		var e ClusterEvent
		if err := rows.Scan(&e.EventID, &e.Source, &e.IsRepresentative, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Transition 状态流转（只改簇状态；不触碰事件处置/封禁/例外）。
func (s *SQLStore) Transition(ctx context.Context, id uuid.UUID, action string) (*Cluster, error) {
	var to, from string
	switch action {
	case "suppress":
		to, from = StatusSuppressed, "('ACTIVE')"
	case "resolve":
		to, from = StatusResolved, "('ACTIVE','SUPPRESSED')"
	default:
		return nil, fmt.Errorf("invalid transition action %q", action)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE ai_noise_clusters SET status=$2, updated_at=now() WHERE id=$1 AND status IN `+from, id, to)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		if _, err := s.Get(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrClusterState
	}
	return s.Get(ctx, id)
}

// Stats 面板统计。
func (s *SQLStore) Stats(ctx context.Context) (*Stats, error) {
	var st Stats
	err := s.db.QueryRow(ctx, `
SELECT
  count(*) FILTER (WHERE status='ACTIVE'),
  COALESCE(sum(event_count) FILTER (WHERE status='ACTIVE'),0),
  count(*) FILTER (WHERE status='ACTIVE' AND ai_verdict='LIKELY_FALSE_POSITIVE'),
  count(*) FILTER (WHERE status='SUPPRESSED')
FROM ai_noise_clusters`).Scan(&st.ActiveClusters, &st.FoldedEvents,
		&st.LikelyFalsePositiveClusters, &st.SuppressedClusters)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// VerdictCandidates ACTIVE、超阈值、未判定的簇（事件数倒序）。
func (s *SQLStore) VerdictCandidates(ctx context.Context, minEvents, limit int) ([]Cluster, error) {
	return s.queryClusters(ctx, `
SELECT `+clusterColumns+` FROM ai_noise_clusters
WHERE status='ACTIVE' AND ai_verdict='UNKNOWN' AND event_count >= $1
ORDER BY event_count DESC LIMIT $2`, minEvents, limit)
}

// FalsePositiveCandidates 疑似误报且超阈值的活跃簇。
func (s *SQLStore) FalsePositiveCandidates(ctx context.Context, minEvents, limit int) ([]Cluster, error) {
	return s.queryClusters(ctx, `
SELECT `+clusterColumns+` FROM ai_noise_clusters
WHERE status='ACTIVE' AND ai_verdict='LIKELY_FALSE_POSITIVE' AND event_count >= $1
ORDER BY event_count DESC LIMIT $2`, minEvents, limit)
}

func (s *SQLStore) queryClusters(ctx context.Context, q string, minEvents, limit int) ([]Cluster, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx, q, minEvents, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Cluster{}
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateVerdict 写回 LLM 判定（verdict 取值校验防脏数据）。
func (s *SQLStore) UpdateVerdict(ctx context.Context, id uuid.UUID, verdict string, confidence *float64, summary string) error {
	switch verdict {
	case VerdictTruePositive, VerdictLikelyFalsePositive, VerdictUnknown:
	default:
		return fmt.Errorf("invalid verdict %q", verdict)
	}
	_, err := s.db.Exec(ctx, `
UPDATE ai_noise_clusters SET ai_verdict=$2, ai_confidence=$3, ai_summary=$4, updated_at=now()
WHERE id=$1`, id, verdict, confidence, summary)
	return err
}

// HasOpenRecommendation 同簇已有 DRAFT/PENDING_REVIEW 降噪推荐则跳过（防重复推荐）。
func (s *SQLStore) HasOpenRecommendation(ctx context.Context, clusterID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM ai_recommendations
  WHERE recommendation_type='NOISE_REDUCTION' AND target_id=$1 AND status IN ('DRAFT','PENDING_REVIEW'))`,
		clusterID.String()).Scan(&exists)
	return exists, err
}

// Evidence 组装簇证据摘要（代表事件 + 规则命中 + 时间分布；全部取自数据库事实）。
func (s *SQLStore) Evidence(ctx context.Context, clusterID uuid.UUID) (*Evidence, error) {
	c, err := s.Get(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	ev := &Evidence{Cluster: *c, RuleHits: []string{}}
	minutes := c.LastSeen.Sub(c.FirstSeen).Minutes()
	if minutes < 1 {
		minutes = 1
	}
	ev.EventsPerMinute = float64(c.EventCount) / minutes
	var repID uuid.UUID
	err = s.db.QueryRow(ctx, `
SELECT event_id FROM ai_noise_cluster_events
WHERE cluster_id=$1 AND is_representative LIMIT 1`, clusterID).Scan(&repID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ev, nil // 无代表事件：仅簇属性参与评分
		}
		return nil, err
	}
	ev.RepresentativeID = &repID
	switch c.Source {
	case SourceWAF:
		_ = s.db.QueryRow(ctx, `
SELECT attack_type, severity, action FROM security_events WHERE id=$1`, repID).
			Scan(&ev.AttackType, &ev.Severity, &ev.Action)
		rows, err := s.db.Query(ctx, `
SELECT rule_id, COALESCE(rule_name,'') FROM security_event_matches
WHERE event_id=$1 ORDER BY anomaly_score DESC, rule_id LIMIT 5`, repID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var rid int
			var name string
			if err := rows.Scan(&rid, &name); err != nil {
				return nil, err
			}
			name = wafrules.LocalizeRule(rid, "", name)
			ev.RuleHits = append(ev.RuleHits, fmt.Sprintf("rule %d: %s", rid, name))
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	case SourceAPI:
		var riskLevel, finalAction string
		_ = s.db.QueryRow(ctx, `
SELECT risk_level, final_action FROM api_runtime_events WHERE id=$1`, repID).
			Scan(&riskLevel, &finalAction)
		ev.AttackType = riskLevel
		ev.Action = finalAction
		if c.DetectorCode != "" {
			ev.RuleHits = append(ev.RuleHits, "detector "+c.DetectorCode)
		}
	}
	return ev, nil
}

// RecordSweepRun 记录一次扫描运行。
func (s *SQLStore) RecordSweepRun(ctx context.Context, run *SweepRun) error {
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_noise_sweep_runs (id, started_at, finished_at, scanned_events, new_clusters,
  updated_clusters, llm_calls, tokens_used, status, error)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		run.ID, run.StartedAt, run.FinishedAt, run.ScannedEvents, run.NewClusters,
		run.UpdatedClusters, run.LLMCalls, run.TokensUsed, run.Status, run.Error)
	return err
}

// ListSweepRuns 扫描历史（开始时间倒序）。
func (s *SQLStore) ListSweepRuns(ctx context.Context, page, pageSize int) ([]SweepRun, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_noise_sweep_runs`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, started_at, finished_at, scanned_events, new_clusters, updated_clusters,
  llm_calls, tokens_used, status, error
FROM ai_noise_sweep_runs ORDER BY started_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SweepRun{}
	for rows.Next() {
		var r SweepRun
		if err := rows.Scan(&r.ID, &r.StartedAt, &r.FinishedAt, &r.ScannedEvents, &r.NewClusters,
			&r.UpdatedClusters, &r.LLMCalls, &r.TokensUsed, &r.Status, &r.Error); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

var _ Store = (*SQLStore)(nil)
