// Package apiassets API 端点资产管理（发现、列表、确认、合并/拆分、学习与分类）。
package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound 端点不存在。
	ErrNotFound = errors.New("api endpoint not found")
	// ErrEndpointConflict 端点键已存在（拆分目标路径与现有端点冲突）。
	ErrEndpointConflict = errors.New("api endpoint already exists")
	// ErrLearningRunning 端点已有运行中的学习任务。
	ErrLearningRunning = errors.New("learning job already running")
	// ErrLearningNotRunning 端点没有运行中的学习任务。
	ErrLearningNotRunning = errors.New("no running learning job")
	// ErrClassificationLocked 端点分类已锁定，禁止自动分类覆盖。
	ErrClassificationLocked = errors.New("classification locked")
)

// 资产状态白名单（asset_status）。
var validAssetStatuses = map[string]bool{
	"DISCOVERED": true,
	"CONFIRMED":  true,
	"IGNORED":    true,
	"DEPRECATED": true,
}

// 学习状态白名单（learning_status）。
var validLearningStatuses = map[string]bool{
	"NOT_STARTED": true,
	"LEARNING":    true,
	"PAUSED":      true,
	"LEARNED":     true,
}

// Endpoint API 端点（列名对齐迁移 000018）。
type Endpoint struct {
	ID                    uuid.UUID  `json:"id"`
	ApplicationID         *uuid.UUID `json:"application_id,omitempty"`
	DomainID              *uuid.UUID `json:"domain_id,omitempty"`
	HTTPMethod            string     `json:"http_method"`
	NormalizedPath        string     `json:"normalized_path"`
	RawPathExample        string     `json:"raw_path_example"`
	EndpointKey           string     `json:"endpoint_key"`
	APIConfidence         float64    `json:"api_confidence"`
	AssetStatus           string     `json:"asset_status"`
	ProtocolType          string     `json:"protocol_type"`
	LearningStatus        string     `json:"learning_status"`
	CurrentModelVersionID *uuid.UUID `json:"current_model_version_id,omitempty"`
	ClassificationLocked  bool       `json:"classification_locked"`
	IsAPI                 bool       `json:"is_api"`
	HitCount              int64      `json:"hit_count"`
	FirstSeenAt           time.Time  `json:"first_seen_at"`
	LastSeenAt            time.Time  `json:"last_seen_at"`
	ConfirmedAt           *time.Time `json:"confirmed_at,omitempty"`
	// Asset 业务维度扩展（来自 api_assets，详情接口附带，无记录时为空）。
	Asset *Asset `json:"asset,omitempty"`
}

// Asset api_assets 业务维度归属。
type Asset struct {
	EndpointID         uuid.UUID `json:"endpoint_id"`
	Purpose            string    `json:"purpose"`
	Exposure           string    `json:"exposure"`
	DataClassification string    `json:"data_classification"`
	Owner              string    `json:"owner"`
	Tags               []string  `json:"tags"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ClassificationDimension 端点分类维度（api_classification_dimensions）。
type ClassificationDimension struct {
	EndpointID uuid.UUID `json:"endpoint_id"`
	Dimension  string    `json:"dimension"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence"`
}

// LearningJob 学习任务（api_learning_jobs）。
type LearningJob struct {
	ID             uuid.UUID  `json:"id"`
	EndpointID     uuid.UUID  `json:"endpoint_id"`
	Status         string     `json:"status"`
	SampleTarget   int        `json:"sample_target"`
	CollectedCount int        `json:"collected_count"`
	ValidCount     int        `json:"valid_count"`
	ExcludedCount  int        `json:"excluded_count"`
	LastError      string     `json:"last_error,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	StoppedAt      *time.Time `json:"stopped_at,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// SampleStats 学习样本统计（api_learning_samples 聚合）。
type SampleStats struct {
	Total    int64 `json:"total"`
	Accepted int64 `json:"accepted"`
	Excluded int64 `json:"excluded"`
}

// ListFilter 端点列表过滤条件。
type ListFilter struct {
	AssetStatus    string
	LearningStatus string
	Keyword        string
	ApplicationID  *uuid.UUID
	Page           int
	PageSize       int
}

// endpointColumns 端点全列（扫描顺序固定）。
const endpointColumns = `id, application_id, domain_id, http_method, normalized_path, raw_path_example,
	endpoint_key, api_confidence, asset_status, protocol_type, learning_status,
	current_model_version_id, classification_locked, is_api, hit_count,
	first_seen_at, last_seen_at, confirmed_at`

// learningJobColumns 学习任务全列（扫描顺序固定）。
const learningJobColumns = `id, endpoint_id, status, sample_target, collected_count, valid_count,
	excluded_count, last_error, started_at, stopped_at, created_by, created_at`

// rowScanner 抽象 pgx.Row / pgx.Rows 的 Scan。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(rs rowScanner) (*Endpoint, error) {
	var e Endpoint
	err := rs.Scan(&e.ID, &e.ApplicationID, &e.DomainID, &e.HTTPMethod, &e.NormalizedPath,
		&e.RawPathExample, &e.EndpointKey, &e.APIConfidence, &e.AssetStatus, &e.ProtocolType,
		&e.LearningStatus, &e.CurrentModelVersionID, &e.ClassificationLocked, &e.IsAPI,
		&e.HitCount, &e.FirstSeenAt, &e.LastSeenAt, &e.ConfirmedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func scanLearningJob(rs rowScanner) (*LearningJob, error) {
	var j LearningJob
	err := rs.Scan(&j.ID, &j.EndpointID, &j.Status, &j.SampleTarget, &j.CollectedCount,
		&j.ValidCount, &j.ExcludedCount, &j.LastError, &j.StartedAt, &j.StoppedAt,
		&j.CreatedBy, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// Store 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// UpsertDiscovery 发现/命中端点（按 endpoint_key 幂等）。
// 参数名为发现侧约定，内部写入 http_method / normalized_path。
func (s *Store) UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*Endpoint, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	pathTemplate = strings.TrimSpace(pathTemplate)
	if method == "" || pathTemplate == "" {
		return nil, fmt.Errorf("method and path_template required")
	}
	key := method + " " + pathTemplate
	e, err := scanEndpoint(s.db.QueryRow(ctx, `
INSERT INTO api_endpoints (http_method, normalized_path, raw_path_example, endpoint_key, api_confidence, is_api, hit_count, asset_status)
VALUES ($1,$2,$2,$3,$4,$5,1,'DISCOVERED')
ON CONFLICT (endpoint_key) DO UPDATE SET
  hit_count = api_endpoints.hit_count + 1,
  last_seen_at = now(),
  api_confidence = GREATEST(api_endpoints.api_confidence, EXCLUDED.api_confidence),
  updated_at = now()
RETURNING `+endpointColumns,
		method, pathTemplate, key, confidence, isAPI,
	))
	if err != nil {
		return nil, err
	}
	return e, nil
}

// List 分页列表（asset_status / learning_status / keyword / application_id 过滤）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Endpoint, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.AssetStatus != "" {
		add("asset_status = $%d", f.AssetStatus)
	}
	if f.LearningStatus != "" {
		add("learning_status = $%d", f.LearningStatus)
	}
	if f.Keyword != "" {
		add("normalized_path ILIKE $%d", "%"+f.Keyword+"%")
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	q := fmt.Sprintf(`
SELECT %s FROM api_endpoints WHERE %s ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		endpointColumns, where, len(args)-1, len(args))
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// Confirm 人工确认端点（asset_status=CONFIRMED）。
func (s *Store) Confirm(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	e, err := scanEndpoint(s.db.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status='CONFIRMED', confirmed_at=now(), updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// GetByID 查询。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Endpoint, error) {
	e, err := scanEndpoint(s.db.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// Merge 把 other 端点并入 primary：命中数累加、other 历史端点键归档进
// api_endpoint_aliases、删除 other、写生命周期 MERGED（事务）。
func (s *Store) Merge(ctx context.Context, primaryID, otherID uuid.UUID, actor string) (*Endpoint, error) {
	if primaryID == otherID {
		return nil, fmt.Errorf("不能将端点合并到自身")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 单语句按固定扫描顺序锁定两端点，避免并发合并相互死锁
	type mergeRow struct {
		key      string
		hits     int64
		lastSeen time.Time
	}
	locked := map[uuid.UUID]mergeRow{}
	rows, err := tx.Query(ctx, `
SELECT id, endpoint_key, hit_count, last_seen_at FROM api_endpoints
WHERE id IN ($1,$2) FOR UPDATE`, primaryID, otherID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var r mergeRow
		if err := rows.Scan(&id, &r.key, &r.hits, &r.lastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		locked[id] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(locked) != 2 {
		return nil, ErrNotFound
	}
	other := locked[otherID]

	// other 的历史端点键归档到 primary（重复归档幂等）
	if _, err = tx.Exec(ctx, `
INSERT INTO api_endpoint_aliases (endpoint_id, alias_key, created_reason)
VALUES ($1,$2,'merge')
ON CONFLICT (alias_key) DO NOTHING`, primaryID, other.key); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET hit_count = hit_count + $2,
  last_seen_at = GREATEST(last_seen_at, $3), updated_at = now()
WHERE id = $1`, primaryID, other.hits, other.lastSeen); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM api_endpoints WHERE id = $1`, otherID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'','MERGED',$2,$3)`,
		primaryID, fmt.Sprintf("合并端点 %s（%s）", otherID, other.key), actor); err != nil {
		return nil, err
	}
	merged, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1`, primaryID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return merged, nil
}

// Split 按给定归一化路径从 id 端点拆分出新端点（继承 http_method/api_confidence
// 等身份属性，asset_status=DISCOVERED），原端点写生命周期 SPLIT（事务）。
func (s *Store) Split(ctx context.Context, id uuid.UUID, newPaths []string, actor string) ([]Endpoint, error) {
	if len(newPaths) == 0 {
		return nil, fmt.Errorf("拆分路径不能为空")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	src, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	created := []Endpoint{}
	for _, p := range newPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("拆分路径不能为空")
		}
		key := src.HTTPMethod + " " + p
		e, err := scanEndpoint(tx.QueryRow(ctx, `
INSERT INTO api_endpoints (application_id, domain_id, http_method, normalized_path, raw_path_example,
  endpoint_key, api_confidence, asset_status, protocol_type, is_api)
VALUES ($1,$2,$3,$4,$4,$5,$6,'DISCOVERED',$7,$8)
ON CONFLICT (endpoint_key) DO NOTHING
RETURNING `+endpointColumns,
			src.ApplicationID, src.DomainID, src.HTTPMethod, p, key, src.APIConfidence, src.ProtocolType, src.IsAPI))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrEndpointConflict, key)
		}
		if err != nil {
			return nil, err
		}
		created = append(created, *e)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'','SPLIT',$2,$3)`,
		id, fmt.Sprintf("拆分出 %d 个端点：%s", len(created), strings.Join(newPaths, ", ")), actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// SetAssetStatus 变更资产状态（忽略/恢复等），写生命周期事件（事务）。
func (s *Store) SetAssetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*Endpoint, error) {
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validAssetStatuses[status] {
		return nil, fmt.Errorf("无效的资产状态：%s", status)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT asset_status FROM api_endpoints WHERE id=$1 FOR UPDATE`, id).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e, err := scanEndpoint(tx.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status=$2, updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id, status))
	if err != nil {
		return nil, err
	}
	if from != status {
		if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,$2,$3,'资产状态变更',$4)`, id, from, status, actor); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// GetAsset 读取端点业务维度扩展；无记录返回 (nil, nil)。
func (s *Store) GetAsset(ctx context.Context, endpointID uuid.UUID) (*Asset, error) {
	var a Asset
	var tags []byte
	err := s.db.QueryRow(ctx, `
SELECT endpoint_id, purpose, exposure, data_classification, owner, tags, created_at, updated_at
FROM api_assets WHERE endpoint_id=$1`, endpointID).Scan(
		&a.EndpointID, &a.Purpose, &a.Exposure, &a.DataClassification, &a.Owner, &tags, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Tags = []string{}
	if err := json.Unmarshal(tags, &a.Tags); err != nil {
		return nil, fmt.Errorf("解析资产标签失败：%w", err)
	}
	return &a, nil
}

// UpsertAsset 按端点 upsert 业务维度扩展（purpose/exposure/owner/tags 全量替换）。
func (s *Store) UpsertAsset(ctx context.Context, endpointID uuid.UUID, purpose, exposure, owner string, tags []string) (*Asset, error) {
	exposure = strings.ToUpper(strings.TrimSpace(exposure))
	if exposure == "" {
		exposure = "INTERNAL"
	}
	if tags == nil {
		tags = []string{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return nil, fmt.Errorf("序列化资产标签失败：%w", err)
	}
	var a Asset
	var tagsRaw []byte
	err = s.db.QueryRow(ctx, `
INSERT INTO api_assets (endpoint_id, purpose, exposure, owner, tags)
VALUES ($1,$2,$3,$4,$5::jsonb)
ON CONFLICT (endpoint_id) DO UPDATE SET
  purpose = EXCLUDED.purpose, exposure = EXCLUDED.exposure,
  owner = EXCLUDED.owner, tags = EXCLUDED.tags, updated_at = now()
RETURNING endpoint_id, purpose, exposure, data_classification, owner, tags, created_at, updated_at`,
		endpointID, purpose, exposure, owner, string(tagsJSON)).Scan(
		&a.EndpointID, &a.Purpose, &a.Exposure, &a.DataClassification, &a.Owner, &tagsRaw, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	a.Tags = []string{}
	if err := json.Unmarshal(tagsRaw, &a.Tags); err != nil {
		return nil, fmt.Errorf("解析资产标签失败：%w", err)
	}
	return &a, nil
}

// SetClassificationLocked 设置分类锁定标记。
func (s *Store) SetClassificationLocked(ctx context.Context, id uuid.UUID, locked bool) error {
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoints SET classification_locked=$2, updated_at=now() WHERE id=$1`, id, locked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetLearningStatus 更新学习状态（NOT_STARTED/LEARNING/PAUSED/LEARNED）。
func (s *Store) SetLearningStatus(ctx context.Context, id uuid.UUID, status string) error {
	status = strings.ToUpper(strings.TrimSpace(status))
	if !validLearningStatuses[status] {
		return fmt.Errorf("无效的学习状态：%s", status)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_endpoints SET learning_status=$2, updated_at=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AutoClassify 按路径/方法启发式自动分类，写 api_classification_dimensions（source=AUTO）。
// 端点分类已锁定时返回 ErrClassificationLocked（事务）。
func (s *Store) AutoClassify(ctx context.Context, id uuid.UUID) ([]ClassificationDimension, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	e, err := scanEndpoint(tx.QueryRow(ctx, `SELECT `+endpointColumns+` FROM api_endpoints WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if e.ClassificationLocked {
		return nil, ErrClassificationLocked
	}
	dims := classifyByPath(e.HTTPMethod, e.NormalizedPath)
	for i := range dims {
		dims[i].EndpointID = id
		if _, err = tx.Exec(ctx, `
INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
VALUES ($1,$2,$3,'AUTO',$4)
ON CONFLICT (endpoint_id, dimension) DO UPDATE SET
  value = EXCLUDED.value, source = 'AUTO', confidence = EXCLUDED.confidence, updated_at = now()`,
			id, dims[i].Dimension, dims[i].Value, dims[i].Confidence); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return dims, nil
}

// StartLearning 创建 RUNNING 学习任务并置端点 learning_status=LEARNING；
// 已有 RUNNING 任务时返回 ErrLearningRunning（事务）。
func (s *Store) StartLearning(ctx context.Context, endpointID uuid.UUID, createdBy *uuid.UUID) (*LearningJob, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 学习启停互斥：锁定端点行防并发双开；不存在则返回 ErrNotFound
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM api_endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var running bool
	if err = tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM api_learning_jobs WHERE endpoint_id=$1 AND status='RUNNING')`, endpointID).Scan(&running); err != nil {
		return nil, err
	}
	if running {
		return nil, ErrLearningRunning
	}
	job, err := scanLearningJob(tx.QueryRow(ctx, `
INSERT INTO api_learning_jobs (endpoint_id, status, created_by)
VALUES ($1,'RUNNING',$2)
RETURNING `+learningJobColumns, endpointID, createdBy))
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET learning_status='LEARNING', updated_at=now() WHERE id=$1`, endpointID); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// StopLearning 停止运行中的学习任务（置 STOPPED），端点 learning_status=PAUSED；
// 无 RUNNING 任务时返回 ErrLearningNotRunning（事务）。
func (s *Store) StopLearning(ctx context.Context, endpointID uuid.UUID, actor string) (*LearningJob, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 锁定端点行，与 StartLearning 互斥；不存在则返回 ErrNotFound
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM api_endpoints WHERE id=$1 FOR UPDATE`, endpointID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job, err := scanLearningJob(tx.QueryRow(ctx, `
UPDATE api_learning_jobs SET status='STOPPED', stopped_at=now()
WHERE endpoint_id=$1 AND status='RUNNING'
RETURNING `+learningJobColumns, endpointID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLearningNotRunning
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
UPDATE api_endpoints SET learning_status='PAUSED', updated_at=now() WHERE id=$1`, endpointID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'LEARNING','PAUSED','停止学习',$2)`, endpointID, actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return job, nil
}

// LearningStatus 返回最近一次学习任务与样本统计；从未学习时 job 为 nil。
func (s *Store) LearningStatus(ctx context.Context, endpointID uuid.UUID) (*LearningJob, SampleStats, error) {
	var stats SampleStats
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE accepted),
  count(*) FILTER (WHERE NOT accepted)
FROM api_learning_samples WHERE api_endpoint_id=$1`, endpointID).Scan(
		&stats.Total, &stats.Accepted, &stats.Excluded); err != nil {
		return nil, stats, err
	}
	job, err := scanLearningJob(s.db.QueryRow(ctx, `
SELECT `+learningJobColumns+` FROM api_learning_jobs
WHERE endpoint_id=$1 ORDER BY started_at DESC, id DESC LIMIT 1`, endpointID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, stats, nil
	}
	if err != nil {
		return nil, stats, err
	}
	return job, stats, nil
}

// classifyByPath 路径/方法启发式自动分类（AUTO 来源，供 SQL 与内存实现共用）。
func classifyByPath(method, path string) []ClassificationDimension {
	p := strings.ToLower(path)
	purpose, pconf := "GENERAL", 0.5
	switch {
	case strings.Contains(p, "/login"), strings.Contains(p, "/signin"),
		strings.Contains(p, "/auth"), strings.Contains(p, "/token"), strings.Contains(p, "/captcha"):
		purpose, pconf = "AUTH", 0.7
	case strings.Contains(p, "/pay"), strings.Contains(p, "/order"),
		strings.Contains(p, "/trade"), strings.Contains(p, "/billing"):
		purpose, pconf = "TRADE", 0.7
	case strings.Contains(p, "/upload"), strings.Contains(p, "/file"),
		strings.Contains(p, "/download"), strings.Contains(p, "/export"):
		purpose, pconf = "FILE", 0.7
	case strings.Contains(p, "/admin"), strings.Contains(p, "/manage"):
		purpose, pconf = "ADMIN", 0.7
	case strings.Contains(p, "/user"), strings.Contains(p, "/account"), strings.Contains(p, "/profile"):
		purpose, pconf = "USER_MGMT", 0.6
	case strings.Contains(p, "/search"), strings.Contains(p, "/query"), strings.Contains(p, "/list"):
		purpose, pconf = "QUERY", 0.6
	}
	exposure, econf := "INTERNAL", 0.5
	if strings.Contains(p, "/public") || strings.Contains(p, "/openapi") ||
		strings.Contains(p, "/webhook") || strings.Contains(p, "/callback") {
		exposure, econf = "PUBLIC", 0.7
	}
	access := "WRITE"
	if strings.EqualFold(method, "GET") || strings.EqualFold(method, "HEAD") {
		access = "READ"
	}
	return []ClassificationDimension{
		{Dimension: "PURPOSE", Value: purpose, Source: "AUTO", Confidence: pconf},
		{Dimension: "EXPOSURE", Value: exposure, Source: "AUTO", Confidence: econf},
		{Dimension: "ACCESS", Value: access, Source: "AUTO", Confidence: 0.9},
	}
}
