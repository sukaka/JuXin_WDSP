// store.go 攻击活动会话仓储（WDSP AI 自动化渗透防护增强 阶段4；表见迁移 000103）。
// 四类事件源查询统一带 occurred_at 常量下界谓词（security_events /
// access_control_events 为 RANGE 分区表，常量下界保分区裁剪）；水位线派生自
// attack_session_event（max(occurred_at) per source_table）——失败不前移、
// 重放由 UNIQUE(source_table, source_id) + ON CONFLICT DO NOTHING 幂等兜底，
// 与采集器同一断点纪律。
package attacksessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 会话不存在。
var ErrNotFound = errors.New("attack session not found")

// 事件源标识（attack_session_event.source_table 取值）。
const (
	SourceBehaviorEvents      = "identity_behavior_events"
	SourceAccessControlEvents = "access_control_events"
	SourceSecurityEvents      = "security_events"
	SourceAPIRuntimeEvents    = "api_runtime_events"
)

// Session 攻击活动会话行。
type Session struct {
	ID           uuid.UUID  `json:"id"`
	SessionKey   string     `json:"session_key"`
	IdentityID   *uuid.UUID `json:"identity_id"`
	IdentityKey  string     `json:"identity_key"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      time.Time  `json:"end_time"` // = last_event_at
	RequestCount int64      `json:"request_count"`
	EventCount   int64      `json:"event_count"`
	RiskScore    int        `json:"risk_score"`
	RiskLevel    string     `json:"risk_level"`
	AttackStage  string     `json:"attack_stage"`
	Status       string     `json:"status"`
	// AutomationSuspected 疑似自动化攻击派生标注（规则见 automation.go：有效阶段≥3 且
	// 命中无头/枚举/低慢类指示信号；单调 false→true）。AutomationBasis 为判定依据。
	AutomationSuspected bool      `json:"automation_suspected"`
	AutomationBasis     string    `json:"automation_basis"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Event 待聚合的归属事件（四类源统一形态；IdentityID 为空 = 未归属，本期跳过）。
type Event struct {
	SourceTable string
	SourceID    string
	RequestID   string
	IdentityID  *uuid.UUID
	IdentityKey string
	OccurredAt  time.Time
	Score       int
	Stage       string
	// Signal 行为信号（仅 identity_behavior_events 源携带，signal 列契约值；
	// 其余源为空）——自动化攻击标注的指示信号来源（automation.go）。
	Signal string
}

// SessionEvent 会话成员事件（详情接口时间序输出）。
type SessionEvent struct {
	SourceTable string    `json:"source_table"`
	SourceID    string    `json:"source_id"`
	RequestID   string    `json:"request_id"`
	OccurredAt  time.Time `json:"occurred_at"`
	Stage       string    `json:"stage"`
}

// ListFilter 会话列表筛选。
type ListFilter struct {
	Stage     string
	RiskLevel string
	Status    string
	From      *time.Time
	To        *time.Time
	Page      int
	PageSize  int
}

// Store 攻击活动会话仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// sessionColumns 会话全列（扫描顺序固定）。
const sessionColumns = `id, session_key, identity_id, identity_key, start_time, end_time,
  request_count, event_count, risk_score, risk_level, attack_stage, status,
  automation_suspected, automation_basis, created_at, updated_at`

func scanSession(rs rowScanner) (*Session, error) {
	var s Session
	err := rs.Scan(&s.ID, &s.SessionKey, &s.IdentityID, &s.IdentityKey, &s.StartTime, &s.EndTime,
		&s.RequestCount, &s.EventCount, &s.RiskScore, &s.RiskLevel, &s.AttackStage, &s.Status,
		&s.AutomationSuspected, &s.AutomationBasis, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// rowScanner 抽象 pgx.Row / pgx.Rows 的 Scan。
type rowScanner interface {
	Scan(dest ...any) error
}

// ---------- 聚合器：水位线与事件源 ----------

// Watermark 派生源水位线（已链接事件的最大 occurred_at；无记录返回 false）。
func (s *Store) Watermark(ctx context.Context, source string) (time.Time, bool, error) {
	var wm *time.Time
	err := s.db.QueryRow(ctx,
		`SELECT max(occurred_at) FROM attack_session_event WHERE source_table = $1`, source).Scan(&wm)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("watermark %s: %w", source, err)
	}
	if wm == nil {
		return time.Time{}, false, nil
	}
	return *wm, true, nil
}

// FetchBehaviorEvents 行为事件（主锚：identity_id 直挂；identity_id NULL 行本期跳过）。
func (s *Store) FetchBehaviorEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := s.db.Query(ctx, `
SELECT id::text, identity_key, identity_id, occurred_at, risk_score_delta, COALESCE(request_id,''), rule_code, COALESCE(signal,'')
FROM identity_behavior_events
WHERE occurred_at >= $1 AND identity_id IS NOT NULL
ORDER BY occurred_at ASC, id ASC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var identityID uuid.UUID
		var ruleCode string
		if err := rows.Scan(&ev.SourceID, &ev.IdentityKey, &identityID, &ev.OccurredAt,
			&ev.Score, &ev.RequestID, &ruleCode, &ev.Signal); err != nil {
			return nil, err
		}
		ev.SourceTable = SourceBehaviorEvents
		ev.IdentityID = &identityID
		ev.Stage = StageForBehaviorRule(ruleCode)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// FetchAccessControlEvents 访问控制事件（details->>'identity_key' 精确 join client_identity；
// 无 identity_key 载荷的事件类型天然不归属，本期跳过）。分值取 details.score（风险处置事件
// 证据载荷，见迁移 000101），非数字/缺失按 0。阶段 UNKNOWN（处置事件不代表攻击阶段本身）。
func (s *Store) FetchAccessControlEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.id::text, e.occurred_at, e.request_id, ci.id, ci.identity_key,
       CASE WHEN e.details->>'score' ~ '^[0-9]+$' THEN (e.details->>'score')::int ELSE 0 END
FROM access_control_events e
JOIN client_identity ci ON ci.identity_key = e.details->>'identity_key'
WHERE e.occurred_at >= $1
ORDER BY e.occurred_at ASC, e.id ASC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var identityID uuid.UUID
		if err := rows.Scan(&ev.SourceID, &ev.OccurredAt, &ev.RequestID, &identityID,
			&ev.IdentityKey, &ev.Score); err != nil {
			return nil, err
		}
		ev.SourceTable = SourceAccessControlEvents
		ev.IdentityID = &identityID
		ev.Stage = StageUnknown
		out = append(out, ev)
	}
	return out, rows.Err()
}

// 身份关联降级链（三套指纹域不可 join，已证实）：
//
//	首选 request_id 关联 identity_behavior_events（同请求的行为信号携带 identity_id）；
//	兜底 identity_ip_history IP 反查——仅当该 IP 唯一归属一个身份时采纳
//	（NAT/共享出口下多身份歧义标存疑、不强挂：identity_id 置 NULL，本期跳过未归属事件）。
const identityResolveSQL = `
LEFT JOIN LATERAL (
  SELECT ibe.identity_id FROM identity_behavior_events ibe
  WHERE %s AND ibe.request_id IS NOT NULL AND ibe.request_id <> '' AND ibe.identity_id IS NOT NULL
  ORDER BY ibe.occurred_at DESC LIMIT 1
) via_req ON true
LEFT JOIN LATERAL (
  SELECT CASE WHEN count(DISTINCT h.identity_id) = 1 THEN max(h.identity_id::text)::uuid END AS identity_id
  FROM identity_ip_history h WHERE %s
) via_ip ON true`

func fetchSecurityEventsSQL() string {
	return fmt.Sprintf(`
SELECT se.id::text, se.occurred_at, se.request_id, se.anomaly_score, se.attack_type,
       COALESCE(via_req.identity_id, via_ip.identity_id) AS identity_id, ci.identity_key
FROM security_events se
%s
LEFT JOIN client_identity ci ON ci.id = COALESCE(via_req.identity_id, via_ip.identity_id)
WHERE se.occurred_at >= $1
ORDER BY se.occurred_at ASC, se.id ASC LIMIT $2`,
		fmt.Sprintf(identityResolveSQL,
			`ibe.request_id = se.request_id AND se.request_id <> ''`,
			`se.client_ip IS NOT NULL AND h.ip = host(se.client_ip)`))
}

func fetchAPIRuntimeEventsSQL() string {
	return fmt.Sprintf(`
SELECT are.id::text, are.occurred_at, are.request_id, are.risk_score, are.details_json,
       COALESCE(via_req.identity_id, via_ip.identity_id) AS identity_id, ci.identity_key
FROM api_runtime_events are
%s
LEFT JOIN client_identity ci ON ci.id = COALESCE(via_req.identity_id, via_ip.identity_id)
WHERE are.occurred_at >= $1
ORDER BY are.occurred_at ASC, are.id ASC LIMIT $2`,
		fmt.Sprintf(identityResolveSQL,
			`ibe.request_id = are.request_id AND are.request_id <> ''`,
			`are.client_ip IS NOT NULL AND h.ip = are.client_ip`))
}

// FetchSecurityEvents 安全事件（request_id 首选 / IP 反查兜底；SQLi 等仅 IP 事件
// 反查失败不硬挂——identity_id NULL 行由聚合器跳过并计数，代码路径见 aggregator.go）。
func (s *Store) FetchSecurityEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	q := fetchSecurityEventsSQL()
	rows, err := s.db.Query(ctx, q, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var attackType string
		var identityKey *string
		if err := rows.Scan(&ev.SourceID, &ev.OccurredAt, &ev.RequestID, &ev.Score,
			&attackType, &ev.IdentityID, &identityKey); err != nil {
			return nil, err
		}
		ev.SourceTable = SourceSecurityEvents
		if identityKey != nil {
			ev.IdentityKey = *identityKey
		}
		ev.Stage = StageForSecurityEvent(attackType)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// FetchAPIRuntimeEvents API 运行时事件（request_id 首选 / IP 反查兜底；
// details_json 在 Go 侧解析推断阶段——SCHEMA_*/api_parser/waf 明细 EXPLOIT、
// lifecycle.new_endpoint DISCOVERY、sensitive.value DATA_ACCESS 等，见 stage.go）。
func (s *Store) FetchAPIRuntimeEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	q := fetchAPIRuntimeEventsSQL()
	rows, err := s.db.Query(ctx, q, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var details []byte
		var identityKey *string
		if err := rows.Scan(&ev.SourceID, &ev.OccurredAt, &ev.RequestID, &ev.Score,
			&details, &ev.IdentityID, &identityKey); err != nil {
			return nil, err
		}
		ev.SourceTable = SourceAPIRuntimeEvents
		if identityKey != nil {
			ev.IdentityKey = *identityKey
		}
		ev.Stage = StageForRuntimeDetails(parseDetectorMatches(details))
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ---------- 聚合器：会话读写 ----------

// FindOpenSession 取身份最新 OPEN 会话（无则返回 nil, nil）。
func (s *Store) FindOpenSession(ctx context.Context, identityID uuid.UUID) (*Session, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+sessionColumns+` FROM attack_session
WHERE identity_id = $1 AND status = 'OPEN'
ORDER BY end_time DESC LIMIT 1`, identityID)
	sess, err := scanSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// CreateSession 新建会话（session_key 冲突 = 重放/崩溃重建或迟到事件撞上同 30min 桶的
// 旧会话，回读既有行）。返回 created=true 表示本轮实际插入新行（聚合器统计与
// CLOSED 碰撞判定用）；冲突回读时 created=false，调用方须检查返回行 Status。
func (s *Store) CreateSession(ctx context.Context, sess *Session) (*Session, bool, error) {
	row := s.db.QueryRow(ctx, `
INSERT INTO attack_session (session_key, identity_id, identity_key, start_time, end_time,
  request_count, event_count, risk_score, risk_level, attack_stage, status)
VALUES ($1,$2,$3,$4,$4,0,0,0,'LOW',$5,'OPEN')
ON CONFLICT (session_key) DO NOTHING
RETURNING `+sessionColumns,
		sess.SessionKey, sess.IdentityID, sess.IdentityKey, sess.StartTime, StageUnknown)
	created, err := scanSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// 同键已存在（重放/桶碰撞）：回读
		row = s.db.QueryRow(ctx,
			`SELECT `+sessionColumns+` FROM attack_session WHERE session_key = $1`, sess.SessionKey)
		existing, rerr := scanSession(row)
		if rerr != nil {
			return nil, false, rerr
		}
		return existing, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

// CloseOtherOpenSessions 关闭身份其余 OPEN 会话（维持「同身份至多一个 OPEN」不变式；
// 新建会话前调用，excludeID 传新会话 ID——新建未落库时传 uuid.Nil 关闭全部）。
func (s *Store) CloseOtherOpenSessions(ctx context.Context, identityID, excludeID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `
UPDATE attack_session SET status = 'CLOSED', updated_at = now()
WHERE identity_id = $1 AND status = 'OPEN' AND id <> $2`, identityID, excludeID)
	return err
}

// AlreadyLinked 事件挂载判重（UNIQUE(source_table, source_id) 索引点查）：
// 聚合器在建会话前先判重——重放事件不进入会话合并/新建流程，避免「重放产生空会话」。
func (s *Store) AlreadyLinked(ctx context.Context, sourceTable, sourceID string) (uuid.UUID, bool, error) {
	var sessionID uuid.UUID
	err := s.db.QueryRow(ctx, `
SELECT session_id FROM attack_session_event WHERE source_table = $1 AND source_id = $2`,
		sourceTable, sourceID).Scan(&sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return sessionID, true, nil
}

// LinkEvent 事件挂会话（UNIQUE(source_table, source_id) 幂等核心；
// 返回 true = 本轮新挂，false = 已挂过——重放不重复累计会话字段）。
func (s *Store) LinkEvent(ctx context.Context, sessionID uuid.UUID, ev Event) (bool, error) {
	tag, err := s.db.Exec(ctx, `
INSERT INTO attack_session_event (session_id, source_table, source_id, request_id, occurred_at, stage)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (source_table, source_id) DO NOTHING`,
		sessionID, ev.SourceTable, ev.SourceID, ev.RequestID, ev.OccurredAt, ev.Stage)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// HasRequest 会话内是否已挂同 request_id 事件（request_count 去重口径：跨全部源）。
func (s *Store) HasRequest(ctx context.Context, sessionID uuid.UUID, requestID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM attack_session_event
  WHERE session_id = $1 AND request_id = $2 AND request_id <> '')`, sessionID, requestID).Scan(&exists)
	return exists, err
}

// HasRequestFrom 会话内是否已挂同 request_id 且来自指定源的事件
// （WDSP 双落去重口径：仅在 security_events/api_runtime_events 对内判重——
// 同请求的行为信号与安全事件语义不同，不互相去重）。
func (s *Store) HasRequestFrom(ctx context.Context, sessionID uuid.UUID, requestID string, sources ...string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM attack_session_event
  WHERE session_id = $1 AND request_id = $2 AND request_id <> '' AND source_table = ANY($3))`,
		sessionID, requestID, sources).Scan(&exists)
	return exists, err
}

// UpdateSession 绝对值回写会话聚合字段（聚合器单工人顺序处理，无并发写竞争；
// 计数值由聚合器在内存状态上累加后整体回写）。
func (s *Store) UpdateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.Exec(ctx, `
UPDATE attack_session SET start_time=$2, end_time=$3, request_count=$4, event_count=$5,
  risk_score=$6, risk_level=$7, attack_stage=$8, automation_suspected=$9, automation_basis=$10,
  updated_at=now()
WHERE id=$1`,
		sess.ID, sess.StartTime, sess.EndTime, sess.RequestCount, sess.EventCount,
		sess.RiskScore, sess.RiskLevel, sess.AttackStage, sess.AutomationSuspected, sess.AutomationBasis)
	return err
}

// CloseStaleSessions 收口超龄 OPEN 会话（last_event_at < before → CLOSED）。
func (s *Store) CloseStaleSessions(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, `
UPDATE attack_session SET status = 'CLOSED', updated_at = now()
WHERE status = 'OPEN' AND end_time < $1`, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---------- 管理面查询 ----------

// List 会话分页列表（阶段/风险等级/状态/时间窗筛选，end_time DESC）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Session, int64, error) {
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
	if f.Stage != "" {
		add("attack_stage = $%d", f.Stage)
	}
	if f.RiskLevel != "" {
		add("risk_level = $%d", f.RiskLevel)
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.From != nil {
		add("end_time >= $%d", *f.From)
	}
	if f.To != nil {
		add("start_time <= $%d", *f.To)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM attack_session WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+sessionColumns+` FROM attack_session WHERE `+where+
		fmt.Sprintf(" ORDER BY end_time DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *sess)
	}
	return out, total, rows.Err()
}

// GetByID 会话详情（不存在返回 ErrNotFound）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	sess, err := scanSession(s.db.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM attack_session WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// ListEvents 会话成员事件（occurred_at 时间序）。
func (s *Store) ListEvents(ctx context.Context, sessionID uuid.UUID) ([]SessionEvent, error) {
	rows, err := s.db.Query(ctx, `
SELECT source_table, source_id, request_id, occurred_at, stage
FROM attack_session_event WHERE session_id = $1
ORDER BY occurred_at ASC, created_at ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionEvent{}
	for rows.Next() {
		var ev SessionEvent
		if err := rows.Scan(&ev.SourceTable, &ev.SourceID, &ev.RequestID, &ev.OccurredAt, &ev.Stage); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
