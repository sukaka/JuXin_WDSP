package systemalerts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 告警不存在。
var ErrNotFound = errors.New("system alert not found")

// ErrInvalidTransition 状态机不允许的流转（当前状态不支持该操作）。
var ErrInvalidTransition = errors.New("invalid alert status transition")

// Alert 是一条系统告警。
type Alert struct {
	ID              uuid.UUID  `json:"id"`
	AlertType       string     `json:"alert_type"`
	Severity        string     `json:"severity"`
	Component       string     `json:"component"`
	Title           string     `json:"title"`
	Message         string     `json:"message"`
	Status          string     `json:"status"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	OccurrenceCount int        `json:"occurrence_count"`
	AcknowledgedBy  *uuid.UUID `json:"acknowledged_by"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at"`
	ResolvedBy      *uuid.UUID `json:"resolved_by"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	ResolveType     *string    `json:"resolve_type"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Note 是告警备注。
type Note struct {
	ID        uuid.UUID  `json:"id"`
	AlertID   uuid.UUID  `json:"alert_id"`
	Note      string     `json:"note"`
	CreatedBy *uuid.UUID `json:"created_by"`
	Username  string     `json:"username"`
	CreatedAt time.Time  `json:"created_at"`
}

// ListFilter 是告警查询筛选。
type ListFilter struct {
	Status    string
	Severity  string
	AlertType string
	Component string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int
}

// Store 是系统告警仓储（同时实现引擎需要的 EngineStore）。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// ---------- 引擎方法 ----------

// FindOpen 查询同 type+component 的未关闭（OPEN/ACKNOWLEDGED）告警；无则返回 nil, nil。
func (s *Store) FindOpen(ctx context.Context, alertType, component string) (*Alert, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+alertColumns+`
FROM system_alerts
WHERE alert_type = $1 AND component = $2 AND status IN ('OPEN','ACKNOWLEDGED')
ORDER BY last_seen_at DESC LIMIT 1`, alertType, component)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return scanAlert(rows)
	}
	return nil, rows.Err()
}

// Insert 新建告警。
func (s *Store) Insert(ctx context.Context, a *Alert) error {
	return s.db.QueryRow(ctx, `
INSERT INTO system_alerts
(alert_type, severity, component, title, message, status, first_seen_at, last_seen_at, occurrence_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$7,1) RETURNING id, created_at`,
		a.AlertType, a.Severity, a.Component, truncateStr(a.Title, 200), truncateStr(a.Message, 1000),
		a.Status, a.FirstSeenAt,
	).Scan(&a.ID, &a.CreatedAt)
}

// Merge 合并到既有告警：occurrence_count+1、last_seen_at 更新；
// updateMessage 为 true 时同时更新 message 与 severity（冷却期外）。
func (s *Store) Merge(ctx context.Context, id uuid.UUID, message, severity string, updateMessage bool, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE system_alerts SET
  occurrence_count = occurrence_count + 1,
  last_seen_at = $2,
  message = CASE WHEN $3 THEN $4 ELSE message END,
  severity = CASE WHEN $3 THEN $5 ELSE severity END
WHERE id = $1 AND status IN ('OPEN','ACKNOWLEDGED')`,
		id, now, updateMessage, truncateStr(message, 1000), severity)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountOpen 统计 OPEN 状态总数（最大未关闭保护）。
func (s *Store) CountOpen(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM system_alerts WHERE status = 'OPEN'`).Scan(&n)
	return n, err
}

// ListOpenByComponent 查询组件的未关闭告警（限定类型集合；空集合表示全部）。
func (s *Store) ListOpenByComponent(ctx context.Context, component string, alertTypes []string) ([]Alert, error) {
	query := `
SELECT ` + alertColumns + `
FROM system_alerts
WHERE component = $1 AND status IN ('OPEN','ACKNOWLEDGED')`
	args := []interface{}{component}
	if len(alertTypes) > 0 {
		query += ` AND alert_type = ANY($2)`
		args = append(args, alertTypes)
	}
	query += ` ORDER BY last_seen_at DESC`
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// ResolveRecovered 自动恢复：OPEN/ACKNOWLEDGED → RESOLVED(resolve_type=RECOVERED)。
func (s *Store) ResolveRecovered(ctx context.Context, id uuid.UUID, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE system_alerts SET status='RESOLVED', resolved_at=$2, resolve_type='RECOVERED'
WHERE id=$1 AND status IN ('OPEN','ACKNOWLEDGED')`, id, now)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ParseFailureRate 统计窗口内事件解析失败数与已采集事件数（供 EVENT_PARSE_FAILURE_RATE_HIGH 评估）。
func (s *Store) ParseFailureRate(ctx context.Context, window time.Duration) (failures, processed int64, err error) {
	err = s.db.QueryRow(ctx, `
SELECT
  (SELECT count(*) FROM event_parse_failures WHERE occurred_at >= now() - $1::interval AND resolved = FALSE),
  (SELECT count(*) FROM security_events WHERE occurred_at >= now() - $1::interval)`,
		window.String()).Scan(&failures, &processed)
	return failures, processed, err
}

// ---------- 处置与查询方法 ----------

// GetByID 查询告警详情。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Alert, error) {
	row := s.db.QueryRow(ctx, `SELECT `+alertColumns+` FROM system_alerts WHERE id = $1`, id)
	a, err := scanAlert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

// List 分页查询告警。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Alert, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 1000 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.AlertType != "" {
		add("alert_type = $%d", f.AlertType)
	}
	if f.Component != "" {
		add("component = $%d", f.Component)
	}
	if f.StartTime != nil {
		add("last_seen_at >= $%d", *f.StartTime)
	}
	if f.EndTime != nil {
		add("last_seen_at <= $%d", *f.EndTime)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM system_alerts WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + alertColumns + ` FROM system_alerts WHERE ` + where +
		fmt.Sprintf(" ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// Acknowledge 确认告警：仅 OPEN → ACKNOWLEDGED。
func (s *Store) Acknowledge(ctx context.Context, id, by uuid.UUID, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE system_alerts SET status='ACKNOWLEDGED', acknowledged_by=$2, acknowledged_at=$3
WHERE id=$1 AND status='OPEN'`, id, by, now)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

// ResolveManual 手动解决：OPEN/ACKNOWLEDGED → RESOLVED(resolve_type=MANUAL)。
func (s *Store) ResolveManual(ctx context.Context, id, by uuid.UUID, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE system_alerts SET status='RESOLVED', resolved_by=$2, resolved_at=$3, resolve_type='MANUAL'
WHERE id=$1 AND status IN ('OPEN','ACKNOWLEDGED')`, id, by, now)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

// Ignore 忽略告警：OPEN/ACKNOWLEDGED → IGNORED。
func (s *Store) Ignore(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE system_alerts SET status='IGNORED'
WHERE id=$1 AND status IN ('OPEN','ACKNOWLEDGED')`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

// AddNote 添加备注。
func (s *Store) AddNote(ctx context.Context, alertID uuid.UUID, note string, by *uuid.UUID) (*Note, error) {
	n := &Note{AlertID: alertID, Note: truncateStr(note, 1000), CreatedBy: by}
	err := s.db.QueryRow(ctx, `
INSERT INTO system_alert_notes (alert_id, note, created_by) VALUES ($1,$2,$3)
RETURNING id, created_at`, alertID, n.Note, by).Scan(&n.ID, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// ListNotes 查询告警备注（按时间正序，关联用户名）。
func (s *Store) ListNotes(ctx context.Context, alertID uuid.UUID) ([]Note, error) {
	rows, err := s.db.Query(ctx, `
SELECT n.id, n.alert_id, n.note, n.created_by, COALESCE(u.username, ''), n.created_at
FROM system_alert_notes n
LEFT JOIN users u ON u.id = n.created_by
WHERE n.alert_id = $1 ORDER BY n.created_at ASC`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Note{}
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.AlertID, &n.Note, &n.CreatedBy, &n.Username, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

const alertColumns = `
id, alert_type, severity, component, title, message, status,
first_seen_at, last_seen_at, occurrence_count,
acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolve_type, created_at`

func scanAlert(row pgx.Row) (*Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.AlertType, &a.Severity, &a.Component, &a.Title, &a.Message,
		&a.Status, &a.FirstSeenAt, &a.LastSeenAt, &a.OccurrenceCount,
		&a.AcknowledgedBy, &a.AcknowledgedAt, &a.ResolvedBy, &a.ResolvedAt, &a.ResolveType, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
