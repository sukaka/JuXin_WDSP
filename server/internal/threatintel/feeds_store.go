// feeds_store.go 威胁情报多源订阅配置与同步流水仓储（表结构见迁移 000256_ip_library_sync）。
package threatintel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accessrules"
)

// 订阅源模式、触发类型、执行状态与系统设置键（与迁移 000256 CHECK 约束严格一致）。
const (
	SourceModeOfflineOnly = "OFFLINE_ONLY"
	SourceModeOfficial    = "OFFICIAL"
	SourceModeCustomURL   = "CUSTOM_URL"

	TriggerScheduled     = "SCHEDULED"
	TriggerManual        = "MANUAL"
	TriggerOfflineImport = "OFFLINE_IMPORT"

	RunStatusIdle               = "IDLE"
	RunStatusSuccess            = "SUCCESS"
	RunStatusSkippedNotModified = "SKIPPED_NOT_MODIFIED"
	RunStatusGuardAborted       = "GUARD_ABORTED"
	RunStatusFailed             = "FAILED"

	SettingsGroup           = "threat_intel"
	KeyAutoUpdateEnabled    = "auto_update_enabled"
	KeyCircuitThreshold     = "circuit_threshold"
	DefaultScheduleCron     = "0 */6 * * *"
	DefaultMaxDropRatio     = 0.80
	DefaultCircuitThreshold = 5
	MinCircuitThreshold     = 1
	MaxCircuitThreshold     = 20
	DropGuardMinActiveRules = 20
)

// 仓储与同步器哨兵错误。
var (
	ErrFeedNotFound     = errors.New("threat intel feed not found")
	ErrFeedKeyConflict  = errors.New("threat intel feed key already exists")
	ErrBuiltinProtected = errors.New("builtin threat intel feed cannot be deleted")
	ErrInvalidCron      = errors.New("invalid cron expression")
	ErrSyncInProgress   = errors.New("threat intel feed sync already in progress")
	ErrOfflineOnlyFeed  = errors.New("threat intel feed is configured as OFFLINE_ONLY")
)

// Feed 对应 threat_intel_feeds 表记录。
type Feed struct {
	ID                  uuid.UUID  `json:"id"`
	FeedKey             string     `json:"feed_key"`
	Name                string     `json:"name"`
	Description         string     `json:"description"`
	IsBuiltin           bool       `json:"is_builtin"`
	Enabled             bool       `json:"enabled"`
	SourceMode          string     `json:"source_mode"`
	OfficialPreset      string     `json:"official_preset"`
	CustomURL           string     `json:"custom_url"`
	Format              string     `json:"format"`
	AllowCIDR           bool       `json:"allow_cidr"`
	TTLDays             int        `json:"ttl_days"`
	ScheduleCron        string     `json:"schedule_cron"`
	MinEntriesGuard     bool       `json:"min_entries_guard"`
	MaxDropRatio        float64    `json:"max_drop_ratio"`
	ETag                string     `json:"etag"`
	LastModified        string     `json:"last_modified"`
	LastContentSHA256   string     `json:"last_content_sha256"`
	ActiveRuleCount     int        `json:"active_rule_count"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CircuitOpen         bool       `json:"circuit_open"`
	LastSyncAt          *time.Time `json:"last_sync_at,omitempty"`
	LastStatus          string     `json:"last_status"`
	LastError           string     `json:"last_error"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy           *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// SyncRun 对应 threat_intel_sync_runs 表记录。
type SyncRun struct {
	ID              uuid.UUID  `json:"id"`
	FeedKey         string     `json:"feed_key"`
	TriggerType     string     `json:"trigger_type"`
	BatchID         string     `json:"batch_id"`
	Status          string     `json:"status"`
	TotalParsed     int        `json:"total_parsed"`
	Added           int        `json:"added"`
	Refreshed       int        `json:"refreshed"`
	Expired         int        `json:"expired"`
	SkippedConflict int        `json:"skipped_conflict"`
	InvalidCount    int        `json:"invalid_count"`
	Published       bool       `json:"published"`
	ErrorMessage    string     `json:"error_message"`
	OperatorID      *uuid.UUID `json:"operator_id,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      time.Time  `json:"finished_at"`
}

// FeedSyncUpdate 回写单次同步或离线导入后的订阅源运行态。
type FeedSyncUpdate struct {
	ID                  uuid.UUID
	ETag                string
	LastModified        string
	LastContentSHA256   string
	UpdateCacheHeaders  bool // true 时更新 etag/last_modified/last_content_sha256（失败或护栏中止不覆盖）
	ActiveRuleCount     int
	UpdateActiveCount   bool // true 时更新 active_rule_count
	ConsecutiveFailures int
	CircuitOpen         bool
	UpdateCircuit       bool // true 时更新 consecutive_failures 与 circuit_open
	LastSyncAt          time.Time
	LastStatus          string
	LastError           string
	UpdatedBy           *uuid.UUID
}

// RunFilter 查询 threat_intel_sync_runs 的分页过滤参数。
type RunFilter struct {
	FeedKey     string
	TriggerType string
	Status      string
	Page        int
	PageSize    int
}

// FeedRepository 抽象威胁情报多源订阅与流水仓储（PGFeedStore 实现，单测注入内存实现）。
type FeedRepository interface {
	ListFeeds(ctx context.Context) ([]Feed, error)
	GetFeed(ctx context.Context, id uuid.UUID) (*Feed, error)
	GetFeedByKey(ctx context.Context, feedKey string) (*Feed, error)
	CreateFeed(ctx context.Context, feed *Feed) error
	UpdateFeed(ctx context.Context, feed *Feed) error
	DeleteFeed(ctx context.Context, id uuid.UUID) error
	UpdateFeedSyncResult(ctx context.Context, u FeedSyncUpdate) error
	CountActiveFeedRules(ctx context.Context, feedKey string) (int, error)
	InsertRun(ctx context.Context, run *SyncRun) error
	ListRuns(ctx context.Context, f RunFilter) ([]SyncRun, int64, error)
}

// PGFeedStore 是基于 PostgreSQL 的威胁情报订阅源与流水仓储。
type PGFeedStore struct {
	db *pgxpool.Pool
}

// NewPGFeedStore 创建 PostgreSQL 仓储。
func NewPGFeedStore(db *pgxpool.Pool) *PGFeedStore {
	return &PGFeedStore{db: db}
}

var _ FeedRepository = (*PGFeedStore)(nil)

const feedColumns = `
id, feed_key, name, description, is_builtin, enabled,
source_mode, official_preset, custom_url, format, allow_cidr,
ttl_days, schedule_cron, min_entries_guard, max_drop_ratio,
etag, last_modified, last_content_sha256,
active_rule_count, consecutive_failures, circuit_open,
last_sync_at, last_status, last_error,
created_by, updated_by, created_at, updated_at`

func scanFeed(row pgx.Row) (*Feed, error) {
	var f Feed
	err := row.Scan(
		&f.ID, &f.FeedKey, &f.Name, &f.Description, &f.IsBuiltin, &f.Enabled,
		&f.SourceMode, &f.OfficialPreset, &f.CustomURL, &f.Format, &f.AllowCIDR,
		&f.TTLDays, &f.ScheduleCron, &f.MinEntriesGuard, &f.MaxDropRatio,
		&f.ETag, &f.LastModified, &f.LastContentSHA256,
		&f.ActiveRuleCount, &f.ConsecutiveFailures, &f.CircuitOpen,
		&f.LastSyncAt, &f.LastStatus, &f.LastError,
		&f.CreatedBy, &f.UpdatedBy, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// ListFeeds 返回全部订阅源（预置高体量官方源在前，其余按 feed_key 字典序）。
func (s *PGFeedStore) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.Query(ctx, `SELECT `+feedColumns+` FROM threat_intel_feeds ORDER BY is_builtin DESC, CASE feed_key WHEN 'ipsum_l5' THEN 1 WHEN 'spamhaus_drop' THEN 2 WHEN 'et_compromised' THEN 3 WHEN 'feodo' THEN 4 ELSE 50 END, feed_key ASC`)
	if err != nil {
		return nil, fmt.Errorf("list threat_intel_feeds: %w", err)
	}
	defer rows.Close()

	out := []Feed{}
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, fmt.Errorf("scan threat_intel_feeds: %w", err)
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// GetFeed 按主键查询单个订阅源。
func (s *PGFeedStore) GetFeed(ctx context.Context, id uuid.UUID) (*Feed, error) {
	f, err := scanFeed(s.db.QueryRow(ctx, `SELECT `+feedColumns+` FROM threat_intel_feeds WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFeedNotFound
		}
		return nil, fmt.Errorf("get threat_intel_feed %s: %w", id, err)
	}
	return f, nil
}

// GetFeedByKey 按 feed_key 查询单个订阅源。
func (s *PGFeedStore) GetFeedByKey(ctx context.Context, feedKey string) (*Feed, error) {
	key := strings.ToLower(strings.TrimSpace(feedKey))
	f, err := scanFeed(s.db.QueryRow(ctx, `SELECT `+feedColumns+` FROM threat_intel_feeds WHERE feed_key = $1`, key))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFeedNotFound
		}
		return nil, fmt.Errorf("get threat_intel_feed by key %s: %w", key, err)
	}
	return f, nil
}

// CreateFeed 新建自定义威胁情报订阅源（is_builtin 恒为 false）。
func (s *PGFeedStore) CreateFeed(ctx context.Context, feed *Feed) error {
	if feed == nil {
		return fmt.Errorf("%w: feed 不能为空", ErrInvalidInput)
	}
	if feed.ID == uuid.Nil {
		feed.ID = uuid.New()
	}
	if feed.LastStatus == "" {
		feed.LastStatus = RunStatusIdle
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO threat_intel_feeds (
	id, feed_key, name, description, is_builtin, enabled,
	source_mode, official_preset, custom_url, format, allow_cidr,
	ttl_days, schedule_cron, min_entries_guard, max_drop_ratio,
	last_status, created_by, updated_by
) VALUES (
	$1,$2,$3,$4,FALSE,$5,
	$6,$7,$8,$9,$10,
	$11,$12,$13,$14,
	$15,$16,$17
) RETURNING created_at, updated_at`,
		feed.ID, feed.FeedKey, feed.Name, feed.Description, feed.Enabled,
		feed.SourceMode, feed.OfficialPreset, feed.CustomURL, feed.Format, feed.AllowCIDR,
		feed.TTLDays, feed.ScheduleCron, feed.MinEntriesGuard, feed.MaxDropRatio,
		feed.LastStatus, feed.CreatedBy, feed.UpdatedBy,
	).Scan(&feed.CreatedAt, &feed.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrFeedKeyConflict
		}
		return fmt.Errorf("create threat_intel_feed: %w", err)
	}
	feed.IsBuiltin = false
	return nil
}

// UpdateFeed 更新订阅源配置（不改动 feed_key 与 is_builtin；可同时重置变更源后的缓存头）。
func (s *PGFeedStore) UpdateFeed(ctx context.Context, feed *Feed) error {
	if feed == nil {
		return fmt.Errorf("%w: feed 不能为空", ErrInvalidInput)
	}
	err := s.db.QueryRow(ctx, `
UPDATE threat_intel_feeds
SET name = $2,
    description = $3,
    enabled = $4,
    source_mode = $5,
    official_preset = $6,
    custom_url = $7,
    format = $8,
    allow_cidr = $9,
    ttl_days = $10,
    schedule_cron = $11,
    min_entries_guard = $12,
    max_drop_ratio = $13,
    etag = $14,
    last_modified = $15,
    last_content_sha256 = $16,
    updated_by = $17,
    updated_at = now()
WHERE id = $1
RETURNING updated_at`,
		feed.ID, feed.Name, feed.Description, feed.Enabled,
		feed.SourceMode, feed.OfficialPreset, feed.CustomURL, feed.Format, feed.AllowCIDR,
		feed.TTLDays, feed.ScheduleCron, feed.MinEntriesGuard, feed.MaxDropRatio,
		feed.ETag, feed.LastModified, feed.LastContentSHA256, feed.UpdatedBy,
	).Scan(&feed.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrFeedNotFound
		}
		return fmt.Errorf("update threat_intel_feed %s: %w", feed.ID, err)
	}
	return nil
}

// DeleteFeed 删除自定义订阅源；预置源返回 ErrBuiltinProtected，不存在返回 ErrFeedNotFound。
func (s *PGFeedStore) DeleteFeed(ctx context.Context, id uuid.UUID) error {
	var isBuiltin bool
	if err := s.db.QueryRow(ctx, `SELECT is_builtin FROM threat_intel_feeds WHERE id = $1`, id).Scan(&isBuiltin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrFeedNotFound
		}
		return fmt.Errorf("check threat_intel_feed before delete %s: %w", id, err)
	}
	if isBuiltin {
		return ErrBuiltinProtected
	}
	res, err := s.db.Exec(ctx, `DELETE FROM threat_intel_feeds WHERE id = $1 AND is_builtin = FALSE`, id)
	if err != nil {
		return fmt.Errorf("delete threat_intel_feed %s: %w", id, err)
	}
	if res.RowsAffected() == 0 {
		return ErrFeedNotFound
	}
	return nil
}

// UpdateFeedSyncResult 回写订阅源的同步结果、缓存头、生效规则数与熔断计数。
func (s *PGFeedStore) UpdateFeedSyncResult(ctx context.Context, u FeedSyncUpdate) error {
	syncAt := u.LastSyncAt
	if syncAt.IsZero() {
		syncAt = time.Now().UTC()
	}
	res, err := s.db.Exec(ctx, `
UPDATE threat_intel_feeds
SET etag                = CASE WHEN $2 THEN $3 ELSE etag END,
    last_modified       = CASE WHEN $2 THEN $4 ELSE last_modified END,
    last_content_sha256 = CASE WHEN $2 THEN $5 ELSE last_content_sha256 END,
    active_rule_count   = CASE WHEN $6 THEN $7 ELSE active_rule_count END,
    consecutive_failures = CASE WHEN $8 THEN $9 ELSE consecutive_failures END,
    circuit_open        = CASE WHEN $8 THEN $10 ELSE circuit_open END,
    last_sync_at        = $11,
    last_status         = $12,
    last_error          = $13,
    updated_by          = COALESCE($14, updated_by),
    updated_at          = now()
WHERE id = $1`,
		u.ID,
		u.UpdateCacheHeaders, truncateRunes(u.ETag, 255), truncateRunes(u.LastModified, 128), u.LastContentSHA256,
		u.UpdateActiveCount, maxInt(0, u.ActiveRuleCount),
		u.UpdateCircuit, maxInt(0, u.ConsecutiveFailures), u.CircuitOpen,
		syncAt, u.LastStatus, truncateRunes(strings.TrimSpace(u.LastError), 1000), u.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("update threat_intel_feed sync result %s: %w", u.ID, err)
	}
	if res.RowsAffected() == 0 {
		return ErrFeedNotFound
	}
	return nil
}

// CountActiveFeedRules 统计指定订阅源在 ip_access_rules 中当前生效（ACTIVE 且未过期）的黑名单规则数。
func (s *PGFeedStore) CountActiveFeedRules(ctx context.Context, feedKey string) (int, error) {
	key := strings.ToLower(strings.TrimSpace(feedKey))
	if !feedPattern.MatchString(key) {
		return 0, fmt.Errorf("%w: 非法 feed_key: %q", ErrInvalidInput, feedKey)
	}
	var count int
	err := s.db.QueryRow(ctx, `
SELECT count(*) FROM ip_access_rules
WHERE deleted_at IS NULL
  AND rule_type = $1
  AND scope_type = $2
  AND source_type = $3
  AND status = $4
  AND (effective_until IS NULL OR effective_until > now())
  AND reason LIKE $5 ESCAPE '\'`,
		accessrules.RuleTypeDeny, accessrules.ScopeGlobal, accessrules.SourceImport,
		accessrules.StatusActive, likePrefixEscape(matchPrefix(key))+"%").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active threat intel rules for %s: %w", key, err)
	}
	return count, nil
}

// InsertRun 写入一条威胁情报在线拉取或离线导入流水记录。
func (s *PGFeedStore) InsertRun(ctx context.Context, run *SyncRun) error {
	if run == nil {
		return nil
	}
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	if run.FinishedAt.IsZero() {
		run.FinishedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO threat_intel_sync_runs (
	id, feed_key, trigger_type, batch_id, status,
	total_parsed, added, refreshed, expired, skipped_conflict, invalid_count,
	published, error_message, operator_id, started_at, finished_at
) VALUES (
	$1,$2,$3,$4,$5,
	$6,$7,$8,$9,$10,$11,
	$12,$13,$14,$15,$16
)`,
		run.ID, run.FeedKey, run.TriggerType, truncateRunes(run.BatchID, 64), run.Status,
		run.TotalParsed, run.Added, run.Refreshed, run.Expired, run.SkippedConflict, run.InvalidCount,
		run.Published, truncateRunes(strings.TrimSpace(run.ErrorMessage), 1000), run.OperatorID,
		run.StartedAt, run.FinishedAt,
	)
	if err != nil {
		return fmt.Errorf("insert threat_intel_sync_runs: %w", err)
	}
	return nil
}

// ListRuns 分页查询威胁情报同步与离线导入流水历史。
func (s *PGFeedStore) ListRuns(ctx context.Context, f RunFilter) ([]SyncRun, int64, error) {
	page := f.Page
	if page <= 0 {
		page = 1
	}
	pageSize := f.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var conds []string
	var args []any
	addCond := func(expr string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(expr, len(args)))
	}
	if key := strings.ToLower(strings.TrimSpace(f.FeedKey)); key != "" {
		addCond("feed_key = $%d", key)
	}
	if tt := strings.ToUpper(strings.TrimSpace(f.TriggerType)); tt != "" {
		addCond("trigger_type = $%d", tt)
	}
	if st := strings.ToUpper(strings.TrimSpace(f.Status)); st != "" {
		addCond("status = $%d", st)
	}
	whereSQL := ""
	if len(conds) > 0 {
		whereSQL = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM threat_intel_sync_runs"+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count threat_intel_sync_runs: %w", err)
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	query := fmt.Sprintf(`
SELECT id, feed_key, trigger_type, batch_id, status,
       total_parsed, added, refreshed, expired, skipped_conflict, invalid_count,
       published, error_message, operator_id, started_at, finished_at
FROM threat_intel_sync_runs%s
ORDER BY started_at DESC, id DESC
LIMIT $%d OFFSET $%d`, whereSQL, len(args)+1, len(args)+2)

	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list threat_intel_sync_runs: %w", err)
	}
	defer rows.Close()

	out := []SyncRun{}
	for rows.Next() {
		var r SyncRun
		if err := rows.Scan(
			&r.ID, &r.FeedKey, &r.TriggerType, &r.BatchID, &r.Status,
			&r.TotalParsed, &r.Added, &r.Refreshed, &r.Expired, &r.SkippedConflict, &r.InvalidCount,
			&r.Published, &r.ErrorMessage, &r.OperatorID, &r.StartedAt, &r.FinishedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan threat_intel_sync_runs: %w", err)
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
