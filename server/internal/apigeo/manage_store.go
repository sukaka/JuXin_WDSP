// manage_store.go GeoIP 槽位配置与同步流水数据库仓储（表结构见迁移 000256）。
package apigeo

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

// 触发方式与执行状态词表（与迁移 000256 CHECK 约束严格一致）。
const (
	TriggerScheduled     = "SCHEDULED"
	TriggerManual        = "MANUAL"
	TriggerOfflineUpload = "OFFLINE_UPLOAD"
	TriggerRollback      = "ROLLBACK"
	TriggerHAResync      = "HA_RESYNC"

	RunStatusIdle            = "IDLE"
	RunStatusSuccess         = "SUCCESS"
	RunStatusSkippedUnchange = "SKIPPED_UNCHANGED"
	RunStatusPartialHAFailed = "PARTIAL_HA_FAILED"
	RunStatusFailed          = "FAILED"

	SourceModeOfflineOnly = "OFFLINE_ONLY"
	SourceModeOfficial    = "OFFICIAL"
	SourceModeCustomURL   = "CUSTOM_URL"
)

// GeoIP 设置键（system_settings 组 geoip，见迁移 000256）。
const (
	GeoIPSettingsGroup         = "geoip"
	KeyGeoIPAutoUpdateEnabled  = "auto_update_enabled"
	KeyGeoIPScheduleCron       = "schedule_cron"
	KeyGeoIPHASyncEnabled      = "ha_sync_enabled"
	KeyMaxMindAccountID        = "maxmind_account_id"
	KeyMaxMindLicenseKeyEnc    = "maxmind_license_key_encrypted"
	DefaultGeoIPScheduleCron   = "0 3 2 * *"
)

// SlotConfig 对应 geoip_slot_configs 表记录。
type SlotConfig struct {
	Slot             string     `json:"slot"`
	DisplayName      string     `json:"display_name"`
	Enabled          bool       `json:"enabled"`
	SourceMode       string     `json:"source_mode"`
	OfficialPreset   string     `json:"official_preset"`
	CustomURL        string     `json:"custom_url"`
	ActiveFilename   string     `json:"active_filename"`
	ActiveSHA256     string     `json:"active_sha256"`
	ActiveSizeBytes  int64      `json:"active_size_bytes"`
	ActiveSourceType string     `json:"active_source_type"`
	ETag             string     `json:"etag"`
	LastModified     string     `json:"last_modified"`
	LastUpdatedAt    *time.Time `json:"last_updated_at,omitempty"`
	LastStatus       string     `json:"last_status"`
	LastError        string     `json:"last_error"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// HANodeSyncResult 单个 HA 备节点同步 GeoIP 槽位的结果摘要。
type HANodeSyncResult struct {
	NodeID   string `json:"node_id,omitempty"`
	NodeName string `json:"node_name"`
	Status   string `json:"status"` // SUCCESS | FAILED | SKIPPED
	SHA256   string `json:"sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

// SyncRun 对应 geoip_sync_runs 表记录。
type SyncRun struct {
	ID             uuid.UUID          `json:"id"`
	Slot           string             `json:"slot"`
	TriggerType    string             `json:"trigger_type"`
	Status         string             `json:"status"`
	SourceLabel    string             `json:"source_label"`
	PreviousSHA256 string             `json:"previous_sha256"`
	NewSHA256      string             `json:"new_sha256"`
	FileSizeBytes  int64              `json:"file_size_bytes"`
	HAResults      []HANodeSyncResult `json:"ha_results"`
	ErrorMessage   string             `json:"error_message"`
	OperatorID     *uuid.UUID         `json:"operator_id,omitempty"`
	StartedAt      time.Time          `json:"started_at"`
	FinishedAt     time.Time          `json:"finished_at"`
}

// SlotActivationUpdate 激活或失败后回写 geoip_slot_configs 的更新载荷。
type SlotActivationUpdate struct {
	Slot             string
	ActiveFilename   string
	ActiveSHA256     string
	ActiveSizeBytes  int64
	ActiveSourceType string
	ETag             string
	LastModified     string
	Status           string
	ErrorMessage     string
	OperatorID       *uuid.UUID
	UpdatedAt        time.Time
	UpdateActiveFile bool // true 时同时覆盖 active_* 字段；false（失败）时保留既有活跃文件元数据
}

// SlotConfigUpdate 更新单个 GeoIP 槽位配置（PUT /api/v1/geoip/settings）。
type SlotConfigUpdate struct {
	Slot           string
	Enabled        bool
	SourceMode     string
	OfficialPreset string
	CustomURL      string
	OperatorID     *uuid.UUID
	UpdatedAt      time.Time
}

// RunFilter 查询 geoip_sync_runs 分页过滤条件。
type RunFilter struct {
	Slot        string
	TriggerType string
	Status      string
	Page        int
	PageSize    int
}

// ManageRepository 是 GeoIP 管理仓储窄接口（PGManageStore 实现，单测可注入内存实现）。
type ManageRepository interface {
	ListSlotConfigs(ctx context.Context) ([]SlotConfig, error)
	GetSlotConfig(ctx context.Context, slot string) (*SlotConfig, error)
	UpdateSlotConfig(ctx context.Context, u SlotConfigUpdate) error
	UpdateSlotStatus(ctx context.Context, u SlotActivationUpdate) error
	InsertSyncRun(ctx context.Context, run *SyncRun) error
	ListSyncRuns(ctx context.Context, f RunFilter) ([]SyncRun, int64, error)
}

// PGManageStore 基于 PostgreSQL 的 GeoIP 管理仓储。
type PGManageStore struct {
	db *pgxpool.Pool
}

// NewPGManageStore 创建 PG 仓储。
func NewPGManageStore(db *pgxpool.Pool) *PGManageStore {
	return &PGManageStore{db: db}
}

// ListSlotConfigs 按固定槽位顺序返回全部槽位配置。
func (s *PGManageStore) ListSlotConfigs(ctx context.Context) ([]SlotConfig, error) {
	rows, err := s.db.Query(ctx, `
SELECT slot, display_name, enabled, source_mode, official_preset, custom_url,
       active_filename, active_sha256, active_size_bytes, active_source_type,
       etag, last_modified, last_updated_at, last_status, last_error, updated_at
FROM geoip_slot_configs
ORDER BY array_position(ARRAY['ip2region_v4','ip2region_v6','dbip_city','city_ipv6','country']::text[], slot)`)
	if err != nil {
		return nil, fmt.Errorf("list geoip_slot_configs: %w", err)
	}
	defer rows.Close()

	var out []SlotConfig
	for rows.Next() {
		var c SlotConfig
		if err := rows.Scan(
			&c.Slot, &c.DisplayName, &c.Enabled, &c.SourceMode, &c.OfficialPreset, &c.CustomURL,
			&c.ActiveFilename, &c.ActiveSHA256, &c.ActiveSizeBytes, &c.ActiveSourceType,
			&c.ETag, &c.LastModified, &c.LastUpdatedAt, &c.LastStatus, &c.LastError, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan geoip_slot_configs: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetSlotConfig 查询单个槽位配置。
func (s *PGManageStore) GetSlotConfig(ctx context.Context, slot string) (*SlotConfig, error) {
	var c SlotConfig
	err := s.db.QueryRow(ctx, `
SELECT slot, display_name, enabled, source_mode, official_preset, custom_url,
       active_filename, active_sha256, active_size_bytes, active_source_type,
       etag, last_modified, last_updated_at, last_status, last_error, updated_at
FROM geoip_slot_configs
WHERE slot = $1`, slot).Scan(
		&c.Slot, &c.DisplayName, &c.Enabled, &c.SourceMode, &c.OfficialPreset, &c.CustomURL,
		&c.ActiveFilename, &c.ActiveSHA256, &c.ActiveSizeBytes, &c.ActiveSourceType,
		&c.ETag, &c.LastModified, &c.LastUpdatedAt, &c.LastStatus, &c.LastError, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidSlot
		}
		return nil, fmt.Errorf("get geoip_slot_configs %s: %w", slot, err)
	}
	return &c, nil
}

// UpdateSlotConfig 更新单个 GeoIP 槽位来源与启用配置；来源变化时清空旧 ETag/Last-Modified 避免跨源误命中 304。
func (s *PGManageStore) UpdateSlotConfig(ctx context.Context, u SlotConfigUpdate) error {
	now := u.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res, err := s.db.Exec(ctx, `
UPDATE geoip_slot_configs
SET enabled = $2,
    source_mode = $3,
    official_preset = $4,
    custom_url = $5,
    etag = CASE WHEN source_mode <> $3 OR official_preset <> $4 OR custom_url <> $5 THEN '' ELSE etag END,
    last_modified = CASE WHEN source_mode <> $3 OR official_preset <> $4 OR custom_url <> $5 THEN '' ELSE last_modified END,
    updated_by = $6,
    updated_at = $7
WHERE slot = $1`,
		u.Slot, u.Enabled, u.SourceMode, u.OfficialPreset, u.CustomURL, u.OperatorID, now)
	if err != nil {
		return fmt.Errorf("update geoip_slot_configs config %s: %w", u.Slot, err)
	}
	if res.RowsAffected() == 0 {
		return ErrInvalidSlot
	}
	return nil
}

// UpdateSlotStatus 回写槽位执行结果（UpdateActiveFile=true 时同步刷新活跃文件元数据）。
func (s *PGManageStore) UpdateSlotStatus(ctx context.Context, u SlotActivationUpdate) error {
	now := u.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if u.UpdateActiveFile {
		_, err := s.db.Exec(ctx, `
UPDATE geoip_slot_configs
SET active_filename = $2,
    active_sha256 = $3,
    active_size_bytes = $4,
    active_source_type = $5,
    etag = CASE WHEN $6 <> '' THEN $6 ELSE etag END,
    last_modified = CASE WHEN $7 <> '' THEN $7 ELSE last_modified END,
    last_updated_at = $8,
    last_status = $9,
    last_error = $10,
    updated_by = $11,
    updated_at = $8
WHERE slot = $1`,
			u.Slot, u.ActiveFilename, u.ActiveSHA256, u.ActiveSizeBytes, u.ActiveSourceType,
			u.ETag, u.LastModified, now, u.Status, truncateGeoError(u.ErrorMessage, 1000), u.OperatorID)
		if err != nil {
			return fmt.Errorf("update geoip_slot_configs active %s: %w", u.Slot, err)
		}
		return nil
	}
	_, err := s.db.Exec(ctx, `
UPDATE geoip_slot_configs
SET etag = CASE WHEN $2 <> '' THEN $2 ELSE etag END,
    last_modified = CASE WHEN $3 <> '' THEN $3 ELSE last_modified END,
    last_status = $4,
    last_error = $5,
    updated_by = $6,
    updated_at = $7
WHERE slot = $1`,
		u.Slot, u.ETag, u.LastModified, u.Status, truncateGeoError(u.ErrorMessage, 1000), u.OperatorID, now)
	if err != nil {
		return fmt.Errorf("update geoip_slot_configs status %s: %w", u.Slot, err)
	}
	return nil
}

// InsertSyncRun 写入一条 GeoIP 更新/上传/回滚流水记录。
func (s *PGManageStore) InsertSyncRun(ctx context.Context, run *SyncRun) error {
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
	haResults := run.HAResults
	if haResults == nil {
		haResults = []HANodeSyncResult{}
	}
	haJSON, err := json.Marshal(haResults)
	if err != nil {
		haJSON = []byte("[]")
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO geoip_sync_runs (
    id, slot, trigger_type, status, source_label,
    previous_sha256, new_sha256, file_size_bytes,
    ha_results_json, error_message, operator_id, started_at, finished_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		run.ID, run.Slot, run.TriggerType, run.Status, truncateGeoError(run.SourceLabel, 255),
		run.PreviousSHA256, run.NewSHA256, run.FileSizeBytes,
		haJSON, truncateGeoError(run.ErrorMessage, 1000), run.OperatorID, run.StartedAt, run.FinishedAt)
	if err != nil {
		return fmt.Errorf("insert geoip_sync_runs: %w", err)
	}
	return nil
}

// ListSyncRuns 分页查询 GeoIP 同步与上传历史。
func (s *PGManageStore) ListSyncRuns(ctx context.Context, f RunFilter) ([]SyncRun, int64, error) {
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
	if strings.TrimSpace(f.Slot) != "" {
		addCond("slot = $%d", strings.TrimSpace(f.Slot))
	}
	if strings.TrimSpace(f.TriggerType) != "" {
		addCond("trigger_type = $%d", strings.ToUpper(strings.TrimSpace(f.TriggerType)))
	}
	if strings.TrimSpace(f.Status) != "" {
		addCond("status = $%d", strings.ToUpper(strings.TrimSpace(f.Status)))
	}
	whereSQL := ""
	if len(conds) > 0 {
		whereSQL = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM geoip_sync_runs"+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count geoip_sync_runs: %w", err)
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	query := fmt.Sprintf(`
SELECT id, slot, trigger_type, status, source_label,
       previous_sha256, new_sha256, file_size_bytes,
       ha_results_json, error_message, operator_id, started_at, finished_at
FROM geoip_sync_runs%s
ORDER BY started_at DESC, id DESC
LIMIT $%d OFFSET $%d`, whereSQL, len(args)+1, len(args)+2)

	rows, err := s.db.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list geoip_sync_runs: %w", err)
	}
	defer rows.Close()

	out := []SyncRun{}
	for rows.Next() {
		var r SyncRun
		var haRaw []byte
		if err := rows.Scan(
			&r.ID, &r.Slot, &r.TriggerType, &r.Status, &r.SourceLabel,
			&r.PreviousSHA256, &r.NewSHA256, &r.FileSizeBytes,
			&haRaw, &r.ErrorMessage, &r.OperatorID, &r.StartedAt, &r.FinishedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan geoip_sync_runs: %w", err)
		}
		if len(haRaw) > 0 {
			_ = json.Unmarshal(haRaw, &r.HAResults)
		}
		if r.HAResults == nil {
			r.HAResults = []HANodeSyncResult{}
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func truncateGeoError(s string, maxRunes int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= maxRunes {
		return string(r)
	}
	return string(r[:maxRunes])
}
