// Package settings 提供系统设置读取与更新。
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/security"
)

// ErrNotFound 设置不存在。
var ErrNotFound = errors.New("setting not found")

// Setting 是一条系统设置。
type Setting struct {
	ID          uuid.UUID       `json:"id"`
	Group       string          `json:"setting_group"`
	Key         string          `json:"setting_key"`
	Value       json.RawMessage `json:"setting_value"`
	ValueType   string          `json:"value_type"`
	IsSensitive bool            `json:"is_sensitive"`
	Description string          `json:"description"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Version     int             `json:"version"`
}

// Service 是系统设置服务。
type Service struct {
	db *pgxpool.Pool
}

// NewService 创建设置服务。
func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db}
}

// GetString 读取字符串设置。
func (s *Service) GetString(ctx context.Context, group, key, def string) string {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		return def
	}
	var str string
	if err := json.Unmarshal(v, &str); err != nil {
		return def
	}
	return str
}

// GetStringWithSource 读取字符串设置并报告是否命中数据库记录（覆盖来源判定用）。
// 无记录返回 found=false；数据库错误如实返回，不静默回退默认值。
func (s *Service) GetStringWithSource(ctx context.Context, group, key string) (value string, found bool, err error) {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	var str string
	if err := json.Unmarshal(v, &str); err != nil {
		return "", false, err
	}
	return str, true, nil
}

// SensitiveSettingKeys 秘密材料设置键清单（group:key）。
// 用途：1) 运行期写入（UpsertString）命中时强制 is_sensitive=true，List 不回显原文；
// 2) List/Update 审计对该清单内的键脱敏（兼容清单生效前已写入的 is_sensitive=false 行）。
// 与 guardconfig 快照脱敏（provider.go RedactGuardConfig）同一口径。
var SensitiveSettingKeys = map[string]bool{
	// 身份指纹盐 / TLS 会话票据密钥（明文，经系统设置 API 维护，随发布下发）
	"gateway_runtime:identity_salt":          true,
	"gateway_runtime:tls_session_ticket_key": true,
	// 文件签名密钥 / 扫描签名密钥 / Agent CA 材料（密文，由轮换/签发接口运行期写入）
	"gateway_runtime:api_file_signature_key": true,
	"api_scan:signing_key":                   true,
	"apm_agent:ca_material":                  true,
	"traffic_agent_ca:ca_material":           true,
}

// isSensitiveSetting 判定设置是否敏感（DB 行标记或敏感键清单命中）。
func isSensitiveSetting(group, key string, rowSensitive bool) bool {
	return rowSensitive || SensitiveSettingKeys[group+":"+key]
}

// UpsertString 覆盖写入字符串设置（不存在则插入；命中则更新值并自增版本）。
// 用于运行期功能开关类设置（如 api_protection.mode），区别于管理界面带乐观锁的 Update。
// 命中 SensitiveSettingKeys 的键强制按敏感行写入（等价 UpsertSensitiveString）。
func (s *Service) UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error {
	return s.upsertString(ctx, group, key, value, description, false, operatorID)
}

// UpsertSensitiveString 覆盖写入敏感字符串设置（is_sensitive=true，List 接口脱敏
// 不回显原文）。用于含口令的连接串类设置（如 apm:clickhouse_dsn）。
func (s *Service) UpsertSensitiveString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error {
	return s.upsertString(ctx, group, key, value, description, true, operatorID)
}

func (s *Service) upsertString(ctx context.Context, group, key, value, description string, sensitive bool, operatorID uuid.UUID) error {
	// 秘密材料键统一按敏感行落库（调用方漏标时兜底，List/审计脱敏以该标记为准）
	sensitive = sensitive || SensitiveSettingKeys[group+":"+key]
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description, updated_by)
VALUES ($1, $2, $3::jsonb, 'string', $4, $5, $6)
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, is_sensitive = EXCLUDED.is_sensitive,
    updated_by = EXCLUDED.updated_by,
    updated_at = now(), version = system_settings.version + 1`,
		group, key, string(raw), sensitive, description, operatorID)
	return err
}

// UpsertBool 覆盖写入布尔设置（与 UpsertString 同语义，value_type='boolean'）。
// 用于运行期总开关类设置（如 apm:enabled）。
func (s *Service) UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description, updated_by)
VALUES ($1, $2, $3::jsonb, 'boolean', $4, $5)
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_by = EXCLUDED.updated_by,
    updated_at = now(), version = system_settings.version + 1`,
		group, key, string(raw), description, operatorID)
	return err
}

// Delete 删除设置行（清除界面覆盖、回退环境变量兜底值用；不存在不报错）。
func (s *Service) Delete(ctx context.Context, group, key string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM system_settings WHERE setting_group = $1 AND setting_key = $2`, group, key)
	return err
}

// GetBoolWithSource 读取布尔设置并报告是否命中数据库记录（镜像 GetStringWithSource，
// 覆盖来源判定用）。无记录返回 found=false；数据库错误如实返回，不静默回退默认值。
func (s *Service) GetBoolWithSource(ctx context.Context, group, key string) (value bool, found bool, err error) {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, nil
		}
		return false, false, err
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		return false, false, err
	}
	return b, true, nil
}

// GetInt 读取整数设置。
func (s *Service) GetInt(ctx context.Context, group, key string, def int) int {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		return def
	}
	var n int
	if err := json.Unmarshal(v, &n); err != nil {
		return def
	}
	return n
}

// GetFloat 读取浮点设置（JSON 数字；APM 告警比率阈值等小数值用）。
func (s *Service) GetFloat(ctx context.Context, group, key string, def float64) float64 {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		return def
	}
	var n float64
	if err := json.Unmarshal(v, &n); err != nil {
		return def
	}
	return n
}

// GetBool 读取布尔设置。
func (s *Service) GetBool(ctx context.Context, group, key string, def bool) bool {
	v, err := s.getValue(ctx, group, key)
	if err != nil {
		return def
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		return def
	}
	return b
}

func (s *Service) getValue(ctx context.Context, group, key string) (json.RawMessage, error) {
	var v json.RawMessage
	err := s.db.QueryRow(ctx,
		`SELECT setting_value FROM system_settings WHERE setting_group = $1 AND setting_key = $2`,
		group, key).Scan(&v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// PasswordPolicy 读取密码策略。
func (s *Service) PasswordPolicy(ctx context.Context) security.PasswordPolicy {
	def := security.DefaultPasswordPolicy()
	return security.PasswordPolicy{
		MinLength:        s.GetInt(ctx, "password", "min_length", def.MinLength),
		RequireUpper:     s.GetBool(ctx, "password", "require_uppercase", def.RequireUpper),
		RequireLower:     s.GetBool(ctx, "password", "require_lowercase", def.RequireLower),
		RequireDigit:     s.GetBool(ctx, "password", "require_digit", def.RequireDigit),
		RequireSpecial:   s.GetBool(ctx, "password", "require_special", def.RequireSpecial),
		HistoryCount:     s.GetInt(ctx, "password", "history_count", def.HistoryCount),
		ExpireDays:       s.GetInt(ctx, "password", "expire_days", def.ExpireDays),
		ExpireRemindDays: s.GetInt(ctx, "password", "expire_remind_days", def.ExpireRemindDays),
		CheckWeak:        s.GetBool(ctx, "password", "check_weak", def.CheckWeak),
	}
}

// LoginPolicy 是登录策略。
type LoginPolicy struct {
	MaxFailedAttempts    int
	LockMinutes          int
	CaptchaEnabled       bool
	CaptchaExpireSecs    int
	CaptchaCaseSensitive bool
	RateLimitPerMinute   int
	AllowMultiSession    bool
}

// LoginPolicy 读取登录策略。
func (s *Service) LoginPolicy(ctx context.Context) LoginPolicy {
	return LoginPolicy{
		MaxFailedAttempts:    s.GetInt(ctx, "login", "max_failed_attempts", 5),
		LockMinutes:          s.GetInt(ctx, "login", "lock_minutes", 15),
		CaptchaEnabled:       s.GetBool(ctx, "login", "captcha_enabled", true),
		CaptchaExpireSecs:    s.GetInt(ctx, "login", "captcha_expire_seconds", 120),
		CaptchaCaseSensitive: s.GetBool(ctx, "login", "captcha_case_sensitive", false),
		RateLimitPerMinute:   s.GetInt(ctx, "login", "rate_limit_per_minute", 10),
		AllowMultiSession:    s.GetBool(ctx, "login", "allow_multi_session", true),
	}
}

// SessionPolicyValues 读取会话策略（转换为 sessions.Policy 由 app 层完成）。
func (s *Service) SessionPolicyValues(ctx context.Context) (idleMin, absHours, maxPerUser int, allowMulti bool) {
	return s.GetInt(ctx, "session", "idle_timeout_minutes", 30),
		s.GetInt(ctx, "session", "absolute_timeout_hours", 8),
		s.GetInt(ctx, "session", "max_sessions_per_user", 5),
		s.GetBool(ctx, "login", "allow_multi_session", true)
}

// List 按分组列出设置（敏感值脱敏）。
func (s *Service) List(ctx context.Context, group string) ([]Setting, error) {
	var rows pgx.Rows
	var err error
	if group == "" {
		rows, err = s.db.Query(ctx, `
SELECT id, setting_group, setting_key, setting_value, value_type, is_sensitive, description, updated_at, version
FROM system_settings ORDER BY setting_group, setting_key`)
	} else {
		rows, err = s.db.Query(ctx, `
SELECT id, setting_group, setting_key, setting_value, value_type, is_sensitive, description, updated_at, version
FROM system_settings WHERE setting_group = $1 ORDER BY setting_key`, group)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Setting
	for rows.Next() {
		var st Setting
		if err := rows.Scan(&st.ID, &st.Group, &st.Key, &st.Value, &st.ValueType,
			&st.IsSensitive, &st.Description, &st.UpdatedAt, &st.Version); err != nil {
			return nil, err
		}
		if isSensitiveSetting(st.Group, st.Key, st.IsSensitive) {
			st.IsSensitive = true
			st.Value = json.RawMessage(`"********"`)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Update 更新设置（乐观锁 + 类型校验 + 数值范围校验）。
// 返回 sensitive 报告该设置是否为敏感行（DB 标记或 SensitiveSettingKeys 命中），
// 供调用方对审计摘要脱敏。
func (s *Service) Update(ctx context.Context, group, key string, value json.RawMessage, expectedVersion int, operatorID uuid.UUID) (bool, error) {
	// 校验值类型与设置存在性
	var valueType string
	var curVersion int
	var rowSensitive bool
	err := s.db.QueryRow(ctx,
		`SELECT value_type, version, is_sensitive FROM system_settings WHERE setting_group = $1 AND setting_key = $2`,
		group, key).Scan(&valueType, &curVersion, &rowSensitive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	if curVersion != expectedVersion {
		return false, fmt.Errorf("version conflict")
	}
	if err := validateValueType(valueType, value); err != nil {
		return false, err
	}
	if err := validateValueRange(group, key, valueType, value); err != nil {
		return false, err
	}
	res, err := s.db.Exec(ctx, `
UPDATE system_settings SET setting_value = $1, updated_by = $2, updated_at = now(), version = version + 1
WHERE setting_group = $3 AND setting_key = $4 AND version = $5`,
		value, operatorID, group, key, expectedVersion)
	if err != nil {
		return false, err
	}
	if res.RowsAffected() == 0 {
		return false, fmt.Errorf("version conflict")
	}
	return isSensitiveSetting(group, key, rowSensitive), nil
}

// settingValueRanges 数值类安全策略的取值范围（group:key → [min, max]）。
// 防 0/负数等异常值削弱安全控制（如 max_failed_attempts=0 关闭账号锁定、
// min_length=0 放行弱口令）；expire_days/history_count 的 0 为合法语义
// （不过期/不记历史，消费侧已按 0 特判），故下限取 0。
var settingValueRanges = map[string][2]int{
	"password:min_length":            {8, 128},
	"password:history_count":         {0, 50},
	"password:expire_days":           {0, 3650},
	"password:expire_remind_days":    {0, 365},
	"login:max_failed_attempts":      {1, 20},
	"login:lock_minutes":             {1, 1440},
	"login:captcha_expire_seconds":   {30, 3600},
	"login:rate_limit_per_minute":    {1, 10000},
	"session:idle_timeout_minutes":   {1, 1440},
	"session:absolute_timeout_hours": {1, 720},
	"session:max_sessions_per_user":  {1, 100},
	"logging:body_limit_kb":          {1, 1024},
	"logging:retention_days":         {1, 3650},
}

// validateValueRange 校验数值类安全策略的取值范围（仅命中 settingValueRanges 的整数键；
// 错误信息含 "value must be"，handler 据此映射 400）。
func validateValueRange(group, key, valueType string, value json.RawMessage) error {
	r, ok := settingValueRanges[group+":"+key]
	if !ok || valueType != "integer" {
		return nil
	}
	var n int
	if err := json.Unmarshal(value, &n); err != nil {
		return fmt.Errorf("value must be integer")
	}
	if n < r[0] || n > r[1] {
		return fmt.Errorf("value must be in range [%d, %d]（%s:%s）", r[0], r[1], group, key)
	}
	return nil
}

// validateValueType 校验 JSON 值与声明类型一致。
func validateValueType(valueType string, value json.RawMessage) error {
	switch valueType {
	case "integer":
		var n int
		if err := json.Unmarshal(value, &n); err != nil {
			return fmt.Errorf("value must be integer")
		}
	case "boolean":
		var b bool
		if err := json.Unmarshal(value, &b); err != nil {
			return fmt.Errorf("value must be boolean")
		}
	case "string":
		var str string
		if err := json.Unmarshal(value, &str); err != nil {
			return fmt.Errorf("value must be string")
		}
	default:
		var any interface{}
		if err := json.Unmarshal(value, &any); err != nil {
			return fmt.Errorf("value must be valid json")
		}
	}
	return nil
}

// AllowedSettingKeys 返回允许通过接口修改的设置键白名单（防注入未知设置）。
var AllowedSettingKeys = map[string]bool{
	"password:min_length": true, "password:require_uppercase": true,
	"password:require_lowercase": true, "password:require_digit": true,
	"password:require_special": true, "password:history_count": true,
	"password:expire_days": true, "password:expire_remind_days": true,
	"password:check_weak":       true,
	"login:max_failed_attempts": true, "login:lock_minutes": true,
	"login:captcha_enabled": true, "login:captcha_expire_seconds": true,
	"login:captcha_case_sensitive": true, "login:rate_limit_per_minute": true,
	"login:allow_multi_session":    true,
	"session:idle_timeout_minutes": true, "session:absolute_timeout_hours": true,
	"session:revoke_on_password_change": true, "session:max_sessions_per_user": true,
	"session:cookie_samesite": true,
	"display:system_name":     true, "display:system_short_name": true,
	"display:login_title": true, "display:support_info": true,
	"display:default_timezone": true, "display:default_language": true,
	// 全量访问日志（二期）：logging 组
	"logging:access_log_enabled": true, "logging:capture_request_headers": true,
	"logging:capture_request_body": true, "logging:capture_response_headers": true,
	"logging:capture_response_body": true, "logging:body_limit_kb": true,
	"logging:retention_days": true,
	// syslog 外发（三期）：logging 组
	"logging:syslog_enabled": true, "logging:syslog_protocol": true,
	"logging:syslog_address": true, "logging:syslog_facility": true,
	"logging:syslog_forward_security_events":       true,
	"logging:syslog_forward_access_control_events": true,
	"logging:syslog_forward_access_logs":           true,
	"logging:syslog_forward_operation_audits":      true,
	"logging:syslog_forward_login_logs":            true,
	"logging:syslog_forward_system_alerts":         true,
	// 告警通知外发（一期）：notify 组通知层风暴抑制参数
	"notify:notify_rate_limit_per_minute": true, "notify:notify_mute_minutes": true,
	"notify:notify_group_window_seconds": true, "notify:notify_resolved": true,
	// 告警通知外发（二期）：notify 组安全事件聚合告警阈值
	"notify:notify_security_spike_threshold": true, "notify:notify_cc_spike_threshold": true,
	// 阶段8 / WDSP：API 学习自动化调优（learningjobs 消费侧带校验与默认回落）
	"api_learning:sweep_interval_seconds": true, "api_learning:min_valid_samples": true,
	"api_learning:min_unique_ips": true, "api_learning:min_unique_identities": true,
	"api_learning:min_learning_duration_seconds": true, "api_learning:max_learning_duration_seconds": true,
	"api_learning:minimum_success_ratio": true,
	// 阶段8 / WDSP：网关运行时设置（发布通道下发；非法值中止发布）
	"gateway_runtime:behavior_store": true, "gateway_runtime:behavior_store_ttl_seconds": true,
	"gateway_runtime:identity_salt": true, "gateway_runtime:tls_session_ticket_key": true,
	"gateway_runtime:credential_ip_spread_limit":   true,
	"gateway_runtime:credential_concurrency_limit": true, "gateway_runtime:api_write_rate_per_minute": true,
	"gateway_runtime:api_response_fail_policy": true, "gateway_runtime:api_response_capture_max_bytes": true,
	"gateway_runtime:api_llm_allowed_models":   true,
	"gateway_runtime:api_grpc_max_frame_bytes": true, "gateway_runtime:api_grpc_allow_compression": true,
	"gateway_runtime:api_file_watermark_enabled": true, "gateway_runtime:api_file_watermark_template": true,
	"gateway_runtime:api_file_watermark_content_types": true, "gateway_runtime:api_file_watermark_json_key": true,
	// 阶段8 / WDSP：数据出境本土地区配置（apigeo 消费侧校验）
	"api_data:home_regions": true,
	// 阶段8 / WDSP：文件批量下载风险阈值（apifiles 风险规则）
	"api_data:file_bulk_download_threshold": true,
	// 阶段8 / WDSP：文件签名验证时间窗（apifiles 签名验证）
	"api_data:file_signature_max_age_days": true,
	// APM 端点性能告警阈值（systemalerts/endpoint_perf.go 消费侧带区间校验与默认回落；种子见迁移 000089）
	"apm_alert:endpoint_p95_ms": true, "apm_alert:endpoint_error_rate": true,
	"apm_alert:min_requests": true, "apm_alert:sustain_minutes": true,
	// APM 数据面采集滞后阈值（systemalerts/ingest_lag.go 消费侧带区间校验与默认回落；种子见迁移 000094）
	"apm_alert:ingest_lag_seconds": true,
	// APM 深度诊断 kill switch（阶段4；种子见迁移 000093——专用接口
	// POST /apm/diagnostics/kill-switch 之外，允许经系统设置 Update API 在线调整）
	"apm_diagnostics:kill_switch": true,
}
