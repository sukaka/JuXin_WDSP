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

// UpsertString 覆盖写入字符串设置（不存在则插入；命中则更新值并自增版本）。
// 用于运行期功能开关类设置（如 api_protection.mode），区别于管理界面带乐观锁的 Update。
func (s *Service) UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description, updated_by)
VALUES ($1, $2, $3::jsonb, 'string', $4, $5)
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_by = EXCLUDED.updated_by,
    updated_at = now(), version = system_settings.version + 1`,
		group, key, string(raw), description, operatorID)
	return err
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
		if st.IsSensitive {
			st.Value = json.RawMessage(`"********"`)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Update 更新设置（乐观锁 + 类型校验）。
func (s *Service) Update(ctx context.Context, group, key string, value json.RawMessage, expectedVersion int, operatorID uuid.UUID) error {
	// 校验值类型与设置存在性
	var valueType string
	var curVersion int
	err := s.db.QueryRow(ctx,
		`SELECT value_type, version FROM system_settings WHERE setting_group = $1 AND setting_key = $2`,
		group, key).Scan(&valueType, &curVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if curVersion != expectedVersion {
		return fmt.Errorf("version conflict")
	}
	if err := validateValueType(valueType, value); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE system_settings SET setting_value = $1, updated_by = $2, updated_at = now(), version = version + 1
WHERE setting_group = $3 AND setting_key = $4 AND version = $5`,
		value, operatorID, group, key, expectedVersion)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("version conflict")
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
	"logging:syslog_forward_security_events": true,
	"logging:syslog_forward_access_control_events": true,
	"logging:syslog_forward_access_logs": true,
}
