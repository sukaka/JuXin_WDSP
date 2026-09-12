// store.go 通知渠道持久化：config JSONB 中密值字段 AES-256-GCM 加密落库（enc:v1: 前缀），
// 接口读出脱敏为 ********；写入 ******** 表示保留原值（handler 层用现有密文值替换后再走 Store）。
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// ErrNotFound 渠道不存在。
var ErrNotFound = errors.New("notification channel not found")

// MaskedValue 是接口读出的密值占位符；写入该值表示保留原值。
const MaskedValue = "********"

// encPrefix 是加密密值在 config JSONB 中的前缀（区分明文与密文）。
const encPrefix = "enc:v1:"

// secretFields 是各渠道类型 config 中的密值字段。
var secretFields = map[string][]string{
	TypeWecom:  {"webhook_url"},
	TypeFeishu: {"webhook_url", "secret"},
	TypeSMTP:   {"password"},
	TypeSyslog: {},
	TypeSMS:    {"app_secret"},
}

// ChannelStore 是渠道仓储接口（*Store 实现；dispatcher 单测用内存 fake）。
type ChannelStore interface {
	ListDecrypted(ctx context.Context) ([]Channel, error)
}

// Store 是通知渠道仓储。
type Store struct {
	db  *pgxpool.Pool
	enc *encryption.Service
}

// NewStore 创建渠道仓储（enc 为 nil 时密值字段加解密不可用，读写密值配置将报错）。
func NewStore(db *pgxpool.Pool, enc *encryption.Service) *Store {
	return &Store{db: db, enc: enc}
}

// Create 新建渠道（Config 为明文，密值字段加密后落库）。
func (s *Store) Create(ctx context.Context, c *Channel) error {
	cfg, err := s.encryptConfig(c.Type, c.Config)
	if err != nil {
		return err
	}
	c.ID = uuid.New()
	err = s.db.QueryRow(ctx, `
INSERT INTO notification_channels (id, name, type, enabled, min_severity, categories, config)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at, updated_at`,
		c.ID, c.Name, c.Type, c.Enabled, c.MinSeverity, mustJSON(c.Categories), mustJSON(cfg),
	).Scan(&c.CreatedAt, &c.UpdatedAt)
	return err
}

// Update 更新渠道（Config 为明文，密值字段加密后落库；保留原值语义由 handler 预处理）。
func (s *Store) Update(ctx context.Context, c *Channel) error {
	cfg, err := s.encryptConfig(c.Type, c.Config)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `
UPDATE notification_channels SET name=$2, type=$3, enabled=$4, min_severity=$5,
  categories=$6, config=$7, updated_at=now()
WHERE id=$1`,
		c.ID, c.Name, c.Type, c.Enabled, c.MinSeverity, mustJSON(c.Categories), mustJSON(cfg))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete 删除渠道。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM notification_channels WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetDecrypted 查询渠道（密值字段解密为明文，仅服务端内部使用：发送/测试/更新保留原值）。
func (s *Store) GetDecrypted(ctx context.Context, id uuid.UUID) (*Channel, error) {
	c, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	cfg, err := s.decryptConfig(c.Type, c.Config)
	if err != nil {
		return nil, fmt.Errorf("decrypt channel %s config: %w", c.ID, err)
	}
	c.Config = cfg
	return c, nil
}

// ListDecrypted 列出全部渠道（密值字段解密为明文，dispatcher 发送用）。
func (s *Store) ListDecrypted(ctx context.Context) ([]Channel, error) {
	list, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		cfg, err := s.decryptConfig(list[i].Type, list[i].Config)
		if err != nil {
			return nil, fmt.Errorf("decrypt channel %s config: %w", list[i].ID, err)
		}
		list[i].Config = cfg
	}
	return list, nil
}

// GetMasked 查询渠道（密值字段脱敏为 ********，接口读出用）。
func (s *Store) GetMasked(ctx context.Context, id uuid.UUID) (*Channel, error) {
	c, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	c.Config = maskConfig(c.Type, c.Config)
	return c, nil
}

// ListMasked 列出全部渠道（密值字段脱敏，接口读出用）。
func (s *Store) ListMasked(ctx context.Context) ([]Channel, error) {
	list, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Config = maskConfig(list[i].Type, list[i].Config)
	}
	return list, nil
}

func (s *Store) get(ctx context.Context, id uuid.UUID) (*Channel, error) {
	var c Channel
	var categories, config []byte
	err := s.db.QueryRow(ctx, `
SELECT id, name, type, enabled, min_severity, categories, config, created_at, updated_at
FROM notification_channels WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &c.MinSeverity, &categories, &config, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(categories, &c.Categories); err != nil {
		return nil, fmt.Errorf("decode channel categories: %w", err)
	}
	if err := json.Unmarshal(config, &c.Config); err != nil {
		return nil, fmt.Errorf("decode channel config: %w", err)
	}
	c.normalize()
	return &c, nil
}

func (s *Store) list(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, name, type, enabled, min_severity, categories, config, created_at, updated_at
FROM notification_channels ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var c Channel
		var categories, config []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &c.MinSeverity,
			&categories, &config, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(categories, &c.Categories); err != nil {
			return nil, fmt.Errorf("decode channel categories: %w", err)
		}
		if err := json.Unmarshal(config, &c.Config); err != nil {
			return nil, fmt.Errorf("decode channel config: %w", err)
		}
		c.normalize()
		out = append(out, c)
	}
	return out, rows.Err()
}

// normalize 保证 JSON 输出稳定（categories 为 []、config 为 {} 而非 null）。
func (c *Channel) normalize() {
	if c.Categories == nil {
		c.Categories = []string{}
	}
	if c.Config == nil {
		c.Config = map[string]interface{}{}
	}
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// encryptConfig 加密 config 中的密值字段（已带 enc:v1: 前缀的原样保留）。
func (s *Store) encryptConfig(channelType string, cfg map[string]interface{}) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	for k, v := range cfg {
		out[k] = v
	}
	for _, field := range secretFields[channelType] {
		raw, _ := out[field].(string)
		if raw == "" || strings.HasPrefix(raw, encPrefix) {
			continue
		}
		if s.enc == nil {
			return nil, fmt.Errorf("加密服务不可用，无法保存密值字段 %s", field)
		}
		ct, err := s.enc.Encrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("加密密值字段 %s 失败: %w", field, err)
		}
		out[field] = encPrefix + ct
	}
	return out, nil
}

// decryptConfig 解密 config 中的密值字段；密文损坏/密钥不匹配如实返回错误（不静默降级为空）。
func (s *Store) decryptConfig(channelType string, cfg map[string]interface{}) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	for k, v := range cfg {
		out[k] = v
	}
	for _, field := range secretFields[channelType] {
		raw, _ := out[field].(string)
		if !strings.HasPrefix(raw, encPrefix) {
			continue
		}
		if s.enc == nil {
			return nil, fmt.Errorf("加密服务不可用，无法解密密值字段 %s", field)
		}
		plain, err := s.enc.Decrypt(strings.TrimPrefix(raw, encPrefix))
		if err != nil {
			return nil, fmt.Errorf("解密密值字段 %s 失败: %w", field, err)
		}
		out[field] = plain
	}
	return out, nil
}

// maskConfig 脱敏 config 中的密值字段（非空 → ********；空保持空）。
func maskConfig(channelType string, cfg map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range cfg {
		out[k] = v
	}
	for _, field := range secretFields[channelType] {
		if raw, _ := out[field].(string); raw != "" {
			out[field] = MaskedValue
		}
	}
	return out
}

// ---------- config 解析与校验 ----------

// WecomConfig 是企业微信群机器人配置。
type WecomConfig struct {
	WebhookURL string `json:"webhook_url"`
	MentionAll bool   `json:"mention_all"`
}

// FeishuConfig 是飞书自定义机器人配置（Secret 可空，非空时按飞书文档 timestamp+sign 签名）。
type FeishuConfig struct {
	WebhookURL string `json:"webhook_url"`
	Secret     string `json:"secret,omitempty"`
}

// SMTPConfig 是邮件渠道配置。
type SMTPConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Security string   `json:"security"` // none / starttls / ssl
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// SMSConfig 是短信渠道配置（通用 HTTP 短信网关；app_secret 为密值字段，加密落库/脱敏读出）。
type SMSConfig struct {
	GatewayURL string   `json:"gateway_url"`
	AppKey     string   `json:"app_key"`
	AppSecret  string   `json:"app_secret,omitempty"`
	TemplateID string   `json:"template_id"`
	Phones     []string `json:"phones"`
}

// ParseWecomConfig 解析并校验企业微信配置。
func ParseWecomConfig(cfg map[string]interface{}) (WecomConfig, error) {
	var out WecomConfig
	if err := strictDecode(cfg, &out); err != nil {
		return out, err
	}
	if err := checkWebhookURL(TypeWecom, out.WebhookURL); err != nil {
		return out, fmt.Errorf("webhook_url %w", err)
	}
	return out, nil
}

// ParseFeishuConfig 解析并校验飞书配置。
func ParseFeishuConfig(cfg map[string]interface{}) (FeishuConfig, error) {
	var out FeishuConfig
	if err := strictDecode(cfg, &out); err != nil {
		return out, err
	}
	if err := checkWebhookURL(TypeFeishu, out.WebhookURL); err != nil {
		return out, fmt.Errorf("webhook_url %w", err)
	}
	return out, nil
}

// ParseSMTPConfig 解析并校验邮件配置。
func ParseSMTPConfig(cfg map[string]interface{}) (SMTPConfig, error) {
	var out SMTPConfig
	if err := strictDecode(cfg, &out); err != nil {
		return out, err
	}
	if strings.TrimSpace(out.Host) == "" {
		return out, fmt.Errorf("host 不能为空")
	}
	if out.Port < 1 || out.Port > 65535 {
		return out, fmt.Errorf("port 须在 1~65535 之间")
	}
	switch out.Security {
	case "none", "starttls", "ssl":
	default:
		return out, fmt.Errorf("security 须为 none/starttls/ssl")
	}
	if !isValidEmail(out.From) {
		return out, fmt.Errorf("from 须为合法邮箱地址")
	}
	if len(out.To) == 0 {
		return out, fmt.Errorf("to 收件人列表不能为空")
	}
	for _, addr := range out.To {
		if !isValidEmail(addr) {
			return out, fmt.Errorf("to 含非法邮箱地址: %q", addr)
		}
	}
	return out, nil
}

// emailRe 严格邮箱格式（与 reports/schedule.go 同一口径）。
var emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

// isValidEmail 严格校验邮箱地址：格式匹配 emailRe 且显式拒绝控制字符
// （CRLF 等不得混入，防邮件头/信封注入面在配置层落地）。
func isValidEmail(addr string) bool {
	if addr == "" || len(addr) > 254 {
		return false
	}
	for i := 0; i < len(addr); i++ {
		if addr[i] < 0x20 || addr[i] == 0x7f {
			return false
		}
	}
	return emailRe.MatchString(addr)
}

// ParseSMSConfig 解析并校验短信配置。
func ParseSMSConfig(cfg map[string]interface{}) (SMSConfig, error) {
	var out SMSConfig
	if err := strictDecode(cfg, &out); err != nil {
		return out, err
	}
	if err := checkWebhookURL(TypeSMS, out.GatewayURL); err != nil {
		return out, fmt.Errorf("gateway_url %w", err)
	}
	if strings.TrimSpace(out.AppKey) == "" {
		return out, fmt.Errorf("app_key 不能为空")
	}
	if strings.TrimSpace(out.TemplateID) == "" {
		return out, fmt.Errorf("template_id 不能为空")
	}
	if len(out.Phones) == 0 {
		return out, fmt.Errorf("phones 手机号列表不能为空")
	}
	for _, p := range out.Phones {
		if !isValidPhone(p) {
			return out, fmt.Errorf("phones 含非法手机号: %s", p)
		}
	}
	return out, nil
}

// isValidPhone 宽松校验手机号（数字串，可带前导 +，5~20 位；具体号段由厂商网关校验）。
func isValidPhone(p string) bool {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "+")
	if len(p) < 5 || len(p) > 20 {
		return false
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ValidateConfig 按渠道类型校验 config（语法/密值/官方域名；dispatcher 发送前与
// 保存时深度校验 ValidateChannelConfig 共用；CRUD 保存入口请走 Dispatcher.
// ValidateChannelConfig，另含目标地址解析校验）。
func ValidateConfig(channelType string, cfg map[string]interface{}) error {
	switch channelType {
	case TypeWecom:
		_, err := ParseWecomConfig(cfg)
		return err
	case TypeFeishu:
		_, err := ParseFeishuConfig(cfg)
		return err
	case TypeSMTP:
		_, err := ParseSMTPConfig(cfg)
		return err
	case TypeSMS:
		_, err := ParseSMSConfig(cfg)
		return err
	case TypeSyslog:
		return nil // syslog 渠道无自有配置（沿用 logging 组 syslog 配置）
	}
	return fmt.Errorf("未知的渠道类型: %s", channelType)
}

// strictDecode map→结构体（拒绝未知字段，防止配置键拼写错误静默失效）。
func strictDecode(cfg map[string]interface{}, dst interface{}) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config 格式错误: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("config 格式错误: %w", err)
	}
	return nil
}
