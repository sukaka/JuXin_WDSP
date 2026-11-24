// Package acme 提供基于 RFC 8555（ACME v2）的自动 SSL 证书申请、到期自动续约、
// HTTP-01 挑战编排、分布式锁防重与自动网关发布集成能力。
package acme

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ACME CA 提供商词表
const (
	ProviderLetsEncrypt        = "LETSENCRYPT"
	ProviderLetsEncryptStaging = "LETSENCRYPT_STAGING"
	ProviderCustom             = "CUSTOM"

	DirectoryLetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	DirectoryLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// 挑战验证类型词表（一期实现 HTTP01，接口预留 DNS01 扩展）
const (
	ChallengeHTTP01 = "HTTP01"
	ChallengeDNS01  = "DNS01"
)

// 证书密钥算法词表
const (
	KeyTypeEC256   = "EC256"
	KeyTypeEC384   = "EC384"
	KeyTypeRSA2048 = "RSA2048"
)

// 订单触发来源词表
const (
	TriggerAutoInit       = "AUTO_INIT"
	TriggerAutoRenew      = "AUTO_RENEW"
	TriggerAutoDomainSync = "AUTO_DOMAIN_SYNC"
	TriggerManualIssue    = "MANUAL_ISSUE"
	TriggerManualRenew    = "MANUAL_RENEW"
)

// 订单状态词表
const (
	OrderPending       = "PENDING"
	OrderPreparing     = "PREPARING"
	OrderValidating    = "VALIDATING"
	OrderFinalizing    = "FINALIZING"
	OrderIssued        = "ISSUED"
	OrderPublishing    = "PUBLISHING"
	OrderSucceeded     = "SUCCEEDED"
	OrderPublishFailed = "PUBLISH_FAILED"
	OrderFailed        = "FAILED"
)

// 领域错误
var (
	ErrConfigNotEnabled   = errors.New("全局自动证书（ACME）未启用")
	ErrConfigIncomplete   = errors.New("全局 ACME 配置不完整，请先填写联系邮箱并同意服务条款")
	ErrVersionConflict    = errors.New("配置已被其他人修改，请刷新后重试")
	ErrOrderInProgress    = errors.New("该站点已有正在进行的证书申请/续约任务，请稍候")
	ErrNoHTTPSDomains     = errors.New("该站点未启用任何 HTTPS 域名")
	ErrWildcardHTTP01     = errors.New("HTTP-01 验证不支持泛域名，请移除泛域名或手动上传证书")
	ErrMirrorUnsupported  = errors.New("镜像旁路模式不终结 TLS，不支持自动申请证书")
	ErrPrivateDomainOnCA  = errors.New("公网 CA 不支持私有或保留域名，请使用公网可解析域名或自定义私有 ACME CA")
	ErrManualCertNotRenew = errors.New("手动上传的证书不支持直接 ACME 续约，请在站点证书页开启自动 SSL")
	ErrOrderNotFound      = errors.New("证书申请记录不存在")
)

// Config 是全局 ACME 自动证书配置（对外序列化绝不包含 EAB HMAC 明文）。
type Config struct {
	Enabled                  bool       `json:"enabled"`
	Provider                 string     `json:"provider"`
	DirectoryURL             string     `json:"directory_url"`
	EffectiveDirectoryURL    string     `json:"effective_directory_url"`
	CustomDirectoryAllowlist string     `json:"custom_directory_allowlist"`
	Email                    string     `json:"email"`
	TOSAgreed                bool       `json:"tos_agreed"`
	EABKID                   string     `json:"eab_kid"`
	EABHMACConfigured        bool       `json:"eab_hmac_configured"`
	KeyType                  string     `json:"key_type"`
	RenewBeforeDays          int        `json:"renew_before_days"`
	AutoPublish              bool       `json:"auto_publish"`
	UpdatedBy                *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	Version                  int        `json:"version"`

	// 内部解密后的 EAB HMAC Key，永不通过 JSON 序列化暴露
	eabHMACKey string
}

// ConfigUpdateInput 是更新全局 ACME 配置的输入。
type ConfigUpdateInput struct {
	Enabled                  bool
	Provider                 string
	DirectoryURL             string
	CustomDirectoryAllowlist string
	Email                    string
	TOSAgreed                bool
	EABKID                   string
	EABHMACKey               string // 非空时加密覆写；为空时保持原值（除非 ClearEABHMACKey=true）
	ClearEABHMACKey          bool
	KeyType                  string
	RenewBeforeDays          int
	AutoPublish              bool
	UpdatedBy                uuid.UUID
	ExpectedVersion          int
}

// Account 是持久化在数据库中的 ACME 账户。
type Account struct {
	ID                  uuid.UUID
	Provider            string
	DirectoryURL        string
	Email               string
	AccountURI          string
	EncryptedPrivateKey string
	EABKID              string
	Status              string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Order 是一次证书申请/续约任务记录。
type Order struct {
	ID                    uuid.UUID  `json:"id"`
	ApplicationID         uuid.UUID  `json:"application_id"`
	AppCode               string     `json:"app_code,omitempty"`
	AppName               string     `json:"app_name,omitempty"`
	TriggerType           string     `json:"trigger_type"`
	Provider              string     `json:"provider"`
	DirectoryURL          string     `json:"directory_url"`
	ChallengeType         string     `json:"challenge_type"`
	Domains               []string   `json:"domains"`
	Status                string     `json:"status"`
	CertificateID         *uuid.UUID `json:"certificate_id,omitempty"`
	PreviousCertificateID *uuid.UUID `json:"previous_certificate_id,omitempty"`
	PublishTaskID         *uuid.UUID `json:"publish_task_id,omitempty"`
	ErrorCode             string     `json:"error_code"`
	ErrorMessage          string     `json:"error_message"`
	RequestedBy           *uuid.UUID `json:"requested_by,omitempty"`
	RequestID             string     `json:"request_id"`
	StartedAt             *time.Time `json:"started_at,omitempty"`
	FinishedAt            *time.Time `json:"finished_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// OrderFilter 是订单分页筛选条件。
type OrderFilter struct {
	ApplicationID *uuid.UUID
	Status        string
	Page          int
	PageSize      int
}

// ReadinessWarning 是站点自动 SSL 前置就绪检查提示。
type ReadinessWarning struct {
	Code    string `json:"code"`
	Level   string `json:"level"` // error / warning / info
	Message string `json:"message"`
}

// AppAutoSSLStatus 是站点自动 SSL 详情视图。
type AppAutoSSLStatus struct {
	ApplicationID            uuid.UUID          `json:"application_id"`
	Enabled                  bool               `json:"enabled"`
	ChallengeType            string             `json:"challenge_type"`
	RenewBeforeDays          *int               `json:"renew_before_days"`
	EffectiveRenewBeforeDays int                `json:"effective_renew_before_days"`
	GlobalACMEEnabled        bool               `json:"global_acme_enabled"`
	GlobalProvider           string             `json:"global_provider"`
	AutoPublish              bool               `json:"auto_publish"`
	HTTPSDomains             []string           `json:"https_domains"`
	LastStatus               string             `json:"last_status"`
	LastError                string             `json:"last_error"`
	FailCount                int                `json:"fail_count"`
	NextRetryAt              *time.Time         `json:"next_retry_at,omitempty"`
	LastAttemptAt            *time.Time         `json:"last_attempt_at,omitempty"`
	HasActiveOrder           bool               `json:"has_active_order"`
	LatestOrder              *Order             `json:"latest_order,omitempty"`
	Ready                    bool               `json:"ready"`
	Warnings                 []ReadinessWarning `json:"warnings"`
}

// TestConfigResult 是 ACME 目录连通性测试结果。
type TestConfigResult struct {
	Reachable       bool   `json:"reachable"`
	DirectoryURL    string `json:"directory_url"`
	LatencyMs       int64  `json:"latency_ms"`
	AuthzURL        string `json:"authz_url,omitempty"`
	OrderURL        string `json:"order_url,omitempty"`
	ExternalBinding bool   `json:"external_account_required"`
	Message         string `json:"message"`
}

// ValidateProvider 校验 ACME CA 提供商取值。
func ValidateProvider(p string) error {
	switch p {
	case ProviderLetsEncrypt, ProviderLetsEncryptStaging, ProviderCustom:
		return nil
	default:
		return fmt.Errorf("不支持的 ACME 提供商 %q（仅支持 LETSENCRYPT / LETSENCRYPT_STAGING / CUSTOM）", p)
	}
}

// EffectiveDirectoryURL 返回实际生效的 ACME 目录地址。
func EffectiveDirectoryURL(provider, customURL string) (string, error) {
	switch provider {
	case ProviderLetsEncrypt:
		return DirectoryLetsEncrypt, nil
	case ProviderLetsEncryptStaging:
		return DirectoryLetsEncryptStaging, nil
	case ProviderCustom:
		u := strings.TrimSpace(customURL)
		if u == "" {
			return "", fmt.Errorf("自定义 ACME 提供商必须填写目录地址（directory_url）")
		}
		return u, nil
	default:
		return "", ValidateProvider(provider)
	}
}

// ValidateKeyType 校验私钥算法取值。
func ValidateKeyType(kt string) error {
	switch kt {
	case KeyTypeEC256, KeyTypeEC384, KeyTypeRSA2048:
		return nil
	default:
		return fmt.Errorf("不支持的证书密钥算法 %q（仅支持 EC256 / EC384 / RSA2048）", kt)
	}
}

// ValidateEmail 校验 ACME 联系邮箱格式。
func ValidateEmail(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > 255 {
		return fmt.Errorf("请填写有效的联系邮箱")
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil || addr.Address != trimmed || !strings.Contains(trimmed, "@") {
		return fmt.Errorf("联系邮箱格式非法")
	}
	return nil
}

// IsActiveOrderStatus 判断订单是否仍处于进行中。
func IsActiveOrderStatus(s string) bool {
	switch s {
	case OrderPending, OrderPreparing, OrderValidating, OrderFinalizing, OrderIssued, OrderPublishing:
		return true
	default:
		return false
	}
}

// BackoffDuration 计算失败指数退避时长：15m, 30m, 1h, 2h, 4h, 8h, 16h，上限 24h。
func BackoffDuration(failCount int) time.Duration {
	if failCount <= 1 {
		return 15 * time.Minute
	}
	shift := failCount - 1
	if shift > 6 {
		shift = 6
	}
	d := 15 * time.Minute * (1 << shift)
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}
