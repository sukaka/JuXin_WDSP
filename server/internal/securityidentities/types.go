// types.go client_identity 体系管理面类型（WDSP AI 自动化渗透防护增强 阶段1）。
package securityidentities

import (
	"time"

	"github.com/google/uuid"
)

// 身份风险等级/类型/状态合法值（查询筛选校验用；写侧由采集器/网关契约产生）。
var (
	validRiskLevels = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	validTypes      = map[string]bool{"HUMAN": true, "BOT": true, "APPLICATION": true, "SERVICE": true, "AGENT": true, "UNKNOWN": true}
	validSignals    = map[string]bool{
		"URI_ENUMERATION": true, "NOT_FOUND_ENUMERATION": true, "SENSITIVE_PATH_PROBE": true,
		"METHOD_ENUMERATION": true, "PARAMETER_MUTATION": true, "AUTH_FAIL_PROBE": true, "LOW_SLOW_RECON": true,
		"HEADLESS": true, "ACCOUNT_ENUMERATION": true, "OBJECT_ENUMERATION": true,
	}
	validWindows = map[string]bool{"1m": true, "5m": true, "30m": true, "24h": true}
)

// Identity 身份全字段（详情接口）。
type Identity struct {
	ID                 uuid.UUID  `json:"id"`
	IdentityKey        string     `json:"identity_key"`
	IdentityType       string     `json:"identity_type"`
	IdentityConfidence uint8      `json:"identity_confidence"`
	ConfidenceSource   []string   `json:"confidence_source"`
	FirstSeenAt        *time.Time `json:"first_seen_at"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
	PrimaryIP          *string    `json:"primary_ip"`
	ASN                string     `json:"asn"`
	TLSFingerprint     string     `json:"tls_fingerprint"`
	BrowserFingerprint string     `json:"browser_fingerprint"`
	AccountID          string     `json:"account_id"`
	JWTSubject         string     `json:"jwt_subject"`
	APIKeyHash         string     `json:"api_key_hash"`
	OAuthClientID      string     `json:"oauth_client_id"`
	DeviceType         string     `json:"device_type"`
	RiskScore          int        `json:"risk_score"`
	RiskLevel          string     `json:"risk_level"`
	Status             string     `json:"status"`
	RequestCount       int64      `json:"request_count"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// ListItem 身份列表项（含 IP 数聚合）。
type ListItem struct {
	ID                 uuid.UUID  `json:"id"`
	IdentityKey        string     `json:"identity_key"`
	IdentityType       string     `json:"identity_type"`
	IdentityConfidence uint8      `json:"identity_confidence"`
	RiskScore          int        `json:"risk_score"`
	RiskLevel          string     `json:"risk_level"`
	Status             string     `json:"status"`
	PrimaryIP          *string    `json:"primary_ip"`
	IPCount            int64      `json:"ip_count"`
	AccountID          string     `json:"account_id"`
	RequestCount       int64      `json:"request_count"`
	FirstSeenAt        *time.Time `json:"first_seen_at"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
}

// IPHistory 身份 × IP 历史项。
type IPHistory struct {
	IP           string     `json:"ip"`
	FirstSeenAt  *time.Time `json:"first_seen_at"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	RequestCount int64      `json:"request_count"`
}

// CredentialItem 身份凭据指纹项（只含哈希，不落明文凭据）。
type CredentialItem struct {
	CredentialType string     `json:"credential_type"`
	CredentialHash string     `json:"credential_hash"`
	FirstSeenAt    *time.Time `json:"first_seen_at"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
}

// BehaviorEvent 侦察信号事件项。
type BehaviorEvent struct {
	ID                 uuid.UUID      `json:"id"`
	OccurredAt         time.Time      `json:"occurred_at"`
	EventKind          string         `json:"event_kind"`
	RuleCode           string         `json:"rule_code"`
	RuleVersion        string         `json:"rule_version"`
	Signal             string         `json:"signal"`
	RiskScoreDelta     int            `json:"risk_score_delta"`
	Mode               string         `json:"mode"`
	Reason             string         `json:"reason"`
	Metadata           map[string]any `json:"metadata"`
	RequestID          string         `json:"request_id"`
	ClientIP           string         `json:"client_ip"`
	Method             string         `json:"method"`
	Path               string         `json:"path"`
	AppID              string         `json:"app_id"`
	Domain             string         `json:"domain"`
	GatewayNode        string         `json:"gateway_node"`
	IdentityConfidence uint8          `json:"identity_confidence"`
	IdentityEvidence   []string       `json:"identity_evidence"`
}

// BehaviorStat 行为窗口统计项（时间序列）。
type BehaviorStat struct {
	WindowType             string    `json:"window_type"`
	WindowStart            time.Time `json:"window_start"`
	RequestCount           int64     `json:"request_count"`
	UniqueURICount         int64     `json:"unique_uri_count"`
	NewURICount            int64     `json:"new_uri_count"`
	Status401Count         int64     `json:"status_401_count"`
	Status403Count         int64     `json:"status_403_count"`
	Status404Count         int64     `json:"status_404_count"`
	Status405Count         int64     `json:"status_405_count"`
	Status500Count         int64     `json:"status_500_count"`
	AuthFailCount          int64     `json:"auth_fail_count"`
	ParameterMutationCount int64     `json:"parameter_mutation_count"`
	SensitivePathHits      int64     `json:"sensitive_path_hits"`
	AccountEnumCount       int64     `json:"account_enum_count"`
	ObjectEnumCount        int64     `json:"object_enum_count"`
}

// ListFilter 身份列表筛选。
type ListFilter struct {
	RiskLevel    string
	IdentityType string
	Keyword      string // identity_key 前缀或 account_id
	IP           string // 命中 identity_ip_history 任一 IP
	From         *time.Time
	To           *time.Time
	Sort         string // last_seen_at（默认）/ risk_score / request_count / first_seen_at
	Order        string // desc（默认）/ asc
	Page         int
	PageSize     int
}

// BehaviorFilter 行为窗口序列筛选。
type BehaviorFilter struct {
	Window   string
	From     time.Time
	To       time.Time
	Page     int
	PageSize int
}

// EventFilter 信号事件筛选。
type EventFilter struct {
	Signal   string
	From     *time.Time
	To       *time.Time
	Page     int
	PageSize int
}
