// Package jwttrust 业务 JWT 信任链管理面（WDSP P0-03，任务书
// docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md）：按应用的 JWT 验证策略 CRUD/校验/预检，
// 经既有配置发布通道下发网关 jwt_trust 段。服务端不验签（无 JOSE 依赖），
// 仅负责策略结构校验、静态 JWKS 公钥校验（stdlib）、REMOTE_JWKS 地址 SSRF 校验与发布门禁。
package jwttrust

import (
	"time"

	"github.com/google/uuid"
)

// 策略模式（默认 OFF：不校验 Token、不产生可信主体、不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 密钥来源（二选一）。
const (
	KeySourceStaticJWKS = "STATIC_JWKS"
	KeySourceRemoteJWKS = "REMOTE_JWKS"
)

// 支持的签名算法白名单（不由 Token 扩展；拒绝 none/HS 系列）。
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// 校验边界（任务书 §4.1/§5.2 产品限制）。
const (
	MaxIssuers           = 8          // 每策略 issuer 上限
	MaxSelectors         = 64         // 每策略 selector 上限
	DefaultClockSkew     = 30         // clock_skew_seconds 默认值（秒）
	MaxClockSkew         = 120        // clock_skew_seconds 上限（秒）
	MaxIssuerLen         = 512        // issuer 精确值长度上限
	MaxAudienceLen       = 256        // 单 audience 长度上限
	MaxAudiences         = 16         // 每 issuer audience 上限
	MaxSelectorPathLen   = 512        // path_exact/path_prefix 长度上限
	MaxSelectorMethods   = 16         // 单 selector 方法数上限
	MaxTenantClaimLen    = 64         // tenant_claim 长度上限
	MaxReasonLen         = 500        // 变更理由长度上限
	MaxKIDBytes          = 256        // kid 上限（字节，任务书 §5.2）
	MaxJWKSKeys          = 32         // 单份 JWKS 公钥上限
	MaxJWKSBytes         = 256 * 1024 // 单份 JWKS 大小上限（256 KiB）
	MinRSAKeyBits        = 2048       // RSA 公钥最小位数
	remoteJWKSTimeoutSec = 2          // REMOTE_JWKS 受限连通性检查超时（秒，任务书 §6.1）
	// SchemaVersion 是下发网关 jwt_trust 段的配置结构版本（旧网关节点不识别该段时
	// 必须拒绝加载而不是忽略强制语义——任务书 JWT-14；网关侧检查在集成步骤实现）。
	SchemaVersion = 1
)

// Selector 请求范围选择器：methods 大写去重；path_exact/path_prefix 二选一；
// prefix 按完整路径段匹配（/api 匹配 /api 与 /api/orders，不匹配 /apix）；
// 路径不含 query；不同 selector 之间 OR，重叠时 token_required 取 true 优先。
type Selector struct {
	Methods       []string `json:"methods"`
	PathExact     string   `json:"path_exact,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
	TokenRequired bool     `json:"token_required"`
}

// KeySource issuer 密钥来源：STATIC_JWKS 仅公钥 JWKS（拒绝私钥参数/对称密钥）；
// REMOTE_JWKS 仅预配置 HTTPS 地址（SSRF 校验，保存时与预检同一规则）。
type KeySource struct {
	Type string `json:"type"` // STATIC_JWKS | REMOTE_JWKS
	// JWKS 静态公钥集（STATIC_JWKS 必填；原始 JSON，下发前经校验只含公钥）。
	JWKS string `json:"jwks,omitempty"`
	// URL 远程 JWKS 地址（REMOTE_JWKS 必填；仅 HTTPS）。
	URL string `json:"url,omitempty"`
}

// Issuer 受信发行方配置（issuer 为大小写敏感精确值，策略内唯一）。
type Issuer struct {
	Issuer           string    `json:"issuer"`
	Audiences        []string  `json:"audiences"`
	Algorithms       []string  `json:"algorithms"`
	KeySource        KeySource `json:"key_source"`
	ClockSkewSeconds int       `json:"clock_skew_seconds"`
	// TenantClaim 可选、管理员选定的单一受信声明名；只在 VERIFIED 后读取，不自动猜测。
	TenantClaim string `json:"tenant_claim,omitempty"`
}

// Policy 应用 JWT 信任策略（当前草稿；与 jwt_trust_policies 表列对应）。
// Version 为乐观锁版本（不可变递增；PUT 携带 expected_version 防并发覆盖）。
// 无策略记录的应用按 DefaultPolicy 处理（OFF 空策略，version=0）。
type Policy struct {
	ID            uuid.UUID  `json:"id"`
	ApplicationID uuid.UUID  `json:"application_id"`
	Mode          string     `json:"mode"`
	Version       int        `json:"version"`
	Selectors     []Selector `json:"selectors"`
	Issuers       []Issuer   `json:"issuers"`
	UpdatedBy     string     `json:"updated_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// DefaultPolicy 历史应用无记录时的默认策略（OFF 空策略，version=0；
// PUT 以 expected_version=0 创建首版草稿）。
func DefaultPolicy(appID uuid.UUID) *Policy {
	return &Policy{
		ApplicationID: appID,
		Mode:          ModeOff,
		Version:       0,
		Selectors:     []Selector{},
		Issuers:       []Issuer{},
	}
}

// StatusSummary GET 状态摘要：草稿版本 vs 最近成功发布快照中的生效版本。
// state 取值：NOT_CONFIGURED（无草稿）/ DRAFT_PENDING（草稿未发布或领先已发布）/
// PUBLISHED（草稿与最近成功发布一致）；发布失败不回退草稿——旧有效版本继续运行。
type StatusSummary struct {
	State            string `json:"state"`
	DraftVersion     int    `json:"draft_version"`
	PublishedVersion int    `json:"published_version"` // 最近 SUCCESS 发布快照中本应用的策略版本（0=未随发布下发）
}

// 状态词表。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)
