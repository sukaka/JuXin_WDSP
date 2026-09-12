// result.go 冻结 JWT 验证结果契约（与网关侧共享；任务书 §5）。
// 本阶段（服务端管理面）仅冻结类型与枚举供 OpenAPI/事件字段对齐；
// 事件入库与网关上报字段接线在集成步骤完成。
package jwttrust

import "time"

// VerificationStatus 验证状态词表：
//   - NOT_PRESENT：selector 范围内未发现 Bearer Token；
//   - UNVERIFIED：策略关闭或请求不在校验范围（不可信，也非非法）；
//   - VERIFIED：签名/issuer/audience/时间/算法全部通过；
//   - INVALID：根据可用信任配置明确不合法；
//   - UNAVAILABLE：缺可用密钥或验证基础设施异常，不能推出 Token 有效/无效。
type VerificationStatus string

const (
	StatusNotPresent  VerificationStatus = "NOT_PRESENT"
	StatusUnverified  VerificationStatus = "UNVERIFIED"
	StatusVerified    VerificationStatus = "VERIFIED"
	StatusInvalid     VerificationStatus = "INVALID"
	StatusUnavailable VerificationStatus = "UNAVAILABLE"
)

// ReasonCode 固定原因码枚举（16 个；不含原始 Token 或声明，接口与事件共享）。
type ReasonCode string

const (
	ReasonPolicyOff         ReasonCode = "POLICY_OFF"
	ReasonOutOfScope        ReasonCode = "OUT_OF_SCOPE"
	ReasonMissingToken      ReasonCode = "MISSING_TOKEN"
	ReasonMalformedToken    ReasonCode = "MALFORMED_TOKEN"
	ReasonAlgorithmRejected ReasonCode = "ALGORITHM_REJECTED"
	ReasonUnknownIssuer     ReasonCode = "UNKNOWN_ISSUER"
	ReasonUnknownKid        ReasonCode = "UNKNOWN_KID"
	ReasonSignatureInvalid  ReasonCode = "SIGNATURE_INVALID"
	ReasonIssuerMismatch    ReasonCode = "ISSUER_MISMATCH"
	ReasonAudienceMismatch  ReasonCode = "AUDIENCE_MISMATCH"
	ReasonExpired           ReasonCode = "EXPIRED"
	ReasonNotYetValid       ReasonCode = "NOT_YET_VALID"
	ReasonClaimInvalid      ReasonCode = "CLAIM_INVALID"
	ReasonKeysetUnavailable ReasonCode = "KEYSET_UNAVAILABLE"
	ReasonVerifierError     ReasonCode = "VERIFIER_ERROR"
	ReasonValid             ReasonCode = "VALID"
)

// VerificationResult 不可变验证结果（任务书 §5 冻结字段）。
// 脱敏纪律：不含原始 Token、完整 payload、明文 sub/tenant；
// verified_principal_id 为应用隔离 HMAC 指纹（网关侧计算）。
type VerificationResult struct {
	Status     VerificationStatus `json:"status"`
	ReasonCode ReasonCode         `json:"reason_code"`
	// PolicyVersion / IssuerConfigID / KeysetVersion 溯源本次验证依据的策略与密钥集版本。
	PolicyVersion  int    `json:"policy_version"`
	IssuerConfigID string `json:"issuer_config_id,omitempty"`
	KeysetVersion  string `json:"keyset_version,omitempty"`
	// VerifiedPrincipalID 仅 VERIFIED 可非空（HMAC 指纹，非明文主体）。
	VerifiedPrincipalID string `json:"verified_principal_id,omitempty"`
	// VerifiedTenantID 仅 VERIFIED 且配置 tenant_claim 验证成功时可非空。
	VerifiedTenantID string    `json:"verified_tenant_id,omitempty"`
	EvaluatedAt      time.Time `json:"evaluated_at"`
	// EnforceAction 本次处置（none / reject_401 / unavailable_503 等，网关侧填充）。
	EnforceAction string `json:"enforce_action"`
}
