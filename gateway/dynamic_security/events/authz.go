package events

// AuthorizationDecision is the per-check result. Values are deliberately
// small and enumerable so an event never needs to carry claims or raw IDs.
type AuthorizationDecision string

const (
	AuthorizationAllow            AuthorizationDecision = "ALLOW"
	AuthorizationObserveViolation AuthorizationDecision = "OBSERVE_VIOLATION"
	AuthorizationUnknown          AuthorizationDecision = "UNKNOWN"
	// AuthorizationVerifiedViolation NG-AZ-03 第四决策值：违规事实经显式资格判定
	// 成立。它是判定结论而非动作——仅在端点 enforcement=PROTECT 且决策引擎 PROTECT
	// 语义下产出，经 category=BLOCK finding 走既有 BLOCK 定案链实断（final_action
	// 恒为既有词表，本值不进 final_action 列）；UNKNOWN 在任何形态下都不映射
	// BLOCK（全线红线）。
	AuthorizationVerifiedViolation AuthorizationDecision = "VERIFIED_VIOLATION"
)

// AuthorizationCheck is one independent BOLA or BFLA check.
type AuthorizationCheck struct {
	Type          string                `json:"type"`
	Decision      AuthorizationDecision `json:"decision"`
	ReasonCode    string                `json:"reason_code,omitempty"`
	Confidence    float64               `json:"confidence,omitempty"`
	RelationState string                `json:"relation_state,omitempty"`
	ObjectType    string                `json:"object_type,omitempty"`
	ObjectRef     string                `json:"object_ref,omitempty"`
	// Role is intentionally not populated in emitted decisions: role claim
	// values are authorization input and must not be copied into events.
	Role          string `json:"role,omitempty"`
	RoleSource    string `json:"role_source,omitempty"`
	TenantState   string `json:"tenant_state,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	ModelVersion  string `json:"model_version,omitempty"`
	// DependencyUnavailable 依赖不可用标记（NG-AZ-02 D5：租约过期 strict 端点的
	// 如实披露——授权事实源失效，与「不静默降级」区分；omitempty 零变化）。
	DependencyUnavailable bool `json:"dependency_unavailable,omitempty"`
	// ProposedDecision 拟动作保留（NG-AZ-03 §1.1：资格全真但端点 enforcement 或
	// 决策引擎为 OBSERVE 形态时，VERIFIED_VIOLATION 降级 OBSERVE_VIOLATION 同语义
	// 记录，拟判定值经本字段留痕；omitempty 保证未配置 enforcement 的快照零变化）。
	ProposedDecision AuthorizationDecision `json:"proposed_decision,omitempty"`
}

// AuthorizationDecisionGroup aggregates all authorization checks for one
// request. Decision precedence is violation > unknown > allow.
type AuthorizationDecisionGroup struct {
	DecisionID    string                `json:"decision_id"`
	PolicyVersion string                `json:"policy_version,omitempty"`
	Decision      AuthorizationDecision `json:"decision"`
	Checks        []AuthorizationCheck  `json:"checks"`
}

// AuthzEnforcementWatermark 证据内嵌的撤销水位视图（NG-AZ-03 §1.4 形状：
// manual_seq + sources；与 detectors.RevocationWatermark 线契约同形——
// 跨包镜像，不得改名）。
type AuthzEnforcementWatermark struct {
	ManualSeq int64            `json:"manual_seq"`
	Sources   map[string]int64 `json:"sources,omitempty"`
}

// AuthzEnforcementEvidence 「为什么被实断」的可答证据（NG-AZ-03 §1.4 逐键冻结）：
// 每次 VERIFIED_VIOLATION 实断生成一条，内嵌 api_runtime_events 主事件行的
// final_decision.authz_enforcement 随事件落库（不新建主表，复用既有留存/导出链）。
// 冻结键全量恒在（无 omitempty——消费端按冻结键名取数），无值字段以零值如实
// 呈现（如 BFLA 无 object_ref/model 伴随列）。对象标识仅 HMAC 指纹，不落明文。
type AuthzEnforcementEvidence struct {
	Decision            string                    `json:"decision"`
	ReasonCode          string                    `json:"reason_code"`
	Enforced            bool                      `json:"enforced"`
	EndpointKey         string                    `json:"endpoint_key"`
	ModelVersion        string                    `json:"model_version"`
	PolicyVersion       string                    `json:"policy_version"`
	RevocationWatermark AuthzEnforcementWatermark `json:"revocation_watermark"`
	PrincipalSource     string                    `json:"principal_source"`
	ObjectRef           string                    `json:"object_ref"`
	// Eligibility 阻断资格逐因子布尔（BOLA 为 §1.4 冻结八键：trusted_identity/
	// model_applicable/relation_valid/no_conflict/tenant_consistent/evidence_fresh/
	// other_owner/owner_exclusive；BFLA 为其实际评估的资格键集）。
	Eligibility         map[string]bool `json:"eligibility"`
	LeaseSeconds        int             `json:"lease_seconds"`
	AppliedAtAgeSeconds int64           `json:"applied_at_age_seconds"`
	EnforcementOwner    string          `json:"enforcement_owner"`
	EvidenceSource      string          `json:"evidence_source"`
	RecordedAt          string          `json:"recorded_at"`
}
