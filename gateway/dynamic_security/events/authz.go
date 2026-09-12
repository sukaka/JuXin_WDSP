package events

// AuthorizationDecision is the per-check result. Values are deliberately
// small and enumerable so an event never needs to carry claims or raw IDs.
type AuthorizationDecision string

const (
	AuthorizationAllow            AuthorizationDecision = "ALLOW"
	AuthorizationObserveViolation AuthorizationDecision = "OBSERVE_VIOLATION"
	AuthorizationUnknown          AuthorizationDecision = "UNKNOWN"
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
}

// AuthorizationDecisionGroup aggregates all authorization checks for one
// request. Decision precedence is violation > unknown > allow.
type AuthorizationDecisionGroup struct {
	DecisionID    string                `json:"decision_id"`
	PolicyVersion string                `json:"policy_version,omitempty"`
	Decision      AuthorizationDecision `json:"decision"`
	Checks        []AuthorizationCheck  `json:"checks"`
}
