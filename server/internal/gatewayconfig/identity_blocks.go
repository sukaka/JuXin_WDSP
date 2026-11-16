package gatewayconfig

// GuardIdentityBlock 当前 BLOCKED 身份（ID 为 client_identity UUID）。
type GuardIdentityBlock struct {
	ID          string `json:"id"`
	IdentityKey string `json:"identity_key"`
}
