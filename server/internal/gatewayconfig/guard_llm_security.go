package gatewayconfig

// GuardLLMSecurityPolicy 是按应用下发的 LLM 输入与输出保护策略快照。
type GuardLLMSecurityPolicy struct {
	ID                     string   `json:"id"`
	ApplicationID          string   `json:"application_id"`
	Name                   string   `json:"name"`
	Version                int64    `json:"version"`
	Mode                   string   `json:"mode"`
	PromptInjectionEnabled bool     `json:"prompt_injection_enabled"`
	InputContentEnabled    bool     `json:"input_content_enabled,omitempty"`
	PIIDetectionEnabled    bool     `json:"pii_detection_enabled"`
	OutputContentEnabled   bool     `json:"output_content_enabled,omitempty"`
	OutputPIIEnabled       bool     `json:"output_pii_enabled,omitempty"`
	BlockedTopics          []string `json:"blocked_topics,omitempty"`
	MaxPromptBytes         int      `json:"max_prompt_bytes,omitempty"`
	MaxOutputTokens        int      `json:"max_output_tokens,omitempty"`
}
