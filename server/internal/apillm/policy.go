package apillm

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

const (
	SecurityPolicyModeObserve = "OBSERVE"
	SecurityPolicyModeProtect = "PROTECT"
	PermSecurityRead          = "api_llm_security.read"
	PermSecurityManage        = "api_llm_security.manage"
)

var (
	ErrSecurityPolicyNotFound = errors.New("AI 安全策略不存在")
	ErrSecurityPolicyConflict = errors.New("该应用已配置 AI 安全策略")
)

type SecurityPolicy struct {
	ID                     uuid.UUID  `json:"id"`
	ApplicationID          uuid.UUID  `json:"application_id"`
	Name                   string     `json:"name"`
	Mode                   string     `json:"mode"`
	PromptInjectionEnabled bool       `json:"prompt_injection_enabled"`
	InputContentEnabled    bool       `json:"input_content_enabled"`
	PIIDetectionEnabled    bool       `json:"pii_detection_enabled"`
	OutputContentEnabled   bool       `json:"output_content_enabled"`
	OutputPIIEnabled       bool       `json:"output_pii_enabled"`
	BlockedTopics          []string   `json:"blocked_topics"`
	MaxPromptBytes         int        `json:"max_prompt_bytes"`
	MaxOutputTokens        int        `json:"max_output_tokens"`
	Enabled                bool       `json:"enabled"`
	Version                int64      `json:"version"`
	CreatedBy              *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy              *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type SecurityPolicyVersion struct {
	ID             uuid.UUID       `json:"id"`
	PolicyID       uuid.UUID       `json:"policy_id"`
	Version        int64           `json:"version"`
	PolicySnapshot json.RawMessage `json:"policy_snapshot"`
	CreatedBy      *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (p *SecurityPolicy) NormalizeAndValidate() error {
	p.Name = strings.TrimSpace(p.Name)
	p.Mode = strings.ToUpper(strings.TrimSpace(p.Mode))
	if p.ApplicationID == uuid.Nil {
		return errors.New("应用不能为空")
	}
	if p.Name == "" || len([]rune(p.Name)) > 128 {
		return errors.New("策略名称须为 1～128 个字符")
	}
	if p.Mode != SecurityPolicyModeObserve && p.Mode != SecurityPolicyModeProtect {
		return errors.New("mode 仅支持 OBSERVE/PROTECT")
	}
	if p.MaxPromptBytes != 0 && (p.MaxPromptBytes < 512 || p.MaxPromptBytes > 4<<20) {
		return errors.New("提示词体量上限须为 0 或 512～4194304 字节")
	}
	if p.MaxOutputTokens < 0 || p.MaxOutputTokens > 1000000 {
		return errors.New("输出 Token 上限须为 0 或 1～1000000")
	}
	if len(p.BlockedTopics) > 32 {
		return errors.New("受限话题关键词最多 32 项")
	}
	seen := map[string]bool{}
	topics := make([]string, 0, len(p.BlockedTopics))
	for _, topic := range p.BlockedTopics {
		topic = strings.TrimSpace(topic)
		if topic == "" {
			return errors.New("受限话题关键词不能为空")
		}
		if len([]rune(topic)) > 64 {
			return errors.New("单个受限话题关键词不能超过 64 个字符")
		}
		key := strings.ToLower(topic)
		if !seen[key] {
			seen[key] = true
			topics = append(topics, topic)
		}
	}
	p.BlockedTopics = topics
	return nil
}

func (p *SecurityPolicy) GuardConfig() gatewayconfig.GuardLLMSecurityPolicy {
	return gatewayconfig.GuardLLMSecurityPolicy{
		ID: p.ID.String(), ApplicationID: p.ApplicationID.String(), Name: p.Name,
		Version: p.Version, Mode: p.Mode, PromptInjectionEnabled: p.PromptInjectionEnabled,
		InputContentEnabled: p.InputContentEnabled, PIIDetectionEnabled: p.PIIDetectionEnabled,
		OutputContentEnabled: p.OutputContentEnabled, OutputPIIEnabled: p.OutputPIIEnabled,
		BlockedTopics: append([]string(nil), p.BlockedTopics...), MaxPromptBytes: p.MaxPromptBytes,
		MaxOutputTokens: p.MaxOutputTokens,
	}
}
