// llmobs.go LLM API 观测上下文（P2-04 首批，任务书 §152-154；W12-GW 续 §154 MCP）。
// 数据最小化纪律：只含模型标识 / prompt 存在性 / 长度桶 / token 用量 / 流式标记 /
// MCP 方法名（协议标识符），高敏感 Prompt/Response 原文不落上下文、不落事件
// （见 detectors/llm.go、detectors/mcp.go 证据纪律）。
package context

// LLMObservation LLM API 观测（识别为 LLM 端点的流量由请求相位产出、响应相位补全）。
// 字段与事件 llm_observation 键、管理面 api_llm_observations 表列一一对应。
type LLMObservation struct {
	// Model 请求体 model 字段（响应侧回填优先）；空 = 未声明/未采集到。
	Model string `json:"model,omitempty"`
	// PromptPresent 请求体是否携带 prompt 形态字段（messages/prompt/input 存在性，不含内容）。
	PromptPresent bool `json:"prompt_present"`
	// PromptLenBucket prompt 体量桶（由请求体大小推导的近似口径：chat 请求体以 prompt
	// 为主体；数据最小化下不逐字统计原文长度）。取值见 detectors.PromptLenBucket。
	PromptLenBucket string `json:"prompt_len_bucket,omitempty"`
	// TotalTokens 响应 usage.total_tokens（OpenAI 兼容字段；流式/缺失容忍为 0 = 未采集到）。
	TotalTokens int `json:"total_tokens,omitempty"`
	// Stream 流式调用（请求 stream=true 或响应 SSE/流式直通）。
	Stream bool `json:"stream,omitempty"`
	// MCPMethod MCP JSON-RPC 方法名（W12-GW / P2-04 续；仅 MCP 形态流量记录，截断 128；
	// 词表外方法同样如实记录——观测口径；空 = 非 MCP 端点或 JSON-RPC 响应对象）。
	MCPMethod string `json:"mcp_method,omitempty"`
}

// SetLLMObservation 写入/更新 LLM 观测（请求相位首次写入，响应相位补全后覆盖）。
func (c *RequestContext) SetLLMObservation(obs *LLMObservation) {
	if c == nil || obs == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LLMObservation = obs
}

// GetLLMObservation 读取 LLM 观测（未识别为 LLM 端点时为 nil）。
func (c *RequestContext) GetLLMObservation() *LLMObservation {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LLMObservation
}
