// llm.go LLM API 端点识别（P2-04 首批，任务书 §152-154）。
//
// 形态覆盖：OpenAI 兼容 API（/v1/chat/completions、/v1/completions、/v1/embeddings、
// /v1/images/*、/v1/audio/*、/v1/messages）、MCP（POST /mcp JSON-RPC）、
// LLM Gateway（LiteLLM/OneAPI 等代理同一组 OpenAI 兼容路径，随词表覆盖）。
//
// 保守精确纪律：路径词表后缀命中只是候选，必须同时满足
//   - 写方法（POST；识别目标为推理调用，GET /v1/models 等元数据接口不观测）；
//   - 内容形态确认：JSON 体含该端点形态字段（messages/model/prompt/input/jsonrpc 之一），
//     或 multipart 体含 model/file part（audio/images 上传形态）。
//
// 两者缺一不判为 LLM 端点（宁漏勿滥，普通业务接口不误标）。
package classifier

import (
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// LLMKind LLM 端点形态标签（观测维度；extension 透传，不落库）。
type LLMKind string

const (
	// LLMKindOpenAICompat OpenAI 兼容形态（含 Anthropic /v1/messages 等同构 messages 形态）。
	LLMKindOpenAICompat LLMKind = "openai_compat"
	// LLMKindMCP MCP（Model Context Protocol）JSON-RPC 端点形态。
	LLMKindMCP LLMKind = "mcp"
)

// LLMResult LLM 端点识别结果。
type LLMResult struct {
	IsLLM  bool
	Kind   LLMKind
	Signal string // 命中的路径词表项（调试/审计用，非敏感）
}

// llmPathRule 路径词表规则：suffix 命中后仍需形态字段确认（保守精确）。
// shapes 为 JSON 顶层字段名候选（任一存在即确认）；multipartShape 为 true 时
// multipart 体按 part 名（model/file/prompt）确认（audio/images 上传）。
type llmPathRule struct {
	suffix         string
	kind           LLMKind
	shapes         []string
	multipartShape bool
}

// llmPathRules 路径词表（长后缀在前，/chat/completions 先于 /completions 命中）。
// /messages 形态字段仅认 messages（路径较通用，严格确认防误判普通消息接口）。
var llmPathRules = []llmPathRule{
	{suffix: "/chat/completions", kind: LLMKindOpenAICompat, shapes: []string{"messages", "model"}},
	{suffix: "/completions", kind: LLMKindOpenAICompat, shapes: []string{"prompt", "model"}},
	{suffix: "/embeddings", kind: LLMKindOpenAICompat, shapes: []string{"input", "model"}},
	{suffix: "/images/generations", kind: LLMKindOpenAICompat, shapes: []string{"prompt", "model"}},
	{suffix: "/images/edits", kind: LLMKindOpenAICompat, shapes: []string{"prompt", "model"}, multipartShape: true},
	{suffix: "/images/variations", kind: LLMKindOpenAICompat, shapes: []string{"model"}, multipartShape: true},
	{suffix: "/audio/transcriptions", kind: LLMKindOpenAICompat, shapes: []string{"model"}, multipartShape: true},
	{suffix: "/audio/translations", kind: LLMKindOpenAICompat, shapes: []string{"model"}, multipartShape: true},
	{suffix: "/audio/speech", kind: LLMKindOpenAICompat, shapes: []string{"input", "model"}},
	{suffix: "/messages", kind: LLMKindOpenAICompat, shapes: []string{"messages"}},
	{suffix: "/mcp", kind: LLMKindMCP, shapes: []string{"jsonrpc"}},
}

// llmMultipartPartNames multipart 形态确认的 part 名（model 字段 / 文件 part）。
var llmMultipartPartNames = map[string]bool{"model": true, "file": true, "image": true, "prompt": true}

// ClassifyLLM 识别 LLM API 端点（路径词表 + 内容形态双重确认，保守精确）。
// p 为 nil 或非 POST 时不判（推理调用均为写方法；元数据 GET 接口不观测）。
func ClassifyLLM(p *parser.Parsed) LLMResult {
	if p == nil || p.Method != "POST" {
		return LLMResult{}
	}
	path := strings.ToLower(p.RawPath)
	for _, rule := range llmPathRules {
		if !strings.HasSuffix(path, rule.suffix) {
			continue
		}
		if llmShapeConfirmed(p, rule) {
			return LLMResult{IsLLM: true, Kind: rule.kind, Signal: rule.suffix}
		}
		// 路径命中但形态不确认：保守不判（同路径只会命中一条规则，直接返回）
		return LLMResult{}
	}
	return LLMResult{}
}

// llmShapeConfirmed 内容形态确认：JSON 体看顶层形态字段（任一命中）；
// multipart 体（规则允许时）看 part 名；其余形态不确认。
func llmShapeConfirmed(p *parser.Parsed, rule llmPathRule) bool {
	if p.IsJSON {
		for _, field := range rule.shapes {
			if _, ok := p.JSONFields[field]; ok {
				return true
			}
		}
		return false
	}
	if rule.multipartShape && len(p.MultipartParts) > 0 {
		for _, part := range p.MultipartParts {
			if llmMultipartPartNames[strings.ToLower(part.FieldName)] {
				return true
			}
		}
	}
	return false
}
