package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// TestClassifyLLMMatrix 识别矩阵：OpenAI 兼容各路径（JSON 形态确认）判定为 LLM；
// 非 LLM 流量（普通 REST/仅路径命中无形态/GET 元数据）不误判。
func TestClassifyLLMMatrix(t *testing.T) {
	jsonParsed := func(path string, fields ...string) *parser.Parsed {
		p := &parser.Parsed{
			Method: "POST", RawPath: path, ContentType: "application/json",
			IsJSON: true, JSONFields: map[string]string{},
		}
		for _, f := range fields {
			p.JSONFields[f] = "string"
		}
		return p
	}
	positive := []struct {
		name string
		p    *parser.Parsed
		kind LLMKind
	}{
		{"chat_completions", jsonParsed("/v1/chat/completions", "messages", "model"), LLMKindOpenAICompat},
		{"chat_completions_messages_only", jsonParsed("/v1/chat/completions", "messages"), LLMKindOpenAICompat},
		{"chat_completions_model_only", jsonParsed("/v1/chat/completions", "model"), LLMKindOpenAICompat},
		{"completions", jsonParsed("/v1/completions", "model", "prompt"), LLMKindOpenAICompat},
		{"embeddings", jsonParsed("/v1/embeddings", "model", "input"), LLMKindOpenAICompat},
		{"images_generations", jsonParsed("/v1/images/generations", "prompt"), LLMKindOpenAICompat},
		{"audio_speech", jsonParsed("/v1/audio/speech", "model", "input"), LLMKindOpenAICompat},
		{"anthropic_messages", jsonParsed("/v1/messages", "messages", "model"), LLMKindOpenAICompat},
		{"llm_gateway_proxied", jsonParsed("/openai/deployments/x/v1/chat/completions", "messages"), LLMKindOpenAICompat},
		{"mcp", jsonParsed("/mcp", "jsonrpc", "method"), LLMKindMCP},
		{"multipart_audio", &parser.Parsed{
			Method: "POST", RawPath: "/v1/audio/transcriptions", ContentType: "multipart/form-data",
			MultipartParts: []parser.PartMeta{{FieldName: "file", FileName: "a.wav"}, {FieldName: "model"}},
		}, LLMKindOpenAICompat},
	}
	for _, tc := range positive {
		got := ClassifyLLM(tc.p)
		if !got.IsLLM || got.Kind != tc.kind {
			t.Fatalf("%s: expected LLM(%s), got %+v", tc.name, tc.kind, got)
		}
		if got.Signal == "" {
			t.Fatalf("%s: signal empty", tc.name)
		}
	}

	negative := []struct {
		name string
		p    *parser.Parsed
	}{
		{"nil", nil},
		{"get_models_metadata", jsonParsed2("GET", "/v1/models")},
		{"plain_rest", jsonParsed("/v1/orders", "id", "amount")},
		{"path_only_no_shape", jsonParsed("/v1/chat/completions", "foo", "bar")},
		{"path_only_no_body", &parser.Parsed{Method: "POST", RawPath: "/v1/chat/completions"}},
		{"messages_path_without_messages", jsonParsed("/api/v1/messages", "title", "content")},
		{"mcp_without_jsonrpc", jsonParsed("/mcp", "method", "params")},
		{"completions_suffix_business", jsonParsed("/api/tasks/completions", "task_id", "result")},
		{"multipart_audio_no_model_part", &parser.Parsed{
			Method: "POST", RawPath: "/v1/audio/transcriptions", ContentType: "multipart/form-data",
			MultipartParts: []parser.PartMeta{{FieldName: "data"}},
		}},
		{"non_json_chat", &parser.Parsed{Method: "POST", RawPath: "/v1/chat/completions", ContentType: "text/plain"}},
	}
	for _, tc := range negative {
		if got := ClassifyLLM(tc.p); got.IsLLM {
			t.Fatalf("%s: unexpected LLM hit %+v", tc.name, got)
		}
	}
}

// jsonParsed2 GET 快捷构造（矩阵元数据用例）。
func jsonParsed2(method, path string) *parser.Parsed {
	return &parser.Parsed{Method: method, RawPath: path, ContentType: "application/json", IsJSON: true, JSONFields: map[string]string{}}
}
