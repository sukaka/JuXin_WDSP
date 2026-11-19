// Package aimodel AI模型网关：供应商抽象、OpenAI兼容客户端、模型路由、健康检查与故障切换。
// 密钥经 encryption.Service 加密存储，绝不回传前端/日志/Prompt。
package aimodel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 错误定义。
var (
	ErrNoModel        = errors.New("no available model")
	ErrModelDown      = errors.New("model unavailable")
	ErrInvalidRequest = errors.New("invalid model request")
)

// ProviderType 供应商类型。
type ProviderType string

const (
	ProviderOpenAICompatible ProviderType = "openai_compatible"
	ProviderOllama           ProviderType = "ollama"
	ProviderLocal            ProviderType = "local"
)

// Provider 供应商配置。
type Provider struct {
	ID      uuid.UUID
	Name    string
	Type    ProviderType
	BaseURL string
	// CanonicalOrigin binds credentials to the endpoint authority. It is
	// persisted by Store and must change when BaseURL's origin changes.
	CanonicalOrigin string
	// AllowedTargets is the provider-scoped exception list for private hosts.
	AllowedTargets []string
	KeyReference   string
	Status         string
}

// Model 模型配置。
type Model struct {
	ID                uuid.UUID
	ProviderID        uuid.UUID
	Code              string
	DisplayName       string
	ContextWindow     int
	MaxOutputTokens   int
	SupportsTools     bool
	SupportsStreaming bool
	TimeoutSeconds    int
	CostInputUnit     float64 // 每千输入Token
	CostOutputUnit    float64
	Priority          int
	Status            string
}

// ChatMessage 对话消息。
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest 统一对话请求。
type ChatRequest struct {
	Messages    []ChatMessage
	MaxTokens   int
	Temperature float64
	Stream      bool
	JSONMode    bool // 结构化输出（response_format json_object）
}

// ChatResult 统一对话结果。
type ChatResult struct {
	Content      string
	FinishReason string // stop / length / error
	InputTokens  int
	OutputTokens int
	ModelCode    string
}

// Usage 成本计算。
func (r *ChatResult) UsageCost(m *Model) float64 {
	return float64(r.InputTokens)/1000*m.CostInputUnit + float64(r.OutputTokens)/1000*m.CostOutputUnit
}

// StreamCallback 流式输出回调。
type StreamCallback func(delta string, done bool, result *ChatResult) error

// ---------- OpenAI 兼容客户端 ----------

// OpenAIClient OpenAI 兼容协议客户端（Ollama / vLLM / OpenAI 兼容网关通用）。
type OpenAIClient struct {
	httpClient *http.Client
}

// NewOpenAIClient 创建客户端。
func NewOpenAIClient() *OpenAIClient {
	return &OpenAIClient{httpClient: &http.Client{Timeout: 5 * time.Minute}}
}

type oaiRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	Stream      bool          `json:"stream"`
	Format      *oaiFormat    `json:"response_format,omitempty"`
}

type oaiFormat struct {
	Type string `json:"type"`
}

type oaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat 非流式对话。
func (c *OpenAIClient) Chat(ctx context.Context, baseURL, apiKey, modelCode string, req ChatRequest) (*ChatResult, error) {
	p, err := legacyProvider(baseURL)
	if err != nil {
		return nil, err
	}
	return c.ChatProvider(ctx, p, apiKey, modelCode, req)
}

// ChatProvider performs a guarded request using the provider's persisted
// origin and target scope.
func (c *OpenAIClient) ChatProvider(ctx context.Context, p *Provider, apiKey, modelCode string, req ChatRequest) (*ChatResult, error) {
	httpClient, endpoint, err := c.prepareProviderRequest(ctx, p, "/v1/chat/completions")
	if err != nil {
		return nil, err
	}
	defer httpClient.CloseIdleConnections()
	body := oaiRequest{
		Model:       modelCode,
		Messages:    req.Messages,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Stream:      false,
	}
	if req.JSONMode {
		body.Format = &oaiFormat{Type: "json_object"}
	}
	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: provider request failed", ErrModelDown)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrModelDown, resp.StatusCode)
	}
	var out oaiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid model response: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%w: provider returned an error", ErrModelDown)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("%w: empty choices", ErrModelDown)
	}
	return &ChatResult{
		Content:      out.Choices[0].Message.Content,
		FinishReason: normalizeFinish(out.Choices[0].FinishReason),
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
		ModelCode:    modelCode,
	}, nil
}

// ChatStream 流式对话（SSE）。
func (c *OpenAIClient) ChatStream(ctx context.Context, baseURL, apiKey, modelCode string, req ChatRequest, cb StreamCallback) (*ChatResult, error) {
	p, err := legacyProvider(baseURL)
	if err != nil {
		return nil, err
	}
	return c.ChatStreamProvider(ctx, p, apiKey, modelCode, req, cb)
}

const (
	// maxSSEStreamBytes 限制单次 SSE 流式响应读取总字节上限（8 MiB），防止恶意/异常上游耗尽内存。
	maxSSEStreamBytes int64 = 8 << 20
	// maxSSEBufferBytes 限制未分帧 SSE 缓冲上限（1 MiB），防止缺少 \n\n 分隔符时无限膨胀。
	maxSSEBufferBytes = 1 << 20
)

// ChatStreamProvider performs a guarded streaming request.
func (c *OpenAIClient) ChatStreamProvider(ctx context.Context, p *Provider, apiKey, modelCode string, req ChatRequest, cb StreamCallback) (*ChatResult, error) {
	httpClient, endpoint, err := c.prepareProviderRequest(ctx, p, "/v1/chat/completions")
	if err != nil {
		return nil, err
	}
	defer httpClient.CloseIdleConnections()
	body := oaiRequest{
		Model:       modelCode,
		Messages:    req.Messages,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Stream:      true,
	}
	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: provider request failed", ErrModelDown)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("%w: status %d", ErrModelDown, resp.StatusCode)
	}

	var full strings.Builder
	finish := "stop"
	var usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	limitedBody := io.LimitReader(resp.Body, maxSSEStreamBytes+1)
	var totalRead int64
	for {
		n, rerr := limitedBody.Read(tmp)
		if n > 0 {
			totalRead += int64(n)
			if totalRead > maxSSEStreamBytes {
				return nil, fmt.Errorf("%w: SSE stream exceeded %d bytes limit", ErrModelDown, maxSSEStreamBytes)
			}
			if len(buf)+n > maxSSEBufferBytes {
				return nil, fmt.Errorf("%w: SSE frame buffer exceeded %d bytes limit", ErrModelDown, maxSSEBufferBytes)
			}
			buf = append(buf, tmp[:n]...)
			for {
				idx := bytes.Index(buf, []byte("\n\n"))
				if idx < 0 {
					break
				}
				event := buf[:idx]
				buf = buf[idx+2:]
				for _, line := range bytes.Split(event, []byte("\n")) {
					if !bytes.HasPrefix(line, []byte("data:")) {
						continue
					}
					payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
					if bytes.Equal(payload, []byte("[DONE]")) {
						continue
					}
					var chunk struct {
						Choices []struct {
							Delta struct {
								Content string `json:"content"`
							} `json:"delta"`
							FinishReason *string `json:"finish_reason"`
						} `json:"choices"`
						Usage *struct {
							PromptTokens     int `json:"prompt_tokens"`
							CompletionTokens int `json:"completion_tokens"`
						} `json:"usage"`
					}
					if json.Unmarshal(payload, &chunk) != nil {
						continue
					}
					for _, ch := range chunk.Choices {
						if ch.Delta.Content != "" {
							full.WriteString(ch.Delta.Content)
							if err := cb(ch.Delta.Content, false, nil); err != nil {
								return nil, err
							}
						}
						if ch.FinishReason != nil && *ch.FinishReason != "" {
							finish = normalizeFinish(*ch.FinishReason)
						}
					}
					if chunk.Usage != nil {
						usage.PromptTokens = chunk.Usage.PromptTokens
						usage.CompletionTokens = chunk.Usage.CompletionTokens
					}
				}
			}
			if len(buf) == 0 {
				buf = buf[:0]
			} else if cap(buf) > 64*1024 && len(buf) < cap(buf)/4 {
				compacted := make([]byte, len(buf))
				copy(compacted, buf)
				buf = compacted
			}
		}
		if rerr != nil {
			break
		}
	}
	// Token 估算（流式无 usage 时按字符近似，ollama 兼容端点通常返回 usage）
	inTok := usage.PromptTokens
	if inTok == 0 {
		inTok = estimateTokens(messagesText(req.Messages))
	}
	outTok := usage.CompletionTokens
	if outTok == 0 {
		outTok = estimateTokens(full.String())
	}
	res := &ChatResult{
		Content:      full.String(),
		FinishReason: finish,
		InputTokens:  inTok,
		OutputTokens: outTok,
		ModelCode:    modelCode,
	}
	if err := cb("", true, res); err != nil {
		return nil, err
	}
	return res, nil
}

// HealthCheck 模型健康检查（列模型或短对话）。
func (c *OpenAIClient) HealthCheck(ctx context.Context, baseURL, apiKey, modelCode string) error {
	p, err := legacyProvider(baseURL)
	if err != nil {
		return err
	}
	return c.HealthCheckProvider(ctx, p, apiKey, modelCode)
}

// HealthCheckProvider performs a guarded health check through the same
// outbound policy as chat requests.
func (c *OpenAIClient) HealthCheckProvider(ctx context.Context, p *Provider, apiKey, modelCode string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := c.ChatProvider(ctx, p, apiKey, modelCode, ChatRequest{
		Messages:  []ChatMessage{{Role: "user", Content: "ping"}},
		MaxTokens: 5,
	})
	return err
}

func (c *OpenAIClient) prepareProviderRequest(ctx context.Context, p *Provider, suffix string) (*http.Client, *url.URL, error) {
	if err := ValidateProviderEndpoint(ctx, p); err != nil {
		return nil, nil, err
	}
	if err := validatePersistedOrigin(p); err != nil {
		return nil, nil, err
	}
	policy, err := providerPolicy(p)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidProviderEndpoint, err)
	}
	httpClient := policy.Client()
	if c != nil && c.httpClient != nil {
		httpClient.Timeout = c.httpClient.Timeout
	}
	u, err := providerURL(p)
	if err != nil {
		return nil, nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + suffix
	u.RawQuery = ""
	u.Fragment = ""
	return httpClient, u, nil
}

// legacyProvider keeps the historical client methods fail-closed. Callers that
// intentionally use a private endpoint must use the Provider methods and pass a
// persisted provider-scoped allowlist.
func legacyProvider(baseURL string) (*Provider, error) {
	p := &Provider{BaseURL: baseURL}
	_, err := providerURL(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func normalizeFinish(s string) string {
	switch s {
	case "stop", "":
		return "stop"
	case "length", "max_tokens":
		return "length"
	default:
		return s
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func messagesText(ms []ChatMessage) string {
	var b strings.Builder
	for _, m := range ms {
		b.WriteString(m.Content)
	}
	return b.String()
}

// estimateTokens 粗略 Token 估算（中文按~1.5字/token，英文按~4字符/token）。
func estimateTokens(s string) int {
	cjk, other := 0, 0
	for _, r := range s {
		if r > 0x2E7F {
			cjk++
		} else {
			other++
		}
	}
	return cjk*2/3 + other/4 + 1
}
