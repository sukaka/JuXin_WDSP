package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxResponseBytes sidecar 响应体硬上限（16 KiB，防止异常或被控 sidecar 耗尽网关内存）。
	MaxResponseBytes = 16 << 10

	// sidecarBaseURL Unix Domain Socket 本地 HTTP 请求固定主机名（绝不解析 DNS 或访问 TCP）。
	sidecarBaseURL   = "http://unix"
	classifyEndpoint = sidecarBaseURL + "/v1/classify"
	healthzEndpoint  = sidecarBaseURL + "/healthz"
	clientUserAgent  = "jiuzhang-semantic-client/1"
)

// 哨兵错误分类（用于熔断统计、事件 reason 与 FAIL_CLOSED 503 判定）。
var (
	ErrCircuitOpen          = errors.New("semantic: circuit breaker open")
	ErrConcurrencySaturated = errors.New("semantic: concurrency limit saturated")
	ErrTimeout              = errors.New("semantic: sidecar request timeout")
	ErrSidecarUnavailable   = errors.New("semantic: sidecar unavailable")
	ErrResponseTooLarge     = errors.New("semantic: sidecar response exceeds 16KiB limit")
	ErrInvalidResponse      = errors.New("semantic: invalid sidecar response")
)

// ClassifyRequest 发送给本地语义 sidecar 的请求载荷（不含任何 Cookie/Authorization）。
type ClassifyRequest struct {
	RequestID string `json:"request_id"`
	Channel   string `json:"channel"`
	Text      string `json:"text"`
}

// ClassifyResult 本地语义 sidecar 的结构化分类结果。
type ClassifyResult struct {
	Label      string  `json:"label"`
	Score      float64 `json:"score"`
	ModelID    string  `json:"model_id"`
	LatencyMS  int64   `json:"latency_ms"`
	InputRunes int     `json:"input_runes"`
}

// HealthStatus GET http://unix/healthz 的响应结构。
type HealthStatus struct {
	Status      string `json:"status"`
	ModelID     string `json:"model_id"`
	ModelSHA256 string `json:"model_sha256"`
	Backend     string `json:"backend"`
}

// ClientOptions 构造 Client 时的可选依赖注入（主要用于单元测试时钟）。
type ClientOptions struct {
	Now func() time.Time
}

// Client 通过 Unix Domain Socket 调用本地离线语义防火墙 sidecar 的并发安全客户端。
// 强制约束：
//   - 仅使用 net.DialContext("unix", socketPath)，禁用 HTTP 代理与重定向；
//   - 每次调用受硬超时 timeout_ms、非阻塞并发信号量 max_concurrency 与熔断器保护；
//   - 按 rune 安全截断输入文本至 max_input_runes，响应读取严格 <= 16 KiB；
//   - 绝不发送任何 Cookie、Authorization 或业务请求头。
type Client struct {
	socketPath    string
	timeout       time.Duration
	maxInputRunes int
	sem           chan struct{}
	breaker       *CircuitBreaker
	transport     *http.Transport
	httpClient    *http.Client
}

// NewClient 根据已校验的 Policy 构造 Unix Domain Socket 客户端。
func NewClient(pol *Policy, opts ...ClientOptions) (*Client, error) {
	if err := ValidatePolicy(pol); err != nil {
		return nil, err
	}
	var opt ClientOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	socketPath := pol.EffectiveSocketPath()
	timeout := time.Duration(pol.TimeoutMS) * time.Millisecond
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		Proxy:                 nil, // 禁止读取 HTTP_PROXY / HTTPS_PROXY，避免绕过本地 Unix Socket
		DisableCompression:    true,
		MaxIdleConns:          pol.MaxConcurrency,
		MaxIdleConnsPerHost:   pol.MaxConcurrency,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 0,
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// 拒绝跟随 sidecar 返回的任何 3xx 重定向，防止跳转外部地址
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		socketPath:    socketPath,
		timeout:       timeout,
		maxInputRunes: pol.MaxInputRunes,
		sem:           make(chan struct{}, pol.MaxConcurrency),
		breaker:       newCircuitBreakerWithClock(pol.CircuitFailureThreshold, time.Duration(pol.CircuitOpenSeconds)*time.Second, opt.Now),
		transport:     tr,
		httpClient:    hc,
	}, nil
}

// Close 释放空闲连接（幂等、并发安全）。
func (c *Client) Close() {
	if c == nil || c.transport == nil {
		return
	}
	c.transport.CloseIdleConnections()
}

// Breaker 返回底层熔断器（用于状态观测与单元测试）。
func (c *Client) Breaker() *CircuitBreaker {
	if c == nil {
		return nil
	}
	return c.breaker
}

// TruncateRunes 按 Unicode rune 边界安全截断文本，保证绝不劈裂多字节 UTF-8 字符，
// 返回截断后的文本与截断后的 rune 数。
func TruncateRunes(text string, maxRunes int) (string, int) {
	if text == "" || maxRunes <= 0 {
		return "", 0
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	runes := 0
	for idx := range text {
		if runes == maxRunes {
			return text[:idx], runes
		}
		runes++
	}
	return text, runes
}

// wireClassifyResponse 允许 latency_ms 同时兼容整数或浮点 JSON 数字。
type wireClassifyResponse struct {
	Label     string  `json:"label"`
	Score     float64 `json:"score"`
	ModelID   string  `json:"model_id"`
	LatencyMS float64 `json:"latency_ms"`
}

// Classify 调用 POST http://unix/v1/classify 对文本执行本地离线语义分类。
func (c *Client) Classify(ctx context.Context, req ClassifyRequest) (ClassifyResult, error) {
	if c == nil {
		return ClassifyResult{}, ErrSidecarUnavailable
	}
	truncatedText, runeCount := TruncateRunes(req.Text, c.maxInputRunes)

	// 1. 先检查非阻塞并发信号量：满载时立刻拒绝，避免占用 HalfOpen 探测名额或阻塞请求协程。
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	default:
		return ClassifyResult{InputRunes: runeCount}, ErrConcurrencySaturated
	}

	// 2. 检查熔断器（Open 或 HalfOpen 已有在途探针时快速失败）。
	allowed, _ := c.breaker.Allow()
	if !allowed {
		return ClassifyResult{InputRunes: runeCount}, ErrCircuitOpen
	}

	payload, err := json.Marshal(ClassifyRequest{
		RequestID: sanitizeHeaderlessID(req.RequestID),
		Channel:   req.Channel,
		Text:      truncatedText,
	})
	if err != nil {
		c.breaker.RecordFailure()
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: marshal request: %v", ErrSidecarUnavailable, err)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, classifyEndpoint, bytes.NewReader(payload))
	if err != nil {
		c.breaker.RecordFailure()
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: build request: %v", ErrSidecarUnavailable, err)
	}
	// 仅设置最小固定头，严禁携带 Cookie / Authorization 或任何入站业务头。
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", clientUserAgent)

	start := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		c.breaker.RecordFailure()
		if isTimeoutErr(callCtx, err) {
			return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: %v", ErrTimeout, err)
		}
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: %v", ErrSidecarUnavailable, err)
	}
	defer resp.Body.Close()

	rawBody, readErr := readBounded(resp.Body, MaxResponseBytes)
	if readErr != nil {
		c.breaker.RecordFailure()
		if errors.Is(readErr, ErrResponseTooLarge) {
			return ClassifyResult{InputRunes: runeCount}, ErrResponseTooLarge
		}
		if isTimeoutErr(callCtx, readErr) {
			return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: %v", ErrTimeout, readErr)
		}
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: read body: %v", ErrSidecarUnavailable, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		c.breaker.RecordFailure()
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: http status %d", ErrSidecarUnavailable, resp.StatusCode)
	}

	var wire wireClassifyResponse
	if err := json.Unmarshal(rawBody, &wire); err != nil {
		c.breaker.RecordFailure()
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: decode json: %v", ErrInvalidResponse, err)
	}
	label := sanitizeToken(wire.Label, 64)
	if label == "" || !isFiniteFloat(wire.Score) || wire.Score < 0 || wire.Score > 1 {
		c.breaker.RecordFailure()
		return ClassifyResult{InputRunes: runeCount}, fmt.Errorf("%w: invalid label or score", ErrInvalidResponse)
	}
	latencyMS := int64(math.Round(wire.LatencyMS))
	if !isFiniteFloat(wire.LatencyMS) || latencyMS < 0 {
		latencyMS = time.Since(start).Milliseconds()
	}
	c.breaker.RecordSuccess()
	return ClassifyResult{
		Label:      strings.ToLower(label),
		Score:      wire.Score,
		ModelID:    sanitizeToken(wire.ModelID, 128),
		LatencyMS:  latencyMS,
		InputRunes: runeCount,
	}, nil
}

// Healthz 调用 GET http://unix/healthz 探测本地离线语义 sidecar 状态。
// 不消耗推理信号量，也不修改推理熔断器计数，严格遵守硬超时与 16 KiB 响应上限。
func (c *Client) Healthz(ctx context.Context) (HealthStatus, error) {
	if c == nil {
		return HealthStatus{}, ErrSidecarUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodGet, healthzEndpoint, nil)
	if err != nil {
		return HealthStatus{}, fmt.Errorf("%w: build healthz request: %v", ErrSidecarUnavailable, err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", clientUserAgent)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if isTimeoutErr(callCtx, err) {
			return HealthStatus{}, fmt.Errorf("%w: %v", ErrTimeout, err)
		}
		return HealthStatus{}, fmt.Errorf("%w: %v", ErrSidecarUnavailable, err)
	}
	defer resp.Body.Close()

	rawBody, readErr := readBounded(resp.Body, MaxResponseBytes)
	if readErr != nil {
		if errors.Is(readErr, ErrResponseTooLarge) {
			return HealthStatus{}, ErrResponseTooLarge
		}
		if isTimeoutErr(callCtx, readErr) {
			return HealthStatus{}, fmt.Errorf("%w: %v", ErrTimeout, readErr)
		}
		return HealthStatus{}, fmt.Errorf("%w: read healthz body: %v", ErrSidecarUnavailable, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return HealthStatus{}, fmt.Errorf("%w: healthz http status %d", ErrSidecarUnavailable, resp.StatusCode)
	}

	var hs HealthStatus
	if err := json.Unmarshal(rawBody, &hs); err != nil {
		return HealthStatus{}, fmt.Errorf("%w: decode healthz json: %v", ErrInvalidResponse, err)
	}
	hs.Status = sanitizeToken(hs.Status, 32)
	hs.ModelID = sanitizeToken(hs.ModelID, 128)
	hs.ModelSHA256 = sanitizeToken(hs.ModelSHA256, 128)
	hs.Backend = sanitizeToken(hs.Backend, 64)
	return hs, nil
}

func readBounded(r io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func isTimeoutErr(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func sanitizeHeaderlessID(id string) string {
	return sanitizeToken(id, 128)
}

func sanitizeToken(s string, maxBytes int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if maxBytes > 0 && len(s) > maxBytes {
		// 按 rune 边界截断至不超过 maxBytes 字节
		cut := 0
		for idx := range s {
			if idx > maxBytes {
				break
			}
			cut = idx
		}
		if cut == 0 {
			return ""
		}
		return s[:cut]
	}
	return s
}
