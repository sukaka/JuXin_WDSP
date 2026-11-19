// Package transport Agent → WDSP 控制/数据通道 HTTPS 客户端（契约 §3 机器端点）。
//
//   - 基路径与请求/响应结构逐字对齐契约 §3.1~§3.5；
//   - TLS 1.2+，默认校验证书；InsecureSkipVerify 仅 enroll --insecure-skip-verify
//     显式开启（自签实验环境），并写入 agent.json 供 run 沿用；
//   - 除 enroll 外所有请求携带 Authorization: Bearer <credential>；
//     持有有效机器身份证书时另按契约 §8 注入 PoP 三头（pop.go）；
//   - 错误统一解析契约 §2 错误结构，401 可通过 IsUnauthorized 判定。
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// 超时与体积约束。
const (
	requestTimeout   = 15 * time.Second
	maxResponseBytes = 4 << 20
)

// Metrics 心跳携带的指标快照（契约 §3.2 metrics 对象）。
type Metrics struct {
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryMB         float64 `json:"memory_mb"`
	CapturePPS       float64 `json:"capture_pps"`
	CaptureBPS       float64 `json:"capture_bps"`
	ForwardPPS       float64 `json:"forward_pps"`
	ForwardBPS       float64 `json:"forward_bps"`
	DropPPS          float64 `json:"drop_pps"`
	QueueDepth       int     `json:"queue_depth"`
	BufferBytes      int64   `json:"buffer_bytes"`
	PacketsReceived  uint64  `json:"packets_received"`
	PacketsProcessed uint64  `json:"packets_processed"`
	PacketsForwarded uint64  `json:"packets_forwarded"`
	PacketsDropped   uint64  `json:"packets_dropped"`
	KernelDrops      uint64  `json:"kernel_drops"`
	CurrentMbps      float64 `json:"current_mbps"`

	// Phase 2 追加（omitempty 前向兼容，服务端可忽略未知字段）：
	// 当前生效抓包后端（afpacket|ebpf）与 eBPF→AF_PACKET 回退原因。
	CaptureBackend        string `json:"capture_backend,omitempty"`
	BackendFallbackReason string `json:"backend_fallback_reason,omitempty"`
	// 抓包截断帧计数（OrigLen > CapLen，D-06 观测辅助）。
	TruncatedFrames uint64 `json:"truncated_frames,omitempty"`

	// Phase 4 追加（契约 §3.1，omitempty 前向兼容）：
	// 背压降级帽 < L3 时上报当前帽等级（L2|L1|L0|SAMPLE）与累计降级次数。
	BackpressureCap    string `json:"backpressure_cap,omitempty"`
	BackpressureEvents uint64 `json:"backpressure_events,omitempty"`

	// P1-03 统一指标（任务书 §5.7，omitempty 前向兼容，旧服务端忽略）：
	// received=packets_received、queued=queue_depth 沿用既有字段。
	Normalized         uint64            `json:"normalized,omitempty"`          // 规范化产出的 HTTP 记录数（传感器出口）
	Masked             uint64            `json:"masked,omitempty"`              // 实际脱敏的 Header/参数值数
	Accepted           uint64            `json:"accepted,omitempty"`            // 服务端确认接收的条目数（accepted 累加）
	Duplicate          uint64            `json:"duplicate,omitempty"`           // 服务端确认重复（v2 duplicate_count）
	DroppedByReason    map[string]uint64 `json:"dropped_by_reason,omitempty"`   // 丢弃/淘汰按原因分账（段级原因注明单位为段）
	SpoolBytes         int64             `json:"spool_bytes,omitempty"`         // 磁盘缓存当前字节（=buffer_bytes，统一命名）
	OldestAgeSec       float64           `json:"oldest_age_sec,omitempty"`      // 最旧缓存段年龄（秒）
	SourceDisconnects  uint64            `json:"source_disconnect,omitempty"`   // 控制/数据通道断连次数
	AssociationPending int               `json:"association_pending,omitempty"` // 重组中未完成配对的连接数

	// G4b（P1-03 §6）：Kubernetes 元数据采集健康。server 端 metrics 为 jsonb
	// 透传落库（RecordHeartbeat last_metrics 合并），新增键不破坏冻结契约。
	K8sMetaState          string  `json:"k8smeta_state,omitempty"`           // OK | STALE | UNAVAILABLE
	K8sMetaEntries        int     `json:"k8smeta_entries,omitempty"`         // 未过期快照条目数
	K8sMetaInferredOwners int     `json:"k8smeta_inferred_owners,omitempty"` // Workload 为 ReplicaSet 截尾推断的条目数
	K8sMetaStaleSeconds   float64 `json:"k8smeta_stale_seconds,omitempty"`   // 距上次成功同步秒数（非 OK 时）
	K8sMetaSyncFailures   uint64  `json:"k8smeta_sync_failures,omitempty"`   // 累计同步失败次数
}

// InterfaceInfo 注册上报的网卡信息（契约 §3.1）。
type InterfaceInfo struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	MTU       int    `json:"mtu"`
	SpeedMbps int    `json:"speed_mbps"`
}

// Capabilities 能力声明/回执（HTTP 事件 v2 契约 §3：注册/心跳可选扩展；
// 旧服务端无此响应字段、旧 Agent 无此请求字段，双向忽略即为降级协商）。
type Capabilities struct {
	HTTPEventSchemaVersions      []int `json:"http_event_schema_versions"`
	APIObservationSchemaVersions []int `json:"api_observation_schema_versions"`
}

// HasSchemaVersion 能力集是否含指定 HTTP 事件 schema 版本（nil 安全：
// 旧服务端无回执字段 → 仅 v1）。
func (c *Capabilities) HasSchemaVersion(v int) bool {
	if c == nil {
		return false
	}
	for _, x := range c.HTTPEventSchemaVersions {
		if x == v {
			return true
		}
	}
	return false
}

func (c *Capabilities) HasAPIObservationSchemaVersion(v int) bool {
	if c == nil {
		return false
	}
	for _, x := range c.APIObservationSchemaVersions {
		if x == v {
			return true
		}
	}
	return false
}

// DeclaredCapabilities 本 Agent 的 HTTP 与 API Observation 能力声明；生效集以服务端回执为准。
func DeclaredCapabilities() *Capabilities {
	return &Capabilities{
		HTTPEventSchemaVersions:      []int{1, events.HTTPRecordSchemaVersion},
		APIObservationSchemaVersions: []int{apievent.SchemaVersion},
	}
}

// EnrollRequest 注册请求（契约 §3.1；csr_pem 为 Phase 2-B 增量，契约 §7；
// capabilities 为 v2 契约 §3 增量，缺省 = 仅 v1）。
type EnrollRequest struct {
	EnrollmentToken string          `json:"enrollment_token"`
	Hostname        string          `json:"hostname"`
	IP              string          `json:"ip"`
	OS              string          `json:"os"`
	Kernel          string          `json:"kernel"`
	Arch            string          `json:"arch"`
	Version         string          `json:"version"`
	Interfaces      []InterfaceInfo `json:"interfaces"`
	// CSRPEM 机器身份 CSR（CN 留空由服务端填 agent_id）；缺省时服务端不签发证书，
	// 响应证书三字段为 null，Agent 退化 Bearer 模式（契约 §7）。
	CSRPEM string `json:"csr_pem,omitempty"`
	// Capabilities 能力声明（v2 契约 §3）；nil 等价于仅声明 v1。
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// EnrollResponse 注册响应 201（证书三字段为 Phase 2-B 增量，老服务端为 null→空串）。
type EnrollResponse struct {
	AgentID                  string `json:"agent_id"`
	Credential               string `json:"credential"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ConfigVersion            int64  `json:"config_version"`
	AgentCertPEM             string `json:"agent_cert_pem"`
	CACertPEM                string `json:"ca_cert_pem"`
	CertExpiresAt            string `json:"cert_expires_at"`
	// Capabilities 服务端回执的生效能力集（v2 契约 §3；旧服务端无此字段 → nil，
	// 按仅 v1 处理）。
	Capabilities *Capabilities `json:"capabilities"`
}

// RotateCertRequest 证书轮换请求（契约 §9）。
type RotateCertRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RotateCertResponse 证书轮换响应（契约 §9）。
type RotateCertResponse struct {
	AgentCertPEM  string `json:"agent_cert_pem"`
	CACertPEM     string `json:"ca_cert_pem"`
	CertExpiresAt string `json:"cert_expires_at"`
}

// HeartbeatRequest 心跳请求（契约 §3.2；capabilities 为 v2 契约 §3 增量——
// 携带时服务端更新生效集，未携带保持既有值）。
type HeartbeatRequest struct {
	Timestamp    int64         `json:"timestamp"`
	Status       string        `json:"status"` // ONLINE | DEGRADED | ERROR
	Metrics      Metrics       `json:"metrics"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// HeartbeatResponse 心跳响应 200。
type HeartbeatResponse struct {
	ServerTime               int64  `json:"server_time"`
	ConfigVersion            int64  `json:"config_version"`
	DesiredState             string `json:"desired_state"` // ENABLED | DISABLED
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	// Capabilities 服务端回执的生效能力集（v2 契约 §3；旧服务端无此字段 → nil）。
	Capabilities *Capabilities `json:"capabilities"`
}

// ConfigResponse 配置拉取响应（契约 §3.3）；Policy 为 nil 表示无绑定策略。
// Overrides 为 Phase 4 增量（契约 §2.4：顶层字段，未过期规则全量；
// 旧服务端无此字段按空数组处理）。
type ConfigResponse struct {
	Version   int64            `json:"version"`
	Policy    *json.RawMessage `json:"policy"`
	Overrides json.RawMessage  `json:"overrides"`
}

// AckRequest 配置 ACK 请求。
type AckRequest struct {
	Version int64  `json:"version"`
	Status  string `json:"status"` // APPLIED | FAILED
	Error   string `json:"error"`
}

// APIError 契约 §2 统一错误结构。
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	// RetryAfter 429 响应的 Retry-After 解析值（秒数或 HTTP 日期；无该头为 0）。
	RetryAfter time.Duration `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d: %s: %s", e.StatusCode, e.Code, e.Message)
}

// IsUnauthorized 判定 401（credential 失效等）。
func IsUnauthorized(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusUnauthorized
	}
	return false
}

// IsNotFound 判定 404（Phase 3 契约 §10：旧服务端无 /http 端点 → 降级 L0）。
func IsNotFound(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusNotFound
	}
	return false
}

// IsPermanent 判定永久非法（P1-03 §4.2.4：400 记录非法 / 413 正文超限 /
// 422 schema 不支持）。永久失败不重试、不整批转缓存——调用方隔离非法记录
// 重建批次，单条永久失败丢弃并计数（dropped_by_reason=permanent_invalid）。
func IsPermanent(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.StatusCode {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return true
		}
	}
	return false
}

// IsTooManyRequests 判定 429（调用方必须尊重 Retry-After，见 RetryAfterOf）。
func IsTooManyRequests(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// maxRetryAfter Retry-After 上限钳制（防异常服务端把数据通道钉死）。
const maxRetryAfter = 5 * time.Minute

// RetryAfterOf 取错误的 Retry-After 建议等待时长（无则 0；>5min 钳制）。
func RetryAfterOf(err error) time.Duration {
	var ae *APIError
	if errors.As(err, &ae) {
		if ae.RetryAfter > maxRetryAfter {
			return maxRetryAfter
		}
		return ae.RetryAfter
	}
	return 0
}

// parseRetryAfter 解析 Retry-After 头（秒数或 HTTP 日期；非法/过去时刻为 0）。
func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// Client WDSP 机器端点客户端。
type Client struct {
	base  string
	cred  string
	hc    *http.Client
	agent string // User-Agent

	identity      atomic.Pointer[Identity] // PoP 机器身份（nil=仅 Bearer）
	expiredWarned atomic.Bool              // 证书过期 WARN 只记一次
	now           func() time.Time         // 可注入（测试）
}

// New 创建客户端；server 为 https://host[:port] 基地址。
// 安全约束（契约 §1）：非 https 一律拒绝；唯一例外是 loopback 地址的 http
// （本机回环，Bearer credential 不离开主机）——允许但 WARN，避免明文地址
// 被静默固化进 agent.json 后在非本机环境使用。
func New(server string, insecureSkipVerify bool, version string) (*Client, error) {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("server 地址非法（须为 https://host[:port]）: %q", server)
	}
	if u.Scheme == "http" {
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("server 地址必须使用 https（http 明文传输 Bearer credential）；仅 loopback 地址允许 http: %q", server)
		}
		slog.Default().Warn("控制面使用 http loopback 明文通道（仅限本机回环实验用途，生产必须 https）", "server", server)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // MinVersion 已锁 1.2
	if insecureSkipVerify {
		// 仅显式 --insecure-skip-verify 开启（自签实验环境），契约 §1 生产必须 HTTPS+证书校验
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}
	return &Client{
		base:  strings.TrimRight(server, "/"),
		agent: "wdsp-agent/" + version,
		now:   time.Now,
		hc: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: rejectControlRedirect,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConns:        4,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}, nil
}

// SetCredential 设置注册后下发的 credential。
func (c *Client) SetCredential(cred string) { c.cred = cred }

// isLoopbackHost 判定主机名为本机回环（IP loopback 或 localhost）。
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// rejectControlRedirect 防止携带 Bearer/PoP 凭据的控制面请求被重定向到另一主机
// 或从 HTTPS 降级到 HTTP。http.Client 在调用此函数前不会向目标发出后续请求。
func rejectControlRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil || len(via) == 0 || via[len(via)-1].URL == nil {
		return errors.New("拒绝控制面重定向：目标地址无效")
	}
	previous := via[len(via)-1].URL
	if strings.EqualFold(previous.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("拒绝控制面 HTTPS 降级重定向: %s -> %s", previous.Scheme, req.URL.Scheme)
	}
	if !strings.EqualFold(previous.Host, req.URL.Host) {
		return fmt.Errorf("拒绝控制面跨主机重定向: %s -> %s", previous.Host, req.URL.Host)
	}
	return nil
}

// do 执行 JSON 请求；auth=true 时携带 Bearer credential，且持有有效证书时
// 一并注入 PoP 三头（契约 §8，三头一体，签名失败则不发出请求）。
func (c *Client) do(ctx context.Context, method, path string, body any, auth bool, contentType string, raw []byte) ([]byte, int, error) {
	var bodyBytes []byte
	if raw != nil {
		bodyBytes = raw
	} else if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("序列化请求: %w", err)
		}
		bodyBytes = data
		contentType = "application/json"
	}
	var rdr io.Reader
	if bodyBytes != nil {
		rdr = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", c.agent)
	if auth {
		appliedPoP, err := c.applyPoP(req, bodyBytes)
		if err != nil {
			return nil, 0, err
		}
		if !appliedPoP {
			req.Header.Set("Authorization", "Bearer "+c.cred)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求 %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("读取响应: %w", err)
	}
	if resp.StatusCode >= 400 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Code: "UNKNOWN", Message: http.StatusText(resp.StatusCode)}
		apiErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &envelope) == nil && envelope.Error.Code != "" {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return data, resp.StatusCode, apiErr
	}
	return data, resp.StatusCode, nil
}

// Enroll 注册（契约 §3.1，无需 credential）。
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	data, code, err := c.do(ctx, http.MethodPost, "/api/v1/agents/enroll", req, false, "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusCreated {
		return nil, &APIError{StatusCode: code, Code: "UNEXPECTED_STATUS", Message: fmt.Sprintf("期望 201，收到 %d", code)}
	}
	var out EnrollResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析注册响应: %w", err)
	}
	if out.AgentID == "" || out.Credential == "" {
		return nil, &APIError{StatusCode: code, Code: "BAD_RESPONSE", Message: "注册响应缺少 agent_id/credential"}
	}
	return &out, nil
}

// Heartbeat 心跳（契约 §3.2）。
func (c *Client) Heartbeat(ctx context.Context, agentID string, req HeartbeatRequest) (*HeartbeatResponse, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/heartbeat", req, true, "", nil)
	if err != nil {
		return nil, err
	}
	var out HeartbeatResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析心跳响应: %w", err)
	}
	return &out, nil
}

// PostMetrics 独立 metrics 上报（契约 §3.2，204）。
func (c *Client) PostMetrics(ctx context.Context, agentID string, m Metrics) error {
	_, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/metrics", m, true, "", nil)
	return err
}

// GetConfig 拉取配置（契约 §3.3）。
func (c *Client) GetConfig(ctx context.Context, agentID string) (*ConfigResponse, error) {
	data, _, err := c.do(ctx, http.MethodGet, "/api/v1/agents/"+agentID+"/config", nil, true, "", nil)
	if err != nil {
		return nil, err
	}
	var out ConfigResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析配置响应: %w", err)
	}
	return &out, nil
}

// AckConfig 配置 ACK（契约 §3.3）。
func (c *Client) AckConfig(ctx context.Context, agentID string, ack AckRequest) error {
	_, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/config/ack", ack, true, "", nil)
	return err
}

// PostFlows 流量事件批量上报（契约 §3.4，202）。调用方保证 events ≤500。
func (c *Client) PostFlows(ctx context.Context, agentID string, evs []events.FlowEvent) (int, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/flows", events.FlowsRequest{Events: evs}, true, "", nil)
	if err != nil {
		return 0, err
	}
	var out events.FlowsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("解析 flows 响应: %w", err)
	}
	return out.Accepted, nil
}

// PostHTTP HTTP 记录批量上报（Phase 3 契约 §3，202）。调用方保证 records ≤100 且 ≤8MB。
// 404（旧服务端无端点）可通过 IsNotFound 判定，由调用方降级 L0 且不再重试；
// 400/413/422 为永久非法（IsPermanent），429 须尊重 Retry-After（IsTooManyRequests）。
// 返回服务端确认的 accepted 与 duplicate 计数（v1 服务端无 duplicate 字段，恒 0）。
func (c *Client) PostHTTP(ctx context.Context, agentID string, recs []events.HTTPRecord) (accepted, duplicate int, err error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/http", events.HTTPRequest{Records: recs}, true, "", nil)
	if err != nil {
		return 0, 0, err
	}
	var out events.HTTPAcceptedResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, 0, fmt.Errorf("解析 http 响应: %w", err)
	}
	return out.Accepted, out.Duplicate, nil
}

// PostHTTPV2 HTTP 事件 v2 批次上报（v2 契约 §1/§4，202）。调用方保证 records ≤100
// 且 ≤8MB，且该 Agent 已通过能力协商获得 v2 生效集（未协商发送 → 400 永久失败，
// 调用方须降级 v1 采集模式重发，不得无限重试）。
// 返回 accepted/duplicate 分账（契约 §4.3：两者之和须等于输入条数，不符视为服务端
// 协议错误）；400 且响应携带 invalid_records 时返回全部非法记录的可定位索引
// （契约 §4.4，调用方按索引隔离丢弃后重建剩余批次重发，不再二分）。
func (c *Client) PostHTTPV2(ctx context.Context, agentID string, recs []events.HTTPRecordV2) (accepted, duplicate int, invalid []events.InvalidRecord, err error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/http",
		events.HTTPRequestV2{SchemaVersion: events.HTTPRecordSchemaVersion, Records: recs}, true, "", nil)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.StatusCode == http.StatusBadRequest && len(data) > 0 {
			var body struct {
				InvalidRecords []events.InvalidRecord `json:"invalid_records"`
			}
			if json.Unmarshal(data, &body) == nil && len(body.InvalidRecords) > 0 {
				invalid = body.InvalidRecords
			}
		}
		return 0, 0, invalid, err
	}
	var out events.HTTPV2Response
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, 0, nil, fmt.Errorf("解析 http v2 响应: %w", err)
	}
	if out.AcceptedCount < 0 || out.DuplicateCount < 0 || out.AcceptedCount+out.DuplicateCount != len(recs) {
		return 0, 0, nil, fmt.Errorf("http v2 响应计数与输入条数不符（accepted_count=%d duplicate_count=%d records=%d），按服务端错误处理",
			out.AcceptedCount, out.DuplicateCount, len(recs))
	}
	return out.AcceptedCount, out.DuplicateCount, nil, nil
}

// PostPackets RAW 包批量上报（契约 §3.5，202，二进制 body）。
func (c *Client) PostPackets(ctx context.Context, agentID string, batch []byte) (int, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/packets", nil, true,
		"application/x-wdsp-packet-batch", batch)
	if err != nil {
		return 0, err
	}
	var out events.PacketsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("解析 packets 响应: %w", err)
	}
	return out.AcceptedFrames, nil
}

// RotateCert 证书轮换（契约 §9，仅 PoP 认证可用；PoP 头由 do 用当前证书自动注入）。
func (c *Client) RotateCert(ctx context.Context, agentID, csrPEM string) (*RotateCertResponse, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/rotate-cert",
		RotateCertRequest{CSRPEM: csrPEM}, true, "", nil)
	if err != nil {
		return nil, err
	}
	var out RotateCertResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("解析轮换响应: %w", err)
	}
	if out.AgentCertPEM == "" {
		return nil, &APIError{StatusCode: http.StatusOK, Code: "BAD_RESPONSE", Message: "轮换响应缺少 agent_cert_pem"}
	}
	return &out, nil
}

func (c *Client) PostAPIObservations(ctx context.Context, agentID string, records []apievent.Record) (int, int, error) {
	data, _, err := c.do(ctx, http.MethodPost, "/api/v1/agents/"+agentID+"/api-observations",
		apievent.Batch{SchemaVersion: apievent.SchemaVersion, Records: records}, true, "", nil)
	if err != nil {
		return 0, 0, err
	}
	var out apievent.Response
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, 0, fmt.Errorf("解析 API Observation 响应: %w", err)
	}
	if out.AcceptedCount < 0 || out.DuplicateCount < 0 || out.AcceptedCount+out.DuplicateCount != len(records) {
		return 0, 0, fmt.Errorf("API Observation 响应计数与输入不符")
	}
	return out.AcceptedCount, out.DuplicateCount, nil
}
