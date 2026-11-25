// 全量访问日志（二期）：全量请求的完整头体留痕采集。
//
// 设计约束：
//   - 默认关闭（access_log 缺省或 enabled=false 时零行为变化、零额外开销）；
//   - 采集点在 ServeHTTP 入口（APM 阶段1，ADR D9）：人工封禁/IP黑白名单/L7/授权限速/CC 等
//     前置拦截（403/429/重定向/自定义页）与放行链路同样产生记录，单请求只记一条（defer 保证）；
//   - 写文件前做与服务端一致的脱敏（敏感头掩码 + 请求体敏感键值掩码 + 查询串敏感参数掩码），
//     敏感名单与 server/internal/securityevents/normalize.go 保持一致（guard 为独立 module，不能 import server 包）；
//   - 输出 JSON Lines 由管理平台 accesslogs 采集器 tail 入库（对应 access_logs 表）；
//   - 采集失败一律 fail-open（记告警，不阻断业务），与 guard 既有故障策略一致；
//   - WebSocket / SSE / 非文本响应不采响应体，头体超限截断并打 truncated 标记。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/tlsmux"
	"go.uber.org/zap"
)

// accessLogJSON 全量访问日志配置（与管理后端 GuardConfig.AccessLog JSON 约定一致）。
type accessLogJSON struct {
	Enabled                bool   `json:"enabled"`
	CaptureRequestHeaders  bool   `json:"capture_request_headers"`
	CaptureRequestBody     bool   `json:"capture_request_body"`
	CaptureResponseHeaders bool   `json:"capture_response_headers"`
	CaptureResponseBody    bool   `json:"capture_response_body"`
	BodyLimitKB            int    `json:"body_limit_kb,omitempty"`
	LogPath                string `json:"log_path,omitempty"`
}

// 默认配置（未下发或字段缺省时兜底，与服务端 settings 种子一致）。
const (
	defaultAccessLogPath      = "/var/log/caddy/access-full.jsonl"
	defaultAccessLogBodyLimit = 64 * 1024
	maxAccessLogStringLen     = 2048 // 单字段截断（防超大输入撑爆日志）
)

// 敏感请求/响应头：写盘前掩码（与 server 侧 sensitiveHeaders 同一份名单）。
var accessLogSensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

// 敏感参数名（查询串/请求体键值掩码，与 server 侧 sensitiveParams 同一份名单）。
var accessLogSensitiveParams = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "token": true, "access_token": true,
	"refresh_token": true, "secret": true, "api_key": true, "apikey": true, "key": true,
	"session": true, "sessionid": true, "auth": true, "credential": true, "private_key": true,
	"client_secret": true, "id_token": true,
}

// accessLogConnPortKey 请求上下文中的原始连接端口键（RemoteAddr 被改写前由 ServeHTTP 写入）。
type accessLogConnPortKey struct{}

// waf_action 三态（APM 阶段1，ADR D9；网关不再发出空串，旧空串数据由服务端按 ALLOW 口径归一）：
// BLOCK 任一防护组件拦截（前置拦截、Coraza 中断、API 管线阻断）；OBSERVE 仅观察命中未拦截
// （CC/API 观察）；ALLOW 其余放行。
const (
	wafActionBlock   = "BLOCK"
	wafActionObserve = "OBSERVE"
	wafActionAllow   = "ALLOW"
)

// accessLogAnnotationKey 请求上下文中的访问日志标注键（仅访问日志开启时由 ServeHTTP 写入）。
type accessLogAnnotationKey struct{}

// accessLogAnnotation 请求级访问日志标注：前置拦截/观察分支写入 waf_action，采集点读取。
// 请求处理链单 goroutine 顺序执行，无需加锁。
type accessLogAnnotation struct {
	wafAction string
}

// mark 标注 waf_action；BLOCK 最高优先不被覆盖，OBSERVE 仅在未标注时落定。
func (a *accessLogAnnotation) mark(action string) {
	if action == wafActionBlock || a.wafAction == "" {
		a.wafAction = action
	}
}

// accessLogAnnotate 向请求访问日志标注 waf_action（访问日志关闭时上下文无标注，no-op）。
func accessLogAnnotate(ctx context.Context, action string) {
	if a, ok := ctx.Value(accessLogAnnotationKey{}).(*accessLogAnnotation); ok && a != nil {
		a.mark(action)
	}
}

// ttfbTrackerKey 请求上下文中的 TTFB 计量键（仅访问日志开启时由 ServeHTTP 写入）。
type ttfbTrackerKey struct{}

// ttfbTracker TTFB 计量（APM 阶段1，ADR D8）：serveNext 进入下游链时打点，
// 包装 writer 首个 Write/WriteHeader/Flush 时结算。前置拦截无下游阶段，ttfb_ms 缺省（omitempty）。
type ttfbTracker struct {
	downstreamStart time.Time
	ttfbMS          int64
	settled         bool
}

// markDownstreamEntry 记录下游链进入时刻（serveNext 调用；幂等取首次）。
func (t *ttfbTracker) markDownstreamEntry() {
	if t.downstreamStart.IsZero() {
		t.downstreamStart = time.Now()
	}
}

// markFirstByte 首个响应字节外发时结算 TTFB（相对下游链进入时刻，含 WAF 检测 + 上游到首字节）。
func (t *ttfbTracker) markFirstByte() {
	if t.settled || t.downstreamStart.IsZero() {
		return
	}
	t.settled = true
	t.ttfbMS = time.Since(t.downstreamStart).Milliseconds()
}

// markAccessLogDownstreamEntry serveNext 进入下游链打点（访问日志关闭时上下文无 tracker，no-op）。
func markAccessLogDownstreamEntry(ctx context.Context) {
	if t, ok := ctx.Value(ttfbTrackerKey{}).(*ttfbTracker); ok && t != nil {
		t.markDownstreamEntry()
	}
}

// accessLogRecord 单条全量访问日志（字段与 access_logs 表一一对应）。
type accessLogRecord struct {
	OccurredAt    time.Time `json:"occurred_at"`
	RequestID     string    `json:"request_id"`
	ApplicationID string    `json:"application_id,omitempty"`
	Domain        string    `json:"domain"`
	GatewayNode   string    `json:"gateway_node_id"`
	ClientIP      string    `json:"client_ip"`
	ClientPort    int       `json:"client_port"`
	// 阶段5 §6.5 真实 IP 识别日志字段（旧网关不携带时缺省，服务端落 NULL）
	ClientIPSource        string              `json:"client_ip_source,omitempty"`
	TrustedProxyUsed      string              `json:"trusted_proxy_used,omitempty"`
	ForwardedChainSummary string              `json:"forwarded_chain_summary,omitempty"`
	Method                string              `json:"request_method"`
	URI                   string              `json:"request_uri"`
	Path                  string              `json:"request_path"`
	QuerySummary          string              `json:"query_summary"`
	HTTPVersion           string              `json:"http_version"`
	// SSL/TLS/国密加密会话分析字段（明文 HTTP 时 omitempty 省略，保持零行为变化）
	TLSProtocol           string              `json:"tls_protocol,omitempty"`
	TLSCipherSuite        string              `json:"tls_cipher_suite,omitempty"`
	TLSIsGM               bool                `json:"tls_is_gm,omitempty"`
	TLSJA3                string              `json:"tls_ja3,omitempty"`
	ClientHelloVersion    string              `json:"client_hello_version,omitempty"`
	ContentType           string              `json:"content_type"`
	UserAgent             string              `json:"user_agent_summary"`
	Referer               string              `json:"referer_summary"`
	ResponseStatus        int                 `json:"response_status"`
	BytesIn               int64               `json:"bytes_in"`
	BytesOut              int64               `json:"bytes_out"`
	DurationMS            int64               `json:"duration_ms"`
	WAFAction             string              `json:"waf_action"`
	TraceID               string              `json:"trace_id"`
	SpanID                string              `json:"span_id"`
	EndpointKey           string              `json:"endpoint_key"`
	PathTemplate          string              `json:"path_template"`
	TTFBMS                int64               `json:"ttfb_ms,omitempty"`
	RequestHeaders        map[string][]string `json:"request_headers,omitempty"`
	RequestBody           string              `json:"request_body,omitempty"`
	RequestBodyTruncated  bool                `json:"request_body_truncated,omitempty"`
	ResponseHeaders       map[string][]string `json:"response_headers,omitempty"`
	ResponseBody          string              `json:"response_body,omitempty"`
	ResponseBodyTruncated bool                `json:"response_body_truncated,omitempty"`
}

// accessLogWriter JSON Lines 访问日志记录器（并发安全；写失败返回错误由调用方告警）。
type accessLogWriter struct {
	mu sync.Mutex
	f  *os.File
}

func newAccessLogWriter(path string) (*accessLogWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open access log: %w", err)
	}
	return &accessLogWriter{f: f}, nil
}

func (w *accessLogWriter) write(rec *accessLogRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal access log: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write access log: %w", err)
	}
	return nil
}

func (w *accessLogWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// captureResponseWriter 包装下游 ResponseWriter，捕获状态码/响应头/响应体（可选），
// 并经 tracker 结算 TTFB（首个 Write/WriteHeader/Flush 时刻）。
// 实现 http.Flusher（反向代理/SSE 需要透传 Flush）。
type captureResponseWriter struct {
	http.ResponseWriter
	cfg           *accessLogJSON
	bodyLimit     int
	status        int
	bytesOut      int64
	body          bytes.Buffer
	bodyTruncated bool
	captureBody   bool
	decided       bool
	tracker       *ttfbTracker // TTFB 计量（nil = 不计量）
}

func (w *captureResponseWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true
	if !w.cfg.CaptureResponseBody {
		return // 未开启响应体留痕：仅记录状态码与字节数
	}
	if w.status == http.StatusSwitchingProtocols {
		return // WebSocket 升级：不采体
	}
	h := w.Header()
	if !strings.EqualFold(h.Get("Upgrade"), "") {
		return // WebSocket：不采体
	}
	ct := h.Get("Content-Type")
	if !isTextualContentType(ct) {
		return // SSE（text/event-stream）/二进制/未知：不采体
	}
	w.captureBody = true
}

func (w *captureResponseWriter) WriteHeader(code int) {
	// 仅首个最终状态码落定：1xx 信息响应（如 103 Early Hints）不结算状态/采体决策/TTFB，
	// 全部透传下游（与 identitybehavior statusWriter 同一纪律）
	if w.status == 0 && (code < 100 || code >= 200) {
		w.status = code
		w.decide()
		if w.tracker != nil {
			w.tracker.markFirstByte()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.decide()
		if w.tracker != nil {
			w.tracker.markFirstByte()
		}
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesOut += int64(n)
	if w.captureBody && !w.bodyTruncated {
		remain := w.bodyLimit - w.body.Len()
		if remain > 0 {
			if len(p) <= remain {
				w.body.Write(p)
			} else {
				w.body.Write(p[:remain])
				w.bodyTruncated = true
			}
		} else {
			w.bodyTruncated = true
		}
	}
	return n, err
}

// Flush 透传底层 Flusher（SSE/流式响应依赖；无底层能力时退化为 no-op 状态提交）。
func (w *captureResponseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
		w.decide()
		if w.tracker != nil {
			w.tracker.markFirstByte()
		}
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 返回底层 writer（http.ResponseController 依赖，用于透传 Hijack 等可选能力）。
func (w *captureResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack 透传连接劫持（WebSocket 升级需要；底层不支持时如实报错）。
func (w *captureResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

// isTextualContentType 判定响应体是否文本类（SSE 明确排除，防止无限流撑爆内存）。
func isTextualContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if ct == "" || ct == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript",
		"application/x-javascript", "application/x-www-form-urlencoded",
		"application/problem+json", "application/problem+xml":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

// captureAccessLog 自 ServeHTTP 入口包装整条 guard 处理链采集全量访问日志（APM 阶段1 D9：
// 人工封禁/黑白名单/L7/授权限速/CC 等前置拦截分支同样产生记录）；defer 收口保证单请求只记
// 一条（handler panic 也尽力落一条）；采集失败仅告警，不影响请求。
// duration_ms 口径（D8）：自入口起算——前置拦截为网关处理耗时（无下游阶段），放行链路为
// guard 放行链路总耗时；ttfb_ms 为下游链进入到首个响应字节（前置拦截无下游，缺省）。
func (g *Guard) captureAccessLog(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request) error) (err error) {
	cfg := g.AccessLog
	start := time.Now().UTC()
	bodyLimit := cfg.BodyLimitKB * 1024
	if bodyLimit <= 0 {
		bodyLimit = defaultAccessLogBodyLimit
	}

	rec := &accessLogRecord{
		OccurredAt:    start,
		RequestID:     sanitizeAccessLogField(r.Header.Get("X-Request-Id"), 64),
		ApplicationID: g.AppID,
		Domain:        sanitizeAccessLogField(requestHost(r), 255),
		GatewayNode:   g.GatewayNode,
		Method:        sanitizeAccessLogField(r.Method, 16),
		HTTPVersion:   sanitizeAccessLogField(r.Proto, 16),
		ContentType:   sanitizeAccessLogField(r.Header.Get("Content-Type"), 255),
		UserAgent:     sanitizeAccessLogField(r.UserAgent(), 512),
		Referer:       sanitizeAccessLogField(r.Referer(), 512),
	}
	// SSL/TLS/国密加密会话分析字段：优先取 jiuzhang_tls_mux 连接元数据（含 ClientHello 与 JA3），回退 r.TLS
	if meta := tlsConnMetaFrom(r.Context()); meta != nil {
		rec.TLSProtocol = sanitizeAccessLogField(meta.NegotiatedProtocol, 24)
		rec.TLSCipherSuite = sanitizeAccessLogField(meta.CipherSuite, 64)
		rec.TLSIsGM = meta.IsGM
		rec.TLSJA3 = sanitizeAccessLogField(meta.JA3Hash, 64)
		rec.ClientHelloVersion = sanitizeAccessLogField(meta.DetectedProtocol, 24)
	} else if r.TLS != nil {
		isGM := r.TLS.Version == tlsmux.VersionTLCP11 || tlsmux.IsGMCipherSuite(r.TLS.CipherSuite)
		rec.TLSProtocol = sanitizeAccessLogField(tlsmux.ProtocolLabel(r.TLS.Version), 24)
		rec.TLSCipherSuite = sanitizeAccessLogField(tlsmux.CipherSuiteDisplayName(r.TLS.CipherSuite, isGM), 64)
		rec.TLSIsGM = isGM
	}
	// APM 阶段1（D6/D7）：trace 关联键与端点归一化对所有请求计算（归一化为纯函数，
	// 不依赖 API 动态防护管线，WAF-only 站点同样可用）；path 为空时端点字段留空
	tc := traceContextFrom(r.Context())
	rec.TraceID = tc.TraceID
	rec.SpanID = tc.SpanID
	if p := r.URL.Path; p != "" {
		rec.PathTemplate = sanitizeAccessLogField(normalizer.NormalizePath(p), 512)
		rec.EndpointKey = sanitizeAccessLogField(normalizer.EndpointKey(r.Method, p), 560)
	}
	// 原始连接端口须在入口提取：handler 内 serveGuard 会把 RemoteAddr 改写为「真实IP:0」
	// 而丢失连接端口（ServeHTTP 入口亦已将其经上下文传入兜底）。client_ip 不在此处取值——
	// 真实 IP 识别发生在 handler 内，入口时 RemoteAddr 尚是连接源地址（可信 LB 后会误记
	// LB 地址），统一在 defer 收口处取识别结果（与安全事件 ClientIP 口径一致）。
	if _, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if p, err := strconv.Atoi(port); err == nil {
			rec.ClientPort = p
		}
	}
	if p, ok := r.Context().Value(accessLogConnPortKey{}).(int); ok {
		rec.ClientPort = p
	}
	uri := r.URL.RequestURI()
	rec.URI = sanitizeAccessLogField(maskAccessLogURI(uri), maxAccessLogStringLen)
	rec.Path = sanitizeAccessLogField(r.URL.Path, 1024)
	rec.QuerySummary = sanitizeAccessLogField(maskAccessLogQuery(r.URL.RawQuery), 1024)
	rec.BytesIn = r.ContentLength // 未知时为 -1，入库前归一为 0

	if cfg.CaptureRequestHeaders {
		rec.RequestHeaders = maskAccessLogHeaders(r.Header)
	}
	// 请求体：开启时留痕。限流读（多读 1 字节探测超限）：本采集在预认证阶段生效，
	// Coraza 的 12.5MB 请求体限制在更下游、保护不到此处，整包读入有内存耗尽面；
	// 超限只留痕前缀并标 truncated，已读前缀 + 剩余流拼回完整 Body 交下游 WAF/反代
	// （护栏风格与 preserveRequestBody 一致：留痕截断不影响业务报文完整性）。
	if cfg.CaptureRequestBody && r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		b, err := io.ReadAll(io.LimitReader(r.Body, int64(bodyLimit)+1))
		over := err == nil && len(b) > bodyLimit
		if over || err != nil {
			// 剩余流不丢弃：尽力还原完整请求体给下游（含读失败的已读部分）
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		} else {
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		if err == nil {
			if over {
				rec.RequestBodyTruncated = true
				b = b[:bodyLimit]
				// BytesIn 保持 ContentLength（未知则入库前归一 0）：超限后不编造总长度
			} else {
				rec.BytesIn = int64(len(b))
			}
			rec.RequestBody = sanitizeAccessLogBody(maskAccessLogBody(string(b), r.Header.Get("Content-Type")))
		}
	}

	tracker, _ := r.Context().Value(ttfbTrackerKey{}).(*ttfbTracker)
	ann, _ := r.Context().Value(accessLogAnnotationKey{}).(*accessLogAnnotation)
	cw := &captureResponseWriter{ResponseWriter: w, cfg: cfg, bodyLimit: bodyLimit, tracker: tracker}

	// 请求结束（含 panic 路径）：组装响应字段并落盘（失败只记日志）
	defer func() {
		rec.DurationMS = time.Since(start).Milliseconds()
		rec.ResponseStatus = cw.status
		// client_ip 收口取值：优先真实 IP 识别结果（serveGuard 识别后写入请求上下文，
		// 可信 LB 后不再误记连接源/LB 地址）；识别结果缺失（连接源不可解析被入口拒绝等
		// 未写入场景）回落当前 RemoteAddr——放行链路此时已被改写为真实 IP，口径一致
		if res, ok := clientIPResultFrom(r.Context()); ok && res.ClientIP.IsValid() {
			rec.ClientIP = res.ClientIP.String()
			// 阶段5 §6.5：识别来源/可信代理命中/代理链摘要（与事件同口径）
			rec.ClientIPSource = sanitizeAccessLogField(string(res.Source), 32)
			rec.TrustedProxyUsed = sanitizeAccessLogField(res.TrustedProxyUsed, 128)
			rec.ForwardedChainSummary = sanitizeAccessLogField(res.ChainSummary, 256)
		} else if host, _, serr := net.SplitHostPort(r.RemoteAddr); serr == nil {
			rec.ClientIP = host
		} else {
			rec.ClientIP = r.RemoteAddr
		}
		if err == nil {
			// 处理器未显式写状态码且正常返回：归一为 200，
			// 与 API 捕获侧 outcome()（apiresponse.go）同一归一规则
			if rec.ResponseStatus == 0 {
				rec.ResponseStatus = http.StatusOK
			}
		} else {
			// 仅当错误链确证 WAF 归属（coraza 中断 / guard API 防护管线阻断）才标 BLOCK；
			// 源站自返 403 与普通 HandlerError 不标 BLOCK（不误归因，回落 ALLOW）。
			// Coraza 请求相位阻断不写响应、仅返回 HandlerError（见 apicoraza.go 调查结论）：
			// 从错误链兜底取中断状态码，避免被拦截请求 response_status 记 0
			var he caddyhttp.HandlerError
			if isWAFInterception(err) && ann != nil {
				ann.mark(wafActionBlock)
			}
			if rec.ResponseStatus == 0 && errors.As(err, &he) {
				rec.ResponseStatus = he.StatusCode
			}
		}
		// waf_action 三态收口（D9）：分支标注 > 统一上下文最终决策（API 管线阻断/观察）> 放行；
		// 网关不再发出空串
		action := ""
		if ann != nil {
			action = ann.wafAction
		}
		if action != wafActionBlock {
			if rc := RequestContextFrom(r); rc != nil {
				switch rc.GetFinalAction() {
				case dsctx.ActionBlock, dsctx.ActionRateLimit, dsctx.ActionTempBlock:
					action = wafActionBlock
				case dsctx.ActionObserve:
					if action == "" {
						action = wafActionObserve
					}
				}
			}
		}
		if action == "" {
			action = wafActionAllow
		}
		rec.WAFAction = action
		if tracker != nil {
			rec.TTFBMS = tracker.ttfbMS
		}
		rec.BytesOut = cw.bytesOut
		if rec.BytesIn < 0 {
			rec.BytesIn = 0
		}
		if cfg.CaptureResponseHeaders {
			rec.ResponseHeaders = maskAccessLogHeaders(cw.Header())
		}
		if cw.captureBody {
			rec.ResponseBody = sanitizeAccessLogBody(maskAccessLogBody(cw.body.String(), cw.Header().Get("Content-Type")))
			rec.ResponseBodyTruncated = cw.bodyTruncated
		}
		if g.accessLog != nil {
			if werr := g.accessLog.write(rec); werr != nil {
				g.logger.Warn("access log write failed", zap.Error(werr))
			}
		}
	}()
	return handler(cw, r)
}

// guardBlockErrorMessages guard 自身在放行链路内（API 动态防护管线）返回的阻断错误消息。
// 字面量与 apiprotect.go runAPIProtection 的 caddyhttp.Error 调用耦合：消息变更必须同步复核。
var guardBlockErrorMessages = map[string]bool{
	"request blocked by api protection": true,
	"api request rate limited":          true,
	"api client temporarily blocked":    true,
}

// isWAFInterception 判定下游返回错误是否确证 WAF 归属的拦截：
// coraza-caddy 中断哨兵（见 apicoraza.go）或 guard API 动态防护管线阻断（均为 caddyhttp.HandlerError）。
// 其余错误（反代故障、普通 HandlerError）一律不归因。Coraza 响应头相位（phase 3）阻断无错误
// 返回、与源站 403 不可区分，同样不标（与 apicoraza.go 声明的局限一致，宁漏不误标）。
func isWAFInterception(err error) bool {
	if _, _, ok := corazaInterruption(err); ok {
		return true
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.Err == nil {
		return false
	}
	return guardBlockErrorMessages[he.Err.Error()]
}

// ---------- 脱敏（敏感名单与 server/internal/securityevents/normalize.go 一致） ----------

// maskAccessLogHeaders 返回敏感头掩码后的头部副本。
func maskAccessLogHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if accessLogSensitiveHeaders[strings.ToLower(k)] {
			masked := make([]string, len(v))
			for i := range masked {
				masked[i] = "masked"
			}
			out[k] = masked
			continue
		}
		cp := make([]string, len(v))
		for i, val := range v {
			cp[i] = sanitizeAccessLogField(val, 1024)
		}
		out[k] = cp
	}
	return out
}

// maskAccessLogBody 脱敏请求体敏感键值，按 Content-Type 分发：
//   - JSON 族（application/json、*+json）：优先 encoding/json 解析重建——任意空白形态
//     （"k":"v" / "k" : "v" 等）、嵌套结构与值内转义字符均由解析器正确处理；
//     解析失败（多为超限截断的残片）回退转义感知的字符串扫描；
//   - 表单（application/x-www-form-urlencoded）：按 & / ; 分段，键 URL-decode 后比对敏感名单
//     （pass%77ord= 等编码键亦可命中），命中掩码原始（未解码）值，其余字节原样保留；
//   - 其他/未知类型：保守起见表单与 JSON 两种字符串启发式都跑。
func maskAccessLogBody(body, contentType string) string {
	if body == "" {
		return body
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch {
	case ct == "application/json" || strings.HasSuffix(ct, "+json"):
		if out, ok := maskJSONBodyParsed(body); ok {
			return out
		}
		return maskJSONBodyHeuristic(body)
	case ct == "application/x-www-form-urlencoded":
		return maskFormHeuristic(maskFormBody(body))
	default:
		return maskJSONBodyHeuristic(maskFormHeuristic(body))
	}
}

// maskJSONBodyParsed 解析式 JSON 掩码：完整 JSON 解析-重建，敏感键（大小写不敏感）值替换为
// "masked"。重建按 encoding/json 规则重排键序，数值经 json.Number 保留字面量——仅影响留痕
// 表示，不影响业务报文。解析失败（截断残片/非法 JSON/顶层多值）返回 ok=false 由调用方回退。
func maskJSONBodyParsed(body string) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	if dec.More() {
		return "", false // 顶层值后仍有数据（残片/拼接）：不做解析式掩码
	}
	maskJSONSensitive(v)
	out, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// maskJSONSensitive 原地掩码 JSON 值树中的敏感键值（对象键大小写不敏感，嵌套对象/数组递归）。
func maskJSONSensitive(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if accessLogSensitiveParams[strings.ToLower(k)] {
				t[k] = "masked"
				continue
			}
			maskJSONSensitive(val)
		}
	case []any:
		for _, e := range t {
			maskJSONSensitive(e)
		}
	}
}

// maskJSONBodyHeuristic 字符串扫描式 JSON 掩码（截断残片等解析失败场景的兜底）：
// 匹配 "name" + 任意空白 + ':' + 任意空白 + '"' 的全部形态；值扫描感知 \ 转义，
// 值内 \" 不再被当作收尾引号（旧实现会在此截断，导致转义引号后的剩余内容泄漏）。
// 残余缝隙（如实声明）：非字符串标量值（"k": 123/true）不掩；键名被截断拆散的残片
// 无法识别；字符串值内部形似 "k":"v" 的内容会被过掩（安全方向）。
func maskJSONBodyHeuristic(body string) string {
	for name := range accessLogSensitiveParams {
		needle := `"` + name + `"`
		pos := 0
		for {
			idx := indexASCIIFold(body, needle, pos)
			if idx < 0 {
				break
			}
			p := skipJSONSpace(body, idx+len(needle))
			if p >= len(body) || body[p] != ':' {
				pos = idx + len(needle)
				continue
			}
			p = skipJSONSpace(body, p+1)
			if p >= len(body) || body[p] != '"' {
				pos = idx + len(needle)
				continue
			}
			start := p + 1
			end := start
			for end < len(body) {
				if body[end] == '\\' {
					end += 2 // 跳过转义序列（残片可能截断在 \ 后，由下方钳制）
					continue
				}
				if body[end] == '"' {
					break
				}
				end++
			}
			if end > len(body) {
				end = len(body)
			}
			body = body[:start] + "masked" + body[end:]
			pos = start + len("masked")
		}
	}
	return body
}

// maskFormBody 表单体掩码：按 & / ; 分段，键经 URL-decode 后比对敏感名单（大小写不敏感，
// pass%77ord= 等编码键亦可命中），命中以 "masked" 替换原始（未解码）值；其余字节原样保留。
// 键解码失败（非法 % 转义）的分段保持原样（无法确证敏感，不过掩）。
func maskFormBody(body string) string {
	var sb strings.Builder
	sb.Grow(len(body))
	for len(body) > 0 {
		seg, sep, rest := body, "", ""
		if i := strings.IndexAny(body, "&;"); i >= 0 {
			seg, sep, rest = body[:i], body[i:i+1], body[i+1:]
		}
		if eq := strings.IndexByte(seg, '='); eq >= 0 {
			if key, err := url.QueryUnescape(seg[:eq]); err == nil && accessLogSensitiveParams[strings.ToLower(key)] {
				seg = seg[:eq+1] + "masked"
			}
		}
		sb.WriteString(seg)
		sb.WriteString(sep)
		body = rest
	}
	return sb.String()
}

// maskFormHeuristic 原始 needle 扫描（name=value，值到 & ; 空格或结尾）：
// 未知 Content-Type 的保守兜底，兼作表单分段掩码后遗漏形态（如段内含空格）的回补。
func maskFormHeuristic(body string) string {
	for name := range accessLogSensitiveParams {
		needle := name + "="
		pos := 0
		for {
			idx := indexASCIIFold(body, needle, pos)
			if idx < 0 {
				break
			}
			start := idx + len(needle)
			end := start
			for end < len(body) && body[end] != '&' && body[end] != ';' && body[end] != ' ' {
				end++
			}
			body = body[:start] + "masked" + body[end:]
			pos = start + len("masked")
		}
	}
	return body
}

// skipJSONSpace 跳过 JSON 允许的空白字符。
func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

// indexASCIIFold 在 s 中从 from 起查找 needle（须为小写 ASCII），ASCII 大小写不敏感。
// 不做整串 ToLower：非 ASCII 字符（如 U+0130）小写化后字节长度会变，位置索引随之错位，
// 可能掩错字节而留下原文——逐字节比较规避该缝隙。
func indexASCIIFold(s, needle string, from int) int {
	for i := from; i+len(needle) <= len(s); i++ {
		j := 0
		for j < len(needle) {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				break
			}
			j++
		}
		if j == len(needle) {
			return i
		}
	}
	return -1
}

// maskAccessLogURI 对 URI 查询串敏感参数脱敏。
func maskAccessLogURI(uri string) string {
	qIdx := strings.Index(uri, "?")
	if qIdx < 0 {
		return uri
	}
	return uri[:qIdx] + "?" + maskAccessLogQuery(uri[qIdx+1:])
}

// maskAccessLogQuery 对查询串敏感参数值脱敏：参数名先 URL 解码再比对敏感名单
// （pass%77ord= 等编码键亦可命中，与 maskFormBody 同一纪律），命中以 "masked"
// 替换原始（未解码）值；解码失败（非法 % 转义）保持原样不过掩（无法确证敏感）。
func maskAccessLogQuery(query string) string {
	if query == "" {
		return ""
	}
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		name, err := url.QueryUnescape(p[:eq])
		if err != nil {
			continue
		}
		if accessLogSensitiveParams[strings.ToLower(name)] {
			parts[i] = p[:eq+1] + "masked"
		}
	}
	return strings.Join(parts, "&")
}

// sanitizeAccessLogField 剥离控制字符（防日志注入）并截断。
func sanitizeAccessLogField(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// sanitizeAccessLogBody 剥离 NUL（PostgreSQL text 列拒绝 0x00）。
func sanitizeAccessLogBody(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
