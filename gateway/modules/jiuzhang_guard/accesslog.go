// 全量访问日志（二期）：放行请求的完整头体留痕采集。
//
// 设计约束：
//   - 默认关闭（access_log 缺省或 enabled=false 时零行为变化、零额外开销）；
//   - 写文件前做与服务端一致的脱敏（敏感头掩码 + 请求体敏感键值掩码 + 查询串敏感参数掩码），
//     敏感名单与 server/internal/securityevents/normalize.go 保持一致（guard 为独立 module，不能 import server 包）；
//   - 输出 JSON Lines 由管理平台 accesslogs 采集器 tail 入库（对应 access_logs 表）；
//   - 采集失败一律 fail-open（记告警，不阻断业务），与 guard 既有故障策略一致；
//   - WebSocket / SSE / 非文本响应不采响应体，头体超限截断并打 truncated 标记。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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

// accessLogRecord 单条全量访问日志（字段与 access_logs 表一一对应）。
type accessLogRecord struct {
	OccurredAt            time.Time           `json:"occurred_at"`
	RequestID             string              `json:"request_id"`
	ApplicationID         string              `json:"application_id,omitempty"`
	Domain                string              `json:"domain"`
	GatewayNode           string              `json:"gateway_node_id"`
	ClientIP              string              `json:"client_ip"`
	ClientPort            int                 `json:"client_port"`
	Method                string              `json:"request_method"`
	URI                   string              `json:"request_uri"`
	Path                  string              `json:"request_path"`
	QuerySummary          string              `json:"query_summary"`
	HTTPVersion           string              `json:"http_version"`
	ContentType           string              `json:"content_type"`
	UserAgent             string              `json:"user_agent_summary"`
	Referer               string              `json:"referer_summary"`
	ResponseStatus        int                 `json:"response_status"`
	BytesIn               int64               `json:"bytes_in"`
	BytesOut              int64               `json:"bytes_out"`
	DurationMS            int64               `json:"duration_ms"`
	WAFAction             string              `json:"waf_action,omitempty"`
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

// captureResponseWriter 包装下游 ResponseWriter，捕获状态码/响应头/响应体（可选）。
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
	if w.status == 0 {
		w.status = code
		w.decide()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
		w.decide()
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

// captureAccessLog 包装放行链路采集全量访问日志；采集失败仅告警，不影响请求。
func (g *Guard) captureAccessLog(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request) error) error {
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
	if host, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		rec.ClientIP = host
		if p, err := strconv.Atoi(port); err == nil {
			rec.ClientPort = p
		}
	} else {
		rec.ClientIP = r.RemoteAddr
	}
	// RemoteAddr 已被改写为「真实IP:0」：原始连接端口由 ServeHTTP 经上下文传入
	if p, ok := r.Context().Value(accessLogConnPortKey{}).(int); ok {
		rec.ClientPort = p
	}
	uri := r.URL.RequestURI()
	rec.URI = sanitizeAccessLogField(maskAccessLogURI(uri), maxAccessLogStringLen)
	rec.Path = sanitizeAccessLogField(r.URL.Path, 1024)
	rec.QuerySummary = sanitizeAccessLogField(maskAccessLogQuery(r.URL.RawQuery), 1024)
	rec.BytesIn = r.ContentLength // 未知时为 -1，入库前归一为 0

	// 请求体：开启时完整读出（截断仅影响留痕内容，完整还原给下游 WAF/反代）
	if cfg.CaptureRequestHeaders {
		rec.RequestHeaders = maskAccessLogHeaders(r.Header)
	}
	if cfg.CaptureRequestBody && r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b)) // 尽力还原（含读失败的已读部分）
		if err == nil {
			rec.BytesIn = int64(len(b))
			if len(b) > bodyLimit {
				b = b[:bodyLimit]
				rec.RequestBodyTruncated = true
			}
			rec.RequestBody = sanitizeAccessLogBody(maskAccessLogBody(string(b)))
		}
	}

	cw := &captureResponseWriter{ResponseWriter: w, cfg: cfg, bodyLimit: bodyLimit}
	err := handler(cw, r)

	// 请求结束：组装响应字段并落盘（失败只记日志）
	rec.DurationMS = time.Since(start).Milliseconds()
	rec.ResponseStatus = cw.status
	rec.BytesOut = cw.bytesOut
	if rec.BytesIn < 0 {
		rec.BytesIn = 0
	}
	if cw.status == http.StatusForbidden {
		// 放行路径经过下游 WAF 段，403 按 WAF 拦截记录；其余状态不推断（不编造）
		rec.WAFAction = "BLOCK"
	}
	if cfg.CaptureResponseHeaders {
		rec.ResponseHeaders = maskAccessLogHeaders(cw.Header())
	}
	if cw.captureBody {
		rec.ResponseBody = sanitizeAccessLogBody(cw.body.String())
		rec.ResponseBodyTruncated = cw.bodyTruncated
	}
	if g.accessLog != nil {
		if werr := g.accessLog.write(rec); werr != nil {
			g.logger.Warn("access log write failed", zap.Error(werr))
		}
	}
	return err
}

// ---------- 脱敏（与 server/internal/securityevents/normalize.go 等价实现） ----------

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

// maskAccessLogBody 脱敏请求体敏感键值：表单 k=v、JSON "k":"v" / "k": "v" 两种形态。
func maskAccessLogBody(body string) string {
	if body == "" {
		return body
	}
	for name := range accessLogSensitiveParams {
		// 表单形态 name=value（值到 & ; 空格 或结尾）
		needle := name + "="
		idx := strings.Index(strings.ToLower(body), needle)
		for idx >= 0 {
			start := idx + len(needle)
			end := start
			for end < len(body) && body[end] != '&' && body[end] != ';' && body[end] != ' ' {
				end++
			}
			body = body[:start] + "masked" + body[end:]
			next := strings.Index(strings.ToLower(body[start+len("masked"):]), needle)
			if next < 0 {
				break
			}
			idx = start + len("masked") + next
		}
		// JSON 形态 "name":"value" 或 "name": "value"
		for _, pat := range []string{`"` + name + `":"`, `"` + name + `": "`} {
			idx := strings.Index(strings.ToLower(body), pat)
			for idx >= 0 {
				start := idx + len(pat)
				end := start
				for end < len(body) && body[end] != '"' {
					end++
				}
				body = body[:start] + "masked" + body[end:]
				next := strings.Index(strings.ToLower(body[start+len("masked"):]), pat)
				if next < 0 {
					break
				}
				idx = start + len("masked") + next
			}
		}
	}
	return body
}

// maskAccessLogURI 对 URI 查询串敏感参数脱敏。
func maskAccessLogURI(uri string) string {
	qIdx := strings.Index(uri, "?")
	if qIdx < 0 {
		return uri
	}
	return uri[:qIdx] + "?" + maskAccessLogQuery(uri[qIdx+1:])
}

// maskAccessLogQuery 对查询串敏感参数值脱敏。
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
		if accessLogSensitiveParams[strings.ToLower(p[:eq])] {
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
