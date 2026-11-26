// report_endpoint.go 保留本地端点 POST /_wdsp/csp/v1/report（绝不反向代理）：
//   - 仅接受 POST（非 POST 405 Allow: POST）；
//   - 每客户端 IP 有界内存限速（30 req/min，最多跟踪 4096 个 IP，超限 429）；
//   - 严格限制请求体 <= 16 KiB（超限 413）；
//   - 兼容解析三种上报格式：标准 CSP Report ({"csp-report":{...}})、Reporting API v1 数组
//     ([{"type":"csp-violation","body":{...}}])、客户端防窃取探针告警 ({"type":"probe-alert",...})；
//   - 所有 URL 上报入事件前强制剥离凭据（user:pass@）、查询串（?...）与片段（#...），防止敏感信息泄露；
//   - 正常接收返回 204 No Content。
package clientside

import (
	"bytes"
	"container/list"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReportEvent 从 /_wdsp/csp/v1/report 解析出的标准化违规/探针事件（URL 已脱敏）。
type ReportEvent struct {
	ViolationType     string // CSP_VIOLATION | PROBE_ALERT
	ScriptURL         string
	ScriptOrigin      string
	PagePath          string
	ViolatedDirective string
	BlockedURI        string
	ActionTaken       string // REPORTED | CSP_ENFORCED
	Reason            string
}

// ReportOutcome 上报端点处理结果。
type ReportOutcome struct {
	Status int
	Events []ReportEvent
}

// ServeReportRequest 处理 POST /_wdsp/csp/v1/report 本地请求。
func (e *Engine) ServeReportRequest(w http.ResponseWriter, r *http.Request, clientIP string) ReportOutcome {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 method not allowed"))
		return ReportOutcome{Status: http.StatusMethodNotAllowed}
	}

	if allowed, retrySec := e.reportLimiter.Allow(clientIP, e.now()); !allowed {
		if retrySec < 1 {
			retrySec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retrySec))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("429 too many requests"))
		return ReportOutcome{Status: http.StatusTooManyRequests}
	}

	if r.Body == nil {
		w.WriteHeader(http.StatusBadRequest)
		return ReportOutcome{Status: http.StatusBadRequest}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxReportBodyBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return ReportOutcome{Status: http.StatusBadRequest}
	}
	if len(raw) > MaxReportBodyBytes {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte("413 payload too large"))
		return ReportOutcome{Status: http.StatusRequestEntityTooLarge}
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return ReportOutcome{Status: http.StatusBadRequest}
	}

	defaultEnforced := e.policy != nil && e.policy.CSPMode == CSPModeEnforce
	parsed, err := ParseReportPayload(trimmed, defaultEnforced)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return ReportOutcome{Status: http.StatusBadRequest}
	}

	w.WriteHeader(http.StatusNoContent)
	return ReportOutcome{
		Status: http.StatusNoContent,
		Events: parsed,
	}
}

type legacyCSPEnvelope struct {
	CSPReport *legacyCSPBody `json:"csp-report"`
	Type      string         `json:"type"`
	Kind      string         `json:"kind"`
	Target    string         `json:"target"`
	Page      string         `json:"page"`
}

type legacyCSPBody struct {
	DocumentURI        string `json:"document-uri"`
	ViolatedDirective  string `json:"violated-directive"`
	EffectiveDirective string `json:"effective-directive"`
	BlockedURI         string `json:"blocked-uri"`
	Disposition        string `json:"disposition"`
}

type reportingAPIItem struct {
	Type string          `json:"type"`
	URL  string          `json:"url"`
	Body json.RawMessage `json:"body"`
}

type reportingAPICSPBody struct {
	DocumentURL        string `json:"documentURL"`
	DocumentURI        string `json:"document-uri"`
	EffectiveDirective string `json:"effectiveDirective"`
	EffectiveDirKebab  string `json:"effective-directive"`
	ViolatedDirective  string `json:"violatedDirective"`
	ViolatedDirKebab   string `json:"violated-directive"`
	BlockedURL         string `json:"blockedURL"`
	BlockedURI         string `json:"blocked-uri"`
	Disposition        string `json:"disposition"`
}

type probeAlertBody struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Page   string `json:"page"`
}

// ParseReportPayload 解析标准 CSP 报告、Reporting API v1 数组或探针告警，并脱敏所有 URL。
func ParseReportPayload(raw []byte, defaultEnforced bool) ([]ReportEvent, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, io.ErrUnexpectedEOF
	}

	// 1. Reporting API v1 JSON 数组格式
	if trimmed[0] == '[' {
		var items []reportingAPIItem
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, err
		}
		out := make([]ReportEvent, 0, minInt(len(items), MaxReportsPerBatch))
		for _, it := range items {
			if len(out) >= MaxReportsPerBatch {
				break
			}
			switch strings.ToLower(strings.TrimSpace(it.Type)) {
			case "csp-violation":
				var b reportingAPICSPBody
				if err := json.Unmarshal(it.Body, &b); err != nil {
					continue
				}
				doc := firstNonEmpty(b.DocumentURL, b.DocumentURI, it.URL)
				dir := firstNonEmpty(b.EffectiveDirective, b.EffectiveDirKebab, b.ViolatedDirective, b.ViolatedDirKebab)
				blocked := firstNonEmpty(b.BlockedURL, b.BlockedURI)
				out = append(out, buildCSPViolationEvent(doc, dir, blocked, b.Disposition, defaultEnforced))
			case "probe-alert":
				var b probeAlertBody
				if err := json.Unmarshal(it.Body, &b); err != nil {
					continue
				}
				out = append(out, buildProbeAlertEvent(b.Kind, b.Target, firstNonEmpty(b.Page, it.URL)))
			}
		}
		return out, nil
	}

	// 2. 对象格式：标准 CSP Report 或探针告警
	var env legacyCSPEnvelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, err
	}
	if env.CSPReport != nil {
		dir := firstNonEmpty(env.CSPReport.EffectiveDirective, env.CSPReport.ViolatedDirective)
		return []ReportEvent{
			buildCSPViolationEvent(env.CSPReport.DocumentURI, dir, env.CSPReport.BlockedURI, env.CSPReport.Disposition, defaultEnforced),
		}, nil
	}
	if strings.EqualFold(strings.TrimSpace(env.Type), "probe-alert") {
		return []ReportEvent{
			buildProbeAlertEvent(env.Kind, env.Target, env.Page),
		}, nil
	}
	return nil, nil
}

func buildCSPViolationEvent(docURI, directive, blockedURI, disposition string, defaultEnforced bool) ReportEvent {
	cleanBlocked := SanitizeReportURL(blockedURI)
	cleanDir := sanitizeDirective(directive)
	action := ActionReported
	switch strings.ToLower(strings.TrimSpace(disposition)) {
	case "enforce":
		action = ActionCSPEnforced
	case "report":
		action = ActionReported
	default:
		if defaultEnforced {
			action = ActionCSPEnforced
		}
	}
	scriptURL := ""
	if strings.HasPrefix(strings.ToLower(cleanDir), "script-src") && cleanBlocked != "" {
		scriptURL = cleanBlocked
	}
	return ReportEvent{
		ViolationType:     ViolationCSPViolation,
		ScriptURL:         scriptURL,
		ScriptOrigin:      ExtractOrigin(cleanBlocked),
		PagePath:          ExtractReportPagePath(docURI),
		ViolatedDirective: cleanDir,
		BlockedURI:        cleanBlocked,
		ActionTaken:       action,
		Reason:            "CSP_VIOLATION",
	}
}

func buildProbeAlertEvent(kind, target, page string) ReportEvent {
	cleanKind := strings.TrimSpace(stripControls(kind))
	if len(cleanKind) > 64 {
		cleanKind = cleanKind[:64]
	}
	if cleanKind == "" {
		cleanKind = "probe_alert"
	}
	cleanTarget := SanitizeReportURL(target)
	scriptURL := ""
	if strings.Contains(strings.ToLower(cleanKind), "script") {
		scriptURL = cleanTarget
	}
	return ReportEvent{
		ViolationType: ViolationProbeAlert,
		ScriptURL:     scriptURL,
		ScriptOrigin:  ExtractOrigin(cleanTarget),
		PagePath:      ExtractReportPagePath(page),
		BlockedURI:    cleanTarget,
		ActionTaken:   ActionReported,
		Reason:        cleanKind,
	}
}

// SanitizeReportURL 剥离 URL 中的凭据（user:pass@）、查询串（?...）、片段（#...）及控制字符，
// 对 data:/javascript: 仅保留 scheme，防止敏感凭据或脚本正文泄露到日志与告警表。
func SanitizeReportURL(raw string) string {
	s := strings.TrimSpace(stripControls(raw))
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	switch lower {
	case "inline", "eval", "data", "blob", "filesystem", "self", "wasm-eval", "trusted-types-sink", "trusted-types-policy":
		return lower
	}
	if strings.HasPrefix(lower, "data:") {
		return "data:"
	}
	if strings.HasPrefix(lower, "javascript:") {
		return "javascript:"
	}
	if strings.HasPrefix(lower, "blob:") {
		inner := SanitizeReportURL(s[5:])
		if inner != "" {
			return "blob:" + inner
		}
		return "blob:"
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		if idx := strings.IndexAny(s, "?#"); idx >= 0 {
			s = s[:idx]
		}
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		if idx := strings.IndexAny(s, "?#"); idx >= 0 {
			s = s[:idx]
		}
		if at := strings.Index(s, "@"); at >= 0 {
			s = s[at+1:]
		}
		return s
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	if u.Scheme != "" {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if u.Host != "" {
		u.Host = normalizeOriginHost(u.Scheme, u.Host)
	}
	return u.String()
}

// ExtractReportPagePath 从页面 URL 或路径中提取纯路径部分（去除协议/域名/凭据/查询串/片段）。
func ExtractReportPagePath(raw string) string {
	s := strings.TrimSpace(stripControls(raw))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		if idx := strings.IndexAny(s, "?#"); idx >= 0 {
			s = s[:idx]
		}
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		if idx := strings.IndexAny(s, "?#"); idx >= 0 {
			s = s[:idx]
		}
		return s
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}

func sanitizeDirective(raw string) string {
	s := strings.TrimSpace(stripControls(raw))
	if s == "" {
		return ""
	}
	// CSP Level 2 violated-directive 可能携带整条策略（如 "script-src 'self'"），仅取首指令名。
	if fields := strings.Fields(s); len(fields) > 0 {
		s = fields[0]
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func stripControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------- 有界每 IP 内存限速器（30 req/min，最多跟踪 4096 个 IP） ----------

type ipRateEntry struct {
	ip          string
	windowStart time.Time
	count       int
}

type ipRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	maxIPs int
	ll     *list.List
	items  map[string]*list.Element
}

func newIPRateLimiter(limit int, window time.Duration, maxIPs int) *ipRateLimiter {
	return &ipRateLimiter{
		limit:  limit,
		window: window,
		maxIPs: maxIPs,
		ll:     list.New(),
		items:  make(map[string]*list.Element),
	}
}

// Allow 检查并累加指定 IP 在当前时间窗口内的上报次数。
func (l *ipRateLimiter) Allow(ip string, now time.Time) (allowed bool, retryAfterSec int) {
	if ip == "" {
		ip = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if elem, ok := l.items[ip]; ok {
		ent := elem.Value.(*ipRateEntry)
		if now.Sub(ent.windowStart) >= l.window {
			ent.windowStart = now
			ent.count = 1
			l.ll.MoveToFront(elem)
			return true, 0
		}
		if ent.count >= l.limit {
			rem := l.window - now.Sub(ent.windowStart)
			sec := int(rem.Seconds()) + 1
			if sec < 1 {
				sec = 1
			}
			l.ll.MoveToFront(elem)
			return false, sec
		}
		ent.count++
		l.ll.MoveToFront(elem)
		return true, 0
	}

	for len(l.items) >= l.maxIPs {
		back := l.ll.Back()
		if back == nil {
			break
		}
		l.ll.Remove(back)
		delete(l.items, back.Value.(*ipRateEntry).ip)
	}
	elem := l.ll.PushFront(&ipRateEntry{
		ip:          ip,
		windowStart: now,
		count:       1,
	})
	l.items[ip] = elem
	return true, 0
}

// Len 返回当前跟踪的 IP 数量（测试用）。
func (l *ipRateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}
