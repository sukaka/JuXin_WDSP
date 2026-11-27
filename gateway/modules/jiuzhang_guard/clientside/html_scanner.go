// html_scanner.go 有界（<=1MiB）未压缩 2xx text/html 单遍脚本扫描、SRI 篡改检测、
// 可选未授权脚本剥离、防窃取探针注入与 LRU/TTL 观测去重缓存。
package clientside

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// ScanFinding 单次 HTML 扫描产出的单条客户端安全事件输入（映射至 events.Event）。
type ScanFinding struct {
	ViolationType string // SCRIPT_OBSERVED | UNAUTHORIZED_SCRIPT | SCRIPT_TAMPERED
	ScriptURL     string
	ScriptOrigin  string
	ScriptType    string // EXTERNAL | INLINE_HASH
	ExpectedSRI   string
	ObservedSRI   string
	PagePath      string
	ActionTaken   string // OBSERVED | STRIPPED
	Reason        string
}

// ScanResult HTML 扫描结果。
type ScanResult struct {
	Body          []byte
	Modified      bool
	StrippedCount int
	ProbeInjected bool
	Findings      []ScanFinding
}

// ScanContext 单次扫描的页面上下文（用于解析相对脚本 URL 与同源判定）。
type ScanContext struct {
	Scheme      string // "https" | "http"
	Host        string // r.Host
	PagePath    string // 规范化路径（无查询串）
	InjectProbe bool
}

// ScanAndRewriteHTML 对 <=1MiB 的未压缩 HTML 正文执行单遍 golang.org/x/net/html 词法扫描：
//   - 提取所有可执行 <script src>（含 integrity SRI 属性）与内联 <script>（计算 sha256-<base64>）；
//   - 对照 authorized_scripts 与 allowed_script_origins 判定未授权/封禁脚本与 SRI 篡改；
//   - 当 mode == PROTECT && strip_unauthorized_scripts == true 时干净移除未授权/篡改 <script> 元素；
//   - 当 sc.InjectProbe == true 时在 </head>（回退 </body>）前注入带预计算 SRI 的探针脚本；
//   - 通过有界 LRU/TTL 缓存（60s / max 4096）对 SCRIPT_OBSERVED 去重，防止热点页面撑爆日志。
func (e *Engine) ScanAndRewriteHTML(body []byte, sc ScanContext) ScanResult {
	res := ScanResult{Body: body}
	if e == nil || e.policy.Mode == ModeOff || len(body) == 0 {
		return res
	}

	stripEnabled := e.policy.Mode == ModeProtect && e.policy.StripUnauthorizedScripts
	canModify := stripEnabled || sc.InjectProbe

	scheme := strings.ToLower(strings.TrimSpace(sc.Scheme))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	pageOrigin := ""
	if h := strings.TrimSpace(sc.Host); h != "" {
		pageOrigin = ExtractOrigin(scheme + "://" + h)
	}
	pageBaseURL := buildPageBaseURL(scheme, sc.Host, sc.PagePath)

	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	if canModify {
		out.Grow(len(body) + 128)
	}

	headClosePos := -1
	bodyClosePos := -1
	probeAlreadyPresent := false

	inScript := false
	var scriptSrc string
	var scriptIntegrity string
	var scriptTypeAttr string
	var scriptRawBuf bytes.Buffer
	var scriptInlineBuf bytes.Buffer

	now := e.now()

	flushScript := func() {
		defer func() {
			inScript = false
			scriptSrc = ""
			scriptIntegrity = ""
			scriptTypeAttr = ""
			scriptRawBuf.Reset()
			scriptInlineBuf.Reset()
		}()

		if !isExecutableScriptType(scriptTypeAttr) {
			if canModify {
				_, _ = out.Write(scriptRawBuf.Bytes())
			}
			return
		}

		var shouldStrip bool
		if scriptSrc != "" {
			if isOwnProbeScriptSrc(scriptSrc, pageBaseURL) {
				probeAlreadyPresent = true
				if canModify {
					_, _ = out.Write(scriptRawBuf.Bytes())
				}
				return
			}
			findings, strip := e.evaluateExternalScript(scriptSrc, scriptIntegrity, pageBaseURL, pageOrigin, scheme, sc.PagePath, stripEnabled, now)
			res.Findings = append(res.Findings, findings...)
			shouldStrip = strip
		} else {
			inlineBytes := scriptInlineBuf.Bytes()
			if len(inlineBytes) > 0 {
				findings, strip := e.evaluateInlineScript(inlineBytes, pageOrigin, sc.PagePath, stripEnabled, now)
				res.Findings = append(res.Findings, findings...)
				shouldStrip = strip
			}
		}

		if shouldStrip {
			res.Modified = true
			res.StrippedCount++
		} else if canModify {
			_, _ = out.Write(scriptRawBuf.Bytes())
		}
	}

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if inScript {
				flushScript()
			}
			if z.Err() == io.EOF {
				break
			}
			// 非预期解析错误：保守回退原正文，不破坏业务响应。
			res.Body = body
			res.Modified = false
			return res
		}

		// 在调用 TagName / TagAttr / Text 之前先拷贝原始字节（避免 x/net/html 原地小写化污染）。
		var rawCopy []byte
		if canModify {
			raw := z.Raw()
			rawCopy = make([]byte, len(raw))
			copy(rawCopy, raw)
		}

		if inScript {
			if tt == html.EndTagToken {
				tagName, _ := z.TagName()
				if bytes.Equal(tagName, []byte("script")) {
					if canModify {
						_, _ = scriptRawBuf.Write(rawCopy)
					}
					flushScript()
					continue
				}
			}
			if canModify {
				_, _ = scriptRawBuf.Write(rawCopy)
			}
			if tt == html.TextToken {
				_, _ = scriptInlineBuf.Write(z.Text())
			}
			continue
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttr := z.TagName()
			if bytes.Equal(tagName, []byte("script")) {
				scriptSrc = ""
				scriptIntegrity = ""
				scriptTypeAttr = ""
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					switch string(k) {
					case "src":
						scriptSrc = strings.TrimSpace(string(v))
					case "integrity":
						scriptIntegrity = strings.TrimSpace(string(v))
					case "type":
						scriptTypeAttr = strings.TrimSpace(string(v))
					}
				}
				inScript = true
				scriptRawBuf.Reset()
				scriptInlineBuf.Reset()
				if canModify {
					_, _ = scriptRawBuf.Write(rawCopy)
				}
				if tt == html.SelfClosingTagToken {
					flushScript()
				}
				continue
			}
			if canModify {
				_, _ = out.Write(rawCopy)
			}
		case html.EndTagToken:
			tagName, _ := z.TagName()
			if canModify {
				if headClosePos < 0 && bytes.Equal(tagName, []byte("head")) {
					headClosePos = out.Len()
				} else if bytes.Equal(tagName, []byte("body")) {
					bodyClosePos = out.Len()
				}
				_, _ = out.Write(rawCopy)
			}
		default:
			if canModify {
				_, _ = out.Write(rawCopy)
			}
		}
	}

	if canModify && sc.InjectProbe && !probeAlreadyPresent {
		insertAt := headClosePos
		if insertAt < 0 {
			insertAt = bodyClosePos
		}
		if insertAt >= 0 {
			tag := ProbeScriptTag()
			bufBytes := out.Bytes()
			injected := make([]byte, 0, len(bufBytes)+len(tag))
			injected = append(injected, bufBytes[:insertAt]...)
			injected = append(injected, tag...)
			injected = append(injected, bufBytes[insertAt:]...)
			res.Body = injected
			res.Modified = true
			res.ProbeInjected = true
			return res
		}
	}

	if res.Modified {
		res.Body = append([]byte(nil), out.Bytes()...)
	}
	return res
}

func (e *Engine) evaluateExternalScript(
	rawSrc, observedIntegrity string,
	pageBaseURL *url.URL,
	pageOrigin, pageScheme, pagePath string,
	stripEnabled bool,
	now time.Time,
) ([]ScanFinding, bool) {
	resolvedURL, displayURL, scriptOrigin, sameOrigin := resolveExternalScript(rawSrc, pageBaseURL, pageOrigin, pageScheme)
	var findings []ScanFinding

	// 1. 去重后记录观测事件（更新资产清单 observed_sri / observed_count）。
	if e.dedup.ShouldEmit(displayURL, observedIntegrity, now) {
		findings = append(findings, ScanFinding{
			ViolationType: ViolationScriptObserved,
			ScriptURL:     displayURL,
			ScriptOrigin:  scriptOrigin,
			ScriptType:    ScriptTypeExternal,
			ObservedSRI:   observedIntegrity,
			PagePath:      pagePath,
			ActionTaken:   ActionObserved,
		})
	}

	// 2. 查表 authorized_scripts（显式 BLOCKED 优先于来源白名单）。
	if auth, ok := e.lookupAuthorizedExternal(rawSrc, displayURL, resolvedURL); ok {
		if auth.Status == ScriptStatusBlocked {
			action := ActionObserved
			if stripEnabled {
				action = ActionStripped
			}
			findings = append(findings, ScanFinding{
				ViolationType: ViolationUnauthorizedScript,
				ScriptURL:     displayURL,
				ScriptOrigin:  scriptOrigin,
				ScriptType:    ScriptTypeExternal,
				ExpectedSRI:   auth.SRIHash,
				ObservedSRI:   observedIntegrity,
				PagePath:      pagePath,
				ActionTaken:   action,
				Reason:        "SCRIPT_EXPLICITLY_BLOCKED",
			})
			return findings, stripEnabled
		}
		// AUTHORIZED：若已钉选 sri_hash，则核对观察到的 integrity 属性。
		if auth.SRIHash != "" && !sriMatches(auth.SRIHash, observedIntegrity) {
			reason := "SRI_MISMATCH"
			if observedIntegrity == "" {
				reason = "SRI_MISSING"
			}
			action := ActionObserved
			if stripEnabled {
				action = ActionStripped
			}
			findings = append(findings, ScanFinding{
				ViolationType: ViolationScriptTampered,
				ScriptURL:     displayURL,
				ScriptOrigin:  scriptOrigin,
				ScriptType:    ScriptTypeExternal,
				ExpectedSRI:   auth.SRIHash,
				ObservedSRI:   observedIntegrity,
				PagePath:      pagePath,
				ActionTaken:   action,
				Reason:        reason,
			})
			return findings, stripEnabled
		}
		return findings, false
	}

	// 3. 未在 authorized_scripts 命中时，核对 allowed_script_origins。
	if e.isOriginAllowed(resolvedURL, sameOrigin, pageScheme) {
		return findings, false
	}

	action := ActionObserved
	if stripEnabled {
		action = ActionStripped
	}
	findings = append(findings, ScanFinding{
		ViolationType: ViolationUnauthorizedScript,
		ScriptURL:     displayURL,
		ScriptOrigin:  scriptOrigin,
		ScriptType:    ScriptTypeExternal,
		ObservedSRI:   observedIntegrity,
		PagePath:      pagePath,
		ActionTaken:   action,
		Reason:        "UNAUTHORIZED_EXTERNAL_SCRIPT",
	})
	return findings, stripEnabled
}

func (e *Engine) evaluateInlineScript(
	inlineBytes []byte,
	pageOrigin, pagePath string,
	stripEnabled bool,
	now time.Time,
) ([]ScanFinding, bool) {
	sum := sha256.Sum256(inlineBytes)
	hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	displayURL := "inline:" + hash
	origin := pageOrigin
	if origin == "" {
		origin = "'self'"
	}
	var findings []ScanFinding

	if e.dedup.ShouldEmit(displayURL, hash, now) {
		findings = append(findings, ScanFinding{
			ViolationType: ViolationScriptObserved,
			ScriptURL:     displayURL,
			ScriptOrigin:  origin,
			ScriptType:    ScriptTypeInlineHash,
			ObservedSRI:   hash,
			PagePath:      pagePath,
			ActionTaken:   ActionObserved,
		})
	}

	if auth, ok := e.authInline[hash]; ok {
		if auth.Status == ScriptStatusBlocked {
			action := ActionObserved
			if stripEnabled {
				action = ActionStripped
			}
			findings = append(findings, ScanFinding{
				ViolationType: ViolationUnauthorizedScript,
				ScriptURL:     displayURL,
				ScriptOrigin:  origin,
				ScriptType:    ScriptTypeInlineHash,
				ExpectedSRI:   auth.SRIHash,
				ObservedSRI:   hash,
				PagePath:      pagePath,
				ActionTaken:   action,
				Reason:        "INLINE_SCRIPT_BLOCKED",
			})
			return findings, stripEnabled
		}
	}

	return findings, false
}

func (e *Engine) lookupAuthorizedExternal(rawSrc, displayURL string, resolved *url.URL) (AuthorizedScript, bool) {
	candidates := make([]string, 0, 5)
	if trimmed := strings.TrimSpace(rawSrc); trimmed != "" {
		candidates = append(candidates, trimmed)
		if stripped := stripQueryFragmentCreds(trimmed); stripped != "" && stripped != trimmed {
			candidates = append(candidates, stripped)
		}
	}
	if displayURL != "" {
		candidates = append(candidates, displayURL)
	}
	if resolved != nil {
		cleanResolved := *resolved
		cleanResolved.User = nil
		cleanResolved.RawQuery = ""
		cleanResolved.ForceQuery = false
		cleanResolved.Fragment = ""
		cleanResolved.Scheme = strings.ToLower(cleanResolved.Scheme)
		cleanResolved.Host = normalizeOriginHost(cleanResolved.Scheme, cleanResolved.Host)
		candidates = append(candidates, cleanResolved.String())
		if cleanResolved.Path != "" {
			candidates = append(candidates, cleanResolved.Path)
		}
	}
	for _, k := range candidates {
		if sc, ok := e.authExternal[k]; ok {
			return sc, true
		}
	}
	return AuthorizedScript{}, false
}

func (e *Engine) isOriginAllowed(resolved *url.URL, sameOrigin bool, pageScheme string) bool {
	if resolved == nil || len(e.allowedOrigins) == 0 {
		return false
	}
	for _, m := range e.allowedOrigins {
		if m.matches(resolved, sameOrigin, pageScheme) {
			return true
		}
	}
	return false
}

func sriMatches(expected, observed string) bool {
	expected = strings.TrimSpace(expected)
	observed = strings.TrimSpace(observed)
	if expected == "" {
		return true
	}
	if observed == "" {
		return false
	}
	if expected == observed {
		return true
	}
	// 当钉选值为单个摘要时，允许 HTML integrity 属性包含多算法摘要列表（只要包含钉选摘要即匹配）。
	expTokens := strings.Fields(expected)
	obsTokens := strings.Fields(observed)
	if len(expTokens) == 1 {
		for _, tok := range obsTokens {
			if tok == expTokens[0] {
				return true
			}
		}
		return false
	}
	// 多摘要钉选：全部钉选摘要均须出现。
	obsSet := make(map[string]bool, len(obsTokens))
	for _, tok := range obsTokens {
		obsSet[tok] = true
	}
	for _, tok := range expTokens {
		if !obsSet[tok] {
			return false
		}
	}
	return true
}

func buildPageBaseURL(scheme, host, pagePath string) *url.URL {
	if pagePath == "" {
		pagePath = "/"
	}
	if host == "" {
		host = "localhost"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   normalizeOriginHost(scheme, host),
		Path:   pagePath,
	}
}

func resolveExternalScript(rawSrc string, pageBaseURL *url.URL, pageOrigin, pageScheme string) (resolved *url.URL, displayURL, scriptOrigin string, sameOrigin bool) {
	trimmed := strings.TrimSpace(rawSrc)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "data:") {
		u := &url.URL{Scheme: "data"}
		return u, "data:", "data:", false
	}
	if strings.HasPrefix(lower, "javascript:") {
		u := &url.URL{Scheme: "javascript"}
		return u, "javascript:", "javascript:", false
	}
	if strings.HasPrefix(lower, "blob:") {
		u, _ := url.Parse(trimmed)
		if u == nil {
			u = &url.URL{Scheme: "blob"}
		}
		orig := ExtractOrigin(trimmed)
		return u, SanitizeReportURL(trimmed), orig, false
	}

	ref, err := url.Parse(trimmed)
	if err != nil {
		return nil, SanitizeReportURL(trimmed), "", false
	}

	isRelative := ref.Scheme == "" && ref.Host == ""
	if ref.Scheme == "" && ref.Host != "" {
		// 协议相对 URL：//cdn.example.com/app.js
		ref.Scheme = pageScheme
	}

	if pageBaseURL != nil {
		resolved = pageBaseURL.ResolveReference(ref)
	} else {
		resolved = ref
	}
	resolved.Scheme = strings.ToLower(resolved.Scheme)
	resolved.Host = normalizeOriginHost(resolved.Scheme, resolved.Host)
	resolved.User = nil
	resolved.RawQuery = ""
	resolved.ForceQuery = false
	resolved.Fragment = ""

	scriptOrigin = ExtractOrigin(resolved.String())
	if isRelative {
		sameOrigin = true
		displayURL = resolved.Path
		if displayURL == "" {
			displayURL = "/"
		}
		if pageOrigin != "" {
			scriptOrigin = pageOrigin
		} else {
			scriptOrigin = "'self'"
		}
		return resolved, displayURL, scriptOrigin, true
	}

	sameOrigin = pageOrigin != "" && scriptOrigin == pageOrigin
	displayURL = resolved.String()
	return resolved, displayURL, scriptOrigin, sameOrigin
}

func isOwnProbeScriptSrc(rawSrc string, pageBaseURL *url.URL) bool {
	trimmed := strings.TrimSpace(rawSrc)
	if trimmed == ProbeScriptPath {
		return true
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	if u.Scheme == "" && u.Host == "" && u.Path == ProbeScriptPath {
		return true
	}
	if pageBaseURL != nil {
		res := pageBaseURL.ResolveReference(u)
		if res.Path == ProbeScriptPath && normalizeOriginHost(strings.ToLower(res.Scheme), res.Host) == pageBaseURL.Host {
			return true
		}
	}
	return false
}

func isExecutableScriptType(typeAttr string) bool {
	t := strings.ToLower(strings.TrimSpace(strings.SplitN(typeAttr, ";", 2)[0]))
	switch t {
	case "", "module",
		"text/javascript", "application/javascript",
		"text/ecmascript", "application/ecmascript",
		"text/x-javascript", "application/x-javascript",
		"text/x-ecmascript", "application/x-ecmascript",
		"text/jscript", "text/livescript",
		"text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
		"text/javascript1.3", "text/javascript1.4", "text/javascript1.5":
		return true
	default:
		return false
	}
}

// ---------- 有界 LRU/TTL 脚本观测去重缓存 ----------

type dedupEntry struct {
	key       string
	expiresAt time.Time
}

type scriptDedupCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	ll         *list.List
	items      map[string]*list.Element
}

func newScriptDedupCache(ttl time.Duration, maxEntries int) *scriptDedupCache {
	return &scriptDedupCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		ll:         list.New(),
		items:      make(map[string]*list.Element),
	}
}

// ShouldEmit 判断该 (script_url, observed_sri) 是否应输出观测事件；TTL 内重复返回 false。
func (c *scriptDedupCache) ShouldEmit(scriptURL, observedSRI string, now time.Time) bool {
	key := scriptURL + "\x00" + observedSRI
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		ent := elem.Value.(*dedupEntry)
		if now.Before(ent.expiresAt) {
			c.ll.MoveToFront(elem)
			return false
		}
		ent.expiresAt = now.Add(c.ttl)
		c.ll.MoveToFront(elem)
		return true
	}

	for len(c.items) >= c.maxEntries {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		delete(c.items, back.Value.(*dedupEntry).key)
	}
	elem := c.ll.PushFront(&dedupEntry{
		key:       key,
		expiresAt: now.Add(c.ttl),
	})
	c.items[key] = elem
	return true
}

// Len 返回当前去重缓存条目数（测试与观测用）。
func (c *scriptDedupCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// ---------- 有界 HTML 响应包装器 ----------

// HTMLResponseWrapper 有界 HTML 响应包装器：
//   - 对 2xx text/html 响应自动注入 CSP 响应头（即使响应为压缩/流式/超大也生效）；
//   - 仅缓冲未压缩且 <=1MiB 的 2xx text/html 响应正文进行脚本扫描、可选剥离与敏感路径探针注入；
//   - 压缩、流式（Flush）、Upgrade/Hijack、非 2xx、非 HTML 或超过 1MiB 的响应立即无损透传，绝不做虚假声明。
type HTMLResponseWrapper struct {
	base        http.ResponseWriter
	engine      *Engine
	sc          ScanContext
	isHead      bool
	onFindings  func(findings []ScanFinding)
	status      int
	buf         bytes.Buffer
	passthrough bool
	committed   bool
	hijacked    bool
}

// NewHTMLResponseWrapper 构造有界 HTML 响应包装器。
func (e *Engine) NewHTMLResponseWrapper(
	base http.ResponseWriter,
	r *http.Request,
	pagePath string,
	onFindings func(findings []ScanFinding),
) *HTMLResponseWrapper {
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	host := ""
	isHead := false
	if r != nil {
		host = r.Host
		isHead = r.Method == http.MethodHead
	}
	return &HTMLResponseWrapper{
		base:   base,
		engine: e,
		sc: ScanContext{
			Scheme:      scheme,
			Host:        host,
			PagePath:    pagePath,
			InjectProbe: e.ShouldInjectProbe(pagePath),
		},
		isHead:     isHead,
		onFindings: onFindings,
	}
}

func (w *HTMLResponseWrapper) Header() http.Header { return w.base.Header() }

func (w *HTMLResponseWrapper) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if w.status == 0 {
			w.base.WriteHeader(code)
		}
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code

	// 2xx HTML 文档在写头前注入 CSP 策略头（压缩/流式/超大 HTML 同样获得浏览器端 CSP 保护）。
	if code >= 200 && code < 300 && isHTMLContentType(w.Header().Get("Content-Type")) && w.Header().Get("Upgrade") == "" {
		if name, val := w.engine.CSPHeader(); name != "" && val != "" {
			w.Header().Set(name, val)
		}
	}

	if !w.eligibleForBodyScan() {
		w.switchPassthrough()
	}
}

func (w *HTMLResponseWrapper) eligibleForBodyScan() bool {
	if w.isHead {
		return false
	}
	if w.status < 200 || w.status >= 300 {
		return false
	}
	if !isHTMLContentType(w.Header().Get("Content-Type")) {
		return false
	}
	if ce := strings.ToLower(strings.TrimSpace(w.Header().Get("Content-Encoding"))); ce != "" && ce != "identity" {
		return false
	}
	if w.Header().Get("Upgrade") != "" {
		return false
	}
	if cl := strings.TrimSpace(w.Header().Get("Content-Length")); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n > MaxHTMLScanBytes {
			return false
		}
	}
	return true
}

func (w *HTMLResponseWrapper) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.passthrough {
		return w.base.Write(p)
	}
	if w.buf.Len()+len(p) > MaxHTMLScanBytes {
		w.switchPassthrough()
		return w.base.Write(p)
	}
	return w.buf.Write(p)
}

func (w *HTMLResponseWrapper) switchPassthrough() {
	if w.passthrough || w.committed || w.hijacked {
		return
	}
	w.passthrough = true
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.base.WriteHeader(w.status)
	if w.buf.Len() > 0 {
		_, _ = w.base.Write(w.buf.Bytes())
		w.buf.Reset()
	}
}

// Finish 在下游处理完成后提交缓冲响应；skip=true（网关本地终止或下游报错）时原样透出不改写不扫描。
func (w *HTMLResponseWrapper) Finish(skip bool) {
	if w.committed || w.hijacked || w.passthrough {
		return
	}
	if w.status == 0 && w.buf.Len() == 0 {
		return
	}
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	body := w.buf.Bytes()
	if !skip && w.eligibleForBodyScan() && len(body) > 0 {
		sr := w.engine.ScanAndRewriteHTML(body, w.sc)
		if len(sr.Findings) > 0 && w.onFindings != nil {
			w.onFindings(sr.Findings)
		}
		if sr.Modified {
			body = sr.Body
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Del("ETag")
		}
	}
	w.base.WriteHeader(w.status)
	if len(body) > 0 {
		_, _ = w.base.Write(body)
	}
	w.buf.Reset()
}

func (w *HTMLResponseWrapper) Flush() {
	if w.hijacked {
		return
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.switchPassthrough()
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
		return
	}
	_ = http.NewResponseController(w.base).Flush()
}

func (w *HTMLResponseWrapper) Unwrap() http.ResponseWriter { return w.base }

func (w *HTMLResponseWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	var (
		conn net.Conn
		rw   *bufio.ReadWriter
		err  error
	)
	if h, ok := w.base.(http.Hijacker); ok {
		conn, rw, err = h.Hijack()
	} else {
		conn, rw, err = http.NewResponseController(w.base).Hijack()
	}
	if err == nil {
		w.hijacked = true
		w.passthrough = true
	}
	return conn, rw, err
}

func isHTMLContentType(ct string) bool {
	media := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return media == "text/html"
}
