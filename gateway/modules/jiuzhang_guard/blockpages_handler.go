// blockpages_handler.go 自定义多版本拦截页面网关运行时渲染模块（迁移 000251）：
//   - 注册 Caddy HTTP 处理器 http.handlers.jiuzhang_block_page，置于 server errors 路由链首；
//   - 消费 jiuzhang_guard 写入请求变量（caddyhttp.VarsCtxKey）的 app_code / client_ip / request_id / block_scene，
//     按四级优先级 (app, scene) > (app, DEFAULT) > (global, scene) > (global, DEFAULT) 选取已编译拦截页；
//   - 仅接管 403 / 429 拦截响应，未命中绑定或其他状态码（502/503/404 等）透明调用 next.ServeHTTP
//     回落既有静态 /blockpage.html 或通用状态响应；
//   - 所有运行时占位符严格经 html.EscapeString 转义后字面替换（无模板执行，零 SSTI 风险）。
package jiuzhang_guard

import (
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
)

func init() {
	caddy.RegisterModule(&BlockPageHandler{})
}

// 自定义拦截页场景冻结词表（与 server 侧同口径）。
const (
	blockSceneDefault       = "DEFAULT"
	blockSceneWAF           = "WAF"
	blockSceneAccessControl = "ACCESS_CONTROL"
	blockSceneRateLimit     = "RATE_LIMIT"

	maxBlockPageHTMLBytes = 65536
)

// Caddy 请求上下文变量键（由 jiuzhang_guard 写入，供 errors 链中的 jiuzhang_block_page 消费）。
const (
	varBlockPageAppCode   = "jiuzhang.block_app_code"
	varBlockPageAppID     = "jiuzhang.block_app_id"
	varBlockPageClientIP  = "jiuzhang.block_client_ip"
	varBlockPageRequestID = "jiuzhang.block_request_id"
	varBlockPageScene     = "jiuzhang.block_scene"
)

var validGuardBlockPageScenes = map[string]bool{
	blockSceneDefault:       true,
	blockSceneWAF:           true,
	blockSceneAccessControl: true,
	blockSceneRateLimit:     true,
}

var cstZone = time.FixedZone("CST", 8*3600)

// blockPageItemJSON 单个生效拦截页的下发结构（与 gatewayconfig.GuardBlockPageItem 一一对应）。
type blockPageItemJSON struct {
	PageID      string `json:"page_id"`
	PageName    string `json:"page_name,omitempty"`
	Version     int    `json:"version"`
	StatusCode  int    `json:"status_code,omitempty"`
	HTML        string `json:"html"`
	JSONCode    string `json:"json_code,omitempty"`
	JSONMessage string `json:"json_message,omitempty"`
}

// compiledBlockPage 装配期预净化后的拦截页运行态产物（热路径只读无锁）。
type compiledBlockPage struct {
	pageID      string
	version     int
	statusCode  int
	html        string
	jsonCode    string
	jsonMessage string
}

// BlockPageHandler 是挂接于 Caddy server errors 路由链首的自定义拦截页渲染处理器。
type BlockPageHandler struct {
	Global        map[string]*blockPageItemJSON            `json:"global,omitempty"`
	Apps          map[string]map[string]*blockPageItemJSON `json:"apps,omitempty"`
	HostToAppCode map[string]string                        `json:"host_to_app_code,omitempty"`

	globalCompiled map[string]*compiledBlockPage
	appsCompiled   map[string]map[string]*compiledBlockPage
	hostMap        map[string]string
}

// CaddyModule 返回 Caddy 模块元信息。
func (BlockPageHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_block_page",
		New: func() caddy.Module { return new(BlockPageHandler) },
	}
}

// Provision 校验并预编译（净化）所有下发的自定义拦截页模板。
func (h *BlockPageHandler) Provision(_ caddy.Context) error {
	if err := h.Validate(); err != nil {
		return err
	}
	var err error
	h.globalCompiled, err = compileBlockPageMap(h.Global)
	if err != nil {
		return fmt.Errorf("jiuzhang_block_page global: %w", err)
	}
	if len(h.Apps) > 0 {
		h.appsCompiled = make(map[string]map[string]*compiledBlockPage, len(h.Apps))
		for appCode, scenes := range h.Apps {
			compiled, err := compileBlockPageMap(scenes)
			if err != nil {
				return fmt.Errorf("jiuzhang_block_page apps[%s]: %w", appCode, err)
			}
			if len(compiled) > 0 {
				h.appsCompiled[appCode] = compiled
			}
		}
	}
	if len(h.HostToAppCode) > 0 {
		h.hostMap = make(map[string]string, len(h.HostToAppCode))
		for host, code := range h.HostToAppCode {
			norm := strings.ToLower(strings.TrimSpace(host))
			if norm != "" && strings.TrimSpace(code) != "" {
				h.hostMap[norm] = strings.TrimSpace(code)
			}
		}
	}
	return nil
}

// Validate 装配期严格校验（fail-closed）。
func (h *BlockPageHandler) Validate() error {
	if err := validateBlockPageMap(h.Global); err != nil {
		return err
	}
	for appCode, scenes := range h.Apps {
		if err := validateBlockPageMap(scenes); err != nil {
			return fmt.Errorf("app %s: %w", appCode, err)
		}
	}
	return nil
}

func validateBlockPageItem(scene string, item *blockPageItemJSON) error {
	normScene := strings.ToUpper(strings.TrimSpace(scene))
	if !validGuardBlockPageScenes[normScene] {
		return fmt.Errorf("block_pages 非法场景 %q", scene)
	}
	if item == nil {
		return fmt.Errorf("block_pages.%s 不能为空", normScene)
	}
	if strings.TrimSpace(item.HTML) == "" {
		return fmt.Errorf("block_pages.%s html 不能为空", normScene)
	}
	if len(item.HTML) > maxBlockPageHTMLBytes {
		return fmt.Errorf("block_pages.%s html 超过上限 %d 字节：%d", normScene, maxBlockPageHTMLBytes, len(item.HTML))
	}
	if item.StatusCode != 0 && (item.StatusCode < 400 || item.StatusCode > 599) {
		return fmt.Errorf("block_pages.%s status_code 非法：%d", normScene, item.StatusCode)
	}
	if len(item.JSONCode) > maxBlockResponseJSONCode {
		return fmt.Errorf("block_pages.%s json_code 超过上限 %d 字节", normScene, maxBlockResponseJSONCode)
	}
	if item.JSONCode != "" && !blockResponseCodePattern.MatchString(item.JSONCode) {
		return fmt.Errorf("block_pages.%s json_code 非法取值", normScene)
	}
	if len(item.JSONMessage) > maxBlockResponseJSONMsgBytes {
		return fmt.Errorf("block_pages.%s json_message 超过上限 %d 字节", normScene, maxBlockResponseJSONMsgBytes)
	}
	return nil
}

func validateBlockPageMap(m map[string]*blockPageItemJSON) error {
	for scene, item := range m {
		if err := validateBlockPageItem(scene, item); err != nil {
			return err
		}
	}
	return nil
}

func compileBlockPageMap(m map[string]*blockPageItemJSON) (map[string]*compiledBlockPage, error) {
	if len(m) == 0 {
		return nil, nil
	}
	if err := validateBlockPageMap(m); err != nil {
		return nil, err
	}
	out := make(map[string]*compiledBlockPage, len(m))
	for scene, item := range m {
		norm := strings.ToUpper(strings.TrimSpace(scene))
		sanitized := sanitizeRichBlockHTML(item.HTML)
		if strings.TrimSpace(sanitized) == "" {
			return nil, fmt.Errorf("block_pages.%s 净化后为空", norm)
		}
		out[norm] = &compiledBlockPage{
			pageID:      item.PageID,
			version:     item.Version,
			statusCode:  item.StatusCode,
			html:        sanitized,
			jsonCode:    item.JSONCode,
			jsonMessage: item.JSONMessage,
		}
	}
	return out, nil
}

// resolve 按四级优先级解析生效拦截页：
// (appCode, scene) > (appCode, DEFAULT) > (global, scene) > (global, DEFAULT)。
func (h *BlockPageHandler) resolve(appCode, scene string) *compiledBlockPage {
	normScene := strings.ToUpper(strings.TrimSpace(scene))
	if normScene == "" {
		normScene = blockSceneDefault
	}
	if appCode != "" && len(h.appsCompiled) > 0 {
		if am := h.appsCompiled[appCode]; am != nil {
			if p := am[normScene]; p != nil {
				return p
			}
			if normScene != blockSceneDefault {
				if p := am[blockSceneDefault]; p != nil {
					return p
				}
			}
		}
	}
	if len(h.globalCompiled) > 0 {
		if p := h.globalCompiled[normScene]; p != nil {
			return p
		}
		if normScene != blockSceneDefault {
			if p := h.globalCompiled[blockSceneDefault]; p != nil {
				return p
			}
		}
	}
	return nil
}

// ServeHTTP 在 Caddy 错误路由中拦截 403/429 错误并渲染自定义多版本拦截页；未命中则透传 next。
func (h *BlockPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	statusCode, rawErr := errorStatusFromContext(r)
	if statusCode != http.StatusForbidden && statusCode != http.StatusTooManyRequests {
		return next.ServeHTTP(w, r)
	}

	appCode := getStringVar(r, varBlockPageAppCode)
	if appCode == "" && len(h.hostMap) > 0 {
		appCode = h.hostMap[stripHostPort(r.Host)]
	}
	scene := getStringVar(r, varBlockPageScene)
	if scene == "" {
		if _, _, ok := corazaInterruption(rawErr); ok {
			scene = blockSceneWAF
		} else if statusCode == http.StatusTooManyRequests {
			scene = blockSceneRateLimit
		} else {
			scene = blockSceneWAF
		}
	}

	page := h.resolve(appCode, scene)
	if page == nil {
		return next.ServeHTTP(w, r)
	}

	requestID := getStringVar(r, varBlockPageRequestID)
	if requestID == "" {
		requestID = r.Header.Get("X-Request-Id")
	}
	clientIP := getStringVar(r, varBlockPageClientIP)
	if clientIP == "" {
		clientIP = stripHostPort(r.RemoteAddr)
	}

	writeCompiledBlockPage(w, r, page, blockPageRenderMeta{
		StatusCode: statusCode,
		Scene:      scene,
		RequestID:  requestID,
		ClientIP:   clientIP,
		AppCode:    appCode,
		RetryAfter: "-",
	})
	return nil
}

// blockPageRenderMeta 渲染单次拦截响应所需的运行时只读上下文。
type blockPageRenderMeta struct {
	StatusCode int
	Scene      string
	RequestID  string
	ClientIP   string
	AppCode    string
	RetryAfter string
	Message    string
}

func blockPageSceneLabel(scene string) string {
	switch strings.ToUpper(strings.TrimSpace(scene)) {
	case blockSceneWAF:
		return "WAF 安全拦截"
	case blockSceneAccessControl:
		return "访问控制拦截"
	case blockSceneRateLimit:
		return "频率限制拦截"
	default:
		return "安全拦截"
	}
}

func defaultJSONForScene(scene string, status int) (string, string) {
	if scene == blockSceneRateLimit || status == http.StatusTooManyRequests {
		return "too_many_requests", "请求过于频繁，请稍后重试"
	}
	if scene == blockSceneAccessControl {
		return "access_blocked", "访问已被安全策略拦截"
	}
	return "security_blocked", "请求已被安全策略阻断"
}

// writeCompiledBlockPage 按内容协商（Accept: application/json vs HTML）输出自定义拦截响应。
func writeCompiledBlockPage(w http.ResponseWriter, r *http.Request, page *compiledBlockPage, meta blockPageRenderMeta) {
	finalStatus := meta.StatusCode
	if page.statusCode >= 400 && page.statusCode <= 599 {
		finalStatus = page.statusCode
	}
	if finalStatus < 400 || finalStatus > 599 {
		finalStatus = http.StatusForbidden
	}

	if meta.RequestID != "" {
		w.Header().Set("X-Jiuzhang-Request-ID", meta.RequestID)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(finalStatus)
		defCode, defMsg := defaultJSONForScene(meta.Scene, finalStatus)
		errCode := page.jsonCode
		if errCode == "" {
			errCode = defCode
		}
		errMsg := page.jsonMessage
		if errMsg == "" {
			if meta.Message != "" {
				errMsg = meta.Message
			} else {
				errMsg = defMsg
			}
		}
		payload := map[string]string{
			"error":      errCode,
			"message":    errMsg,
			"request_id": meta.RequestID,
		}
		if reason := w.Header().Get("X-Jiuzhang-Risk-Reason"); reason != "" {
			payload["reason_code"] = reason
			payload["policy_version"] = w.Header().Get("X-Jiuzhang-Policy-Version")
			payload["event_id"] = w.Header().Get("X-Jiuzhang-Risk-Event-ID")
		}
		body, _ := json.Marshal(payload)
		_, _ = w.Write(body)
		return
	}

	nowUTC := time.Now().UTC()
	pathVal := r.URL.Path
	if len(pathVal) > 256 {
		pathVal = pathVal[:256] + "..."
	}
	retryVal := meta.RetryAfter
	if retryVal == "" {
		retryVal = "-"
	}
	rep := strings.NewReplacer(
		"{{request_id}}", stdhtml.EscapeString(meta.RequestID),
		"{{time}}", stdhtml.EscapeString(nowUTC.Format("2006-01-02 15:04:05 UTC")),
		"{{time_local}}", stdhtml.EscapeString(nowUTC.In(cstZone).Format("2006-01-02 15:04:05 +0800")),
		"{{client_ip}}", stdhtml.EscapeString(meta.ClientIP),
		"{{domain}}", stdhtml.EscapeString(r.Host),
		"{{path}}", stdhtml.EscapeString(pathVal),
		"{{status_code}}", strconv.Itoa(finalStatus),
		"{{scene}}", stdhtml.EscapeString(meta.Scene),
		"{{scene_label}}", stdhtml.EscapeString(blockPageSceneLabel(meta.Scene)),
		"{{app_code}}", stdhtml.EscapeString(meta.AppCode),
		"{{retry_after}}", stdhtml.EscapeString(retryVal),
		"{{message}}", stdhtml.EscapeString(meta.Message),
	)
	rendered := rep.Replace(page.html)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(finalStatus)
	_, _ = w.Write([]byte(rendered))
}

// setBlockPageContext 由 jiuzhang_guard 在真实 IP 识别后写入请求上下文变量，供错误链消费。
func setBlockPageContext(r *http.Request, appCode, appID, clientIP, requestID string) {
	if r == nil {
		return
	}
	ctx := r.Context()
	if _, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any); !ok {
		return
	}
	if appCode != "" {
		caddyhttp.SetVar(ctx, varBlockPageAppCode, appCode)
	}
	if appID != "" {
		caddyhttp.SetVar(ctx, varBlockPageAppID, appID)
	}
	if clientIP != "" {
		caddyhttp.SetVar(ctx, varBlockPageClientIP, clientIP)
	}
	if requestID != "" {
		caddyhttp.SetVar(ctx, varBlockPageRequestID, requestID)
	}
}

// setBlockPageScene 标记本次拦截所属场景（WAF / ACCESS_CONTROL / RATE_LIMIT）。
func setBlockPageScene(r *http.Request, scene string) {
	if r == nil || scene == "" {
		return
	}
	ctx := r.Context()
	if _, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any); !ok {
		return
	}
	caddyhttp.SetVar(ctx, varBlockPageScene, scene)
}

func getStringVar(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	v := caddyhttp.GetVar(r.Context(), key)
	s, _ := v.(string)
	return s
}

func errorStatusFromContext(r *http.Request) (int, error) {
	if raw := r.Context().Value(caddyhttp.ErrorCtxKey); raw != nil {
		if err, ok := raw.(error); ok {
			var he caddyhttp.HandlerError
			if errors.As(err, &he) && he.StatusCode > 0 {
				return he.StatusCode, err
			}
			return 0, err
		}
	}
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && repl != nil {
		if v, ok := repl.Get("http.error.status_code"); ok {
			switch n := v.(type) {
			case int:
				return n, nil
			case string:
				if parsed, err := strconv.Atoi(n); err == nil {
					return parsed, nil
				}
			}
		}
	}
	return 0, nil
}

func stripHostPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.ToLower(strings.Trim(addr, "[]"))
}

// resolveBlockPage 解析 Guard 实例（单应用）在指定场景下的自定义拦截页。
func (g *Guard) resolveBlockPage(scene string) *compiledBlockPage {
	if len(g.blockPages) == 0 {
		return nil
	}
	if p := g.blockPages[scene]; p != nil {
		return p
	}
	return g.blockPages[blockSceneDefault]
}

// resolvedClientIPString 获取当前请求经 Guard 识别后的真实客户端 IP（回退 RemoteAddr）。
func resolvedClientIPString(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ip := getStringVar(r, varBlockPageClientIP); ip != "" {
		return ip
	}
	if res, ok := r.Context().Value(clientIPResultKey{}).(clientip.Result); ok && res.ClientIP.IsValid() {
		return res.ClientIP.String()
	}
	if h := r.Header.Get("X-Real-Ip"); h != "" {
		return h
	}
	return stripHostPort(r.RemoteAddr)
}

var (
	_ caddy.Provisioner           = (*BlockPageHandler)(nil)
	_ caddy.Validator             = (*BlockPageHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*BlockPageHandler)(nil)
)
