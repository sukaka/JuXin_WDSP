// headers.go 站点级 HTTP 头合规与代理配置 + 路径粒度转发的配置构建。
package gatewayconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// HeaderRule 自定义头修改规则（method: set|add|delete）。
type HeaderRule struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Value  string `json:"value,omitempty"`
}

// AppHeaderConfig 应用级头合规与代理配置（无配置时回落到默认静态头，行为与既有版本一致）。
// 说明：下划线请求头由网关内核（Caddy 2.11+，GHSA-f59h-q822-g45g）入口强制丢弃，
// 始终生效、不可配置，故本结构不包含该开关。
type AppHeaderConfig struct {
	ServerAction        string       `json:"server_action"`
	ServerValue         string       `json:"server_value,omitempty"`
	XAuthorAction       string       `json:"x_author_action"`
	XAuthorValue        string       `json:"x_author_value,omitempty"`
	XPoweredByAction    string       `json:"x_powered_by_action"`
	XPoweredByValue     string       `json:"x_powered_by_value,omitempty"`
	XFrameOptions       string       `json:"x_frame_options"` // default|inherit|deny|sameorigin|allow_from
	XFrameOptionsURL    string       `json:"x_frame_options_url,omitempty"`
	XXssProtection      bool         `json:"x_xss_protection"`
	VaryUserAgent       bool         `json:"vary_user_agent"`
	HstsEnabled         bool         `json:"hsts_enabled"`
	HstsMaxAge          int          `json:"hsts_max_age,omitempty"`
	CspMode             string       `json:"csp_mode"` // off|preset|custom
	CspValue            string       `json:"csp_value,omitempty"`
	ResponseBuffering            bool         `json:"response_buffering"`
	XffOverwrite                 bool         `json:"xff_overwrite"`
	HostStripPort                bool         `json:"host_strip_port"`
	AcceptEncodingOff            bool         `json:"accept_encoding_off"`
	ResponseCompressionEnabled   bool         `json:"response_compression_enabled"`
	ResponseCompressionEncodings string       `json:"response_compression_encodings,omitempty"`
	RedirectPortRewrite          bool         `json:"redirect_port_rewrite"`
	CustomRequestRules           []HeaderRule `json:"custom_request_rules,omitempty"`
	CustomResponseRules          []HeaderRule `json:"custom_response_rules,omitempty"`
}

const (
	// ResponseCompressionEncodingsDefault 默认同时启用 zstd 与 gzip（客户端同时支持时优先 zstd）。
	ResponseCompressionEncodingsDefault = "zstd,gzip"
	// ResponseCompressionEncodingsGzip 仅启用 gzip（最大客户端/中间件兼容性）。
	ResponseCompressionEncodingsGzip = "gzip"
	// ResponseCompressionEncodingsZstd 仅启用 zstd（更高压缩率与更低 CPU）。
	ResponseCompressionEncodingsZstd = "zstd"
	// ResponseCompressionMinLength 触发网关响应压缩的最小正文长度（字节，与 Caddy encode 默认值对齐）。
	ResponseCompressionMinLength = 512
)

// NormalizeResponseCompressionEncodings 校验并规范化响应压缩算法配置。
// 空字符串归一化为默认 "zstd,gzip"（兼容未传该字段的存量调用方）；其余仅接受白名单枚举。
func NormalizeResponseCompressionEncodings(raw string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", ResponseCompressionEncodingsDefault:
		return ResponseCompressionEncodingsDefault, true
	case ResponseCompressionEncodingsGzip:
		return ResponseCompressionEncodingsGzip, true
	case ResponseCompressionEncodingsZstd:
		return ResponseCompressionEncodingsZstd, true
	default:
		return "", false
	}
}

// responseCompressionContentTypes 网关侧允许主动压缩的响应 Content-Type 白名单。
// 对齐 Caddy encode 默认常见文本/API/前端类型，但显式列举 text/* 子类型以排除
// text/event-stream（SSE / MCP SSE / AI 流式输出），避免流式推送被压缩缓冲。
var responseCompressionContentTypes = []string{
	"application/atom+xml*",
	"application/eot*",
	"application/font*",
	"application/geo+json*",
	"application/graphql+json*",
	"application/graphql-response+json*",
	"application/javascript*",
	"application/json*",
	"application/ld+json*",
	"application/manifest+json*",
	"application/opentype*",
	"application/otf*",
	"application/rss+xml*",
	"application/truetype*",
	"application/ttf*",
	"application/vnd.api+json*",
	"application/vnd.ms-fontobject*",
	"application/wasm*",
	"application/x-httpd-cgi*",
	"application/x-javascript*",
	"application/x-opentype*",
	"application/x-otf*",
	"application/x-perl*",
	"application/x-protobuf*",
	"application/x-ttf*",
	"application/xhtml+xml*",
	"application/xml*",
	"font/ttf*",
	"font/otf*",
	"image/svg+xml*",
	"image/vnd.microsoft.icon*",
	"image/x-icon*",
	"multipart/bag*",
	"multipart/mixed*",
	"text/cache-manifest*",
	"text/calendar*",
	"text/css*",
	"text/csv*",
	"text/html*",
	"text/javascript*",
	"text/markdown*",
	"text/plain*",
	"text/vcard*",
	"text/vtt*",
	"text/x-component*",
	"text/x-cross-domain-policy*",
	"text/xml*",
}

// buildEncodeHandler 构建 Caddy 原生 http.handlers.encode 响应压缩处理器。
// 未开启时返回 nil，保持存量站点配置逐字节不变。
// 安全与顺序语义：
//   - 挂载于 requestID 之后、jiuzhang_guard / waf / headerHandler 之前（响应回程最后执行），
//     保证 WAF 响应体检测、API 响应脱敏/加密、HTML 供应链扫描与 A2A 发现均处理明文；
//   - 源站已带 Content-Encoding 或 Cache-Control: no-transform、WebSocket 握手及 <=512B 响应
//     由 Caddy encode 自动跳过，不产生二次压缩；
//   - 显式 MIME 匹配排除 text/event-stream，不干扰 SSE 流式传输。
func buildEncodeHandler(cfg *AppHeaderConfig) mapT {
	if cfg == nil || !cfg.ResponseCompressionEnabled {
		return nil
	}
	mode, ok := NormalizeResponseCompressionEncodings(cfg.ResponseCompressionEncodings)
	if !ok {
		mode = ResponseCompressionEncodingsDefault
	}
	encodings := mapT{}
	var prefer []string
	switch mode {
	case ResponseCompressionEncodingsGzip:
		encodings["gzip"] = mapT{}
		prefer = []string{"gzip"}
	case ResponseCompressionEncodingsZstd:
		encodings["zstd"] = mapT{}
		prefer = []string{"zstd"}
	default:
		encodings["zstd"] = mapT{}
		encodings["gzip"] = mapT{}
		prefer = []string{"zstd", "gzip"}
	}
	contentTypes := append([]string(nil), responseCompressionContentTypes...)
	return mapT{
		"handler":        "encode",
		"encodings":      encodings,
		"prefer":         prefer,
		"minimum_length": ResponseCompressionMinLength,
		"match": mapT{
			"headers": mapT{
				"Content-Type": contentTypes,
			},
		},
	}
}

// AppPathRoute 路径粒度转发（应用内路径前缀 → 指定源站）。
type AppPathRoute struct {
	PathPrefix     string `json:"path_prefix"`
	UpstreamScheme string `json:"upstream_scheme"`
	UpstreamHost   string `json:"upstream_host"`
	UpstreamPort   int    `json:"upstream_port"`
	StripPrefix    bool   `json:"strip_prefix"`
	Priority       int    `json:"priority"`
}

// versionDisclosureResponseHeaders 对外响应固定隐藏的中间件与数据库版本头。
var versionDisclosureResponseHeaders = []string{
	"Server", "Via", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator",
	"X-Server-Version", "X-Middleware-Version", "X-DB-Version", "X-Database-Version",
	"X-MySQL-Version", "X-PostgreSQL-Version", "X-Redis-Version", "X-Valkey-Version",
	"X-ClickHouse-Version", "X-ClickHouse-Server-Version",
}

func isVersionDisclosureResponseHeader(name string) bool {
	for _, protected := range versionDisclosureResponseHeaders {
		if strings.EqualFold(name, protected) {
			return true
		}
	}
	return false
}

// buildHeaderHandler 构建安全响应头处理器（含头合规配置与自定义返回头规则）。
// 中间件与数据库版本头始终隐藏，旧配置和自定义响应规则不能重新添加。
// response 必须 deferred=true，确保代理拷贝源站响应头后仍执行最终清理。
func buildHeaderHandler(cfg *AppHeaderConfig) mapT {
	set := map[string][]string{}
	del := append([]string{}, versionDisclosureResponseHeaders...)
	add := map[string][]string{}

	if cfg == nil {
		set["X-Content-Type-Options"] = []string{"nosniff"}
		set["X-Frame-Options"] = []string{"DENY"}
		set["Referrer-Policy"] = []string{"no-referrer"}
		return mapT{"handler": "headers", "response": mapT{"set": set, "delete": del, "deferred": true}}
	}

	applyAction := func(field, action, value string) {
		switch action {
		case "hide":
			del = append(del, field)
		case "replace":
			if value != "" {
				set[field] = []string{value}
			} else {
				del = append(del, field)
			}
		}
	}
	applyAction("X-Author", cfg.XAuthorAction, cfg.XAuthorValue)

	// X-Frame-Options
	switch cfg.XFrameOptions {
	case "inherit":
	case "sameorigin":
		set["X-Frame-Options"] = []string{"SAMEORIGIN"}
	case "allow_from":
		if cfg.XFrameOptionsURL != "" {
			set["X-Frame-Options"] = []string{"ALLOW-FROM " + cfg.XFrameOptionsURL}
		}
	default:
		set["X-Frame-Options"] = []string{"DENY"}
	}

	set["X-Content-Type-Options"] = []string{"nosniff"}
	set["Referrer-Policy"] = []string{"no-referrer"}
	if cfg.XXssProtection {
		set["X-Xss-Protection"] = []string{"1; mode=block"}
	}
	if cfg.VaryUserAgent {
		add["Vary"] = []string{"User-Agent"}
	}
	if cfg.HstsEnabled {
		maxAge := cfg.HstsMaxAge
		if maxAge <= 0 {
			maxAge = 31536000
		}
		set["Strict-Transport-Security"] = []string{fmt.Sprintf("max-age=%d; includeSubDomains", maxAge)}
	}
	switch cfg.CspMode {
	case "preset":
		set["Content-Security-Policy"] = []string{"default-src 'self'; frame-ancestors 'self'; base-uri 'self'"}
	case "custom":
		if cfg.CspValue != "" {
			set["Content-Security-Policy"] = []string{cfg.CspValue}
		}
	}

	for _, rule := range cfg.CustomResponseRules {
		name := strings.TrimSpace(rule.Name)
		if name == "" || isVersionDisclosureResponseHeader(name) {
			continue
		}
		switch rule.Method {
		case "add":
			add[name] = append(add[name], rule.Value)
		case "delete":
			del = append(del, name)
		default:
			set[name] = []string{rule.Value}
		}
	}

	resp := mapT{"set": set, "delete": del, "deferred": true}
	if len(add) > 0 {
		resp["add"] = add
	}
	return mapT{"handler": "headers", "response": resp}
}

// applyProxyOptions 把头合规中的代理配置应用到 reverse_proxy（header_up 与响应缓冲）。
// X-Forwarded-For 上一跳覆盖默认开启（LOW-G3）：jiuzhang_guard 在处理器链前置位已将
// RemoteAddr 改写为已解析的真实客户端 IP，{http.request.remote.host} 即真实 IP——默认
// 覆盖客户端伪造的 XFF 左端；仅当存在头合规配置记录且显式 xff_overwrite=false 时保留
// 入站原值（BYPASS/可信 LB 后需保留 XFF 链的场景须显式关闭）。
func applyProxyOptions(proxy mapT, cfg *AppHeaderConfig) mapT {
	set := map[string][]string{}
	add := map[string][]string{}
	del := []string{}
	if cfg == nil || cfg.XffOverwrite {
		set["X-Forwarded-For"] = []string{"{http.request.remote.host}"}
	}
	if cfg == nil {
		if len(set) > 0 {
			proxy["headers"] = mapT{"request": mapT{"set": set}}
		}
		return proxy
	}
	if cfg.HostStripPort {
		set["Host"] = []string{"{http.request.host}"}
	}
	if cfg.AcceptEncodingOff {
		set["Accept-Encoding"] = []string{"identity"}
	}
	for _, rule := range cfg.CustomRequestRules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			continue
		}
		switch rule.Method {
		case "add":
			add[name] = append(add[name], rule.Value)
		case "delete":
			del = append(del, name)
		default:
			set[name] = []string{rule.Value}
		}
	}
	if len(set) > 0 || len(add) > 0 || len(del) > 0 {
		req := mapT{}
		if len(set) > 0 {
			req["set"] = set
		}
		if len(add) > 0 {
			req["add"] = add
		}
		if len(del) > 0 {
			req["delete"] = del
		}
		proxy["headers"] = mapT{"request": req}
	}
	if cfg.ResponseBuffering {
		// -1 表示缓冲完整响应后再下发（默认 0 为即时流式）
		proxy["flush_interval"] = "-1"
	}
	return proxy
}

// pathRouteEntries 为应用+域名构建路径粒度转发路由（在默认路由之前评估）。
// 排序：priority 升序，前缀长度降序（确定性）；strip_prefix 用 Caddy handle_path 剥离。
// publicPort 为该批路由所在监听的接入端口。
func pathRouteEntries(in GenerateInput, app AppData, hosts []string, publicPort int) []routeEntry {
	if len(app.PathRoutes) == 0 {
		return nil
	}
	rts := append([]AppPathRoute{}, app.PathRoutes...)
	sort.SliceStable(rts, func(i, j int) bool {
		if rts[i].Priority != rts[j].Priority {
			return rts[i].Priority < rts[j].Priority
		}
		return len(rts[i].PathPrefix) > len(rts[j].PathPrefix)
	})
	var out []routeEntry
	for _, pr := range rts {
		prefix := pr.PathPrefix
		if !strings.HasPrefix(prefix, "/") {
			continue
		}
		upstream := applications.Upstream{
			Scheme: pr.UpstreamScheme, NormalizedHost: pr.UpstreamHost, Port: pr.UpstreamPort,
			Status: "ACTIVE",
			// 路径转发无逐路由证书校验开关，跟随应用源站字段的库默认（tls_verify DEFAULT TRUE）：
			// https 回源默认校验证书（SNI/证名取源站主机名，见 buildReverseProxy）
			TLSVerify: true,
		}
		proxy := applyProxyOptions(buildReverseProxyWithTLS([]applications.Upstream{upstream}, app.TLSConfig), app.HeaderConfig)
		var preProxy []interface{}
		if pr.StripPrefix {
			// 安全底线（H-15）：strip_path_prefix 必须位于 jiuzhang_guard 与 Coraza WAF 之后、
			// reverse_proxy 正前方，防止改写路径后绕过基于原始路径的 L7/API/Bot/WAF 规则。
			preProxy = []interface{}{mapT{"handler": "rewrite", "strip_path_prefix": prefix}}
		}
		handles := buildChainHandlesWithPreProxy(in, app, proxy, publicPort, preProxy...)
		route := mapT{
			"match":  []interface{}{mapT{"host": hosts, "path": []string{prefix + "*"}}},
			"handle": handles,
		}
		out = append(out, routeEntry{appCode: app.Code, route: route})
	}
	return out
}

// buildChainHandles 构建除反代外的通用处理链。软件旁路启用配置存在时，正常检测链与
// 纯透传链在同一选择器内预编译，二者共用外层 reverse_proxy；超阈时不会经过 guard/WAF。
// BYPASS（数据透传）模式的两条链均为纯透传，保持手工应急直通的绝对优先级。
func buildChainHandles(in GenerateInput, app AppData, proxy mapT, publicPort int) []interface{} {
	return buildChainHandlesWithPreProxy(in, app, proxy, publicPort)
}

func buildChainHandlesWithPreProxy(in GenerateInput, app AppData, proxy mapT, publicPort int, preProxy ...interface{}) []interface{} {
	requestID := mapT{
		"handler": "headers",
		"request": mapT{"set": mapT{"X-Request-Id": []string{"{http.request.uuid}"}},
			"delete": []string{}},
		"response": mapT{"set": mapT{"X-Jiuzhang-Request-ID": []string{"{http.request.header.X-Request-Id}"}}},
	}
	normal := []interface{}{requestID}
	bypass := []interface{}{requestID}
	if encodeHandler := buildEncodeHandler(app.HeaderConfig); encodeHandler != nil {
		normal = append(normal, encodeHandler)
		bypass = append(bypass, encodeHandler)
	}
	if app.ProtectionMode != applications.ModeBypass {
		if in.Guard != nil {
			gh := buildGuardHandler(in.Guard, app, publicPort)
			if versions := restrictedAllowedHTTPVersions(app.TLSConfig); len(versions) > 0 {
				gh["allowed_http_versions"] = versions
			}
			normal = append(normal, gh)
		}
		ruleEngine := modeToRuleEngine[app.ProtectionMode]
		if ruleEngine == "" {
			ruleEngine = "DetectionOnly"
		}
		directives := buildWAFDirectivesWithBase(in.RulesBasePath, ruleEngine, app, in.Exceptions, in.CustomRules, app.RuleOverrideSecLang)
		normal = append(normal, mapT{
			"handler":    "waf",
			"directives": directives,
		})
	}
	headerHandler := buildHeaderHandler(app.HeaderConfig)
	normal = append(normal, headerHandler)
	bypass = append(bypass, headerHandler)
	if in.Guard != nil && in.Guard.SoftwareBypass != nil {
		cfg := in.Guard.SoftwareBypass
		selector := mapT{
			"handler":                  "jiuzhang_software_bypass",
			"app_id":                   app.AppID,
			"node":                     in.Guard.GatewayNode,
			"enabled":                  cfg.Enabled,
			"cpu_threshold_percent":    cfg.CPUThresholdPercent,
			"memory_threshold_percent": cfg.MemoryThresholdPercent,
			"min_hold_seconds":         cfg.MinHoldSeconds,
			"session_cookie_names":     cfg.SessionCookieNames,
			"normal":                   mapT{"routes": []interface{}{mapT{"handle": normal}}},
			"bypass":                   mapT{"routes": []interface{}{mapT{"handle": bypass}}},
		}
		out := []interface{}{selector}
		out = append(out, preProxy...)
		return append(out, proxy)
	}
	if app.ProtectionMode == applications.ModeBypass {
		out := append(bypass, preProxy...)
		return append(out, proxy)
	}
	out := append(normal, preProxy...)
	return append(out, proxy)
}
