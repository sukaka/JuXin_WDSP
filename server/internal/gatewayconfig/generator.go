// Package gatewayconfig 提供网关配置生成器：将数据库业务数据转换为确定性 Caddy JSON 配置。
package gatewayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// 防护模式到 SecRuleEngine 的映射
var modeToRuleEngine = map[string]string{
	applications.ModeOff:     "Off",
	applications.ModeObserve: "DetectionOnly",
	applications.ModeProtect: "On",
}

// GenerateInput 是配置生成输入。
type GenerateInput struct {
	// Apps 为已组装的应用（含域名与源站）。
	Apps []AppData
	// BlockPagePath 阻断页面在网关内的路径。
	BlockPagePath string
	// AdminSocket Caddy Admin Unix Socket 路径（必须始终包含，防配置覆盖丢失）。
	AdminSocket string
	// CertFileDir 证书文件在网关内的目录。
	CertFileDir string
	// Exceptions 启用的例外策略规则（SecLang 文本，加入 before-crs 加载段）。
	Exceptions []ExceptionRule
	// CustomRules 启用的自定义规则 SecLang（CRS 之后加载，替代仅静态 include）。
	CustomRules []string
	// Guard 阶段5访问控制/CC 配置（nil 表示不注入 jiuzhang_guard 处理器，兼容阶段3/4）。
	Guard *GuardConfig
	// GatewayTracing 网关 Caddy 原生 OTel tracing 下发开关（APM 阶段2 收尾，默认关；
	// 发布侧由 GATEWAY_TRACING_ENABLED 注入）。开启时在每个 server 的每条路由链首注入
	// http.handlers.tracing handler（Caddy 中间件语义：链首包裹整条后续处理链）。
	// 注意：Caddy 2.11 该模块的 exporter/采样不在 JSON 内表达，由网关进程 OTEL_* 环境变量
	// 控制（默认 OTLP http/protobuf → 127.0.0.1:4318，parentbased_always_on 即 100% 头采；
	// 错误/慢请求/WAF 高风险的尾采样在中央 Collector 决策，见 docs/APM_DATA_PLANE_DEPLOYMENT.md）。
	GatewayTracing bool
}

// AppData 是单个应用的完整数据。
type AppData struct {
	AppID          string
	Code           string
	ProtectionMode string
	// DeploymentMode 部署模式（REVERSE_PROXY 默认 / ROUTED 路由牵引 / MIRROR 镜像旁路 /
	// TRANSPARENT 透明串接，docs/NETWORK_MODES_DESIGN.md §4）；空串按 REVERSE_PROXY 处理。
	// MIRROR 应用不生成内联站点路由（流量经镜像口到达，不在反代链上）。
	DeploymentMode string
	Domains        []applications.Domain
	Upstreams      []applications.Upstream
	// 证书（HTTPS 应用）：PEM 与私钥 PEM（发布时解密提供）。
	CertID       string
	CertFileName string // 写入网关证书目录的文件名（不含目录）
	HasCert      bool
	// 阶段4策略参数（可选，为零值时使用默认）
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
	// RuleOverrideSecLang 本应用生效的规则覆盖 SecLang（DISABLE → ctl:ruleRemoveById，置于 CRS 前）
	RuleOverrideSecLang []string
	// HeaderConfig 头合规与代理配置（nil 时使用默认静态头行为）
	HeaderConfig *AppHeaderConfig
	// PathRoutes 路径粒度转发（ENABLED 且校验通过的条目）
	PathRoutes []AppPathRoute
}

// Generated 是生成结果。
type Generated struct {
	JSON        string `json:"json"`
	Hash        string `json:"hash"`
	ServerCount int    `json:"server_count"`
	RouteCount  int    `json:"route_count"`
}

// mapT 简化 JSON 构造。
type mapT = map[string]interface{}

// Generate 生成 Caddy JSON 配置（确定性）。
func Generate(in GenerateInput) (*Generated, error) {
	if in.AdminSocket == "" {
		return nil, fmt.Errorf("admin socket path is required")
	}
	if in.BlockPagePath == "" {
		in.BlockPagePath = "/srv/jiuzhang/blockpage.html"
	}
	if in.CertFileDir == "" {
		in.CertFileDir = "/etc/caddy/certs"
	}

	servers, routeCount := buildServers(in)
	if len(servers) == 0 {
		// 无应用时生成最小空配置（仅 admin 与空 servers）
	}

	// 网关原生 tracing（默认关）：向每条路由链首注入 http.handlers.tracing
	if in.GatewayTracing {
		injectTracingHandlers(servers)
	}

	// admin.listen 必须是 "unix/<path>" 形式（Caddy 将无前缀路径误解析为 TCP 地址）
	adminListen := in.AdminSocket
	if !strings.HasPrefix(adminListen, "unix/") && !strings.HasPrefix(adminListen, "tcp/") {
		adminListen = "unix/" + adminListen
	}

	config := mapT{
		"admin": mapT{"listen": adminListen},
		"logging": mapT{
			"logs": mapT{
				"default": mapT{"writer": mapT{"output": "file", "filename": "/var/log/caddy/caddy.log"}, "encoder": mapT{"format": "json"}},
				// 阶段6：结构化访问日志（请求统计指标数据源）
				"access": mapT{"writer": mapT{"output": "file", "filename": "/var/log/caddy/access.log"}, "encoder": mapT{"format": "json"}},
			},
		},
		"apps": mapT{
			"http": mapT{
				"servers": servers,
			},
		},
	}

	// apps.tls 段（证书文件加载 + TLS 会话票据密钥），任一存在才产出：
	//   - certificates.load_files：HTTPS 应用证书，引用发布器写入网关证书目录的
	//     <certID>.pem/.key（files.go WriteCertificateFiles 落盘约定），每个证书以
	//     certTag 打标，供 server tls_connection_policies 的
	//     certificate_selection.any_tag 选择（见 buildTLSPolicies）；
	//   - session_tickets（HA §7.2）：配置了下发 tls.stek.jiuzhang 静态键
	//     （主备多节点共用 → 会话恢复跨节点可用）；
	// 均未配置保持缺省（无 apps.tls 段，Go 标准库进程内随机票据键，跨节点恢复
	// 回退完整握手，如实记录）。
	tlsApp := mapT{}
	if pairs := buildCertFilePairs(in); len(pairs) > 0 {
		tlsApp["certificates"] = mapT{"load_files": pairs}
	}
	if in.Guard != nil && in.Guard.TLSSessionTicketKey != "" {
		tlsApp["session_tickets"] = mapT{
			"key_source": mapT{
				"provider": "jiuzhang",
				"keys_hex": []string{in.Guard.TLSSessionTicketKey},
			},
		}
	}
	if len(tlsApp) > 0 {
		config["apps"].(mapT)["tls"] = tlsApp
	}

	// 确定性序列化（固定缩进与键顺序由 encoding/json 保证 map 键排序）
	buf, err := marshalDeterministic(config)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(buf)
	return &Generated{
		JSON:        string(buf),
		Hash:        hex.EncodeToString(hash[:]),
		ServerCount: len(servers),
		RouteCount:  routeCount,
	}, nil
}

// marshalDeterministic 确定性 JSON 序列化。
// encoding/json 对 map 键自动按字典序排序，保证确定性。
func marshalDeterministic(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// gatewayTracingSpanName 网关 tracing server span 名（http.handlers.tracing 的 span 字段）。
const gatewayTracingSpanName = "jiuzhang-gateway"

// injectTracingHandlers 将 Caddy 原生 tracing handler（http.handlers.tracing，Caddy 2.11
// 内建模块，JSON 仅暴露 span/span_attributes 字段）注入每个 server 每条路由的处理链首：
// Caddy 中间件语义下链首 handler 包裹整条后续链（RequestID→guard→WAF→反代），
// 等价 Caddyfile 站点级 tracing 指令的 adapt 形态；HTTP→HTTPS 重定向与路径转发路由同样覆盖。
// 仅处理请求主路由（routes），不触碰 errors 内部错误路由（非真实请求入口）。
func injectTracingHandlers(servers map[string]interface{}) {
	for _, srv := range servers {
		server, ok := srv.(mapT)
		if !ok {
			continue
		}
		routes, ok := server["routes"].([]interface{})
		if !ok {
			continue
		}
		for _, r := range routes {
			route, ok := r.(mapT)
			if !ok {
				continue
			}
			handle, ok := route["handle"].([]interface{})
			if !ok || len(handle) == 0 {
				continue
			}
			tracing := mapT{
				"handler": "tracing",
				"span":    gatewayTracingSpanName,
			}
			route["handle"] = append([]interface{}{tracing}, handle...)
		}
	}
}

// sortedKeys 返回 map 的键按字典序排序。
func sortedKeys(m map[string][]routeEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// routeEntry 是带应用编码的路由条目（用于确定性排序）。
type routeEntry struct {
	appCode string
	route   mapT
}

// buildServers 按监听端口分组构建 servers。
func buildServers(in GenerateInput) (map[string]interface{}, int) {
	httpServers := map[string][]routeEntry{}  // listen addr -> routes
	httpsServers := map[string][]routeEntry{} // listen addr -> routes

	for _, app := range in.Apps {
		// MIRROR（镜像旁路）应用不生成内联站点路由：其流量经镜像口到达 mirrorcap 采集器，
		// 不在反代链上（docs/NETWORK_MODES_DESIGN.md §4.2）；边车配置由发布通道另行写出。
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		for _, d := range app.Domains {
			hosts := []string{d.NormalizedHostname}
			// 泛域名 Caddy 用 *.example.com 形式（Caddy 支持通配符 host matcher）
			route := mapT{}
			if d.HTTPEnabled && d.HTTPPort != nil {
				addr := fmt.Sprintf(":%d", *d.HTTPPort)
				r := mapT{
					"match":  []interface{}{mapT{"host": hosts}},
					"handle": buildHandles(in, app, d, *d.HTTPPort),
				}
				// HTTP 跳 HTTPS：仅返回重定向
				if d.RedirectHTTPToHTTPS && d.HTTPSEnabled {
					r = mapT{
						"match": []interface{}{mapT{"host": hosts}},
						"handle": []interface{}{
							mapT{"handler": "static_response", "status_code": 308,
								"headers": mapT{"Location": []string{"https://{http.request.host}{http.request.uri}"}}},
						},
					}
				}
				httpServers[addr] = append(httpServers[addr], pathRouteEntries(in, app, hosts, *d.HTTPPort)...)
				httpServers[addr] = append(httpServers[addr], routeEntry{appCode: app.Code, route: r})
			}
			if d.HTTPSEnabled && d.HTTPSPort != nil {
				addr := fmt.Sprintf(":%d", *d.HTTPSPort)
				route = mapT{
					"match":  []interface{}{mapT{"host": hosts}},
					"handle": buildHandles(in, app, d, *d.HTTPSPort),
				}
				httpsServers[addr] = append(httpsServers[addr], pathRouteEntries(in, app, hosts, *d.HTTPSPort)...)
				httpsServers[addr] = append(httpsServers[addr], routeEntry{appCode: app.Code, route: route})
			}
		}
	}

	servers := mapT{}
	routeCount := 0
	serverIdx := 0

	// HTTP servers
	for _, addr := range sortedKeys(httpServers) {
		entries := httpServers[addr]
		// 路由按应用编码排序（确定性）；stable 保持同应用内路径转发先于默认路由
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].appCode < entries[j].appCode })
		var routes []interface{}
		for _, e := range entries {
			routes = append(routes, e.route)
			routeCount++
		}
		servers[fmt.Sprintf("srv%d", serverIdx)] = mapT{
			"listen":          []string{addr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
			"logs":            mapT{"default_logger_name": "access"},
			"errors":          buildErrorRoutes(in),
		}
		serverIdx++
	}
	// HTTPS servers（带证书）
	for _, addr := range sortedKeys(httpsServers) {
		entries := httpsServers[addr]
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].appCode < entries[j].appCode })
		var routes []interface{}
		for _, e := range entries {
			routes = append(routes, e.route)
			routeCount++
		}
		server := mapT{
			"listen":          []string{addr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
			"logs":            mapT{"default_logger_name": "access"},
			"errors":          buildErrorRoutes(in),
		}
		// TLS 连接策略：按域名关联证书
		tlsPolicies := buildTLSPolicies(in)
		if len(tlsPolicies) > 0 {
			server["tls_connection_policies"] = tlsPolicies
		}
		servers[fmt.Sprintf("srv%d", serverIdx)] = server
		serverIdx++
	}
	return servers, routeCount
}

// buildErrorRoutes 构建 server 级错误路由（等价静态 Caddyfile 的 handle_errors 块）。
// Coraza 阻断时返回 caddyhttp.HandlerError，由 errors 路由统一接管：
// 403 返回九章自定义阻断页（带 X-Jiuzhang-Request-ID 响应头，不暴露规则细节），
// 其他错误返回通用状态响应。结构镜像静态 Caddyfile 经 caddy adapt 产出的 JSON 形态。
func buildErrorRoutes(in GenerateInput) mapT {
	// 阻断页文件名与根目录来自 BlockPagePath（Generate 已兜底默认值）
	blockPageURI := "/" + filepath.Base(in.BlockPagePath)
	blockPageRoot := filepath.Dir(in.BlockPagePath)
	return mapT{
		"routes": []interface{}{
			mapT{
				"handle": []interface{}{mapT{
					"handler": "subroute",
					"routes": []interface{}{
						mapT{"handle": []interface{}{mapT{
							"handler": "headers",
							"response": mapT{"set": mapT{
								"Content-Type":          []string{"text/html; charset=utf-8"},
								"X-Jiuzhang-Request-ID": []string{"{http.request.header.X-Request-Id}"},
							}},
						}}},
						mapT{"handle": []interface{}{mapT{
							"handler": "rewrite",
							"uri":     blockPageURI,
						}}},
						mapT{"handle": []interface{}{
							mapT{"handler": "templates"},
							mapT{"handler": "file_server", "root": blockPageRoot},
						}},
					},
				}},
				"match": []interface{}{mapT{
					// CEL 匹配器 UnmarshalJSON 强制要求 expr 与 name 同时存在（缺 name 会 panic）
					"expression": mapT{"expr": "{http.error.status_code} == 403", "name": "blocked"},
				}},
			},
			// 其他错误返回通用状态响应，不暴露内部细节
			mapT{
				"handle": []interface{}{mapT{
					"handler": "subroute",
					"routes": []interface{}{
						mapT{"handle": []interface{}{mapT{
							"handler":     "static_response",
							"body":        "{http.error.status_code} {http.error.status_text}",
							"status_code": "{http.error.status_code}",
						}}},
					},
				}},
			},
		},
	}
}

// certTag 返回证书选择标签：取证书 ID（发布器 buildSnapshot 保证随 HasCert 一并设置）；
// 缺失 ID 的输入退化为证书文件名。load_files 与连接策略经同一函数取标签，保证两侧一致。
func certTag(app AppData) string {
	if app.CertID != "" {
		return app.CertID
	}
	return app.CertFileName
}

// buildCertFilePairs 构建 apps.tls.certificates.load_files 条目（Caddy v2.11.4
// tls.certificates.load_files，modules/caddytls/fileloader.go）：引用发布器写入
// 网关证书目录（CertFileDir 为网关内路径）的证书/私钥文件，每个证书以 certTag 打标；
// 同一证书被多应用绑定只加载一次（按 tag 去重），条目按 tag 排序保证确定性。
func buildCertFilePairs(in GenerateInput) []interface{} {
	seen := map[string]bool{}
	var pairs []interface{}
	for _, app := range in.Apps {
		// 无证书或缺文件名无从引用；MIRROR 应用无内联站点路由，不加载其证书
		if !app.HasCert || app.CertFileName == "" {
			continue
		}
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		tag := certTag(app)
		if seen[tag] {
			continue
		}
		seen[tag] = true
		pairs = append(pairs, mapT{
			"certificate": filepath.Join(in.CertFileDir, app.CertFileName),
			// 私钥文件名与 WriteCertificateFiles 落盘约定一致（<name>.pem 对应 <name>.key）
			"key":  filepath.Join(in.CertFileDir, strings.TrimSuffix(app.CertFileName, ".pem")+".key"),
			"tags": []string{tag},
		})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].(mapT)["tags"].([]string)[0] < pairs[j].(mapT)["tags"].([]string)[0]
	})
	return pairs
}

// buildTLSPolicies 构建 TLS 连接策略（证书文件引用）：按证书 tag 分组，每组一条策略——
// SNI 命中该组域名时由 certificate_selection.any_tag 选中 load_files 以同一 tag 加载的
// 证书，使每个域名关联到本应用的证书。any_tag 在 Caddy v2.11.4 为 []string
// （modules/caddytls/certselection.go），输出字符串会在 /load 直接失败。
func buildTLSPolicies(in GenerateInput) []interface{} {
	groups := map[string][]string{} // cert tag -> sni domains
	for _, app := range in.Apps {
		if !app.HasCert || app.CertFileName == "" {
			continue
		}
		// MIRROR 应用无内联站点路由，不为其域名生成 TLS 连接策略
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		tag := certTag(app)
		for _, d := range app.Domains {
			if d.HTTPSEnabled {
				groups[tag] = append(groups[tag], d.NormalizedHostname)
			}
		}
	}
	if len(groups) == 0 {
		return nil
	}
	tags := make([]string, 0, len(groups))
	for tag := range groups {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var policies []interface{}
	for _, tag := range tags {
		domains := groups[tag]
		sort.Strings(domains)
		policies = append(policies, mapT{
			"match":                 mapT{"sni": domains},
			"certificate_selection": mapT{"any_tag": []string{tag}},
		})
	}
	return policies
}

// buildHandles 构建请求处理链：RequestID → WAF → reverse_proxy → 错误处理。
// publicPort 为路由所在监听的接入端口（302 Location 端口改写目标）。
func buildHandles(in GenerateInput, app AppData, d applications.Domain, publicPort int) []interface{} {
	proxy := applyProxyOptions(buildReverseProxy(app.Upstreams), app.HeaderConfig)
	return buildChainHandles(in, app, proxy, publicPort)
}

// buildWAFDirectives 构建 WAF SecLang 指令（固定加载顺序）。
func buildWAFDirectives(ruleEngine string) string {
	return buildWAFDirectivesWithPolicy(ruleEngine, AppData{}, nil, nil, nil)
}

// exceptionAppliesToApp 判断例外是否应下发到指定应用的 WAF 指令段：
// GLOBAL（及未标注作用域的兼容数据）下发到全部应用；APPLICATION 仅下发到归属应用；
// 其余作用域取值（如 POLICY，当前 API 不可创建）不下发——fail-closed，
// 例外未生效仅意味着保持完整 WAF 防护，不会放大暴露面。
func exceptionAppliesToApp(ex ExceptionRule, app AppData) bool {
	switch ex.ScopeType {
	case "", "GLOBAL":
		return true
	case "APPLICATION":
		return ex.ApplicationID != "" && ex.ApplicationID == app.AppID
	default:
		return false
	}
}

// buildWAFDirectivesWithPolicy 构建带策略参数、例外、规则覆盖与自定义规则的 WAF SecLang 指令。
// 阶段4：策略参数（PL/阈值）注入 crs-setup；例外与规则覆盖放 CRS 之前；
// 自定义规则放 CRS 之后（与静态 jiuzhang-custom 一并加载）。
func buildWAFDirectivesWithPolicy(ruleEngine string, app AppData, exceptions []ExceptionRule, customRules, ruleOverrides []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("SecRuleEngine %s\n", ruleEngine))
	b.WriteString("Include /etc/caddy/rules/coraza.conf\n")
	// 生产审计策略（LOW-G15）：coraza.conf 的 SecAuditEngine On + Parts 含 C 是
	// 阶段1 POC 为 go-ftw 日志标记所设，全量请求体落盘不得进入生产。SecLang 同类
	// 单值指令顺序求值、后写覆盖（coraza v3.7.0 directives.go 直接赋值 WAF 字段），
	// 故在 Include 之后覆盖为 RelevantOnly（仅记录命中/异常事务），Parts 去掉 C
	// （完整请求体）；保留 E（中断响应体）——仅出现于被阻断事务且体量有界，用于取证。
	b.WriteString("SecAuditEngine RelevantOnly\n")
	b.WriteString("SecAuditLogParts ABIJDEFHZ\n")
	// 策略参数（PL 与异常阈值，覆盖 crs-setup.conf 默认值）
	pl := app.ParanoiaLevel
	if pl <= 0 {
		pl = 1
	}
	inbound := app.InboundThreshold
	if inbound <= 0 {
		inbound = 5
	}
	outbound := app.OutboundThreshold
	if outbound <= 0 {
		outbound = 4
	}
	b.WriteString(fmt.Sprintf("SecAction \"id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", pl, inbound, outbound))
	b.WriteString("Include /etc/caddy/rules/crs/crs-setup.conf\n")
	// CRS 插件（官方加载顺序：config → before → CRS 主规则 → contrib → after）
	b.WriteString("Include /etc/caddy/rules/crs/plugins/*/plugins/*-config.conf\n")
	b.WriteString("Include /etc/caddy/rules/crs/plugins/*/plugins/*-before.conf\n")
	b.WriteString("Include /etc/caddy/rules/exclusions/before-crs.conf\n")
	// 例外策略规则（运行时例外，放 CRS 规则之前）；
	// 按作用域过滤下发：GLOBAL 下发到全部应用，APPLICATION 仅下发到归属应用——
	// 否则单应用例外发布的 SecLang 会对所有应用摘除规则（SecLang 条件不编码应用归属）
	for _, ex := range exceptions {
		if !exceptionAppliesToApp(ex, app) {
			continue
		}
		// 稳定反查锚点（P0-04）：映射注释写在效果规则（effect）行之前——
		// ex.RuleID 为 effect 规则 ID；SecLang 自身另带 tag:'exc:'/tag:'excv:' 双锚点。
		if ex.ExceptionID != "" {
			fmt.Fprintf(&b, "# jiuzhang-exc-map: %d %s %d\n", ex.RuleID, ex.ExceptionID, ex.ExceptionVersion)
		}
		b.WriteString(ex.SecLang)
		b.WriteString("\n")
	}
	// 规则覆盖 DISABLE（ctl:ruleRemoveById，优先级已在组装时解析）
	for _, line := range ruleOverrides {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			b.WriteString("\n")
		}
	}
	b.WriteString("Include /etc/caddy/rules/crs/rules/*.conf\n")
	// 第三方与自建规则包（阶段：规则量扩展，放 CRS 主规则之后）
	b.WriteString("Include /etc/caddy/rules/contrib/*/*.conf\n")
	b.WriteString("Include /etc/caddy/rules/crs/plugins/*/plugins/*-after.conf\n")
	b.WriteString("Include /etc/caddy/rules/exclusions/after-crs.conf\n")
	b.WriteString("Include /etc/caddy/rules/jiuzhang/jiuzhang-custom.conf\n")
	// 管理面启用的自定义规则（确定性：按调用方已排序的切片顺序写出）
	for _, line := range customRules {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			b.WriteString("\n")
		}
	}
	// 二次阻断评估：必须始终是最后一条 Include（晚于一切计分规则）。
	// CRS 949 阻断评估在 crs/rules/ 内部完成，晚于它执行的 contrib/插件/自定义
	// 计分规则需由该文件重新汇总分数并阻断。
	b.WriteString("Include /etc/caddy/rules/jiuzhang/post-contrib-blocking.conf\n")
	return b.String()
}

// buildReverseProxy 构建反向代理（源站、负载均衡、健康检查）。
func buildReverseProxy(upstreams []applications.Upstream) mapT {
	// 仅活动源站
	var active []applications.Upstream
	for _, u := range upstreams {
		if u.Status == "ACTIVE" {
			active = append(active, u)
		}
	}
	// 确定性排序（按 host:port）
	sort.Slice(active, func(i, j int) bool {
		ai := fmt.Sprintf("%s:%d", active[i].NormalizedHost, active[i].Port)
		aj := fmt.Sprintf("%s:%d", active[j].NormalizedHost, active[j].Port)
		return ai < aj
	})

	var ups []interface{}
	var weights []int
	for _, u := range active {
		dial := fmt.Sprintf("%s:%d", u.NormalizedHost, u.Port)
		ups = append(ups, mapT{"dial": dial})
		// Caddy upstream 不支持 weight 字段；权重通过 selection_policy.weights 数组表达
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		weights = append(weights, w)
	}

	proxy := mapT{
		"handler":   "reverse_proxy",
		"upstreams": ups,
	}

	// 负载均衡（多源站加权轮询）：weights 数组与 upstreams 顺序一一对应
	if len(active) > 1 {
		lb := mapT{
			"selection_policy": mapT{
				"policy":  "weighted_round_robin",
				"weights": weights,
			},
		}
		if active[0].MaxRetries > 0 {
			lb["retries"] = active[0].MaxRetries
		}
		proxy["load_balancing"] = lb
	}

	// 健康检查（第一个启用健康检查的源站配置）
	for _, u := range active {
		if u.HealthCheckEnabled {
			proxy["health_checks"] = mapT{
				"active": mapT{
					"path":     u.HealthCheckPath,
					"interval": fmt.Sprintf("%ds", u.HealthCheckIntervalSeconds),
					"timeout":  fmt.Sprintf("%ds", u.HealthCheckTimeoutSeconds),
				},
				"passive": mapT{
					"fail_duration": "30s",
					"max_fails":     3,
				},
			}
			break
		}
	}

	// 传输层与超时配置（取首个活动源站；Caddy 要求同一 reverse_proxy 的全部源站
	// 使用同一 scheme/transport，与超时取值口径一致——同应用多源站须同 scheme）
	if len(active) > 0 {
		u := active[0]
		transport := mapT{
			"protocol":                "http",
			"dial_timeout":            fmt.Sprintf("%dms", u.ConnectTimeoutMs),
			"response_header_timeout": fmt.Sprintf("%dms", u.ResponseHeaderTimeoutMs),
		}
		// h2c 明文回源（NG-GRPC G1：gRPC 源站只讲 HTTP/2 prior knowledge——
		// Caddy http transport 默认 versions 不含 h2c，须显式声明（协商失败即 502）；
		// scheme=h2c 仅声明协议族，tls 段不挂（明文语义与 https 互斥）
		if u.Scheme == "h2c" {
			transport["versions"] = []string{"h2c"}
		}
		// HTTPS 回源：http transport 携带 tls 段（Caddy v2.11.4 reverseproxy
		// httptransport.go：TLSConfig 非空即对回源连接启用 TLS）。
		// server_name 取 TLSServerName，缺省回退源站主机名（TLS SNI 与证书校验证名）；
		// insecure_skip_verify 取反于 TLSVerify（默认校验源站证书，显式关闭才跳过）。
		if u.Scheme == "https" {
			tls := mapT{}
			serverName := u.TLSServerName
			if serverName == "" {
				serverName = u.NormalizedHost
			}
			if serverName != "" {
				tls["server_name"] = serverName
			}
			if !u.TLSVerify {
				tls["insecure_skip_verify"] = true
			}
			transport["tls"] = tls
		}
		proxy["transport"] = transport
	}

	return proxy
}
