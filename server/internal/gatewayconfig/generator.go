// Package gatewayconfig 提供网关配置生成器：将数据库业务数据转换为确定性 Caddy JSON 配置。
package gatewayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
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
	// CustomRules 启用的自定义规则 SecLang（位于例外与规则覆盖之后、CRS 主规则之前加载）。
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
	// TransparentHTTPListen 透明串接模式专用 HTTP 回环监听地址（与 tproxyd.json target 同步，
	// 缺省 127.0.0.1:15080；避免与业务/控制台 8080 端口冲突）。
	TransparentHTTPListen string
	// TransparentHTTPSListen 透明串接模式专用 HTTPS 回环监听地址（与 tproxyd.json target_tls 同步，
	// 缺省 127.0.0.1:15443；避免与控制台 8443 端口冲突）。
	TransparentHTTPSListen string
	// ACMEHTTP01 自动 SSL HTTP-01 挑战应答配置（nil 或 Enabled=false 时零变化）。
	ACMEHTTP01 *ACMEHTTP01Config
	// TLSSessionLogPath jiuzhang_tls_mux 加密会话分析 JSONL 日志路径（空串取 DefaultTLSSessionLogPath）。
	TLSSessionLogPath string
}

// DefaultTLSSessionLogPath 是 jiuzhang_tls_mux 加密会话握手事件的默认 JSONL 落盘路径
// （与网关 tlsmux.DefaultSessionLogPath 一致）。
const DefaultTLSSessionLogPath = "/var/log/caddy/tls-handshake-events.jsonl"

// ACMEHTTP01Config 是网关 ACME HTTP-01 挑战应答配置（jiuzhang_acme_http01）。
type ACMEHTTP01Config struct {
	Enabled      bool         `json:"enabled"`
	ChallengeDir string       `json:"challenge_dir,omitempty"`
	Valkey       *GuardValkey `json:"valkey,omitempty"`
}

// DomainPolicy 是单个域名覆盖的 WAF 防护策略参数（未设置则继承所属应用策略）。
type DomainPolicy struct {
	PolicyID            string
	ProtectionMode      string
	ParanoiaLevel       int
	InboundThreshold    int
	OutboundThreshold   int
	HasRuleOverrides    bool
	RuleOverrideSecLang []string
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
	// 证书（HTTPS 应用）：PEM 与私钥 PEM（发布时解密提供，仅内存流转，不入审计日志）。
	CertID       string
	CertFileName string // 写入网关证书目录的文件名（不含目录，向后兼容 load_files 回退）
	CertPEM      string // 证书 PEM（与 KeyPEM 同时非空时优先产出 Caddy 原生 load_pem）
	ChainPEM     string // 证书链 PEM（可选，合并至 certificate 尾部）
	KeyPEM       string // 私钥 PEM（仅内存流转，版本表与预览强制脱敏）
	HasCert      bool
	// 国密 TLCP 1.1 双证书（SM2 签名证书 + SM2 加密证书；仅内存流转，版本表与预览强制脱敏）。
	HasGMCert     bool
	GMCertID      string
	GMSignCertPEM string
	GMSignKeyPEM  string
	GMEncCertPEM  string
	GMEncKeyPEM   string
	GMChainPEM    string
	// TLSConfig 应用级国密/国际协议自识别、TLS/HTTP 协议降级与加密会话分析策略（nil 表示默认兼容路径）。
	TLSConfig *AppTLSConfig
	// PendingAutoSSL 标记开启自动 SSL 且尚未签发首次证书的应用：
	// 允许先发布 :80 HTTP 与 ACME 挑战路由，暂缓生成 :443 HTTPS 与 308 跳转，待证书签发后再自动发布上线。
	PendingAutoSSL bool
	// 阶段4策略参数（可选，为零值时使用默认）
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
	// RuleOverrideSecLang 本应用生效的规则覆盖 SecLang（DISABLE → ctl:ruleRemoveById，置于 CRS 前）
	RuleOverrideSecLang []string
	// DomainPolicies 按域名 ID（空 ID 回退规范化域名）索引的域名级防护策略覆盖。
	DomainPolicies map[string]DomainPolicy
	// HeaderConfig 头合规与代理配置（nil 时使用默认静态头行为）
	HeaderConfig *AppHeaderConfig
	// PathRoutes 路径粒度转发（ENABLED 且校验通过的条目）
	PathRoutes []AppPathRoute
}

// effectiveAppForDomain 计算单个域名的生效策略视图：
//   - 若应用处于 BYPASS（手工透传或授权失效强制透传），必须绝对保持 BYPASS，不得被域名级策略覆盖；
//   - 若域名绑定了独立防护策略，则覆盖防护模式、PL、异常阈值及对应策略解析的规则覆盖；
//   - 否则原样继承所属应用策略。
func effectiveAppForDomain(app AppData, d applications.Domain) AppData {
	if len(app.DomainPolicies) == 0 {
		return app
	}
	var dp DomainPolicy
	var ok bool
	if d.ID != uuid.Nil {
		dp, ok = app.DomainPolicies[d.ID.String()]
	}
	if !ok && d.NormalizedHostname != "" {
		dp, ok = app.DomainPolicies[d.NormalizedHostname]
	}
	if !ok && d.Hostname != "" {
		dp, ok = app.DomainPolicies[d.Hostname]
	}
	if !ok {
		return app
	}
	eff := app
	if eff.ProtectionMode != applications.ModeBypass && dp.ProtectionMode != "" {
		eff.ProtectionMode = dp.ProtectionMode
	}
	if dp.ParanoiaLevel > 0 {
		eff.ParanoiaLevel = dp.ParanoiaLevel
	}
	if dp.InboundThreshold > 0 {
		eff.InboundThreshold = dp.InboundThreshold
	}
	if dp.OutboundThreshold > 0 {
		eff.OutboundThreshold = dp.OutboundThreshold
	}
	if dp.HasRuleOverrides {
		eff.RuleOverrideSecLang = dp.RuleOverrideSecLang
	}
	return eff
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
	if err := validatePublishSmokeRouteConflicts(in.Apps, in.Guard); err != nil {
		return nil, err
	}

	servers, routeCount, legacyHTTPSApps := buildServers(in)
	if in.Guard != nil && in.Guard.SoftwareBypass != nil {
		injectConnectionMetrics(servers)
	}
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

	// apps.tls 段（内联 PEM 证书 / 兼容证书文件加载 + TLS 会话票据密钥），任一存在才产出：
	//   - certificates.load_pem：优先路径，使用 Caddy 原生 PEMLoader 在内存中直接加载证书链与私钥
	//     （跨节点扇出无需共享本地证书目录，版本存储由 RedactConfigSecrets 强制脱敏 key 为 "***"）；
	//   - certificates.load_files：向后兼容路径，仅当应用仅提供 CertFileName 而无内联 PEM 时产出；
	//   - 若应用的全部 HTTPS 监听已由 jiuzhang_tls_mux 接管，则证书直接内嵌于 mux.sites[*]，不重复写入 load_pem/load_files；
	//   - session_tickets（HA §7.2）：配置了下发 tls.stek.jiuzhang 静态键（支持 1~2 键平滑轮换，
	//     主备多节点共用 → 会话恢复跨节点可用）；
	// 均未配置保持缺省（无 apps.tls 段，Go 标准库进程内随机票据键，跨节点恢复回退完整握手）。
	tlsApp := mapT{}
	certsCfg := mapT{}
	if pemPairs := buildCertPEMPairs(in, legacyHTTPSApps); len(pemPairs) > 0 {
		certsCfg["load_pem"] = pemPairs
	}
	if filePairs := buildCertFilePairs(in, legacyHTTPSApps); len(filePairs) > 0 {
		certsCfg["load_files"] = filePairs
	}
	if len(certsCfg) > 0 {
		tlsApp["certificates"] = certsCfg
	}
	if ticketKeys := in.Guard.EffectiveTLSSessionTicketKeys(); len(ticketKeys) > 0 {
		tlsApp["session_tickets"] = mapT{
			"key_source": mapT{
				"provider": "jiuzhang",
				"keys_hex": ticketKeys,
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

func injectConnectionMetrics(servers map[string]interface{}) {
	for _, raw := range servers {
		server, ok := raw.(mapT)
		if !ok {
			continue
		}
		existing, _ := server["listener_wrappers"].([]interface{})
		hasMetrics := false
		for _, w := range existing {
			if wm, ok := w.(mapT); ok && wm["wrapper"] == "jiuzhang_connection_metrics" {
				hasMetrics = true
				break
			}
		}
		if hasMetrics {
			continue
		}
		merged := make([]interface{}, 0, len(existing)+1)
		merged = append(merged, mapT{"wrapper": "jiuzhang_connection_metrics"})
		merged = append(merged, existing...)
		server["listener_wrappers"] = merged
	}
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

// httpsServerApp 记录某个 HTTPS 监听服务器上的单个应用及其归属 HTTPS 域名集合。
type httpsServerApp struct {
	appIdx  int
	app     AppData
	domains []string
}

// buildServers 按监听端口分组构建 servers，并返回至少在一个非 mux 传统 HTTPS 监听上提供服务的应用索引集合。
// TRANSPARENT（透明串接）应用分流到专用内部回环 server（srv_transparent_http /
// srv_transparent_https，挂 proxy_protocol / tls 或 jiuzhang_tls_mux listener_wrappers），与公网反代/路由
// 站点（srv0/srv1...）完全隔离，避免端口冲突且确保 tproxyd PROXY v1 正常解包。
func buildServers(in GenerateInput) (map[string]interface{}, int, map[int]bool) {
	httpServers := map[string][]routeEntry{}  // listen addr -> routes (REVERSE_PROXY/ROUTED)
	httpsServers := map[string][]routeEntry{} // listen addr -> routes (REVERSE_PROXY/ROUTED)
	httpsServerApps := map[string]map[int]*httpsServerApp{}
	var transparentHTTPRoutes []routeEntry
	var transparentHTTPSRoutes []routeEntry
	transparentHTTPSApps := map[int]*httpsServerApp{}

	recordHTTPSApp := func(bucket map[int]*httpsServerApp, appIdx int, app AppData, host string) {
		entry, ok := bucket[appIdx]
		if !ok {
			entry = &httpsServerApp{appIdx: appIdx, app: app}
			bucket[appIdx] = entry
		}
		entry.domains = append(entry.domains, host)
	}

	for appIdx, app := range in.Apps {
		// MIRROR（镜像旁路）应用不生成内联站点路由：其流量经镜像口到达 mirrorcap 采集器，
		// 不在反代链上（docs/NETWORK_MODES_DESIGN.md §4.2）；边车配置由发布通道另行写出。
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		isTransparent := app.DeploymentMode == applications.DeployModeTransparent
		for _, d := range app.Domains {
			effApp := effectiveAppForDomain(app, d)
			hosts := []string{d.NormalizedHostname}
			// 泛域名 Caddy 用 *.example.com 形式（Caddy 支持通配符 host matcher）
			if d.HTTPEnabled && d.HTTPPort != nil {
				var entries []routeEntry
				// HTTP 跳 HTTPS：仅返回 308 重定向，绝不下发路径转发路由绕过 HTTPS 强制跳转；
				// 处于 PendingAutoSSL 首次等待签发期时暂缓 308 跳转，避免把流量导向尚未就绪的 HTTPS 端口。
				if d.RedirectHTTPToHTTPS && d.HTTPSEnabled && !app.PendingAutoSSL {
					location := "https://{http.request.host}{http.request.uri}"
					if d.HTTPSPort != nil && *d.HTTPSPort != 443 {
						location = fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", *d.HTTPSPort)
					}
					r := mapT{
						"match": []interface{}{mapT{"host": hosts}},
						"handle": []interface{}{
							mapT{"handler": "static_response", "status_code": 308,
								"headers": mapT{"Location": []string{location}}},
						},
					}
					entries = append(entries, routeEntry{appCode: app.Code, route: r})
				} else {
					r := mapT{
						"match":  []interface{}{mapT{"host": hosts}},
						"handle": buildHandles(in, effApp, d, *d.HTTPPort),
					}
					entries = append(entries, pathRouteEntries(in, effApp, hosts, *d.HTTPPort)...)
					entries = append(entries, routeEntry{appCode: app.Code, route: r})
				}
				if isTransparent {
					transparentHTTPRoutes = append(transparentHTTPRoutes, entries...)
				} else {
					addr := fmt.Sprintf(":%d", *d.HTTPPort)
					httpServers[addr] = append(httpServers[addr], entries...)
				}
			}
			if d.HTTPSEnabled && d.HTTPSPort != nil && !app.PendingAutoSSL {
				route := mapT{
					"match":  []interface{}{mapT{"host": hosts}},
					"handle": buildHandles(in, effApp, d, *d.HTTPSPort),
				}
				entries := append(pathRouteEntries(in, effApp, hosts, *d.HTTPSPort), routeEntry{appCode: app.Code, route: route})
				if isTransparent {
					transparentHTTPSRoutes = append(transparentHTTPSRoutes, entries...)
					recordHTTPSApp(transparentHTTPSApps, appIdx, app, d.NormalizedHostname)
				} else {
					addr := fmt.Sprintf(":%d", *d.HTTPSPort)
					httpsServers[addr] = append(httpsServers[addr], entries...)
					if httpsServerApps[addr] == nil {
						httpsServerApps[addr] = map[int]*httpsServerApp{}
					}
					recordHTTPSApp(httpsServerApps[addr], appIdx, app, d.NormalizedHostname)
				}
			}
		}
	}

	servers := mapT{}
	routeCount := 0
	serverIdx := 0
	legacyHTTPSApps := map[int]bool{}

	acmeEnabled := in.ACMEHTTP01 != nil && in.ACMEHTTP01.Enabled
	hasPublicPort80 := false

	// HTTP servers（REVERSE_PROXY / ROUTED）
	for _, addr := range sortedKeys(httpServers) {
		entries := httpServers[addr]
		// 路由按应用编码排序（确定性）；stable 保持同应用内路径转发先于默认路由
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].appCode < entries[j].appCode })
		var routes []interface{}
		if acmeEnabled && addr == ":80" {
			hasPublicPort80 = true
			routes = append(routes, buildACMEHTTP01Route(in))
			routeCount++
		}
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
	// 开启 ACME HTTP-01 但尚无公网 :80 站点时，合成专用 :80 挑战应答 server（保证纯 HTTPS 站点或首个自动 SSL 站点完成 HTTP-01）
	if acmeEnabled && !hasPublicPort80 {
		servers["srv_acme_http01"] = mapT{
			"listen": []string{":80"},
			"routes": []interface{}{
				buildACMEHTTP01Route(in),
				mapT{
					"handle": []interface{}{
						mapT{"handler": "static_response", "status_code": 404, "body": "404 Not Found"},
					},
				},
			},
			"automatic_https": mapT{"disable": true},
			"logs":            mapT{"default_logger_name": "access"},
			"errors":          buildErrorRoutes(in),
		}
		routeCount++
	}
	// HTTPS servers（REVERSE_PROXY / ROUTED，带证书或 jiuzhang_tls_mux）
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
		srvApps := sortedHTTPSServerApps(httpsServerApps[addr])
		if serverNeedsTLSMux(srvApps) {
			muxWrapper, protocols := buildTLSMuxWrapper(in, srvApps)
			server["listener_wrappers"] = []interface{}{muxWrapper}
			server["protocols"] = protocols
		} else {
			for _, sa := range srvApps {
				legacyHTTPSApps[sa.appIdx] = true
			}
			// TLS 连接策略：按域名关联证书（兼容传统国际 TLS 路径）
			if tlsPolicies := buildTLSPoliciesForApps(srvApps); len(tlsPolicies) > 0 {
				server["tls_connection_policies"] = tlsPolicies
			}
		}
		servers[fmt.Sprintf("srv%d", serverIdx)] = server
		serverIdx++
	}

	// 透明串接专用回环 HTTP server（仅接收本机 tproxyd PROXY v1 转发）
	if len(transparentHTTPRoutes) > 0 {
		sort.SliceStable(transparentHTTPRoutes, func(i, j int) bool {
			return transparentHTTPRoutes[i].appCode < transparentHTTPRoutes[j].appCode
		})
		routes := make([]interface{}, 0, len(transparentHTTPRoutes)+1)
		if acmeEnabled {
			routes = append(routes, buildACMEHTTP01Route(in))
			routeCount++
		}
		for _, e := range transparentHTTPRoutes {
			routes = append(routes, e.route)
			routeCount++
		}
		listenAddr := strings.TrimSpace(in.TransparentHTTPListen)
		if listenAddr == "" {
			listenAddr = DefaultTproxydTarget
		}
		servers["srv_transparent_http"] = mapT{
			"listen":          []string{listenAddr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
			"logs":            mapT{"default_logger_name": "access"},
			"errors":          buildErrorRoutes(in),
			"listener_wrappers": []interface{}{
				mapT{"wrapper": "proxy_protocol", "allow": []string{"127.0.0.1/32"}},
			},
		}
	}

	// 透明串接专用回环 HTTPS server（proxy_protocol 必须位于 tls / jiuzhang_tls_mux 之前以先剥离 PROXY v1 头）
	if len(transparentHTTPSRoutes) > 0 {
		sort.SliceStable(transparentHTTPSRoutes, func(i, j int) bool {
			return transparentHTTPSRoutes[i].appCode < transparentHTTPSRoutes[j].appCode
		})
		routes := make([]interface{}, 0, len(transparentHTTPSRoutes))
		for _, e := range transparentHTTPSRoutes {
			routes = append(routes, e.route)
			routeCount++
		}
		listenAddr := strings.TrimSpace(in.TransparentHTTPSListen)
		if listenAddr == "" {
			listenAddr = DefaultTproxydTargetTLS
		}
		server := mapT{
			"listen":          []string{listenAddr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
			"logs":            mapT{"default_logger_name": "access"},
			"errors":          buildErrorRoutes(in),
		}
		tApps := sortedHTTPSServerApps(transparentHTTPSApps)
		if serverNeedsTLSMux(tApps) {
			muxWrapper, protocols := buildTLSMuxWrapper(in, tApps)
			server["listener_wrappers"] = []interface{}{
				mapT{"wrapper": "proxy_protocol", "allow": []string{"127.0.0.1/32"}},
				muxWrapper,
			}
			server["protocols"] = protocols
		} else {
			for _, sa := range tApps {
				legacyHTTPSApps[sa.appIdx] = true
			}
			server["listener_wrappers"] = []interface{}{
				mapT{"wrapper": "proxy_protocol", "allow": []string{"127.0.0.1/32"}},
				mapT{"wrapper": "tls"},
			}
			if tlsPolicies := buildTLSPoliciesForApps(tApps); len(tlsPolicies) > 0 {
				server["tls_connection_policies"] = tlsPolicies
			}
		}
		servers["srv_transparent_https"] = server
	}
	return servers, routeCount, legacyHTTPSApps
}

// buildACMEHTTP01Route 构建 ACME HTTP-01 挑战应答路由（位于 :80 路由表最前，优先于 308 跳转、Guard 与 WAF）。
// 未命中已注册挑战令牌时由 jiuzhang_acme_http01 原样透传后续路由。
func buildACMEHTTP01Route(in GenerateInput) mapT {
	challengeDir := ""
	if in.ACMEHTTP01 != nil {
		challengeDir = strings.TrimSpace(in.ACMEHTTP01.ChallengeDir)
	}
	if challengeDir == "" {
		challengeDir = filepath.Join(in.CertFileDir, ".acme-challenges")
	}
	handler := mapT{
		"handler":       "jiuzhang_acme_http01",
		"challenge_dir": challengeDir,
	}
	if in.ACMEHTTP01 != nil && in.ACMEHTTP01.Valkey != nil && strings.TrimSpace(in.ACMEHTTP01.Valkey.Address) != "" {
		handler["valkey"] = in.ACMEHTTP01.Valkey
	}
	return mapT{
		"match": []interface{}{
			mapT{"path": []string{"/.well-known/acme-challenge/*"}},
		},
		"handle": []interface{}{handler},
	}
}

// buildErrorRoutes 构建 server 级错误路由（等价静态 Caddyfile 的 handle_errors 块）。
// Coraza 阻断时返回 caddyhttp.HandlerError，由 errors 路由统一接管：
// 403 返回九章自定义阻断页（带 X-Jiuzhang-Request-ID 响应头，不暴露规则细节），
// 其他错误返回通用状态响应。结构镜像静态 Caddyfile 经 caddy adapt 产出的 JSON 形态。
func buildErrorRoutes(in GenerateInput) mapT {
	// 阻断页文件名与根目录来自 BlockPagePath（Generate 已兜底默认值）
	blockPageURI := "/" + filepath.Base(in.BlockPagePath)
	blockPageRoot := filepath.Dir(in.BlockPagePath)
	routes := make([]interface{}, 0, 3)
	// 自定义多版本拦截页面（迁移 000251）：仅在存在生效绑定时置于错误路由链首；
	// 命中 (app_code, scene) 映射时直接渲染净化后的自定义页面并终止，未命中则透传回退至
	// 下方既有静态 /blockpage.html（403）或通用状态响应，零配置时生成结果与历史版本逐字节一致。
	if in.Guard != nil && in.Guard.BlockPages != nil && !in.Guard.BlockPages.IsEmpty() {
		bpHandler := mapT{
			"handler": "jiuzhang_block_page",
		}
		if len(in.Guard.BlockPages.Global) > 0 {
			bpHandler["global"] = in.Guard.BlockPages.Global
		}
		if len(in.Guard.BlockPages.Apps) > 0 {
			bpHandler["apps"] = in.Guard.BlockPages.Apps
		}
		if hostMap := buildHostToAppCode(in.Apps); len(hostMap) > 0 {
			bpHandler["host_to_app_code"] = hostMap
		}
		routes = append(routes, mapT{
			"handle": []interface{}{bpHandler},
		})
	}
	routes = append(routes,
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
	)
	return mapT{
		"routes": routes,
	}
}

// certTag 返回证书选择标签：取证书 ID（发布器 buildSnapshot 保证随 HasCert 一并设置）；
// 缺失 ID 的输入依次退化为证书文件名/应用标识。load_pem/load_files 与连接策略经同一函数取标签，保证两侧一致。
func certTag(app AppData) string {
	if app.CertID != "" {
		return app.CertID
	}
	if app.CertFileName != "" {
		return app.CertFileName
	}
	if app.AppID != "" {
		return app.AppID
	}
	return app.Code
}

func hasCertPEM(app AppData) bool {
	return app.HasCert && strings.TrimSpace(app.CertPEM) != "" && strings.TrimSpace(app.KeyPEM) != ""
}

func hasCertFile(app AppData) bool {
	return app.HasCert && app.CertFileName != ""
}

func hasGMCertPEM(app AppData) bool {
	return app.HasGMCert &&
		strings.TrimSpace(app.GMSignCertPEM) != "" &&
		strings.TrimSpace(app.GMSignKeyPEM) != "" &&
		strings.TrimSpace(app.GMEncCertPEM) != "" &&
		strings.TrimSpace(app.GMEncKeyPEM) != ""
}

func gmCertTag(app AppData) string {
	if app.GMCertID != "" {
		return app.GMCertID
	}
	if app.AppID != "" {
		return app.AppID
	}
	return app.Code
}

func sliceContainsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), target) {
			return true
		}
	}
	return false
}

// restrictedAllowedHTTPVersions 返回站点显式裁剪后的允许 HTTP 版本列表；
// 未配置或全量开放（HTTP/1.0 + HTTP/1.1 + HTTP/2）时返回 nil（零开销、与存量逐字节一致）。
func restrictedAllowedHTTPVersions(cfg *AppTLSConfig) []string {
	if cfg == nil || len(cfg.HTTPVersions) == 0 {
		return nil
	}
	var (
		has10, has11, has2 bool
		seen               = make(map[string]bool, len(cfg.HTTPVersions))
		out                = make([]string, 0, len(cfg.HTTPVersions))
	)
	for _, raw := range cfg.HTTPVersions {
		v := strings.ToUpper(strings.TrimSpace(raw))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		switch v {
		case HTTPVersion10:
			has10 = true
		case HTTPVersion11:
			has11 = true
		case HTTPVersion2, "H2", "HTTP/2.0":
			has2 = true
		}
	}
	if len(out) == 0 || (has10 && has11 && has2) {
		return nil
	}
	return out
}

func siteAllowsHTTP2(cfg *AppTLSConfig) bool {
	if cfg == nil || len(cfg.HTTPVersions) == 0 {
		return true
	}
	for _, raw := range cfg.HTTPVersions {
		switch strings.ToUpper(strings.TrimSpace(raw)) {
		case HTTPVersion2, "H2", "HTTP/2.0":
			return true
		}
	}
	return false
}

func tlsVersionsRequireMux(versions []string) bool {
	if len(versions) == 0 {
		return false
	}
	has12, has13 := false, false
	for _, raw := range versions {
		switch strings.ToUpper(strings.TrimSpace(raw)) {
		case TLSVersion12:
			has12 = true
		case TLSVersion13:
			has13 = true
		case "":
		default:
			// 包含 TLS1.0 / TLS1.1 / TLCP1.1 等均须走 jiuzhang_tls_mux
			return true
		}
	}
	return !(has12 && has13)
}

// appNeedsTLSMux 判定单个 HTTPS 应用是否需要启用 caddy.listeners.jiuzhang_tls_mux 监听包装器：
// 国密双证书、自定义 TLS 协议模式/版本降级（TLS1.0/1.1/TLCP1.1/单版本约束）、HTTP/2 降级、
// 弱协议识别分析或加密会话分析开启均由 jiuzhang_tls_mux 接管。
func appNeedsTLSMux(app AppData) bool {
	if app.HasGMCert {
		return true
	}
	if app.TLSConfig == nil {
		return false
	}
	cfg := app.TLSConfig
	if cfg.SessionAnalysisEnabled {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(cfg.TLSProtocolMode), TLSProtocolModeGMOnly) {
		return true
	}
	if len(cfg.LegacySSLAnalysisVersions) > 0 {
		return true
	}
	if tlsVersionsRequireMux(cfg.AllowedTLSVersions) {
		return true
	}
	if !siteAllowsHTTP2(cfg) {
		return true
	}
	return false
}

func appHasActiveHTTPS(app AppData) bool {
	if app.DeploymentMode == applications.DeployModeMirror || app.PendingAutoSSL {
		return false
	}
	for _, d := range app.Domains {
		if d.HTTPSEnabled && d.HTTPSPort != nil {
			return true
		}
	}
	return false
}

func serverNeedsTLSMux(srvApps []*httpsServerApp) bool {
	for _, sa := range srvApps {
		if appNeedsTLSMux(sa.app) {
			return true
		}
	}
	return false
}

func sortedHTTPSServerApps(bucket map[int]*httpsServerApp) []*httpsServerApp {
	out := make([]*httpsServerApp, 0, len(bucket))
	for _, sa := range bucket {
		seen := make(map[string]bool, len(sa.domains))
		uniq := make([]string, 0, len(sa.domains))
		for _, dom := range sa.domains {
			d := strings.TrimSpace(dom)
			if d != "" && !seen[d] {
				seen[d] = true
				uniq = append(uniq, d)
			}
		}
		sort.Strings(uniq)
		sa.domains = uniq
		out = append(out, sa)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].app.Code != out[j].app.Code {
			return out[i].app.Code < out[j].app.Code
		}
		if out[i].app.AppID != out[j].app.AppID {
			return out[i].app.AppID < out[j].app.AppID
		}
		return out[i].appIdx < out[j].appIdx
	})
	return out
}

// buildTLSMuxWrapper 构建 caddy.listeners.jiuzhang_tls_mux 监听包装器与 server["protocols"]：
// 至少一个站点允许 HTTP/2 时 protocols=["h1","h2"]，否则 ["h1"]（保证 HTTP/2 降级与 HTTP/1.0/1.1 兼容）。
func buildTLSMuxWrapper(in GenerateInput, srvApps []*httpsServerApp) (mapT, []string) {
	sites := make([]interface{}, 0, len(srvApps))
	anyAllowsH2 := false
	anySessionAnalysis := false

	for _, sa := range srvApps {
		app := sa.app
		site := mapT{
			"domains": sa.domains,
		}
		if app.AppID != "" {
			site["app_id"] = app.AppID
		}
		if app.TLSConfig != nil {
			cfg := app.TLSConfig
			mode := strings.ToUpper(strings.TrimSpace(cfg.TLSProtocolMode))
			if mode == "" {
				mode = TLSProtocolModeAutoDetect
			}
			site["tls_protocol_mode"] = mode
			if len(cfg.AllowedTLSVersions) > 0 {
				site["allowed_tls_versions"] = append([]string(nil), cfg.AllowedTLSVersions...)
			}
			legacy := make([]string, len(cfg.LegacySSLAnalysisVersions))
			copy(legacy, cfg.LegacySSLAnalysisVersions)
			site["legacy_ssl_analysis_versions"] = legacy
			if len(cfg.HTTPVersions) > 0 {
				site["http_versions"] = append([]string(nil), cfg.HTTPVersions...)
			}
			site["session_analysis_enabled"] = cfg.SessionAnalysisEnabled
			if cfg.SessionAnalysisEnabled {
				anySessionAnalysis = true
			}
		} else {
			hasIntl := hasCertPEM(app)
			hasGM := hasGMCertPEM(app)
			mode := TLSProtocolModeAutoDetect
			var allowed []string
			switch {
			case hasGM && hasIntl:
				allowed = []string{TLSVersion12, TLSVersion13, TLSVersionTLCP11}
			case hasGM && !hasIntl:
				mode = TLSProtocolModeGMOnly
				allowed = []string{TLSVersionTLCP11}
			default:
				allowed = []string{TLSVersion12, TLSVersion13}
			}
			site["tls_protocol_mode"] = mode
			site["allowed_tls_versions"] = allowed
			site["legacy_ssl_analysis_versions"] = []string{LegacySSLv2, LegacySSLv2v3, LegacySSLv3}
			site["http_versions"] = []string{HTTPVersion10, HTTPVersion11, HTTPVersion2}
			site["session_analysis_enabled"] = true
			anySessionAnalysis = true
		}
		if siteAllowsHTTP2(app.TLSConfig) {
			anyAllowsH2 = true
		}
		if hasCertPEM(app) {
			if cid := certTag(app); cid != "" {
				site["cert_id"] = cid
			}
			site["cert_pem"] = mergeCertChainPEM(app.CertPEM, app.ChainPEM)
			site["key_pem"] = app.KeyPEM
		}
		if hasGMCertPEM(app) {
			if gcid := gmCertTag(app); gcid != "" {
				site["gm_cert_id"] = gcid
			}
			site["gm_sign_cert_pem"] = mergeCertChainPEM(app.GMSignCertPEM, app.GMChainPEM)
			site["gm_sign_key_pem"] = app.GMSignKeyPEM
			site["gm_enc_cert_pem"] = mergeCertChainPEM(app.GMEncCertPEM, app.GMChainPEM)
			site["gm_enc_key_pem"] = app.GMEncKeyPEM
		}
		sites = append(sites, site)
	}

	wrapper := mapT{
		"wrapper": "jiuzhang_tls_mux",
		"sites":   sites,
	}
	if in.Guard != nil && strings.TrimSpace(in.Guard.GatewayNode) != "" {
		wrapper["gateway_node"] = strings.TrimSpace(in.Guard.GatewayNode)
	}
	if anySessionAnalysis {
		logPath := strings.TrimSpace(in.TLSSessionLogPath)
		if logPath == "" {
			logPath = DefaultTLSSessionLogPath
		}
		wrapper["session_log_path"] = logPath
	}
	if ticketKeys := in.Guard.EffectiveTLSSessionTicketKeys(); len(ticketKeys) > 0 {
		wrapper["session_ticket_keys_hex"] = ticketKeys
	}
	protocols := []string{"h1"}
	if anyAllowsH2 {
		protocols = append(protocols, "h2")
	}
	return wrapper, protocols
}

// upstreamUsesJiuzhangTLSTransport 判定源站是否需要走 http.reverse_proxy.transport.jiuzhang_tls。
func upstreamUsesJiuzhangTLSTransport(u applications.Upstream, tlsCfg *AppTLSConfig) bool {
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "tlcp" {
		return true
	}
	if tlsCfg == nil {
		return false
	}
	minVer := strings.ToUpper(strings.TrimSpace(tlsCfg.UpstreamTLSMinVersion))
	httpVer := strings.ToUpper(strings.TrimSpace(tlsCfg.UpstreamHTTPVersion))
	if scheme == "https" && (minVer == TLSVersion10 || minVer == TLSVersion11 || httpVer == HTTPVersion10 || httpVer == HTTPVersion11) {
		return true
	}
	if scheme == "http" && httpVer == HTTPVersion10 {
		return true
	}
	return false
}

// mergeCertChainPEM 将非空证书链合并到主证书 PEM 尾部（若主证书内尚未包含该链）。
func mergeCertChainPEM(certPEM, chainPEM string) string {
	chainTrim := strings.TrimSpace(chainPEM)
	if chainTrim == "" {
		return certPEM
	}
	certTrim := strings.TrimSpace(certPEM)
	if certTrim == "" {
		return chainPEM
	}
	normCert := strings.ReplaceAll(certTrim, "\r\n", "\n")
	normChain := strings.ReplaceAll(chainTrim, "\r\n", "\n")
	if strings.Contains(normCert, normChain) {
		return certPEM
	}
	return normCert + "\n" + normChain + "\n"
}

// buildCertPEMPairs 构建 apps.tls.certificates.load_pem 条目（Caddy v2.11.4
// tls.certificates.load_pem，modules/caddytls/pemloader.go）：将证书链与私钥直接以
// PEM 形式下发内存加载，彻底解除跨节点共享证书磁盘文件的依赖；同一证书多应用绑定按 tag 去重并排序。
// 已完全由 jiuzhang_tls_mux 接管的 HTTPS 应用不重复输出到 load_pem。
func buildCertPEMPairs(in GenerateInput, legacyHTTPSApps map[int]bool) []interface{} {
	seen := map[string]bool{}
	var pairs []interface{}
	for idx, app := range in.Apps {
		if !hasCertPEM(app) {
			continue
		}
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		if legacyHTTPSApps != nil && appHasActiveHTTPS(app) && !legacyHTTPSApps[idx] {
			continue
		}
		tag := certTag(app)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		pairs = append(pairs, mapT{
			"certificate": mergeCertChainPEM(app.CertPEM, app.ChainPEM),
			"key":         app.KeyPEM,
			"tags":        []string{tag},
		})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].(mapT)["tags"].([]string)[0] < pairs[j].(mapT)["tags"].([]string)[0]
	})
	return pairs
}

// buildCertFilePairs 构建 apps.tls.certificates.load_files 条目（向后兼容路径）：
// 仅在应用未提供内联 PEM（CertPEM/KeyPEM 为空）且具备 CertFileName 时产出；
// 同一证书被多应用绑定或已由 load_pem 加载时只加载一次（按 tag 去重），按 tag 排序保证确定性。
func buildCertFilePairs(in GenerateInput, legacyHTTPSApps map[int]bool) []interface{} {
	pemTags := map[string]bool{}
	for idx, app := range in.Apps {
		if legacyHTTPSApps != nil && appHasActiveHTTPS(app) && !legacyHTTPSApps[idx] {
			continue
		}
		if hasCertPEM(app) && app.DeploymentMode != applications.DeployModeMirror {
			if tag := certTag(app); tag != "" {
				pemTags[tag] = true
			}
		}
	}
	seen := map[string]bool{}
	var pairs []interface{}
	for idx, app := range in.Apps {
		// 优先使用 load_pem；无内联 PEM 且缺文件名无从引用；MIRROR 应用无内联站点路由，不加载其证书
		if hasCertPEM(app) || !hasCertFile(app) {
			continue
		}
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		if legacyHTTPSApps != nil && appHasActiveHTTPS(app) && !legacyHTTPSApps[idx] {
			continue
		}
		tag := certTag(app)
		if tag == "" || pemTags[tag] || seen[tag] {
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

// buildTLSPoliciesForApps 为指定非 mux HTTPS server 上的应用构建 tls_connection_policies。
func buildTLSPoliciesForApps(srvApps []*httpsServerApp) []interface{} {
	groups := map[string][]string{} // cert tag -> sni domains
	for _, sa := range srvApps {
		app := sa.app
		if !hasCertPEM(app) && !hasCertFile(app) {
			continue
		}
		tag := certTag(app)
		if tag == "" {
			continue
		}
		groups[tag] = append(groups[tag], sa.domains...)
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

// buildTLSPolicies 构建 TLS 连接策略（证书选择）：默认用于公网 HTTPS server。
func buildTLSPolicies(in GenerateInput) []interface{} {
	return buildTLSPoliciesForMode(in, false)
}

// buildTLSPoliciesForMode 按透明/非透明模式隔离构建 TLS 连接策略：按证书 tag 分组，
// 每组一条策略——SNI 命中该组域名时由 certificate_selection.any_tag 选中 load_pem/load_files 以
// 同一 tag 加载的证书，使每个域名关联到本应用的证书。any_tag 在 Caddy v2.11.4 为 []string
// （modules/caddytls/certselection.go），输出字符串会在 /load 直接失败。
func buildTLSPoliciesForMode(in GenerateInput, transparentOnly bool) []interface{} {
	groups := map[string][]string{} // cert tag -> sni domains
	for _, app := range in.Apps {
		if !hasCertPEM(app) && !hasCertFile(app) {
			continue
		}
		// MIRROR 应用无内联站点路由，不为其域名生成 TLS 连接策略
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		isTransparent := app.DeploymentMode == applications.DeployModeTransparent
		if isTransparent != transparentOnly {
			continue
		}
		tag := certTag(app)
		if tag == "" {
			continue
		}
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

// buildHandles 构建请求处理链：可选软件旁路选择器包裹检测/纯透传子链，共用 reverse_proxy。
// publicPort 为路由所在监听的接入端口（302 Location 端口改写目标）。
func buildHandles(in GenerateInput, app AppData, d applications.Domain, publicPort int) []interface{} {
	proxy := applyProxyOptions(buildReverseProxyWithTLS(app.Upstreams, app.TLSConfig), app.HeaderConfig)
	return buildChainHandles(in, app, proxy, publicPort)
}

// buildWAFDirectives 构建 WAF SecLang 指令（固定加载顺序）。
func buildWAFDirectives(ruleEngine string) string {
	return buildWAFDirectivesWithPolicy(ruleEngine, AppData{}, nil, nil, nil)
}

// BuildPolicyDirectives 生成单个防护策略对应的完整 Coraza SecLang 指令文本
// （与真实发布管线 buildWAFDirectivesWithPolicy 共享同一套指令顺序与语法）。
func BuildPolicyDirectives(protectionMode string, paranoiaLevel, inboundThreshold, outboundThreshold int, exceptions []ExceptionRule, customRules, ruleOverrides []string) string {
	ruleEngine := modeToRuleEngine[protectionMode]
	if ruleEngine == "" {
		ruleEngine = "DetectionOnly"
	}
	return buildWAFDirectivesWithPolicy(ruleEngine, AppData{
		ParanoiaLevel:     paranoiaLevel,
		InboundThreshold:  inboundThreshold,
		OutboundThreshold: outboundThreshold,
	}, exceptions, customRules, ruleOverrides)
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
// 管理面自定义规则放例外与规则覆盖之后、CRS 主规则之前（确保 phase:2 自定义阻断规则优先于
// CRS 949 生效，且仍受其前例外与规则覆盖控制）；静态 jiuzhang-custom 与 contrib 包保持在 CRS 之后。
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
	// 显式内联 phase 1~5 默认动作（与 gateway/rules/crs/crs-setup.conf 同口径）：
	// 避免增量镜像升级后宿主只读挂载的旧版 crs-setup.conf 缺失 phase:1/3/4/5 默认动作，
	// 导致 phase:1/3/4 规则命中不写入审计日志 messages、攻击类型退化为「其他」。
	b.WriteString("SecDefaultAction \"phase:1,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:2,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:3,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:4,log,auditlog,pass\"\n")
	b.WriteString("SecDefaultAction \"phase:5,log,auditlog,pass\"\n")
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
	// 管理面启用的自定义规则（确定性：按调用方已排序的切片顺序写出）。
	// 置于例外与规则覆盖之后、CRS 主规则之前：既保留例外与规则覆盖对自定义规则的摘除优先级，
	// 又避免 phase:2 自定义阻断规则被 CRS 949 阻断评估提前抢占。
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
	b.WriteString("Include /etc/caddy/rules/crs/rules/*.conf\n")
	// 第三方与自建规则包（阶段：规则量扩展，放 CRS 主规则之后）
	b.WriteString("Include /etc/caddy/rules/contrib/*/*.conf\n")
	b.WriteString("Include /etc/caddy/rules/crs/plugins/*/plugins/*-after.conf\n")
	b.WriteString("Include /etc/caddy/rules/exclusions/after-crs.conf\n")
	b.WriteString("Include /etc/caddy/rules/jiuzhang/jiuzhang-custom.conf\n")
	// 二次阻断评估：必须始终是最后一条 Include（晚于一切计分规则）。
	// CRS 949 阻断评估在 crs/rules/ 内部完成，晚于它执行的 contrib/插件/after-crs
	// 计分规则需由该文件重新汇总分数并阻断。
	b.WriteString("Include /etc/caddy/rules/jiuzhang/post-contrib-blocking.conf\n")
	return b.String()
}

// buildReverseProxy 构建反向代理（源站、负载均衡、健康检查；兼容不带站点 TLSConfig 的调用方）。
func buildReverseProxy(upstreams []applications.Upstream) mapT {
	return buildReverseProxyWithTLS(upstreams, nil)
}

// buildReverseProxyWithTLS 构建反向代理（源站、负载均衡、健康检查与协议感知传输层）。
// 支持国密 tlcp 回源、HTTPS TLS 1.0/1.1 或 HTTP/1.0/1.1 降级回源及 HTTP/1.0 明文回源；
// 常规 http/https/h2c 源站保持原有 Caddy http transport 形态零变化。
func buildReverseProxyWithTLS(upstreams []applications.Upstream, tlsCfg *AppTLSConfig) mapT {
	// 仅活动源站
	var active []applications.Upstream
	for _, u := range upstreams {
		if u.Status == "ACTIVE" {
			active = append(active, u)
		}
	}
	// 确定性排序（按 host:port，IPv6 经 JoinHostPort 规范化方括号）
	sort.Slice(active, func(i, j int) bool {
		ai := net.JoinHostPort(active[i].NormalizedHost, strconv.Itoa(active[i].Port))
		aj := net.JoinHostPort(active[j].NormalizedHost, strconv.Itoa(active[j].Port))
		return ai < aj
	})

	var ups []interface{}
	var weights []int
	for _, u := range active {
		dial := net.JoinHostPort(u.NormalizedHost, strconv.Itoa(u.Port))
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
		proxy["transport"] = buildUpstreamTransport(active[0], tlsCfg)
	}

	return proxy
}

// buildUpstreamTransport 构建反向代理回源传输层：
//   - scheme=tlcp：使用 http.reverse_proxy.transport.jiuzhang_tls（mode="tlcp"）；
//   - scheme=https 且 TLSConfig 指定 TLS1.0/TLS1.1 或 HTTP/1.0/HTTP/1.1：使用 jiuzhang_tls（mode="tls"）；
//   - scheme=http 且 TLSConfig 指定 HTTP/1.0：使用 jiuzhang_tls（mode="plain"）；
//   - 其他场景保持 Caddy 原生 http transport 形态（与存量配置逐字节一致）。
func buildUpstreamTransport(u applications.Upstream, tlsCfg *AppTLSConfig) mapT {
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if upstreamUsesJiuzhangTLSTransport(u, tlsCfg) {
		dialMs := u.ConnectTimeoutMs
		if dialMs <= 0 {
			dialMs = 3000
		}
		respHdrMs := u.ResponseHeaderTimeoutMs
		if respHdrMs <= 0 {
			respHdrMs = 10000
		}
		serverName := strings.TrimSpace(u.TLSServerName)
		if serverName == "" {
			serverName = u.NormalizedHost
		}
		httpVer := UpstreamHTTPAuto
		minVer := TLSVersion12
		if tlsCfg != nil {
			if v := strings.ToUpper(strings.TrimSpace(tlsCfg.UpstreamHTTPVersion)); v != "" {
				httpVer = v
			}
			if v := strings.ToUpper(strings.TrimSpace(tlsCfg.UpstreamTLSMinVersion)); v != "" {
				minVer = v
			}
		}
		switch scheme {
		case "tlcp":
			tr := mapT{
				"protocol":                "jiuzhang_tls",
				"mode":                    "tlcp",
				"http_version":            httpVer,
				"dial_timeout":            fmt.Sprintf("%dms", dialMs),
				"response_header_timeout": fmt.Sprintf("%dms", respHdrMs),
			}
			if serverName != "" {
				tr["server_name"] = serverName
			}
			if !u.TLSVerify {
				tr["insecure_skip_verify"] = true
			}
			return tr
		case "https":
			tr := mapT{
				"protocol":                "jiuzhang_tls",
				"mode":                    "tls",
				"tls_min_version":         minVer,
				"http_version":            httpVer,
				"dial_timeout":            fmt.Sprintf("%dms", dialMs),
				"response_header_timeout": fmt.Sprintf("%dms", respHdrMs),
			}
			if serverName != "" {
				tr["server_name"] = serverName
			}
			if !u.TLSVerify {
				tr["insecure_skip_verify"] = true
			}
			return tr
		case "http":
			return mapT{
				"protocol":                "jiuzhang_tls",
				"mode":                    "plain",
				"http_version":            httpVer,
				"dial_timeout":            fmt.Sprintf("%dms", dialMs),
				"response_header_timeout": fmt.Sprintf("%dms", respHdrMs),
			}
		}
	}

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
	return transport
}
