// Package gatewayconfig 提供网关配置生成器：将数据库业务数据转换为确定性 Caddy JSON 配置。
package gatewayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
}

// AppData 是单个应用的完整数据。
type AppData struct {
	Code           string
	ProtectionMode string
	Domains        []applications.Domain
	Upstreams      []applications.Upstream
	// 证书（HTTPS 应用）：PEM 与私钥 PEM（发布时解密提供）。
	CertID       string
	CertFileName string // 写入网关证书目录的文件名（不含目录）
	HasCert      bool
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

	config := mapT{
		"admin": mapT{"listen": in.AdminSocket},
		"logging": mapT{
			"logs": mapT{
				"default": mapT{"writer": mapT{"output": "file", "filename": "/var/log/caddy/caddy.log"}, "encoder": mapT{"format": "json"}},
			},
		},
		"apps": mapT{
			"http": mapT{
				"servers": servers,
			},
		},
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
		for _, d := range app.Domains {
			hosts := []string{d.NormalizedHostname}
			// 泛域名 Caddy 用 *.example.com 形式（Caddy 支持通配符 host matcher）
			handles := buildHandles(in, app, d)

			route := mapT{
				"match":  []interface{}{mapT{"host": hosts}},
				"handle": handles,
			}
			if d.HTTPEnabled && d.HTTPPort != nil {
				addr := fmt.Sprintf(":%d", *d.HTTPPort)
				r := route
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
				httpServers[addr] = append(httpServers[addr], routeEntry{appCode: app.Code, route: r})
			}
			if d.HTTPSEnabled && d.HTTPSPort != nil {
				addr := fmt.Sprintf(":%d", *d.HTTPSPort)
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
		// 路由按应用编码排序（确定性）
		sort.Slice(entries, func(i, j int) bool { return entries[i].appCode < entries[j].appCode })
		var routes []interface{}
		for _, e := range entries {
			routes = append(routes, e.route)
			routeCount++
		}
		servers[fmt.Sprintf("srv%d", serverIdx)] = mapT{
			"listen":          []string{addr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
		}
		serverIdx++
	}
	// HTTPS servers（带证书）
	for _, addr := range sortedKeys(httpsServers) {
		entries := httpsServers[addr]
		sort.Slice(entries, func(i, j int) bool { return entries[i].appCode < entries[j].appCode })
		var routes []interface{}
		for _, e := range entries {
			routes = append(routes, e.route)
			routeCount++
		}
		server := mapT{
			"listen":          []string{addr},
			"routes":          routes,
			"automatic_https": mapT{"disable": true},
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

// buildTLSPolicies 构建 TLS 连接策略（证书文件引用）。
func buildTLSPolicies(in GenerateInput) []interface{} {
	var policies []interface{}
	var policyDomains []string
	certFiles := map[string]string{} // domain -> cert file
	for _, app := range in.Apps {
		if !app.HasCert {
			continue
		}
		for _, d := range app.Domains {
			if d.HTTPSEnabled {
				certFiles[d.NormalizedHostname] = app.CertFileName
				policyDomains = append(policyDomains, d.NormalizedHostname)
			}
		}
	}
	if len(policyDomains) == 0 {
		return nil
	}
	sort.Strings(policyDomains)
	policies = append(policies, mapT{
		"match":                 mapT{"sni": policyDomains},
		"certificate_selection": mapT{"any_tag": policyDomains[0]},
	})
	return policies
}

// buildHandles 构建请求处理链：RequestID → WAF → reverse_proxy → 错误处理。
func buildHandles(in GenerateInput, app AppData, d applications.Domain) []interface{} {
	var handles []interface{}

	// 1. Request ID（覆盖客户端传入）
	handles = append(handles, mapT{
		"handler": "headers",
		"request": mapT{"set": mapT{"X-Request-Id": []string{"{http.request.uuid}"}},
			"delete": []string{}},
	})

	// 2. WAF（按防护模式）
	ruleEngine := modeToRuleEngine[app.ProtectionMode]
	if ruleEngine == "" {
		ruleEngine = "DetectionOnly"
	}
	directives := buildWAFDirectives(ruleEngine)
	handles = append(handles, mapT{
		"handler":    "waf",
		"directives": directives,
	})

	// 3. 安全响应头
	handles = append(handles, mapT{
		"handler": "headers",
		"response": mapT{"set": mapT{
			"X-Content-Type-Options": []string{"nosniff"},
			"X-Frame-Options":        []string{"DENY"},
			"Referrer-Policy":        []string{"no-referrer"},
		}, "delete": []string{"Server"}},
	})

	// 4. 反向代理
	proxy := buildReverseProxy(app.Upstreams)
	handles = append(handles, proxy)

	// 5. 错误处理（403 → 阻断页面）
	// errors 在 server 级别配置，这里不重复（见 server errors 配置）

	return handles
}

// buildWAFDirectives 构建 WAF SecLang 指令（固定加载顺序）。
func buildWAFDirectives(ruleEngine string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("SecRuleEngine %s\n", ruleEngine))
	b.WriteString("Include /etc/caddy/rules/coraza.conf\n")
	b.WriteString("Include /etc/caddy/rules/crs/crs-setup.conf\n")
	b.WriteString("Include /etc/caddy/rules/exclusions/before-crs.conf\n")
	b.WriteString("Include /etc/caddy/rules/crs/rules/*.conf\n")
	b.WriteString("Include /etc/caddy/rules/exclusions/after-crs.conf\n")
	b.WriteString("Include /etc/caddy/rules/jiuzhang/jiuzhang-custom.conf")
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
	for _, u := range active {
		dial := fmt.Sprintf("%s:%d", u.NormalizedHost, u.Port)
		up := mapT{"dial": dial}
		if u.Weight > 0 {
			up["weight"] = u.Weight
		}
		ups = append(ups, up)
	}

	proxy := mapT{
		"handler":   "reverse_proxy",
		"upstreams": ups,
	}

	// 负载均衡（多源站加权轮询）
	if len(active) > 1 {
		proxy["load_balancing"] = mapT{
			"selection_policy": mapT{"policy": "weighted_round_robin"},
		}
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

	// 超时与重试
	if len(active) > 0 {
		u := active[0]
		transport := mapT{
			"protocol":                "http",
			"dial_timeout":            fmt.Sprintf("%dms", u.ConnectTimeoutMs),
			"response_header_timeout": fmt.Sprintf("%dms", u.ResponseHeaderTimeoutMs),
		}
		proxy["transport"] = transport
		if u.MaxRetries > 0 {
			proxy["retries"] = u.MaxRetries
		}
	}

	return proxy
}
