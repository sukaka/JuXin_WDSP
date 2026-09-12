package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

func intPtr(v int) *int { return &v }

func sampleApps() []AppData {
	return []AppData{
		{
			Code:           "portal-system",
			ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{
				{
					ID: uuid.New(), Hostname: "www.example.com", NormalizedHostname: "www.example.com",
					DomainType: "EXACT", IsPrimary: true, HTTPEnabled: true, HTTPSEnabled: false,
					HTTPPort: intPtr(8080), Status: "ACTIVE",
				},
			},
			Upstreams: []applications.Upstream{
				{ID: uuid.New(), Name: "b1", Scheme: "http", Host: "192.0.2.1", NormalizedHost: "192.0.2.1", Port: 9001, Weight: 10, Status: "ACTIVE", HealthCheckEnabled: true, HealthCheckPath: "/health", HealthCheckIntervalSeconds: 30, HealthCheckTimeoutSeconds: 5, ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000, MaxRetries: 1},
			},
		},
	}
}

func TestGenerateDeterministic(t *testing.T) {
	in := GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
	}
	g1, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	g2, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if g1.Hash != g2.Hash {
		t.Errorf("same input produced different hashes: %s vs %s", g1.Hash, g2.Hash)
	}
	if g1.JSON != g2.JSON {
		t.Error("same input produced different JSON")
	}
}

func TestGenerateStructure(t *testing.T) {
	in := GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
	}
	g, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}
	// admin socket 必须存在
	admin := cfg["admin"].(map[string]interface{})
	if admin["listen"] != "unix//var/run/caddy/admin.sock" {
		t.Errorf("admin.listen = %v", admin["listen"])
	}
	// server 存在
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers generated")
	}
	if g.RouteCount == 0 {
		t.Error("no routes generated")
	}
	// 校验路由含 host matcher 与 reverse_proxy
	srv := servers["srv0"].(map[string]interface{})
	routes := srv["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	matches := route["match"].([]interface{})[0].(map[string]interface{})
	hosts := matches["host"].([]interface{})
	if hosts[0] != "www.example.com" {
		t.Errorf("route host = %v", hosts[0])
	}
}

func TestGenerateProtectionModes(t *testing.T) {
	modes := []struct {
		mode     string
		expected string
	}{
		{applications.ModeOff, "SecRuleEngine Off"},
		{applications.ModeObserve, "SecRuleEngine DetectionOnly"},
		{applications.ModeProtect, "SecRuleEngine On"},
	}
	for _, m := range modes {
		apps := sampleApps()
		apps[0].ProtectionMode = m.mode
		g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !contains(g.JSON, m.expected) {
			t.Errorf("mode %s: expected %q in config", m.mode, m.expected)
		}
	}
}

func TestGenerateIncludesCustomRulesAndPolicyParams(t *testing.T) {
	apps := sampleApps()
	apps[0].ParanoiaLevel = 2
	apps[0].InboundThreshold = 10
	apps[0].OutboundThreshold = 8
	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
		CustomRules: []string{`SecRule ARGS "@rx test" "id:7100001,phase:2,block,msg:'x'"`},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "tx.blocking_paranoia_level=2") {
		t.Error("expected PL=2 in directives")
	}
	if !contains(g.JSON, "tx.inbound_anomaly_score_threshold=10") {
		t.Error("expected inbound threshold 10")
	}
	if !contains(g.JSON, "id:7100001") {
		t.Error("expected custom rule SecLang in WAF directives")
	}
}

func TestGeneratePostContribBlockingLast(t *testing.T) {
	apps := sampleApps()
	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
		CustomRules: []string{`SecRule ARGS "@rx test" "id:7100001,phase:2,block,msg:'x'"`},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const blocking = "Include /etc/caddy/rules/jiuzhang/post-contrib-blocking.conf"
	const contrib = "Include /etc/caddy/rules/contrib/*/*.conf"
	blockIdx := strings.LastIndex(g.JSON, blocking)
	if blockIdx < 0 {
		t.Fatal("post-contrib-blocking.conf include missing")
	}
	if ci := strings.Index(g.JSON, contrib); ci < 0 || ci > blockIdx {
		t.Error("post-contrib-blocking.conf must load after contrib rules")
	}
	// 必须是最后一条 Include（晚于管理面自定义规则等一切计分规则）
	if strings.LastIndex(g.JSON, "Include /etc/caddy/rules/") != blockIdx {
		t.Error("post-contrib-blocking.conf must be the last Include in WAF directives")
	}
	// 管理面自定义规则在其之前
	if ri := strings.LastIndex(g.JSON, "id:7100001"); ri < 0 || ri > blockIdx {
		t.Error("management custom rules must load before post-contrib-blocking.conf")
	}
}

// LOW-G15：生产生成配置必须覆盖 coraza.conf 的 POC 审计默认（On + Parts 含 C，
// 全量请求体落盘）——Include 之后写 RelevantOnly 且 Parts 不含 C。
func TestGenerateProductionAuditOverridesPOC(t *testing.T) {
	g, err := Generate(GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const inc = "Include /etc/caddy/rules/coraza.conf"
	incIdx := strings.Index(g.JSON, inc)
	if incIdx < 0 {
		t.Fatal("coraza.conf include missing")
	}
	engIdx := strings.Index(g.JSON, "SecAuditEngine RelevantOnly")
	if engIdx < 0 {
		t.Fatal("SecAuditEngine RelevantOnly override missing")
	}
	partsIdx := strings.Index(g.JSON, "SecAuditLogParts ABIJDEFHZ")
	if partsIdx < 0 {
		t.Fatal("SecAuditLogParts without C override missing")
	}
	// 覆盖必须落在 Include 之后（SecLang 顺序求值、后写覆盖），且在 crs-setup 之前
	if engIdx < incIdx || partsIdx < incIdx {
		t.Error("audit overrides must come after the coraza.conf Include to take effect")
	}
	if crsIdx := strings.Index(g.JSON, "Include /etc/caddy/rules/crs/crs-setup.conf"); crsIdx < 0 || engIdx > crsIdx || partsIdx > crsIdx {
		t.Error("audit overrides must come before crs-setup include")
	}
	if strings.Contains(g.JSON, "SecAuditEngine On") {
		t.Error("production config must not enable POC audit engine (full request body capture)")
	}
}

func TestGenerateIncludesRuleOverrides(t *testing.T) {
	apps := sampleApps()
	apps[0].RuleOverrideSecLang = []string{
		`SecRule REQUEST_URI "@rx .*" "id:7200001,phase:1,pass,nolog,ctl:ruleRemoveById=942100,tag:'jiuzhang-rule-override'"`,
	}
	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "ctl:ruleRemoveById=942100") {
		t.Error("expected rule override in WAF directives")
	}
}

func TestGenerateMultiUpstream(t *testing.T) {
	apps := sampleApps()
	apps[0].Upstreams = append(apps[0].Upstreams, applications.Upstream{
		ID: uuid.New(), Name: "b2", Scheme: "http", Host: "192.0.2.2", NormalizedHost: "192.0.2.2",
		Port: 9002, Weight: 20, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
	})
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "weighted_round_robin") {
		t.Error("multi upstream should use weighted_round_robin")
	}
	if !contains(g.JSON, "192.0.2.2:9002") {
		t.Error("second upstream missing")
	}
}

func TestGenerateDisabledUpstreamExcluded(t *testing.T) {
	apps := sampleApps()
	apps[0].Upstreams = append(apps[0].Upstreams, applications.Upstream{
		ID: uuid.New(), Name: "disabled", Scheme: "http", Host: "192.0.2.99", NormalizedHost: "192.0.2.99",
		Port: 9999, Weight: 10, Status: "DISABLED", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
	})
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if contains(g.JSON, "192.0.2.99") {
		t.Error("disabled upstream should be excluded")
	}
}

func TestGenerateHTTPSRedirect(t *testing.T) {
	apps := sampleApps()
	apps[0].Domains[0].RedirectHTTPToHTTPS = true
	apps[0].Domains[0].HTTPSEnabled = true
	apps[0].Domains[0].HTTPSPort = intPtr(443)
	apps[0].HasCert = true
	apps[0].CertID = "cert-1"
	apps[0].CertFileName = "cert1.pem"
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g.JSON, "308") {
		t.Error("http->https redirect should return 308")
	}
}

func TestGenerateBypassModeSkipsGuardAndWAF(t *testing.T) {
	apps := sampleApps()
	apps[0].ProtectionMode = applications.ModeBypass
	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// 透传链：无 waf、无 guard、无 SecRuleEngine，保留 headers 与 reverse_proxy
	for _, banned := range []string{`"handler":"waf"`, "jiuzhang_guard", "SecRuleEngine"} {
		if contains(g.JSON, banned) {
			t.Errorf("BYPASS chain must not contain %q", banned)
		}
	}
	for _, want := range []string{`"handler":"headers"`, `"handler":"reverse_proxy"`, "X-Request-Id"} {
		if !contains(g.JSON, want) {
			t.Errorf("BYPASS chain missing %q", want)
		}
	}
	// 对照：相同 Guard 配置下 PROTECT 仍注入 guard 与 waf
	apps[0].ProtectionMode = applications.ModeProtect
	g2, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !contains(g2.JSON, `"handler":"waf"`) || !contains(g2.JSON, "jiuzhang_guard") {
		t.Error("PROTECT chain must keep guard and waf handlers")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// MIRROR（镜像旁路）应用不生成内联站点路由（流量经镜像口到达，不在反代链上）；
// REVERSE_PROXY/ROUTED/TRANSPARENT 照常生成（docs/NETWORK_MODES_DESIGN.md §4.2）。
func TestGenerateMirrorModeSkipsRoutes(t *testing.T) {
	apps := sampleApps() // REVERSE_PROXY（空串默认）
	mirror := AppData{
		Code:           "mirror-app",
		ProtectionMode: applications.ModeObserve,
		DeploymentMode: applications.DeployModeMirror,
		Domains: []applications.Domain{
			{ID: uuid.New(), Hostname: "mirror.example.com", NormalizedHostname: "mirror.example.com",
				DomainType: "EXACT", IsPrimary: true, HTTPEnabled: true, HTTPPort: intPtr(8090), Status: "ACTIVE"},
		},
		Upstreams: []applications.Upstream{
			{ID: uuid.New(), Name: "m1", Scheme: "http", Host: "192.0.2.9", NormalizedHost: "192.0.2.9", Port: 9001, Weight: 1, Status: "ACTIVE"},
		},
	}
	transparent := AppData{
		Code:           "tproxy-app",
		ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeTransparent,
		Domains: []applications.Domain{
			{ID: uuid.New(), Hostname: "tproxy.example.com", NormalizedHostname: "tproxy.example.com",
				DomainType: "EXACT", IsPrimary: true, HTTPEnabled: true, HTTPPort: intPtr(8091), Status: "ACTIVE"},
		},
		Upstreams: []applications.Upstream{
			{ID: uuid.New(), Name: "t1", Scheme: "http", Host: "192.0.2.10", NormalizedHost: "192.0.2.10", Port: 9001, Weight: 1, Status: "ACTIVE"},
		},
	}
	apps = append(apps, mirror, transparent)
	g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if contains(g.JSON, "mirror.example.com") {
		t.Error("MIRROR app must not produce inline site routes")
	}
	for _, want := range []string{"www.example.com", "tproxy.example.com"} {
		if !contains(g.JSON, want) {
			t.Errorf("non-MIRROR app route missing host %q", want)
		}
	}

	// 全量 MIRROR 应用时：无 server、无路由，配置仍合法（仅 admin/logging/空 servers）
	g, err = Generate(GenerateInput{Apps: []AppData{mirror}, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if g.ServerCount != 0 || g.RouteCount != 0 {
		t.Errorf("mirror-only config servers/routes = %d/%d, want 0/0", g.ServerCount, g.RouteCount)
	}
	if contains(g.JSON, "mirror.example.com") {
		t.Error("mirror-only config must not reference mirror domain")
	}
}

// server 级 errors 错误路由：403 返回自定义阻断页并携带 X-Jiuzhang-Request-ID 响应头，
// 其他错误返回通用状态响应（等价静态 Caddyfile 的 handle_errors 块）。
func TestGenerateErrorRoutes(t *testing.T) {
	g, err := Generate(GenerateInput{Apps: sampleApps(), AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`"errors"`,
		"blockpage.html",
		"X-Jiuzhang-Request-ID",
		"{http.error.status_code} == 403",
		`"name":"blocked"`, // CEL 匹配器 UnmarshalJSON 强制要求 expr+name 成对存在
		`"uri":"/blockpage.html"`,
		`"root":"/srv/jiuzhang"`,
		`"handler":"static_response"`,
	} {
		if !contains(g.JSON, want) {
			t.Errorf("error routes missing %q", want)
		}
	}

	// 自定义 BlockPagePath：rewrite uri 取文件名，file_server root 取目录
	g2, err := Generate(GenerateInput{
		Apps:          sampleApps(),
		AdminSocket:   "unix//var/run/caddy/admin.sock",
		BlockPagePath: "/opt/waf/pages/deny.html",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{`"uri":"/deny.html"`, `"root":"/opt/waf/pages"`} {
		if !contains(g2.JSON, want) {
			t.Errorf("custom BlockPagePath: error routes missing %q", want)
		}
	}
}

// 网关原生 OTel tracing（APM 阶段2 收尾）：默认关，开启时每条路由链首注入
// http.handlers.tracing handler；errors 内部错误路由不注入。
func TestGenerateGatewayTracingOffByDefault(t *testing.T) {
	g, err := Generate(GenerateInput{Apps: sampleApps(), AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if contains(g.JSON, `"handler":"tracing"`) {
		t.Error("tracing handler should not be emitted by default")
	}
}

func TestGenerateGatewayTracingOn(t *testing.T) {
	in := GenerateInput{Apps: sampleApps(), AdminSocket: "unix//var/run/caddy/admin.sock", GatewayTracing: true}
	g, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// 确定性：同输入同哈希
	g2, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if g.Hash != g2.Hash {
		t.Errorf("tracing on: same input produced different hashes: %s vs %s", g.Hash, g2.Hash)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers generated")
	}
	traced := 0
	for _, srv := range servers {
		server := srv.(map[string]interface{})
		for _, r := range server["routes"].([]interface{}) {
			route := r.(map[string]interface{})
			handle := route["handle"].([]interface{})
			first := handle[0].(map[string]interface{})
			if first["handler"] != "tracing" {
				t.Errorf("route first handler = %v, want tracing", first["handler"])
				continue
			}
			if first["span"] != "jiuzhang-gateway" {
				t.Errorf("tracing span = %v, want jiuzhang-gateway", first["span"])
			}
			traced++
		}
		// errors 内部错误路由不注入 tracing（非真实请求入口）
		for _, r := range server["errors"].(map[string]interface{})["routes"].([]interface{}) {
			route := r.(map[string]interface{})
			for _, h := range route["handle"].([]interface{}) {
				if h.(map[string]interface{})["handler"] == "tracing" {
					t.Error("errors routes should not contain tracing handler")
				}
			}
		}
	}
	if traced == 0 {
		t.Error("no route got tracing handler injected")
	}
}

// TestExceptionAppliesToApp 回归：例外曾整表注入每个应用的 WAF 指令段，
// ScopeType=APPLICATION 的例外发布后对全部应用摘除规则。
func TestExceptionAppliesToApp(t *testing.T) {
	appA := AppData{AppID: "550e8400-e29b-41d4-a716-446655440000", Code: "app-a"}
	appB := AppData{AppID: "550e8400-e29b-41d4-a716-446655440001", Code: "app-b"}

	global := ExceptionRule{RuleID: 8000001, SecLang: "SecRule REQUEST_URI \"@rx /x\" \"id:8000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100\"", ScopeType: "GLOBAL"}
	forA := ExceptionRule{RuleID: 8000002, SecLang: "SecRule REQUEST_URI \"@rx /a\" \"id:8000002,phase:1,pass,nolog,ctl:ruleRemoveById=941160\"", ScopeType: "APPLICATION", ApplicationID: appA.AppID}
	noApp := ExceptionRule{RuleID: 8000003, SecLang: "SecRule REQUEST_URI \"@rx /b\" \"id:8000003,phase:1,pass,nolog\"", ScopeType: "APPLICATION"}
	policy := ExceptionRule{RuleID: 8000004, SecLang: "SecRule REQUEST_URI \"@rx /c\" \"id:8000004,phase:1,pass,nolog\"", ScopeType: "POLICY", PolicyID: "p-1"}

	if !exceptionAppliesToApp(global, appA) || !exceptionAppliesToApp(global, appB) {
		t.Error("GLOBAL exception should apply to every app")
	}
	if !exceptionAppliesToApp(forA, appA) {
		t.Error("APPLICATION exception should apply to its owning app")
	}
	if exceptionAppliesToApp(forA, appB) {
		t.Error("APPLICATION exception must not leak into other apps")
	}
	if exceptionAppliesToApp(noApp, appA) {
		t.Error("APPLICATION exception without application_id must not apply anywhere")
	}
	if exceptionAppliesToApp(policy, appA) {
		t.Error("POLICY scope is not publishable (fail-closed)")
	}
	// 未标注作用域的兼容数据按 GLOBAL 处理（与修复前行为一致）
	legacy := ExceptionRule{RuleID: 8000005, SecLang: "SecRule REQUEST_URI \"@rx /d\" \"id:8000005,phase:1,pass,nolog\""}
	if !exceptionAppliesToApp(legacy, appA) {
		t.Error("empty scope should keep legacy global behavior")
	}

	// 端到端：buildWAFDirectivesWithPolicy 注入结果按应用区分
	exceptions := []ExceptionRule{global, forA}
	dirA := buildWAFDirectivesWithPolicy("On", appA, exceptions, nil, nil)
	dirB := buildWAFDirectivesWithPolicy("On", appB, exceptions, nil, nil)
	if !strings.Contains(dirA, "id:8000002") {
		t.Error("owning app directives should contain its APPLICATION exception")
	}
	if strings.Contains(dirB, "id:8000002") {
		t.Error("other app directives must not contain the APPLICATION exception")
	}
	if !strings.Contains(dirB, "id:8000001") {
		t.Error("GLOBAL exception should still reach every app")
	}
}

// httpsOnlyApp 构造仅监听 HTTPS 的测试应用（绑定证书 + 单活动源站）。
func httpsOnlyApp(code, certID, certFile string, hosts ...string) AppData {
	var domains []applications.Domain
	for _, h := range hosts {
		domains = append(domains, applications.Domain{
			ID: uuid.New(), Hostname: h, NormalizedHostname: h,
			DomainType: "EXACT", HTTPSEnabled: true, HTTPSPort: intPtr(443), Status: "ACTIVE",
		})
	}
	return AppData{
		Code:           code,
		ProtectionMode: applications.ModeProtect,
		Domains:        domains,
		Upstreams: []applications.Upstream{
			{ID: uuid.New(), Name: "b1", Scheme: "http", Host: "192.0.2.1", NormalizedHost: "192.0.2.1", Port: 9001, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000},
		},
		HasCert:      true,
		CertID:       certID,
		CertFileName: certFile,
	}
}

// HTTPS 应用发布产物：apps.tls.certificates.load_files 引用发布器落盘的 pem/key
// 并以证书 ID 打 tag；server tls_connection_policies 按证书分组，any_tag 为数组
// （Caddy v2.11.4 certselection.go 契约）；同一证书多应用绑定只加载一次；
// 与 session_tickets 同处 apps.tls 段互不覆盖。
func TestGenerateHTTPSCertLoadFilesAndPolicies(t *testing.T) {
	apps := []AppData{
		httpsOnlyApp("app-a", "cert-id-a", "a.pem", "a.example.com"),
		httpsOnlyApp("app-b", "cert-id-b", "b.pem", "b.example.com"),
		// 与 app-a 共用同一证书（多应用绑定场景）
		httpsOnlyApp("app-c", "cert-id-a", "a.pem", "c.example.com"),
	}
	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       &GuardConfig{TLSSessionTicketKey: testTicketKey},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}

	// apps.tls：certificates.load_files 与 session_tickets 并存
	tlsApp, ok := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("apps.tls 缺失: %s", g.JSON)
	}
	if _, ok := tlsApp["session_tickets"]; !ok {
		t.Error("apps.tls.session_tickets 应保留（与 load_files 并存）")
	}
	loadFiles, ok := tlsApp["certificates"].(map[string]interface{})["load_files"].([]interface{})
	if !ok || len(loadFiles) != 2 {
		t.Fatalf("load_files 应为 2 条（同证书去重）: %v", tlsApp["certificates"])
	}
	// 按 tag 排序：cert-id-a 在前
	first := loadFiles[0].(map[string]interface{})
	if first["certificate"] != "/etc/caddy/certs/a.pem" || first["key"] != "/etc/caddy/certs/a.key" {
		t.Errorf("load_files[0] 路径 = %v / %v", first["certificate"], first["key"])
	}
	if tags := first["tags"].([]interface{}); len(tags) != 1 || tags[0] != "cert-id-a" {
		t.Errorf("load_files[0].tags = %v, want [cert-id-a]", first["tags"])
	}
	second := loadFiles[1].(map[string]interface{})
	if second["certificate"] != "/etc/caddy/certs/b.pem" || second["key"] != "/etc/caddy/certs/b.key" {
		t.Errorf("load_files[1] 路径 = %v / %v", second["certificate"], second["key"])
	}

	// HTTPS server：tls_connection_policies 按证书分组，any_tag 为数组
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	if len(servers) != 1 {
		t.Fatalf("HTTPS server 数量 = %d, want 1", len(servers))
	}
	policies, ok := servers["srv0"].(map[string]interface{})["tls_connection_policies"].([]interface{})
	if !ok || len(policies) != 2 {
		t.Fatalf("tls_connection_policies = %v", servers["srv0"].(map[string]interface{})["tls_connection_policies"])
	}
	p0 := policies[0].(map[string]interface{})
	sni0 := p0["match"].(map[string]interface{})["sni"].([]interface{})
	if len(sni0) != 2 || sni0[0] != "a.example.com" || sni0[1] != "c.example.com" {
		t.Errorf("policies[0].sni = %v, want [a.example.com c.example.com]（同证书域名合并）", sni0)
	}
	anyTag0, ok := p0["certificate_selection"].(map[string]interface{})["any_tag"].([]interface{})
	if !ok {
		t.Fatalf("any_tag 必须是数组（Caddy v2.11.4 契约）: %v", p0["certificate_selection"])
	}
	if len(anyTag0) != 1 || anyTag0[0] != "cert-id-a" {
		t.Errorf("policies[0].any_tag = %v, want [cert-id-a]", anyTag0)
	}
	p1 := policies[1].(map[string]interface{})
	sni1 := p1["match"].(map[string]interface{})["sni"].([]interface{})
	if len(sni1) != 1 || sni1[0] != "b.example.com" {
		t.Errorf("policies[1].sni = %v, want [b.example.com]", sni1)
	}
	anyTag1 := p1["certificate_selection"].(map[string]interface{})["any_tag"].([]interface{})
	if len(anyTag1) != 1 || anyTag1[0] != "cert-id-b" {
		t.Errorf("policies[1].any_tag = %v, want [cert-id-b]", anyTag1)
	}
}

// 纯 HTTP 应用不产出 apps.tls 段（保持无证书时的既有语义）。
func TestGenerateHTTPCertLoadFilesAbsent(t *testing.T) {
	g, err := Generate(GenerateInput{Apps: sampleApps(), AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["apps"].(map[string]interface{})["tls"]; ok {
		t.Error("纯 HTTP 应用不应产出 apps.tls 段")
	}
}

// https 源站生成带 tls 的 transport：server_name 取 TLSServerName（缺省回退源站主机名），
// insecure_skip_verify 取反于 TLSVerify；http 源站输出保持不变（无 tls 段）。
func TestBuildReverseProxyHTTPSTransport(t *testing.T) {
	mk := func(mutate func(u *applications.Upstream)) applications.Upstream {
		u := applications.Upstream{
			ID: uuid.New(), Name: "b1", Scheme: "https", Host: "origin.internal", NormalizedHost: "origin.internal",
			Port: 443, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
			TLSServerName: "origin.example.internal", TLSVerify: true,
		}
		mutate(&u)
		return u
	}
	tlsOf := func(t *testing.T, u applications.Upstream) mapT {
		t.Helper()
		proxy := buildReverseProxy([]applications.Upstream{u})
		transport, ok := proxy["transport"].(mapT)
		if !ok {
			t.Fatalf("transport 缺失: %v", proxy)
		}
		if transport["protocol"] != "http" {
			t.Errorf("transport.protocol = %v, want http", transport["protocol"])
		}
		tls, ok := transport["tls"].(mapT)
		if !ok {
			t.Fatalf("https 源站应有 tls transport 段: %v", transport)
		}
		return tls
	}

	t.Run("server_name 取 TLSServerName", func(t *testing.T) {
		tls := tlsOf(t, mk(func(u *applications.Upstream) {}))
		if tls["server_name"] != "origin.example.internal" {
			t.Errorf("server_name = %v", tls["server_name"])
		}
		if _, ok := tls["insecure_skip_verify"]; ok {
			t.Error("TLSVerify=true 不应输出 insecure_skip_verify")
		}
	})
	t.Run("TLSServerName 为空回退源站主机名", func(t *testing.T) {
		tls := tlsOf(t, mk(func(u *applications.Upstream) { u.TLSServerName = "" }))
		if tls["server_name"] != "origin.internal" {
			t.Errorf("server_name = %v, want origin.internal", tls["server_name"])
		}
	})
	t.Run("TLSVerify=false 输出 insecure_skip_verify", func(t *testing.T) {
		tls := tlsOf(t, mk(func(u *applications.Upstream) { u.TLSVerify = false }))
		if tls["insecure_skip_verify"] != true {
			t.Errorf("insecure_skip_verify = %v, want true", tls["insecure_skip_verify"])
		}
	})
	t.Run("http 源站输出不变（无 tls 段）", func(t *testing.T) {
		proxy := buildReverseProxy([]applications.Upstream{mk(func(u *applications.Upstream) { u.Scheme = "http"; u.Port = 8080 })})
		transport := proxy["transport"].(mapT)
		if _, ok := transport["tls"]; ok {
			t.Errorf("http 源站不应输出 tls 段: %v", transport)
		}
		if transport["dial_timeout"] != "3000ms" || transport["response_header_timeout"] != "10000ms" {
			t.Errorf("超时字段应保持不变: %v", transport)
		}
	})
}

// Generate 全链路：https 源站的 reverse_proxy handler 带 tls transport（http 源站不带）。
func TestGenerateUpstreamTLSInProxyHandler(t *testing.T) {
	proxyOf := func(t *testing.T, apps []AppData) map[string]interface{} {
		t.Helper()
		g, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock"})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
			t.Fatal(err)
		}
		servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
		for _, srv := range servers {
			for _, r := range srv.(map[string]interface{})["routes"].([]interface{}) {
				for _, h := range r.(map[string]interface{})["handle"].([]interface{}) {
					if h.(map[string]interface{})["handler"] == "reverse_proxy" {
						return h.(map[string]interface{})
					}
				}
			}
		}
		t.Fatal("未找到 reverse_proxy handler")
		return nil
	}

	httpsApps := sampleApps()
	httpsApps[0].Upstreams[0].Scheme = "https"
	httpsApps[0].Upstreams[0].Port = 443
	httpsApps[0].Upstreams[0].TLSServerName = "origin.example.internal"
	httpsApps[0].Upstreams[0].TLSVerify = true
	proxy := proxyOf(t, httpsApps)
	tls, ok := proxy["transport"].(map[string]interface{})["tls"].(map[string]interface{})
	if !ok || tls["server_name"] != "origin.example.internal" {
		t.Errorf("https 源站发布产物应带 tls.server_name: %v", proxy["transport"])
	}

	httpProxy := proxyOf(t, sampleApps())
	if _, ok := httpProxy["transport"].(map[string]interface{})["tls"]; ok {
		t.Errorf("http 源站发布产物不应带 tls 段: %v", httpProxy["transport"])
	}
}

// LOW-G3：X-Forwarded-For 上一跳覆盖默认开启——无头合规配置记录（nil = 管理员未做选择）
// 时按安全默认覆盖伪造 XFF 左端（网关前置链已将 RemoteAddr 改写为真实客户端 IP，
// {http.request.remote.host} 即真实 IP）；显式 xff_overwrite=false 尊重关闭。
func TestApplyProxyOptionsXffDefaultOn(t *testing.T) {
	mk := func() mapT { return mapT{"handler": "reverse_proxy"} }
	xffSet := func(t *testing.T, proxy mapT) []string {
		t.Helper()
		headers, ok := proxy["headers"].(mapT)
		if !ok {
			return nil
		}
		req, ok := headers["request"].(mapT)
		if !ok {
			return nil
		}
		set, ok := req["set"].(map[string][]string)
		if !ok {
			return nil
		}
		return set["X-Forwarded-For"]
	}

	def := xffSet(t, applyProxyOptions(mk(), nil))
	if len(def) != 1 || def[0] != "{http.request.remote.host}" {
		t.Fatalf("nil header config must default to XFF overwrite: %v", def)
	}
	if got := xffSet(t, applyProxyOptions(mk(), &AppHeaderConfig{})); got != nil {
		t.Fatalf("explicit xff_overwrite=false must be respected: %v", got)
	}
	on := xffSet(t, applyProxyOptions(mk(), &AppHeaderConfig{XffOverwrite: true}))
	if len(on) != 1 || on[0] != "{http.request.remote.host}" {
		t.Fatalf("explicit xff_overwrite=true must set XFF: %v", on)
	}
}
