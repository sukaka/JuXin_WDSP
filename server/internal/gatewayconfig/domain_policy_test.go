package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

func extractRouteWAFDirectivesByHost(t *testing.T, cfgJSON string) map[string][]string {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	result := make(map[string][]string)
	for _, rawSrv := range servers {
		srv := rawSrv.(map[string]interface{})
		routes, _ := srv["routes"].([]interface{})
		for _, rawRoute := range routes {
			route := rawRoute.(map[string]interface{})
			matches, _ := route["match"].([]interface{})
			if len(matches) == 0 {
				continue
			}
			m0 := matches[0].(map[string]interface{})
			hosts, _ := m0["host"].([]interface{})
			if len(hosts) == 0 {
				continue
			}
			host := hosts[0].(string)
			pathSuffix := ""
			if paths, ok := m0["path"].([]interface{}); ok && len(paths) > 0 {
				pathSuffix = "|" + paths[0].(string)
			}
			key := host + pathSuffix
			handles, _ := route["handle"].([]interface{})
			for _, rawH := range handles {
				h := rawH.(map[string]interface{})
				if h["handler"] == "waf" {
					if dir, ok := h["directives"].(string); ok {
						result[key] = append(result[key], dir)
					}
				}
			}
		}
	}
	return result
}

func TestGeneratePerDomainProtectionPolicyOverridesAndInheritance(t *testing.T) {
	domStrictID := uuid.New()
	domInheritID := uuid.New()
	domOffID := uuid.New()
	app := AppData{
		AppID:             uuid.NewString(),
		Code:              "multi-domain",
		ProtectionMode:    applications.ModeObserve,
		ParanoiaLevel:     1,
		InboundThreshold:  10,
		OutboundThreshold: 5,
		RuleOverrideSecLang: []string{
			`SecRule REQUEST_URI "@rx .*" "id:7200001,phase:1,pass,nolog,ctl:ruleRemoveById=942100,tag:'jiuzhang-rule-override'"`,
		},
		Domains: []applications.Domain{
			{
				ID: domStrictID, Hostname: "strict.jxdr.cn", NormalizedHostname: "strict.jxdr.cn",
				DomainType: "EXACT", IsPrimary: true, HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE",
			},
			{
				ID: domInheritID, Hostname: "inherit.jxdr.cn", NormalizedHostname: "inherit.jxdr.cn",
				DomainType: "EXACT", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE",
			},
			{
				ID: domOffID, Hostname: "off.jxdr.cn", NormalizedHostname: "off.jxdr.cn",
				DomainType: "EXACT", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE",
			},
		},
		DomainPolicies: map[string]DomainPolicy{
			domStrictID.String(): {
				PolicyID:          uuid.NewString(),
				ProtectionMode:    applications.ModeProtect,
				ParanoiaLevel:     3,
				InboundThreshold:  4,
				OutboundThreshold: 3,
				// 域名策略不禁用 942100（显式覆盖为空切片，不能遗留应用策略的规则禁用）
				HasRuleOverrides:    true,
				RuleOverrideSecLang: nil,
			},
			domOffID.String(): {
				PolicyID:          uuid.NewString(),
				ProtectionMode:    applications.ModeOff,
				ParanoiaLevel:     1,
				InboundThreshold:  5,
				OutboundThreshold: 4,
			},
		},
		PathRoutes: []AppPathRoute{
			{PathPrefix: "/api", UpstreamScheme: "http", UpstreamHost: "192.0.2.2", UpstreamPort: 9002, Priority: 1},
		},
		Upstreams: []applications.Upstream{
			{ID: uuid.New(), Name: "u1", Scheme: "http", Host: "192.0.2.1", NormalizedHost: "192.0.2.1", Port: 9001, Weight: 10, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000},
		},
	}

	g, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	byHost := extractRouteWAFDirectivesByHost(t, g.JSON)

	// strict.jxdr.cn 默认路由与 /api* 路径路由均须生效域名级严格策略
	for _, key := range []string{"strict.jxdr.cn", "strict.jxdr.cn|/api*"} {
		dirs := byHost[key]
		if len(dirs) != 1 {
			t.Fatalf("%s: expected 1 waf handler, got %d", key, len(dirs))
		}
		d := dirs[0]
		if !strings.Contains(d, "SecRuleEngine On") {
			t.Errorf("%s: expected SecRuleEngine On, got %s", key, d)
		}
		if !strings.Contains(d, "setvar:tx.blocking_paranoia_level=3,setvar:tx.inbound_anomaly_score_threshold=4,setvar:tx.outbound_anomaly_score_threshold=3") {
			t.Errorf("%s: expected strict PL3/4/3, got %s", key, d)
		}
		if strings.Contains(d, "ctl:ruleRemoveById=942100") {
			t.Errorf("%s: domain policy cleared rule overrides, should not inherit app policy override", key)
		}
	}

	// inherit.jxdr.cn 保持应用默认策略（OBSERVE + PL1/10/5 + 应用规则覆盖）
	for _, key := range []string{"inherit.jxdr.cn", "inherit.jxdr.cn|/api*"} {
		dirs := byHost[key]
		if len(dirs) != 1 {
			t.Fatalf("%s: expected 1 waf handler, got %d", key, len(dirs))
		}
		d := dirs[0]
		if !strings.Contains(d, "SecRuleEngine DetectionOnly") {
			t.Errorf("%s: expected SecRuleEngine DetectionOnly, got %s", key, d)
		}
		if !strings.Contains(d, "setvar:tx.blocking_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=10,setvar:tx.outbound_anomaly_score_threshold=5") {
			t.Errorf("%s: expected inherited PL1/10/5, got %s", key, d)
		}
		if !strings.Contains(d, "ctl:ruleRemoveById=942100") {
			t.Errorf("%s: expected inherited app rule override", key)
		}
	}

	// off.jxdr.cn 使用域名级 OFF 策略
	offDirs := byHost["off.jxdr.cn"]
	if len(offDirs) != 1 || !strings.Contains(offDirs[0], "SecRuleEngine Off") {
		t.Fatalf("off.jxdr.cn: expected SecRuleEngine Off, got %v", offDirs)
	}
}

func TestGenerateAppBypassAlwaysOverridesDomainPolicy(t *testing.T) {
	domID := uuid.New()
	apps := sampleApps()
	apps[0].ProtectionMode = applications.ModeBypass
	apps[0].Domains[0].ID = domID
	apps[0].DomainPolicies = map[string]DomainPolicy{
		domID.String(): {
			PolicyID:          uuid.NewString(),
			ProtectionMode:    applications.ModeProtect,
			ParanoiaLevel:     2,
			InboundThreshold:  5,
			OutboundThreshold: 4,
		},
	}

	g, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	byHost := extractRouteWAFDirectivesByHost(t, g.JSON)
	if len(byHost) != 0 {
		t.Fatalf("BYPASS app must not emit WAF handlers even with domain policy, got %v", byHost)
	}
}

func TestSidecarsRespectDomainPolicyOverridesAndBypass(t *testing.T) {
	domOn := uuid.New()
	domOff := uuid.New()
	tpxApp := AppData{
		Code:           "tpx-mixed",
		DeploymentMode: applications.DeployModeTransparent,
		ProtectionMode: applications.ModeOff, // 应用默认 OFF，但 domOn 覆盖为 PROTECT
		Domains: []applications.Domain{
			{ID: domOn, Hostname: "on.jxdr.cn", NormalizedHostname: "on.jxdr.cn", HTTPEnabled: true, HTTPPort: intPtr(80), HTTPSEnabled: true, HTTPSPort: intPtr(443), Status: "ACTIVE"},
			{ID: domOff, Hostname: "off.jxdr.cn", NormalizedHostname: "off.jxdr.cn", HTTPEnabled: true, HTTPPort: intPtr(8081), HTTPSEnabled: true, HTTPSPort: intPtr(8443), Status: "ACTIVE"},
		},
		DomainPolicies: map[string]DomainPolicy{
			domOn.String(): {ProtectionMode: applications.ModeProtect, ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4},
		},
	}
	tpx := buildTproxydSidecar([]AppData{tpxApp})
	if !tpx.Enabled || len(tpx.ProtectHosts) != 1 || tpx.ProtectHosts[0] != "on.jxdr.cn" {
		t.Fatalf("tproxyd should include only domain with active policy, got %+v", tpx)
	}
	if len(tpx.Ports) != 2 || tpx.Ports[0] != 80 || tpx.Ports[1] != 443 {
		t.Fatalf("tproxyd ports mismatch: %v", tpx.Ports)
	}

	// 应用级 BYPASS 必须覆盖域名级 PROTECT，关闭透明牵引
	tpxApp.ProtectionMode = applications.ModeBypass
	tpxBypass := buildTproxydSidecar([]AppData{tpxApp})
	if tpxBypass.Enabled || len(tpxBypass.ProtectHosts) != 0 || len(tpxBypass.Ports) != 0 {
		t.Fatalf("tproxyd must stay disabled under app BYPASS, got %+v", tpxBypass)
	}

	// MIRROR：应用 OBSERVE，但其中一个域名覆盖为 OFF，仅收集启用检测的域名与端口
	mirApp := AppData{
		Code:           "mir-mixed",
		DeploymentMode: applications.DeployModeMirror,
		ProtectionMode: applications.ModeObserve,
		Domains: []applications.Domain{
			{ID: domOn, Hostname: "detect.jxdr.cn", NormalizedHostname: "detect.jxdr.cn", HTTPEnabled: true, HTTPPort: intPtr(80), Status: "ACTIVE"},
			{ID: domOff, Hostname: "skip.jxdr.cn", NormalizedHostname: "skip.jxdr.cn", HTTPEnabled: true, HTTPPort: intPtr(8082), Status: "ACTIVE"},
		},
		DomainPolicies: map[string]DomainPolicy{
			domOff.String(): {ProtectionMode: applications.ModeOff},
		},
	}
	mir := buildMirrorcapSidecar([]AppData{mirApp}, "node-1", []string{"eth1"}, MirrorcapDiscovery{})
	if !mir.Enabled || len(mir.Domains) != 1 || mir.Domains[0] != "detect.jxdr.cn" || len(mir.Ports) != 1 || mir.Ports[0] != 80 {
		t.Fatalf("mirrorcap should exclude domain overridden to OFF, got %+v", mir)
	}
}
