// publisher_license_test.go 离线授权发布门控单元测试：
// 授权无效 → 生成配置无 jiuzhang_guard / 无 waf handler、应用强制 BYPASS（纯透传）；
// 授权有效且 max_qps>0 → guard JSON 携带 license_max_qps（0 不注入）；
// 快照 mode 与实发配置一致；调用方 GuardConfig 不被污染。
package gatewayconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// licenseTestApps 单应用生成输入（PROTECT，含域名与源站）。
func licenseTestApps() []AppData {
	return []AppData{{
		AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect,
		Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
		Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
	}}
}

// licenseTestSnapshot 与 licenseTestApps 平行的发布快照（buildSnapshot 产出形态）。
func licenseTestSnapshot() map[string]interface{} {
	return map[string]interface{}{"apps": []map[string]interface{}{
		{"code": "shop", "mode": applications.ModeProtect, "domains": 1, "upstreams": 1},
	}}
}

func TestApplyLicenseStateInvalidForcesPassthrough(t *testing.T) {
	snap := licenseTestSnapshot()
	apps, guard := applyLicenseState(licenseTestApps(), testGuardConfig(), snap, false, 0)

	if guard != nil {
		t.Fatal("无效授权 Guard 必须为 nil（不注入 jiuzhang_guard）")
	}
	if apps[0].ProtectionMode != applications.ModeBypass {
		t.Fatalf("无效授权应用应强制 BYPASS，got %s", apps[0].ProtectionMode)
	}
	// 快照 mode 同步修正（版本记录与实发配置一致）
	items := snap["apps"].([]map[string]interface{})
	if items[0]["mode"] != applications.ModeBypass {
		t.Fatalf("快照 mode 应同步为 BYPASS，got %v", items[0]["mode"])
	}

	// 生成配置：无 guard、无 waf handler、无 SecRuleEngine；保留 RequestID 与 reverse_proxy
	gen, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"jiuzhang_guard", `"handler":"waf"`, "SecRuleEngine"} {
		if strings.Contains(gen.JSON, banned) {
			t.Errorf("透传配置不得包含 %q", banned)
		}
	}
	for _, want := range []string{"reverse_proxy", "X-Request-Id"} {
		if !strings.Contains(gen.JSON, want) {
			t.Errorf("透传配置应保留 %q", want)
		}
	}
}

func TestApplyLicenseStateValidInjectsMaxQPS(t *testing.T) {
	snap := licenseTestSnapshot()
	base := testGuardConfig()
	apps, guard := applyLicenseState(licenseTestApps(), base, snap, true, 500)

	if guard == nil || guard.LicenseMaxQPS != 500 {
		t.Fatalf("有效授权且 max_qps=500 应注入 LicenseMaxQPS=500，got %+v", guard)
	}
	// 调用方 GuardConfig 不被污染（拷贝语义；回滚覆盖快照复用安全）
	if base.LicenseMaxQPS != 0 {
		t.Fatalf("不得修改调用方 GuardConfig，got %d", base.LicenseMaxQPS)
	}
	// 有效授权：应用模式与快照不被改动
	if apps[0].ProtectionMode != applications.ModeProtect {
		t.Fatalf("有效授权不应改动应用模式，got %s", apps[0].ProtectionMode)
	}
	if snap["apps"].([]map[string]interface{})[0]["mode"] != applications.ModeProtect {
		t.Fatal("有效授权不应改动快照 mode")
	}

	gen, err := Generate(GenerateInput{
		Apps:        apps,
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gen.JSON, `"license_max_qps":500`) {
		t.Error("guard JSON 应携带 license_max_qps=500")
	}

	// max_qps=0（不限制）：不注入，JSON 与历史一致
	_, guard0 := applyLicenseState(licenseTestApps(), testGuardConfig(), licenseTestSnapshot(), true, 0)
	if guard0 == nil || guard0.LicenseMaxQPS != 0 {
		t.Fatalf("max_qps=0 不应注入配额，got %+v", guard0)
	}
	gen, err = Generate(GenerateInput{
		Apps:        licenseTestApps(),
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       guard0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gen.JSON, "license_max_qps") {
		t.Error("max_qps=0 时 JSON 不得出现 license_max_qps")
	}
}

func TestApplyLicenseStateNilGuardValid(t *testing.T) {
	// 未装配 guard provider（回滚/兼容形态）：有效授权不panic、应用模式不变
	apps, guard := applyLicenseState(licenseTestApps(), nil, licenseTestSnapshot(), true, 500)
	if guard != nil {
		t.Fatal("无 guard 时不应凭空生成 GuardConfig")
	}
	if apps[0].ProtectionMode != applications.ModeProtect {
		t.Fatalf("应用模式不应改动，got %s", apps[0].ProtectionMode)
	}
}
