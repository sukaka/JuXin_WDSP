// guard_file_signature_compliance_test.go 文件签名 v1 与文件合规规则下发键单测
// （W13-GW / P2-02 / P2-03）：api_file_signature 仅 WDSP 开启且启用时注入处理器 JSON；
// api_file_compliance_rules 仅 WDSP 开启且非空时注入；关闭或未配置一律不出现
// （与既有下发面最小纪律一致；json tag 为跨分片契约）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildGuardHandlerFileSignature 签名段注入矩阵：开启+启用注入且 tag 与契约一致；
// WDSP 关闭 / 未配置 / enabled=false 一律不注入。
func TestBuildGuardHandlerFileSignature(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIFileSignature = &GuardFileSignature{
			Enabled: true,
			KID:     "k2026",
			KeyHex:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启 + 启用：段注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_file_signature"`,
		`"enabled":true`,
		`"kid":"k2026"`,
		`"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), `"api_file_signature"`) {
		t.Errorf("api_file_signature must not be injected when api dynamic protection disabled")
	}

	// 开启但未配置：不注入（网关响应侧零行为变化）
	unconfigured := testGuardConfig()
	unconfigured.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(unconfigured, app, 0))
	if strings.Contains(string(raw), `"api_file_signature"`) {
		t.Errorf("api_file_signature must be omitted when unconfigured")
	}

	// enabled=false：不注入
	disabled := testGuardConfig()
	disabled.APIDynamicProtection = true
	disabled.APIFileSignature = &GuardFileSignature{Enabled: false, KID: "k2026", KeyHex: "aa"}
	raw, _ = json.Marshal(buildGuardHandler(disabled, app, 0))
	if strings.Contains(string(raw), `"api_file_signature"`) {
		t.Errorf("api_file_signature must be omitted when enabled=false")
	}
}

// TestBuildGuardHandlerFileComplianceRules 合规规则注入矩阵：开启+非空注入且 tag 与契约一致；
// WDSP 关闭 / 空规则一律不注入。
func TestBuildGuardHandlerFileComplianceRules(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "PROTECT"
		g.APIFileComplianceRules = []GuardFileComplianceRule{
			{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件"},
			{Direction: "DOWNLOAD", Match: "FILENAME_REGEX", Value: `(?i)\.scr$`, Action: "OBSERVE"},
		}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启 + 非空：段注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_file_compliance_rules"`,
		`"direction":"UPLOAD"`,
		`"match":"EXT"`,
		`"value":"exe"`,
		`"action":"BLOCK"`,
		`"reason":"可执行文件"`,
		`"match":"FILENAME_REGEX"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), `"api_file_compliance_rules"`) {
		t.Errorf("api_file_compliance_rules must not be injected when api dynamic protection disabled")
	}

	// 开启但空规则：不注入（网关合规检测零行为）
	empty := testGuardConfig()
	empty.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	if strings.Contains(string(raw), `"api_file_compliance_rules"`) {
		t.Errorf("api_file_compliance_rules must be omitted when empty")
	}
}
