// guard_file_watermark_test.go 文件下载水印 v1 下发键单测（W12-GW / P2-01 最小可行子集）：
// api_file_watermark 仅 WDSP 开启且配置时注入处理器 JSON；关闭或未配置不出现该键
// （与既有下发面最小纪律一致；json tag 为跨分片契约）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildGuardHandlerFileWatermark 水印段注入矩阵：开启+配置注入且 tag 与契约一致；
// WDSP 关闭 / 未配置一律不注入。
func TestBuildGuardHandlerFileWatermark(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIFileWatermark = &GuardFileWatermark{
			Enabled:      true,
			TextTemplate: "wm ip={ip} id={identity}",
			ContentTypes: []string{"text/plain", "application/json"},
			JSONKey:      "_trace",
		}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启 + 配置：段注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_file_watermark"`,
		`"enabled":true`,
		`"text_template":"wm ip={ip} id={identity}"`,
		`"content_types":["text/plain","application/json"]`,
		`"json_key":"_trace"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), `"api_file_watermark"`) {
		t.Errorf("api_file_watermark must not be injected when api dynamic protection disabled")
	}

	// 开启但未配置：不注入（网关响应侧零行为变化）
	unconfigured := testGuardConfig()
	unconfigured.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(unconfigured, app, 0))
	if strings.Contains(string(raw), `"api_file_watermark"`) {
		t.Errorf("api_file_watermark must be omitted when unconfigured")
	}

	// 缺省字段（ContentTypes/JSONKey 空）：omitempty 不下发，网关默认表/"_wm" 兜底
	defaults := testGuardConfig()
	defaults.APIDynamicProtection = true
	defaults.APIFileWatermark = &GuardFileWatermark{Enabled: true, TextTemplate: "wm"}
	raw, _ = json.Marshal(buildGuardHandler(defaults, app, 0))
	j = string(raw)
	if !strings.Contains(j, `"api_file_watermark":{"enabled":true,"text_template":"wm"}`) {
		t.Errorf("default fields must be omitted: %s", j)
	}
}
