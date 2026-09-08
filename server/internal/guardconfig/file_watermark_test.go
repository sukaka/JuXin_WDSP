// file_watermark_test.go 文件下载水印 v1 下发单测（W12-GW / P2-01 最小可行子集，
// 纯函数不依赖数据库）：api_file_watermark_* 键组解析/校验/缺省/非法值如实报错。
package guardconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestParseFileWatermarkSettings 合法键组全量注入；未启用/未配置不下发；
// 白名单归一（小写/去重/去空项）；自定义 JSON 键名透传。
func TestParseFileWatermarkSettings(t *testing.T) {
	// 未配置任何键：nil（不下发，网关零行为变化）
	wm, err := parseFileWatermarkSettings(map[string]string{})
	if err != nil || wm != nil {
		t.Fatalf("empty: wm=%+v err=%v", wm, err)
	}
	// enabled=false：不下发
	wm, err = parseFileWatermarkSettings(map[string]string{"api_file_watermark_enabled": "false"})
	if err != nil || wm != nil {
		t.Fatalf("disabled: wm=%+v err=%v", wm, err)
	}
	// 启用 + 模板：缺省白名单/键名不下发（网关默认表与 "_wm" 兜底，ContentTypes/JSONKey 留空）
	wm, err = parseFileWatermarkSettings(map[string]string{
		"api_file_watermark_enabled":  "true",
		"api_file_watermark_template": "wm ip={ip} id={identity}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if wm == nil || !wm.Enabled || wm.TextTemplate != "wm ip={ip} id={identity}" ||
		len(wm.ContentTypes) != 0 || wm.JSONKey != "" {
		t.Fatalf("wm = %+v", wm)
	}
	// 全量键：白名单归一 + 自定义键名
	wm, err = parseFileWatermarkSettings(map[string]string{
		"api_file_watermark_enabled":       " TRUE ",
		"api_file_watermark_template":      "d={domain} t={time}",
		"api_file_watermark_content_types": " Text/Plain , text/plain,,application/json ",
		"api_file_watermark_json_key":      "watermark",
	})
	if err != nil {
		t.Fatal(err)
	}
	if wm == nil || len(wm.ContentTypes) != 2 || wm.ContentTypes[0] != "text/plain" ||
		wm.ContentTypes[1] != "application/json" || wm.JSONKey != "watermark" {
		t.Fatalf("wm = %+v", wm)
	}
}

// TestParseFileWatermarkSettingsInvalid 非法取值如实报错（中止发布，不静默回退）。
func TestParseFileWatermarkSettingsInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"enabled 非法词": {"api_file_watermark_enabled": "yes"},
		"启用缺模板":       {"api_file_watermark_enabled": "true"},
		"模板含换行": {
			"api_file_watermark_enabled":  "true",
			"api_file_watermark_template": "a\nb",
		},
		"模板超长": {
			"api_file_watermark_enabled":  "true",
			"api_file_watermark_template": strings.Repeat("x", 300),
		},
		"类型缺斜杠": {
			"api_file_watermark_enabled":       "true",
			"api_file_watermark_template":      "wm",
			"api_file_watermark_content_types": "text",
		},
		"类型超 v1 范围": {
			"api_file_watermark_enabled":       "true",
			"api_file_watermark_template":      "wm",
			"api_file_watermark_content_types": "text/plain,application/pdf",
		},
		"类型全空项": {
			"api_file_watermark_enabled":       "true",
			"api_file_watermark_template":      "wm",
			"api_file_watermark_content_types": " , ,",
		},
		"键名含控制字符": {
			"api_file_watermark_enabled":  "true",
			"api_file_watermark_template": "wm",
			"api_file_watermark_json_key": "a\tb",
		},
		"键名超长": {
			"api_file_watermark_enabled":  "true",
			"api_file_watermark_template": "wm",
			"api_file_watermark_json_key": strings.Repeat("k", 80),
		},
	}
	for name, kv := range cases {
		if _, err := parseFileWatermarkSettings(kv); err == nil {
			t.Errorf("%s: %v must fail", name, kv)
		}
	}
}

// TestApplyGatewayRuntimeSettingsFileWatermark 经 applyGatewayRuntimeSettings 注入
// GuardConfig（与 gateway_runtime 组其余键同通路）；非法键组中止发布。
func TestApplyGatewayRuntimeSettingsFileWatermark(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{}
	err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"identity_salt":                "s3cret",
		"api_file_watermark_enabled":   "true",
		"api_file_watermark_template":  "wm ip={ip}",
		"api_file_watermark_json_key":  "_trace",
		"api_file_watermark_empty_key": "", // 空串视同缺省
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIFileWatermark == nil || !cfg.APIFileWatermark.Enabled ||
		cfg.APIFileWatermark.TextTemplate != "wm ip={ip}" || cfg.APIFileWatermark.JSONKey != "_trace" {
		t.Fatalf("cfg.APIFileWatermark = %+v", cfg.APIFileWatermark)
	}
	// 缺省：不下发（nil）
	empty := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(empty, map[string]string{"identity_salt": "s3cret"}); err != nil {
		t.Fatal(err)
	}
	if empty.APIFileWatermark != nil {
		t.Fatalf("default must not deliver watermark: %+v", empty.APIFileWatermark)
	}
	// 非法键组：如实报错（中止发布）
	bad := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(bad, map[string]string{
		"api_file_watermark_enabled": "true",
	}); err == nil {
		t.Fatal("enabled without template must fail")
	}
}
