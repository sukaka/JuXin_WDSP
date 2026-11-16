package guardconfig

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestInlineHTMLWatermarkSetting(t *testing.T) {
	base := map[string]string{
		"api_file_watermark_enabled":       "true",
		"api_file_watermark_template":      "trace {ip}",
		"api_file_watermark_content_types": "text/html",
	}
	wm, err := parseFileWatermarkSettings(base)
	if err != nil || wm == nil || wm.IncludeInlineHTML {
		t.Fatalf("default inline HTML must be off: wm=%+v err=%v", wm, err)
	}
	base["api_file_watermark_include_inline_html"] = " TRUE "
	wm, err = parseFileWatermarkSettings(base)
	if err != nil || !wm.IncludeInlineHTML {
		t.Fatalf("inline HTML setting not applied: wm=%+v err=%v", wm, err)
	}
	base["api_file_watermark_include_inline_html"] = "invalid"
	if _, err := parseFileWatermarkSettings(base); err == nil {
		t.Fatal("invalid inline HTML switch must fail publication")
	}
}

func TestInlineHTMLWatermarkGatewayRuntimeMapping(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"api_file_watermark_enabled":             "true",
		"api_file_watermark_template":            "trace",
		"api_file_watermark_include_inline_html": "true",
	}); err != nil {
		t.Fatal(err)
	}
	if cfg.APIFileWatermark == nil || !cfg.APIFileWatermark.IncludeInlineHTML {
		t.Fatalf("runtime mapping=%+v", cfg.APIFileWatermark)
	}
}
