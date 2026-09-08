package response

import (
	"strings"
	"testing"
)

// wmTestConfig 构造启用的测试水印配置（默认白名单与 "_wm" 键）。
func wmTestConfig(t *testing.T, template string) *FileWatermarkConfig {
	t.Helper()
	cfg, err := NewFileWatermarkConfig(true, template, nil, "")
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	return cfg
}

// TestNewFileWatermarkConfig 配置校验：启用必填模板/禁控制字符/长度与条数护栏/
// 缺省白名单与 "_wm" 键兜底；未启用不强校验（零行为）。
func TestNewFileWatermarkConfig(t *testing.T) {
	// 未启用：模板为空也合法（不生效）
	cfg, err := NewFileWatermarkConfig(false, "", nil, "")
	if err != nil || cfg.Enabled {
		t.Fatalf("disabled: cfg=%+v err=%v", cfg, err)
	}
	// 启用缺省：默认白名单 4 项 + "_wm"
	cfg = wmTestConfig(t, "wm {ip}")
	if len(cfg.ContentTypes) != 4 || cfg.JSONKey != DefaultFileWatermarkJSONKey {
		t.Fatalf("defaults = %+v", cfg)
	}
	// 自定义白名单归一（大小写/空白/去重）与自定义键名
	cfg, err = NewFileWatermarkConfig(true, "t", []string{" Text/Plain ", "text/plain", "application/json"}, "wm2")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ContentTypes) != 2 || cfg.ContentTypes[0] != "text/plain" || cfg.JSONKey != "wm2" {
		t.Fatalf("normalize = %+v", cfg)
	}
	// 非法配置逐项报错
	bad := []struct {
		name     string
		template string
		types    []string
		jsonKey  string
	}{
		{"空模板", "", nil, ""},
		{"模板含换行", "a\nb", nil, ""},
		{"模板超长", strings.Repeat("x", 300), nil, ""},
		{"类型缺斜杠", "not-a-type", []string{"text"}, ""},
		{"类型超 v1 范围", "t", []string{"application/pdf"}, ""},
		{"类型超长", "t", []string{strings.Repeat("a", 120) + "/x"}, ""},
		{"键名含控制字符", "t", nil, "a\tb"},
		{"键名超长", "t", nil, strings.Repeat("k", 80)},
	}
	for _, tc := range bad {
		if _, err := NewFileWatermarkConfig(true, tc.template, tc.types, tc.jsonKey); err == nil {
			t.Errorf("%s: must fail", tc.name)
		}
	}
}

// TestFileWatermarkAllowsContentType 白名单判定：剥离参数、大小写归一；未启用恒 false。
func TestFileWatermarkAllowsContentType(t *testing.T) {
	cfg := wmTestConfig(t, "wm")
	for _, ct := range []string{"text/csv", "text/csv; charset=utf-8", "Application/JSON", " text/markdown "} {
		if !cfg.AllowsContentType(ct) {
			t.Fatalf("%q must be allowed", ct)
		}
	}
	for _, ct := range []string{"application/pdf", "text/html", "", "application/octet-stream"} {
		if cfg.AllowsContentType(ct) {
			t.Fatalf("%q must not be allowed", ct)
		}
	}
	disabled, _ := NewFileWatermarkConfig(false, "", nil, "")
	if disabled.AllowsContentType("text/csv") {
		t.Fatal("disabled config must allow nothing")
	}
}

// TestRenderFileWatermark 占位替换：四占位全换；匿名空身份替换为空串；未知占位原样保留。
func TestRenderFileWatermark(t *testing.T) {
	got := RenderFileWatermark("ip={ip} id={identity} t={time} d={domain} {unknown}", WatermarkVars{
		IP: "203.0.113.9", Identity: "auth:abc", Time: "2026-08-19T00:00:00Z", Domain: "shop.example.com",
	})
	want := "ip=203.0.113.9 id=auth:abc t=2026-08-19T00:00:00Z d=shop.example.com {unknown}"
	if got != want {
		t.Fatalf("render = %q want %q", got, want)
	}
	if got := RenderFileWatermark("[{identity}]", WatermarkVars{}); got != "[]" {
		t.Fatalf("empty identity render = %q", got)
	}
}

// TestApplyFileWatermarkText 文本族追加：无尾换行先补换行；markdown 用 HTML 注释；
// csv/plain 用 "# " 注释行；已有尾换行不产生空行。
func TestApplyFileWatermarkText(t *testing.T) {
	cfg := wmTestConfig(t, "wm-mark")
	// text/plain 无尾换行
	out, applied, err := ApplyFileWatermark([]byte("hello"), "text/plain", cfg, "wm-mark")
	if err != nil || !applied {
		t.Fatalf("plain: applied=%v err=%v", applied, err)
	}
	if string(out) != "hello\n# wm-mark" {
		t.Fatalf("plain out = %q", out)
	}
	// text/csv 已有尾换行：不产生空行
	out, applied, err = ApplyFileWatermark([]byte("a,b\n1,2\n"), "text/csv; charset=utf-8", cfg, "wm-mark")
	if err != nil || !applied {
		t.Fatalf("csv: applied=%v err=%v", applied, err)
	}
	if string(out) != "a,b\n1,2\n# wm-mark" {
		t.Fatalf("csv out = %q", out)
	}
	// text/markdown：HTML 注释（渲染不可见）
	out, applied, err = ApplyFileWatermark([]byte("# Title"), "text/markdown", cfg, "wm-mark")
	if err != nil || !applied {
		t.Fatalf("markdown: applied=%v err=%v", applied, err)
	}
	if string(out) != "# Title\n<!-- wm-mark -->" {
		t.Fatalf("markdown out = %q", out)
	}
}

// TestApplyFileWatermarkJSON JSON 族：顶层加 "_wm"（可配置键名）；数字字面量保留；
// 顶层数组/键已存在/空体/空文本跳过；非法 JSON 返回错误（调用方 FAIL_OPEN）。
func TestApplyFileWatermarkJSON(t *testing.T) {
	cfg := wmTestConfig(t, "wm-json")
	out, applied, err := ApplyFileWatermark([]byte(`{"amount": 100.50, "note": "x"}`), "application/json; charset=utf-8", cfg, "wm-json")
	if err != nil || !applied {
		t.Fatalf("json: applied=%v err=%v", applied, err)
	}
	s := string(out)
	if !strings.Contains(s, `"amount":100.50`) { // UseNumber 保留字面量
		t.Fatalf("number literal drift: %s", s)
	}
	if !strings.Contains(s, `"_wm":"wm-json"`) || !strings.Contains(s, `"note":"x"`) {
		t.Fatalf("watermark field missing: %s", s)
	}
	// 自定义键名
	cfg2, err := NewFileWatermarkConfig(true, "t", []string{"application/json"}, "watermark")
	if err != nil {
		t.Fatal(err)
	}
	out, applied, err = ApplyFileWatermark([]byte(`{"a":1}`), "application/json", cfg2, "mk")
	if err != nil || !applied || !strings.Contains(string(out), `"watermark":"mk"`) {
		t.Fatalf("custom key: applied=%v err=%v out=%s", applied, err, out)
	}
	// 顶层数组：无处加字段，跳过
	if _, applied, err := ApplyFileWatermark([]byte(`[1,2]`), "application/json", cfg, "mk"); err != nil || applied {
		t.Fatalf("array top: applied=%v err=%v", applied, err)
	}
	// 键已存在：不覆盖既有数据
	if out, applied, err := ApplyFileWatermark([]byte(`{"_wm":"origin"}`), "application/json", cfg, "mk"); err != nil || applied || string(out) != `{"_wm":"origin"}` {
		t.Fatalf("existing key: applied=%v err=%v out=%s", applied, err, out)
	}
	// 非法 JSON：返回错误（FAIL_OPEN 由调用方执行）
	if _, applied, err := ApplyFileWatermark([]byte(`{bad`), "application/json", cfg, "mk"); err == nil || applied {
		t.Fatalf("bad json: applied=%v err=%v", applied, err)
	}
	// 空体/空文本/未白名单：跳过
	if _, applied, _ := ApplyFileWatermark(nil, "application/json", cfg, "mk"); applied {
		t.Fatal("empty body must skip")
	}
	if _, applied, _ := ApplyFileWatermark([]byte("{}"), "application/json", cfg, ""); applied {
		t.Fatal("empty text must skip")
	}
	if _, applied, _ := ApplyFileWatermark([]byte("x"), "application/pdf", cfg, "mk"); applied {
		t.Fatal("non-whitelisted must skip")
	}
}

// JSON 下载水印尾随数据回归（LOW-G11）：与 ApplyJSON 同口径——首个值后的尾随数据
// 按解析失败返回错误（重编码只输出第一个值，尾随字节会被静默丢弃；FAIL_OPEN 直通原响应）。
func TestApplyFileWatermarkJSONTrailingData(t *testing.T) {
	cfg := wmTestConfig(t, "wm-json")
	for _, body := range []string{`{"a":1} {"b":2}`, `{"a":1} garbage`} {
		out, applied, err := ApplyFileWatermark([]byte(body), "application/json", cfg, "wm")
		if err == nil || applied {
			t.Fatalf("trailing data must error (FAIL_OPEN passthrough): applied=%v err=%v", applied, err)
		}
		if string(out) != body {
			t.Fatalf("error path must return original body, got %q", out)
		}
	}
	// 仅尾随空白：合法，水印照常注入
	out, applied, err := ApplyFileWatermark([]byte("{\"a\":1}\n"), "application/json", cfg, "wm")
	if err != nil || !applied || !strings.Contains(string(out), `"_wm":"wm"`) {
		t.Fatalf("trailing whitespace: applied=%v err=%v out=%s", applied, err, out)
	}
}
