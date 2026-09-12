// apifilewm_test.go 文件下载水印 v1 端到端（W12-GW / P2-01 最小可行子集）：
// 文本族/JSON 下载响应水印追加与 Content-Length 修正、占位替换（ip/identity/time/domain）、
// file.watermark_applied INFO 明细（不落水印内容）、未启用/未白名单/无下载观测零行为、
// 与 MASK 共存顺序（先 mask 后水印）、JSON 解析失败 FAIL_OPEN 直通、Range 分段跳过。
package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

// newFileWatermarkTestGuard 构造启用文件水印的测试 Guard（编译水印配置，绕过 Provision）。
func newFileWatermarkTestGuard(t *testing.T, mode, template string) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	cfg, err := response.NewFileWatermarkConfig(true, template, nil, "")
	if err != nil {
		t.Fatalf("new watermark config: %v", err)
	}
	g.apiFileWatermark = cfg
	return g, logPath
}

// wmDownloadRequest 构造触发下载的 API 请求（身份凭据供 {identity} 占位）。
func wmDownloadRequest(id string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://shop.example.com/v1/orders/export", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wm-e2e-token-0123456789abcdef")
	req.Header.Set("X-Request-Id", id)
	req.RemoteAddr = "203.0.113.9:5001"
	return req
}

// 文本族下载（text/csv）：文件尾追加 "# " 注释行、占位替换、Content-Length 修正、
// 事件产 file.watermark_applied INFO 明细（证据不含水印内容）。
func TestServeNext_FileWatermarkTextDownload(t *testing.T) {
	g, logPath := newFileWatermarkTestGuard(t, "OBSERVE",
		"wm ip={ip} id={identity} t={time} d={domain}")

	const payload = "order,amount\nA1,100\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-csv-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	// 水印行追加（原体已含尾换行，不产生空行）；四占位全替换
	s := string(body)
	if !strings.HasPrefix(s, payload) {
		t.Fatalf("original content must be preserved: %q", s)
	}
	marker := strings.TrimPrefix(s, payload)
	if !strings.HasPrefix(marker, "# wm ip=203.0.113.9 id=auth:") {
		t.Fatalf("watermark marker = %q", marker)
	}
	if !strings.Contains(marker, "d=shop.example.com") || !strings.Contains(marker, "t=20") {
		t.Fatalf("placeholders not substituted: %q", marker)
	}
	if strings.Contains(marker, "{") || strings.Contains(marker, "wm-e2e-token") {
		t.Fatalf("placeholder left or credential leaked: %q", marker)
	}
	// Content-Length 修正为加水印后长度
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("content-length = %q, want %d", cl, len(body))
	}

	// 事件：file.watermark_applied INFO 明细 + 下载观测保留；证据不落水印内容
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID != "file.watermark_applied" {
			continue
		}
		found = true
		if d.Category != "INFO" || d.Severity != "INFO" {
			t.Fatalf("discipline broken: %s/%s", d.Category, d.Severity)
		}
		if d.Evidence["filename"] != "orders.csv" || d.Evidence["mime"] != "text/csv" {
			t.Fatalf("evidence = %+v", d.Evidence)
		}
		for k, v := range d.Evidence {
			if strings.Contains(v, "wm ip=") || strings.Contains(v, "203.0.113.9") {
				t.Fatalf("evidence must not contain watermark content: %s=%s", k, v)
			}
		}
	}
	if !found {
		t.Fatalf("file.watermark_applied missing: %+v", recs[0].Details)
	}
	if len(recs[0].FileObservations) != 1 || recs[0].FileObservations[0].Direction != "DOWNLOAD" {
		t.Fatalf("download observation must stay: %+v", recs[0].FileObservations)
	}
}

// JSON 下载：顶层加 "_wm" 字段、Content-Length 修正、失效 ETag 清除。
func TestServeNext_FileWatermarkJSONDownload(t *testing.T) {
	g, _ := newFileWatermarkTestGuard(t, "OBSERVE", "wm ip={ip}")

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.json"`)
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true,"amount":100.50}`)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-json-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, `"_wm":"wm ip=203.0.113.9"`) ||
		!strings.Contains(s, `"ok":true`) || !strings.Contains(s, `"amount":100.50`) {
		t.Fatalf("json watermark body = %s", s)
	}
	if resp.Header.Get("ETag") != "" {
		t.Fatalf("stale ETag must be removed after watermark: %v", resp.Header)
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("content-length = %q, want %d", cl, len(body))
	}
}

// Markdown 下载：HTML 注释行（渲染不可见）。
func TestServeNext_FileWatermarkMarkdownDownload(t *testing.T) {
	g, _ := newFileWatermarkTestGuard(t, "OBSERVE", "wm-note")

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/markdown")
		w.Header().Set("Content-Disposition", `attachment; filename="readme.md"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "# Readme")
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-md-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "# Readme\n<!-- wm-note -->" {
		t.Fatalf("markdown watermark body = %q", body)
	}
}

// 未启用（无配置）：体逐字节不变、无水印明细、下载观测照常（直通路径同样计数）。
func TestServeNext_FileWatermarkDisabledZeroChange(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	const payload = "a,b\n1,2\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-off-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("disabled watermark must not touch body: %q", body)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatalf("disabled watermark must not produce detail: %+v", recs[0].Details)
		}
	}
	if len(recs[0].FileObservations) != 1 {
		t.Fatalf("download observation must stay: %+v", recs[0].FileObservations)
	}
}

// 非白名单类型（application/pdf）：直通不改写、无水印明细（下载观测照常）。
func TestServeNext_FileWatermarkTypeNotWhitelisted(t *testing.T) {
	g, logPath := newFileWatermarkTestGuard(t, "OBSERVE", "wm ip={ip}")

	const payload = "FAKE-PDF-BYTES"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", `attachment; filename="statement.pdf"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-pdf-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("non-whitelisted type must not be modified: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("pdf must not be watermarked")
		}
	}
}

// 无 Content-Disposition（普通文本响应，非下载观测命中）：零行为。
func TestServeNext_FileWatermarkNoDownloadObservation(t *testing.T) {
	g, logPath := newFileWatermarkTestGuard(t, "OBSERVE", "wm ip={ip}")

	const payload = "plain text response"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-nodl-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("non-download response must not be modified: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("non-download must not be watermarked")
		}
	}
}

// 与 MASK 共存（PROTECT）：先 mask 后水印——脱敏产物上追加 "_wm"，
// 两条明细并存（response.mask_applied + file.watermark_applied）。
func TestServeNext_FileWatermarkAfterMask(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
		{EndpointKey: "POST /v1/orders/export", FieldPath: "phone", DataType: "phone", Algorithm: "MASK"},
	})
	cfg, err := response.NewFileWatermarkConfig(true, "wm ip={ip}", nil, "")
	if err != nil {
		t.Fatalf("new watermark config: %v", err)
	}
	g.apiFileWatermark = cfg

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="users.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"phone":"13800138000","ok":true}`)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-mask-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	s := string(body)
	// 先 mask：手机号已脱敏；后水印："_wm" 盖在脱敏产物上
	if strings.Contains(s, "13800138000") || !strings.Contains(s, "138****8000") {
		t.Fatalf("mask must run before watermark: %s", s)
	}
	if !strings.Contains(s, `"_wm":"wm ip=203.0.113.9"`) {
		t.Fatalf("watermark must apply on masked body: %s", s)
	}
	var maskApplied, wmApplied bool
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		switch d.RuleID {
		case "response.mask_applied":
			maskApplied = true
		case "file.watermark_applied":
			wmApplied = true
		}
	}
	if !maskApplied || !wmApplied {
		t.Fatalf("mask=%v watermark=%v", maskApplied, wmApplied)
	}
}

// JSON 解析失败（Content-Type 声明 JSON 但体非法）：FAIL_OPEN 直通原体，不 panic。
func TestServeNext_FileWatermarkFailOpenBadJSON(t *testing.T) {
	g, logPath := newFileWatermarkTestGuard(t, "OBSERVE", "wm ip={ip}")

	const payload = `{bad json`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="data.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-badjson-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("bad json must fail-open passthrough: %q", body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("failed watermark must not be reported as applied")
		}
	}
}

// Range 分段下载（206 + Content-Range）：跳过水印（防破坏断点续传重组），原体交付。
func TestServeNext_FileWatermarkPartialContentSkipped(t *testing.T) {
	g, logPath := newFileWatermarkTestGuard(t, "OBSERVE", "wm ip={ip}")

	const payload = "chunk-0-bytes"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="big.csv"`)
		w.Header().Set("Content-Range", "bytes 0-12/100")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-wm-range-1"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPartialContent || string(body) != payload {
		t.Fatalf("partial content must pass through: status=%d body=%q", resp.StatusCode, body)
	}
	for _, d := range readAPIRecords(t, logPath)[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("partial content must not be watermarked")
		}
	}
}
