package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeNext_StaticAndHTMLSuppressedButGETJSONDiscovered 验证：
//  1. 带 Cookie 的静态资源（图片/图标/JS/压缩包）不再因 identity.cookie_present INFO 明细触发 API 事件；
//  2. 带 Cookie 的普通 HTML 页面（GET /products → text/html）不触发 API 事件；
//  3. 无 Accept: application/json 与无 /api/ 前缀的真实 GET JSON 接口经轻量响应头窥视自动升格并发现；
//  4. 无静态后缀的动态导出接口（Content-Disposition: attachment）保留为 FILE_DOWNLOAD API；
//  5. 404 JSON 错误响应不将普通探测路径误判为 API。
func TestServeNext_StaticAndHTMLSuppressedButGETJSONDiscovered(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	// 1) 带 Cookie 的静态资源：全部不产出 API 事件
	staticCases := []struct {
		path string
		ct   string
	}{
		{"/favicon_128x128.ico", "image/x-icon"},
		{"/备案图标.png", "image/png"},
		{"/astro/page.BsuiZEAU.js", "application/javascript"},
		{"/downloads/release-1.0.zip", "application/zip"},
	}
	for _, tc := range staticCases {
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", tc.ct)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("static-bytes"))
			return nil
		})
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Cookie", "sid=browser-session")
		if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("%s serveNext err: %v", tc.path, err)
		}
	}

	// 2) 带 Cookie 的普通 HTML 网页：不产出 API 事件
	htmlNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>products</body></html>"))
		return nil
	})
	htmlReq := httptest.NewRequest(http.MethodGet, "/products", nil)
	htmlReq.Header.Set("Cookie", "sid=browser-session")
	if err := g.serveNext(httptest.NewRecorder(), htmlReq, htmlNext); err != nil {
		t.Fatalf("/products serveNext err: %v", err)
	}

	// 3) 404 JSON 错误页对无信号路径：不误升格为 API
	notFoundNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
		return nil
	})
	notFoundReq := httptest.NewRequest(http.MethodGet, "/nonexistent-page", nil)
	notFoundReq.Header.Set("Cookie", "sid=browser-session")
	if err := g.serveNext(httptest.NewRecorder(), notFoundReq, notFoundNext); err != nil {
		t.Fatalf("/nonexistent-page serveNext err: %v", err)
	}

	// 4) 前端 fetch 无 Accept: application/json 的真实 GET JSON API：响应头窥视升格为 API
	jsonNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[]}`))
		return nil
	})
	jsonReq := httptest.NewRequest(http.MethodGet, "/orders/list", nil)
	jsonReq.Header.Set("Accept", "*/*")
	jsonReq.Header.Set("Cookie", "sid=browser-session")
	if err := g.serveNext(httptest.NewRecorder(), jsonReq, jsonNext); err != nil {
		t.Fatalf("/orders/list serveNext err: %v", err)
	}

	// 5) 动态导出接口（无静态后缀 + Content-Disposition attachment）：升格为 FILE_DOWNLOAD API
	exportNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="orders-export.zip"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PK\x03\x04"))
		return nil
	})
	exportReq := httptest.NewRequest(http.MethodGet, "/reports/export", nil)
	exportReq.Header.Set("Cookie", "sid=browser-session")
	if err := g.serveNext(httptest.NewRecorder(), exportReq, exportNext); err != nil {
		t.Fatalf("/reports/export serveNext err: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want exactly 2 API events (GET /orders/list and GET /reports/export), got %d: %+v", len(recs), recs)
	}
	if recs[0].PathTemplate != "/orders/list" || !recs[0].IsAPI || recs[0].Protocol != "REST_JSON" || recs[0].ResponseStatus != 200 {
		t.Fatalf("unexpected first record: %+v", recs[0])
	}
	if recs[1].PathTemplate != "/reports/export" || !recs[1].IsAPI || recs[1].Protocol != "FILE_DOWNLOAD" || recs[1].ResponseStatus != 200 {
		t.Fatalf("unexpected second record: %+v", recs[1])
	}
}
