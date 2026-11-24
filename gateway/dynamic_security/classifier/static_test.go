package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestIsStaticAssetPath(t *testing.T) {
	staticCases := []struct {
		method string
		path   string
	}{
		{"GET", "/favicon_128x128.ico"},
		{"GET", "/favicon_264x263.png"},
		{"GET", "/备案图标.png"},
		{"GET", "/astro/page.BsuiZEAU.js"},
		{"GET", "/astro/TheFooter.CYhiSQ7R.css"},
		{"GET", "/assets/app.js.map"},
		{"GET", "/fonts/inter.woff2"},
		{"GET", "/downloads/release-v1.0.zip"},
		{"GET", "/downloads/release-v1.0.tar.gz"},
		{"GET", "/downloads/release-v1.0.tar.xz"},
		{"GET", "/files/manual.pdf"},
		{"GET", "/files/archive.7z"},
		{"GET", "/files/backup.rar"},
		{"GET", "/media/demo.mp4"},
		{"HEAD", "/v1/assets/logo.PNG?v=123"},
		{"GET", "/robots.txt"},
		{"GET", "/sitemap.xml"},
		{"GET", "/.well-known/acme-challenge/abc"},
		{"GET", "/index.html"},
	}
	for _, tc := range staticCases {
		if !IsStaticAssetPath(tc.method, tc.path) {
			t.Fatalf("expected static asset for %s %s", tc.method, tc.path)
		}
	}

	nonStaticCases := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/users.json"},
		{"GET", "/api/v1/feed.xml"},
		{"GET", "/legacy/order.do"},
		{"GET", "/service/pay.action"},
		{"GET", "/ajax/check.php"},
		{"GET", "/api/v1/reports/export"},
		{"GET", "/users/{id}"},
		{"GET", "/products"},
		{"POST", "/api/v1/upload/avatar.png"},
		{"PUT", "/api/v1/objects/archive.zip"},
		{"DELETE", "/api/v1/files/demo.js"},
	}
	for _, tc := range nonStaticCases {
		if IsStaticAssetPath(tc.method, tc.path) {
			t.Fatalf("unexpected static asset for %s %s", tc.method, tc.path)
		}
	}
}

func TestStaticFilterConfigCustomRules(t *testing.T) {
	cfg := StaticFilterConfig{
		ExcludeExtensions:   []string{".png", ".js", ".tar.gz"},
		UseCustomExtensions: true,
		ExcludePathPrefixes: []string{"/astro", "/_next/static"},
		IncludePathPrefixes: []string{"/api/public-assets"},
	}
	if ok, reason := cfg.MatchStaticPath("GET", "/astro/TheFooter.CYhiSQ7R"); !ok || reason != "exclude_path_prefix:/astro" {
		t.Fatalf("expected /astro excluded, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := cfg.MatchStaticPath("GET", "/astrology/chart"); ok {
		t.Fatal("segment prefix /astro must not match /astrology/chart")
	}
	if ok, _ := cfg.MatchStaticPath("GET", "/api/public-assets/logo.png"); ok {
		t.Fatal("include whitelist prefix must override static extension")
	}
	if ok, _ := cfg.MatchStaticPath("GET", "/downloads/archive.zip"); ok {
		t.Fatal("custom extension set without .zip should not exclude .zip")
	}
	if ok, reason := cfg.MatchStaticPath("GET", "/pkg/a.tar.gz"); !ok || reason != "static_extension:.tar.gz" {
		t.Fatalf("expected .tar.gz excluded, got ok=%v reason=%q", ok, reason)
	}
}

func TestClassifyStaticAndDynamicDownload(t *testing.T) {
	// 即使路径带 /v1/ 且带 Accept: application/json，静态图片/JS/压缩包仍应归类为 NON_API
	for _, p := range []*parser.Parsed{
		{Method: "GET", RawPath: "/v1/assets/logo.png", Headers: map[string]string{"accept": "application/json"}},
		{Method: "GET", RawPath: "/api/docs/swagger-ui.js", Headers: map[string]string{"accept": "application/json"}},
		{Method: "GET", RawPath: "/v1/downloads/pkg.zip", Headers: map[string]string{"accept": "application/json"}},
	} {
		r := Classify(p)
		if r.IsAPI || r.Level != LevelNonAPI {
			t.Fatalf("%s should be NON_API: %+v", p.RawPath, r)
		}
		r2 := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "application/json"})
		if r2.IsAPI || r2.Level != LevelNonAPI {
			t.Fatalf("%s with json response should still stay NON_API: %+v", p.RawPath, r2)
		}
	}

	// 无后缀路径但响应是图片 / SVG / JS / ZIP（无附件头）→ NON_API
	for _, ct := range []string{"image/png", "image/svg+xml", "application/javascript", "text/css", "application/zip", "font/woff2"} {
		p := &parser.Parsed{Method: "GET", RawPath: "/api/theme/bundle", Headers: map[string]string{"accept": "*/*"}}
		r := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: ct})
		if r.IsAPI || r.Level != LevelNonAPI || !containsSignal(r.Signals, "response_static_mime") {
			t.Fatalf("static mime %s should be NON_API: %+v", ct, r)
		}
	}

	// 动态导出接口（无静态后缀 + Content-Disposition attachment）→ 保持识别为 API
	exportReq := &parser.Parsed{Method: "GET", RawPath: "/api/v1/reports/export"}
	exportRes := ClassifyWithResponse(exportReq, &ResponseEvidence{
		Status:             200,
		ContentType:        "application/zip",
		ContentDisposition: `attachment; filename="orders-2026.zip"`,
	})
	if !exportRes.IsAPI || !containsSignal(exportRes.Signals, "response_attachment") {
		t.Fatalf("dynamic export endpoint should remain API: %+v", exportRes)
	}
}
