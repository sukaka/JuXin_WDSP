package iplibhttp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func TestHandlerRBACSecretMaskingAndValidation(t *testing.T) {
	store := newMemSettingsStore()
	// 模拟迁移 000256 的初始数字种子
	store.ints[SettingsGroup+":"+KeyHTTPTimeoutSeconds] = 120

	cipher := mustTestCipher(t)
	h := NewHandler(store, cipher, nil).SetResolver(staticResolver{
		"proxy.corp.local": {net.ParseIP("10.0.0.5")},
		"meta.corp.local":  {net.ParseIP("169.254.169.254")},
	})

	// 1. 未认证 401
	muxUnauth := http.NewServeMux()
	RegisterRoutes(muxUnauth, noPrincipal, h)
	rec := httptest.NewRecorder()
	muxUnauth.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ip-libraries/outbound-settings", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth GET = %d, want 401", rec.Code)
	}

	// 2. 只有 threat_intel.read 可读 GET，不能写 PUT
	muxTIRead := http.NewServeMux()
	RegisterRoutes(muxTIRead, injectPrincipal(PermThreatIntelRead), h)
	rec = httptest.NewRecorder()
	muxTIRead.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ip-libraries/outbound-settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("threat_intel.read GET = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	muxTIRead.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("threat_intel.read PUT = %d, want 403", rec.Code)
	}

	// 3. 只有 geoip.read 可读 GET，不能写 PUT
	muxGeoRead := http.NewServeMux()
	RegisterRoutes(muxGeoRead, injectPrincipal(PermGeoIPRead), h)
	rec = httptest.NewRecorder()
	muxGeoRead.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ip-libraries/outbound-settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("geoip.read GET = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	muxGeoRead.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("geoip.read PUT = %d, want 403", rec.Code)
	}

	// 4. 无相关权限 403
	muxOther := http.NewServeMux()
	RegisterRoutes(muxOther, injectPrincipal("users.read"), h)
	rec = httptest.NewRecorder()
	muxOther.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ip-libraries/outbound-settings", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unrelated perm GET = %d, want 403", rec.Code)
	}

	// 5. 具备 geoip.manage 读写全流程
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(PermGeoIPRead, PermGeoIPManage), h)

	putBody := `{
		"outbound_allowlist": "10.0.0.0/8, mirror.corp.local",
		"allow_insecure_http_mirror": true,
		"proxy_url": "http://proxy.corp.local:3128",
		"proxy_auth": "svcuser:super-secret-proxy-pass",
		"http_timeout_seconds": 180
	}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(putBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT settings = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-proxy-pass") {
		t.Fatal("proxy_auth plaintext leaked in PUT response")
	}
	encStored := store.strs[SettingsGroup+":"+KeyProxyAuthEncrypted]
	if encStored == "" || strings.Contains(encStored, "super-secret-proxy-pass") {
		t.Fatalf("proxy_auth was not encrypted properly: %q", encStored)
	}
	if strings.Contains(rec.Body.String(), encStored) {
		t.Fatal("proxy_auth ciphertext leaked in PUT response")
	}

	var resp struct {
		Data OutboundSettings `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Data.OutboundAllowlist != "10.0.0.0/8, mirror.corp.local" ||
		!resp.Data.AllowInsecureHTTPMirror ||
		resp.Data.ProxyURL != "http://proxy.corp.local:3128" ||
		!resp.Data.HasProxyAuth ||
		resp.Data.HTTPTimeoutSeconds != 180 {
		t.Fatalf("unexpected saved settings: %+v", resp.Data)
	}

	// 6. GET 回显脱敏且不泄露密钥
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ip-libraries/outbound-settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after PUT = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "super-secret-proxy-pass") || strings.Contains(rec.Body.String(), encStored) {
		t.Fatal("secret leaked in GET response")
	}

	// 7. 再次 PUT 留空 proxy_auth 应保留既有凭据
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(`{
		"outbound_allowlist": "10.0.0.0/8",
		"allow_insecure_http_mirror": false,
		"proxy_url": "http://proxy.corp.local:3128",
		"http_timeout_seconds": 240
	}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT keep auth = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Data.HasProxyAuth || resp.Data.HTTPTimeoutSeconds != 240 {
		t.Fatalf("expected HasProxyAuth preserved and timeout=240, got %+v", resp.Data)
	}

	// 8. clear_proxy_auth=true 清空凭据
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(`{
		"outbound_allowlist": "",
		"allow_insecure_http_mirror": false,
		"proxy_url": "",
		"clear_proxy_auth": true
	}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT clear auth = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.HasProxyAuth || store.strs[SettingsGroup+":"+KeyProxyAuthEncrypted] != "" {
		t.Fatalf("expected proxy auth cleared, got %+v", resp.Data)
	}

	// 9. 参数校验负例矩阵
	badPayloads := []struct {
		name string
		body string
	}{
		{"invalid allowlist bare IP", `{"outbound_allowlist":"8.8.8.8"}`},
		{"invalid allowlist CIDR", `{"outbound_allowlist":"10.0.0.0/33"}`},
		{"timeout too small", `{"http_timeout_seconds":10}`},
		{"timeout too large", `{"http_timeout_seconds":601}`},
		{"proxy embedded userinfo", `{"proxy_url":"http://u:p@10.0.0.5:3128"}`},
		{"proxy cloud metadata IP", `{"proxy_url":"http://169.254.169.254:80"}`},
		{"proxy cloud metadata DNS", `{"proxy_url":"http://meta.corp.local:80"}`},
		{"proxy unsupported scheme", `{"proxy_url":"socks5://10.0.0.5:1080"}`},
		{"proxy auth missing colon", `{"proxy_auth":"onlyuser"}`},
		{"proxy auth with newline", `{"proxy_auth":"user:pa\nss"}`},
		{"conflicting proxy_auth and clear", `{"proxy_auth":"u:p","clear_proxy_auth":true}`},
	}
	for _, tc := range badPayloads {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings", strings.NewReader(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got status %d, want 400 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// 10. 未配置主密钥加密服务时保存 proxy_auth 返回 503，绝不落明文
	hNoCipher := NewHandler(store, nil, nil)
	muxNoCipher := http.NewServeMux()
	RegisterRoutes(muxNoCipher, injectPrincipal(PermGeoIPManage), hNoCipher)
	rec = httptest.NewRecorder()
	muxNoCipher.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/ip-libraries/outbound-settings",
		strings.NewReader(`{"proxy_auth":"u:p"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT proxy_auth without cipher = %d, want 503", rec.Code)
	}
}
