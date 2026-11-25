package appconfigs

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func newTLSConfigTestMux(store Repository) *http.ServeMux {
	return newTestMux(NewHandler(store, nil))
}

func TestTLSConfigPermissionEnforced(t *testing.T) {
	store := NewMemStore()
	mux := http.NewServeMux()
	h := NewHandler(store, nil)
	readOnlyAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{
				UserID:   uuid.New(),
				Username: "auditor",
				PermsSet: map[string]bool{"applications.read": true},
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
	RegisterRoutes(mux, readOnlyAuth, h)

	appID := uuid.New()
	url := "/api/v1/applications/" + appID.String() + "/tls-config"
	if rr := doJSON(t, mux, http.MethodGet, url, nil); rr.Code != http.StatusOK {
		t.Fatalf("read-only GET want 200, got %d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPut, url, map[string]any{"version": 0}); rr.Code != http.StatusForbidden {
		t.Fatalf("read-only PUT want 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTLSConfigCRUDAndProtocolDowngradeValidation(t *testing.T) {
	store := NewMemStore()
	mux := newTLSConfigTestMux(store)
	appID := uuid.New()
	url := "/api/v1/applications/" + appID.String() + "/tls-config"

	// 1. 未配置时返回默认策略 + configured=false + version=0
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET default status=%d body=%s", rr.Code, rr.Body.String())
	}
	var getEnv struct {
		Data struct {
			Config     gatewayconfig.AppTLSConfig `json:"config"`
			Configured bool                       `json:"configured"`
			Version    int                        `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &getEnv); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if getEnv.Data.Configured || getEnv.Data.Version != 0 {
		t.Fatalf("unexpected default metadata: %+v", getEnv.Data)
	}
	if getEnv.Data.Config.TLSProtocolMode != gatewayconfig.TLSProtocolModeAutoDetect {
		t.Errorf("default mode = %q, want AUTO_DETECT", getEnv.Data.Config.TLSProtocolMode)
	}

	// 2. 首次 PUT：启用双协议自识别 + 国密 TLCP1.1 + 降级至 TLS1.0 & HTTP/1.1 + 回源 HTTP/1.1
	putBody := map[string]any{
		"tls_protocol_mode":            "AUTO_DETECT",
		"allowed_tls_versions":         []string{"TLCP1.1", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"},
		"legacy_ssl_analysis_versions": []string{"SSLv2", "SSLv2_v3", "SSLv3"},
		"http_versions":                []string{"HTTP/1.0", "HTTP/1.1"},
		"upstream_http_version":        "HTTP/1.1",
		"upstream_tls_min_version":     "TLS1.0",
		"session_analysis_enabled":     true,
		"version":                      0,
	}
	raw, _ := json.Marshal(putBody)
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT create status=%d body=%s", rr.Code, rr.Body.String())
	}

	// 3. 再次 GET 验证已持久化且 version=1
	req = httptest.NewRequest(http.MethodGet, url, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET saved status=%d", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &getEnv); err != nil {
		t.Fatalf("decode GET saved: %v", err)
	}
	if !getEnv.Data.Configured || getEnv.Data.Version != 1 {
		t.Fatalf("want configured=true version=1, got %+v", getEnv.Data)
	}
	if len(getEnv.Data.Config.HTTPVersions) != 2 || getEnv.Data.Config.UpstreamHTTPVersion != "HTTP/1.1" {
		t.Errorf("protocol downgrade not saved: %+v", getEnv.Data.Config)
	}

	// 4. 乐观锁冲突（继续传 version=0 应返回 409）
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale version status=%d, want 409, body=%s", rr.Code, rr.Body.String())
	}

	// 5. 携带正确 version=1 更新成功并升至 version=2
	putBody["version"] = 1
	putBody["tls_protocol_mode"] = "GM_ONLY"
	putBody["allowed_tls_versions"] = []string{"TLCP1.1"}
	raw, _ = json.Marshal(putBody)
	req = httptest.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT update status=%d body=%s", rr.Code, rr.Body.String())
	}

	// 6. 负向参数校验均应返回 400
	invalidCases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "gm_only_without_tlcp",
			body: map[string]any{
				"tls_protocol_mode":        "GM_ONLY",
				"allowed_tls_versions":     []string{"TLS1.2"},
				"http_versions":            []string{"HTTP/1.1"},
				"upstream_http_version":    "AUTO",
				"upstream_tls_min_version": "TLS1.2",
				"version":                  2,
			},
		},
		{
			name: "intl_only_with_only_tlcp",
			body: map[string]any{
				"tls_protocol_mode":        "INTERNATIONAL_ONLY",
				"allowed_tls_versions":     []string{"TLCP1.1"},
				"http_versions":            []string{"HTTP/1.1"},
				"upstream_http_version":    "AUTO",
				"upstream_tls_min_version": "TLS1.2",
				"version":                  2,
			},
		},
		{
			name: "empty_http_versions",
			body: map[string]any{
				"tls_protocol_mode":        "AUTO_DETECT",
				"allowed_tls_versions":     []string{"TLS1.2"},
				"http_versions":            []string{},
				"upstream_http_version":    "AUTO",
				"upstream_tls_min_version": "TLS1.2",
				"version":                  2,
			},
		},
		{
			name: "invalid_upstream_tls_min",
			body: map[string]any{
				"tls_protocol_mode":        "AUTO_DETECT",
				"allowed_tls_versions":     []string{"TLS1.2"},
				"http_versions":            []string{"HTTP/1.1"},
				"upstream_http_version":    "AUTO",
				"upstream_tls_min_version": "SSLv2",
				"version":                  2,
			},
		},
		{
			name: "invalid_legacy_ssl_item",
			body: map[string]any{
				"tls_protocol_mode":            "AUTO_DETECT",
				"allowed_tls_versions":         []string{"TLS1.2"},
				"legacy_ssl_analysis_versions": []string{"SSLv1"},
				"http_versions":                []string{"HTTP/1.1"},
				"upstream_http_version":        "AUTO",
				"upstream_tls_min_version":     "TLS1.2",
				"version":                      2,
			},
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(b))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: status=%d, want 400, body=%s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestPathRouteAcceptsTLCPScheme(t *testing.T) {
	store := NewMemStore()
	mux := newTLSConfigTestMux(store)
	appID := uuid.New()
	body := `{"path_prefix":"/gm-api","upstream_scheme":"tlcp","upstream_host":"10.0.0.10","upstream_port":8443,"priority":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications/"+appID.String()+"/path-routes", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("create tlcp path route status=%d body=%s", rr.Code, rr.Body.String())
	}
}
