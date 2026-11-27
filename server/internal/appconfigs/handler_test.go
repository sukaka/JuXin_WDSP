package appconfigs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// allPerms 本端点组全部权限点。
var allPerms = []string{"applications.read", "applications.update"}

// injectPrincipal 模拟认证链：注入持有全部权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range allPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal, h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env struct {
		Code string         `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, rr.Body.String())
	}
	return env.Data
}

// validHeaderConfigBody 合法的全量头合规配置（version 由调用方填）。
func validHeaderConfigBody(version int) map[string]any {
	return map[string]any{
		"server_action":       "hide",
		"x_author_action":     "keep",
		"x_powered_by_action": "replace",
		"x_powered_by_value":  "jiuzhang",
		"x_frame_options":     "sameorigin",
		"hsts_enabled":        true,
		"hsts_max_age":        31536000,
		"csp_mode":            "preset",
		"custom_request_rules": []map[string]any{
			{"name": "X-Trace", "method": "set", "value": "1"},
		},
		"custom_response_rules": []map[string]any{
			{"name": "X-Debug", "method": "delete"},
		},
		"version": version,
	}
}

// TestRegisterRoutesPermission 未登录 401、无权限 403。
func TestRegisterRoutesPermission(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)
	appID := uuid.New().String()

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := doJSON(t, muxNoAuth, http.MethodGet, "/api/v1/applications/"+appID+"/header-config", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status=%d", rr.Code)
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	rr = doJSON(t, muxNoPerm, http.MethodGet, "/api/v1/applications/"+appID+"/path-routes", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm status=%d", rr.Code)
	}
}

// TestHeaderConfigHTTP 头合规配置：默认值返回、upsert 往返、乐观锁与校验层。
func TestHeaderConfigHTTP(t *testing.T) {
	h := NewHandler(NewMemStore(), nil) // 无审计服务：recordAudit 应安全跳过
	mux := newTestMux(h)
	appID := uuid.New().String()
	base := "/api/v1/applications/" + appID + "/header-config"

	// ---- 无配置：默认对象 + configured:false + version:0 ----
	rr := doJSON(t, mux, http.MethodGet, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get default status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["configured"] != false || data["version"].(float64) != 0 {
		t.Fatalf("default envelope: %v", data)
	}
	cfg := data["config"].(map[string]any)
	if cfg["server_action"] != "keep" || cfg["x_frame_options"] != "default" ||
		cfg["csp_mode"] != "off" || cfg["hsts_max_age"].(float64) != 31536000 ||
		cfg["xff_overwrite"] != true ||
		cfg["response_compression_enabled"] != false ||
		cfg["response_compression_encodings"] != "zstd,gzip" {
		t.Fatalf("default config: %v", cfg)
	}

	// ---- 非法应用 ID → 400 ----
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/applications/bad/header-config", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad app id status=%d", rr.Code)
	}

	// ---- 创建（version=0）→ version:1，GET 读回一致 ----
	rr = doJSON(t, mux, http.MethodPut, base, validHeaderConfigBody(0))
	if rr.Code != http.StatusOK {
		t.Fatalf("put create status=%d body=%s", rr.Code, rr.Body.String())
	}
	data = decodeData(t, rr)
	if data["configured"] != true || data["version"].(float64) != 1 {
		t.Fatalf("create envelope: %v", data)
	}
	rr = doJSON(t, mux, http.MethodGet, base, nil)
	data = decodeData(t, rr)
	cfg = data["config"].(map[string]any)
	if cfg["server_action"] != "hide" || cfg["x_powered_by_value"] != "jiuzhang" ||
		cfg["response_compression_enabled"] != false || cfg["response_compression_encodings"] != "zstd,gzip" ||
		data["version"].(float64) != 1 {
		t.Fatalf("stored config: %v", data)
	}

	// ---- 重复创建（version=0 但已存在）→ 409 ----
	rr = doJSON(t, mux, http.MethodPut, base, validHeaderConfigBody(0))
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-create status=%d body=%s", rr.Code, rr.Body.String())
	}

	// ---- 正确版本更新（开启响应压缩并切换算法）→ version:2 ----
	updBody := validHeaderConfigBody(1)
	updBody["response_compression_enabled"] = true
	updBody["response_compression_encodings"] = "gzip"
	rr = doJSON(t, mux, http.MethodPut, base, updBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("put update status=%d body=%s", rr.Code, rr.Body.String())
	}
	updData := decodeData(t, rr)
	if v := updData["version"].(float64); v != 2 {
		t.Fatalf("updated version=%v", v)
	}
	updCfg := updData["config"].(map[string]any)
	if updCfg["response_compression_enabled"] != true || updCfg["response_compression_encodings"] != "gzip" {
		t.Fatalf("updated compression config: %v", updCfg)
	}

	// ---- 旧版本更新 → 409 ----
	rr = doJSON(t, mux, http.MethodPut, base, validHeaderConfigBody(1))
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale version status=%d", rr.Code)
	}

	// ---- 校验失败 → 400 ----
	badCases := map[string]func(map[string]any){
		"bad server_action": func(b map[string]any) { b["server_action"] = "drop" },
		"bad x_powered_by":  func(b map[string]any) { b["x_powered_by_action"] = "drop" },
		"bad x_frame_options": func(b map[string]any) {
			b["x_frame_options"] = "allowall"
		},
		"allow_from without url": func(b map[string]any) {
			b["x_frame_options"] = "allow_from"
		},
		"bad csp_mode":        func(b map[string]any) { b["csp_mode"] = "strict" },
		"custom csp no value": func(b map[string]any) { b["csp_mode"] = "custom" },
		"hsts_max_age zero":   func(b map[string]any) { b["hsts_max_age"] = 0 },
		"bad rule method": func(b map[string]any) {
			b["custom_request_rules"] = []map[string]any{{"name": "X-A", "method": "upsert", "value": "1"}}
		},
		"rule name empty": func(b map[string]any) {
			b["custom_request_rules"] = []map[string]any{{"name": "", "method": "set", "value": "1"}}
		},
		"rule name illegal": func(b map[string]any) {
			b["custom_request_rules"] = []map[string]any{{"name": "Bad Header", "method": "set", "value": "1"}}
		},
		"delete rule with value": func(b map[string]any) {
			b["custom_response_rules"] = []map[string]any{{"name": "X-A", "method": "delete", "value": "x"}}
		},
		// H-14: Caddy 占位符外泄与控制字符注入拦截
		"req rule caddy placeholder": func(b map[string]any) {
			b["custom_request_rules"] = []map[string]any{{"name": "X-Leak", "method": "set", "value": "{env.JIUZHANG_MASTER_KEY}"}}
		},
		"resp rule caddy placeholder": func(b map[string]any) {
			b["custom_response_rules"] = []map[string]any{{"name": "X-Leak", "method": "set", "value": "{env.POSTGRES_PASSWORD}"}}
		},
		"resp rule crlf": func(b map[string]any) {
			b["custom_response_rules"] = []map[string]any{{"name": "X-A", "method": "set", "value": "ok\r\nSet-Cookie: evil=1"}}
		},
		"req rule too long": func(b map[string]any) {
			b["custom_request_rules"] = []map[string]any{{"name": "X-A", "method": "set", "value": strings.Repeat("a", 1025)}}
		},
		"server_value placeholder": func(b map[string]any) {
			b["server_action"] = "replace"
			b["server_value"] = "{env.SECRET}"
		},
		"x_powered_by placeholder": func(b map[string]any) {
			b["x_powered_by_action"] = "replace"
			b["x_powered_by_value"] = "php/{env.KEY}"
		},
		"x_author control char": func(b map[string]any) {
			b["x_author_action"] = "replace"
			b["x_author_value"] = "team\nheader"
		},
		"x_frame_options_url placeholder": func(b map[string]any) {
			b["x_frame_options"] = "allow_from"
			b["x_frame_options_url"] = "https://{env.HOST}"
		},
		"csp_value placeholder": func(b map[string]any) {
			b["csp_mode"] = "custom"
			b["csp_value"] = "default-src 'self' https://{env.SECRET}.evil.com"
		},
		"csp_value too long": func(b map[string]any) {
			b["csp_mode"] = "custom"
			b["csp_value"] = strings.Repeat("a", 4097)
		},
		"bad response_compression_encodings": func(b map[string]any) {
			b["response_compression_enabled"] = true
			b["response_compression_encodings"] = "brotli"
		},
		"response_compression_encodings placeholder": func(b map[string]any) {
			b["response_compression_enabled"] = true
			b["response_compression_encodings"] = "{env.ENC}"
		},
	}
	for name, mutate := range badCases {
		body := validHeaderConfigBody(2)
		mutate(body)
		rr = doJSON(t, mux, http.MethodPut, base, body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

// validRouteBody 合法路径转发请求体。
func validRouteBody() map[string]any {
	return map[string]any{
		"path_prefix":     "/api",
		"upstream_scheme": "http",
		"upstream_host":   "10.0.0.1",
		"upstream_port":   8080,
		"strip_prefix":    true,
		"description":     "API 源站",
	}
}

// TestPathRoutesHTTP 路径转发 CRUD、分页、校验层与乐观锁。
func TestPathRoutesHTTP(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)
	mux := newTestMux(h)
	appID := uuid.New().String()
	base := "/api/v1/applications/" + appID + "/path-routes"

	// ---- 空列表 ----
	rr := doJSON(t, mux, http.MethodGet, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var pageEnv struct {
		Data struct {
			Items []PathRoute `json:"items"`
			Total int64       `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pageEnv); err != nil {
		t.Fatal(err)
	}
	if pageEnv.Data.Total != 0 {
		t.Fatalf("empty total=%d", pageEnv.Data.Total)
	}

	// ---- 创建（缺省 scheme/status/priority）----
	rr = doJSON(t, mux, http.MethodPost, base, validRouteBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	route := data["route"].(map[string]any)
	rid := route["id"].(string)
	if route["status"] != "ENABLED" || route["upstream_scheme"] != "http" || route["priority"].(float64) != 100 {
		t.Fatalf("route defaults: %v", route)
	}
	if route["version"].(float64) != 1 {
		t.Fatalf("route version=%v", route["version"])
	}

	// ---- 重复创建（同前缀+源站）→ 409 ----
	rr = doJSON(t, mux, http.MethodPost, base, validRouteBody())
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate create status=%d body=%s", rr.Code, rr.Body.String())
	}

	// ---- 列表分页 ----
	body2 := validRouteBody()
	body2["path_prefix"] = "/static"
	body2["priority"] = 10
	if rr := doJSON(t, mux, http.MethodPost, base, body2); rr.Code != http.StatusOK {
		t.Fatalf("create 2 status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, mux, http.MethodGet, base+"?page=1&page_size=1", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &pageEnv); err != nil {
		t.Fatal(err)
	}
	if pageEnv.Data.Total != 2 || len(pageEnv.Data.Items) != 1 {
		t.Fatalf("page total=%d items=%d", pageEnv.Data.Total, len(pageEnv.Data.Items))
	}
	// priority 小者（/static）排前
	if pageEnv.Data.Items[0].PathPrefix != "/static" {
		t.Fatalf("order[0]=%s", pageEnv.Data.Items[0].PathPrefix)
	}

	// ---- 非法路径前缀 → 400 ----
	for _, prefix := range []string{"api", "/a?b=1", "/a#frag", "/a/../b"} {
		body := validRouteBody()
		body["path_prefix"] = prefix
		rr = doJSON(t, mux, http.MethodPost, base, body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("prefix %q: status=%d body=%s", prefix, rr.Code, rr.Body.String())
		}
	}

	// ---- 其他校验失败 → 400 ----
	badCases := map[string]func(map[string]any){
		"host empty":          func(b map[string]any) { b["upstream_host"] = "" },
		"host with scheme":    func(b map[string]any) { b["upstream_host"] = "http://10.0.0.1" },
		"host with port":      func(b map[string]any) { b["upstream_host"] = "10.0.0.1:9000" },
		"host with path":      func(b map[string]any) { b["upstream_host"] = "backend.internal/admin" },
		"host with userinfo":  func(b map[string]any) { b["upstream_host"] = "user:pass@backend.internal" },
		"host with wildcard":  func(b map[string]any) { b["upstream_host"] = "*.example.com" },
		"host with brace":     func(b map[string]any) { b["upstream_host"] = "{env.HOST}" },
		"port zero":           func(b map[string]any) { b["upstream_port"] = 0 },
		"port too big":        func(b map[string]any) { b["upstream_port"] = 65536 },
		"bad scheme":          func(b map[string]any) { b["upstream_scheme"] = "ftp" },
		"bad status":          func(b map[string]any) { b["status"] = "ACTIVE" },
	}
	for name, mutate := range badCases {
		body := validRouteBody()
		body["path_prefix"] = "/" + name
		mutate(body)
		rr = doJSON(t, mux, http.MethodPost, base, body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// ---- 更新（全量替换 + version）----
	upd := validRouteBody()
	upd["upstream_port"] = 9090
	upd["status"] = "DISABLED"
	upd["version"] = 1
	rr = doJSON(t, mux, http.MethodPatch, base+"/"+rid, upd)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	route = decodeData(t, rr)["route"].(map[string]any)
	if route["upstream_port"].(float64) != 9090 || route["status"] != "DISABLED" || route["version"].(float64) != 2 {
		t.Fatalf("patched route: %v", route)
	}

	// ---- 旧版本更新 → 409；不存在 → 404；非法 rid → 400 ----
	rr = doJSON(t, mux, http.MethodPatch, base+"/"+rid, upd) // upd 仍是 version:1
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale patch status=%d", rr.Code)
	}
	upd["version"] = 1
	rr = doJSON(t, mux, http.MethodPatch, base+"/"+uuid.New().String(), upd)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing patch status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPatch, base+"/not-a-uuid", upd)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad rid status=%d", rr.Code)
	}
	// 非法应用 ID → 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/applications/bad/path-routes", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad app id list status=%d", rr.Code)
	}

	// ---- 删除 → 200；重复删除 → 404 ----
	rr = doJSON(t, mux, http.MethodDelete, base+"/"+rid, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, mux, http.MethodDelete, base+"/"+rid, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("re-delete status=%d", rr.Code)
	}
}

// TestListEnabledPathRoutes 发布侧读取：仅 ENABLED，priority 升序、同优先级长前缀优先。
func TestListEnabledPathRoutes(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	appID := uuid.New()

	routes := []PathRoute{
		{ApplicationID: appID, PathPrefix: "/api", UpstreamScheme: "http", UpstreamHost: "h1", UpstreamPort: 80, Priority: 20, Status: "ENABLED"},
		{ApplicationID: appID, PathPrefix: "/api/v2", UpstreamScheme: "http", UpstreamHost: "h2", UpstreamPort: 80, Priority: 20, Status: "ENABLED"},
		{ApplicationID: appID, PathPrefix: "/off", UpstreamScheme: "http", UpstreamHost: "h3", UpstreamPort: 80, Priority: 1, Status: "DISABLED"},
		{ApplicationID: appID, PathPrefix: "/first", UpstreamScheme: "http", UpstreamHost: "h4", UpstreamPort: 80, Priority: 1, Status: "ENABLED"},
	}
	for i := range routes {
		if err := store.CreatePathRoute(ctx, &routes[i]); err != nil {
			t.Fatal(err)
		}
	}
	enabled, err := store.ListEnabledPathRoutes(ctx, appID)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 3 {
		t.Fatalf("enabled=%d", len(enabled))
	}
	want := []string{"/first", "/api/v2", "/api"}
	for i, w := range want {
		if enabled[i].PathPrefix != w {
			t.Fatalf("order[%d]=%s want %s", i, enabled[i].PathPrefix, w)
		}
	}
	// 无记录应用：空切片而非 nil
	empty, err := store.ListEnabledPathRoutes(ctx, uuid.New())
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty=%v err=%v", empty, err)
	}
	// 无配置应用：GetHeaderConfig 返回 (nil, nil)
	cfg, err := store.GetHeaderConfig(ctx, uuid.New())
	if err != nil || cfg != nil {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
}
