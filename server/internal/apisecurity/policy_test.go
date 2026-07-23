// policy_test.go 策略接口组与敏感字段 handler 校验层测试（httptest + 假 PolicySettings，不依赖数据库）。
package apisecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// policyPerms 本测试覆盖的全部权限点。
var policyPerms = []string{"api_runtime.read", "api_policy.read", "api_policy.edit", "api_policy.publish"}

// injectPolicyPrincipal 模拟认证链：注入持有权限点的主体与 Request ID。
func injectPolicyPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range policyPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newPolicyTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPolicyPrincipal, h)
	return mux
}

func doReq(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
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

// fakePolicySettings 内存版 PolicySettings（map 模拟 settings 表）。
type fakePolicySettings struct {
	values       map[string]string
	getErr       error
	upsertCalls  int
	lastUpserted string
}

func (f *fakePolicySettings) GetStringWithSource(ctx context.Context, group, key string) (string, bool, error) {
	_ = ctx
	if f.getErr != nil {
		return "", false, f.getErr
	}
	v, ok := f.values[group+":"+key]
	return v, ok, nil
}

func (f *fakePolicySettings) UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error {
	_ = ctx
	_ = description
	_ = operatorID
	f.values[group+":"+key] = value
	f.upsertCalls++
	f.lastUpserted = value
	return nil
}

func testPolicySource() PolicySource {
	return PolicySource{
		Edition: "wdsp", APIDynamicProtection: true,
		Mode: "OBSERVE", ModeFromEnv: false,
		MaxBodyParseBytes: 1 << 20, MaxBodySampleBytes: 64 << 10,
		MaxJSONDepth: 32, MaxFieldCount: 2048,
	}
}

// decodePolicyData 解包响应 envelope 的 data 字段。
func decodePolicyData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
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

// TestPolicyRoutesPermission 未登录 401、无权限 403（策略三组 + 敏感字段）。
func TestPolicyRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)
	h.SetPolicySource(testPolicySource())

	targets := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-security/policy"},
		{http.MethodPut, "/api/v1/api-security/policy"},
		{http.MethodPost, "/api/v1/api-security/policy/publish"},
		{http.MethodGet, "/api/v1/api-security/sensitive-fields"},
	}
	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, tg := range targets {
		rr := doReq(t, muxNoAuth, tg.method, tg.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", tg.method, tg.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	for _, tg := range targets {
		rr := doReq(t, muxNoPerm, tg.method, tg.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", tg.method, tg.path, rr.Code)
		}
	}
}

// TestSensitiveFieldsValidation 敏感字段列表校验层（400 在访问 store 之前返回，nil store 不触发 panic）。
func TestSensitiveFieldsValidation(t *testing.T) {
	h := NewHandler(nil, nil)
	mux := newPolicyTestMux(h)

	rr := doReq(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-fields?endpoint_id=bad", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint_id status=%d", rr.Code)
	}
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-fields?direction=BOTH", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad direction status=%d", rr.Code)
	}
}

// TestGetPolicy 策略视图：mode_source 取值顺序 db > env > default；覆盖值非法回退；读库错误如实 500。
func TestGetPolicy(t *testing.T) {
	fs := &fakePolicySettings{values: map[string]string{}}
	h := NewHandler(nil, nil)
	h.SetPolicySource(testPolicySource())
	h.SetPolicySettings(fs)
	mux := newPolicyTestMux(h)

	// 无覆盖 + ModeFromEnv=false → default
	rr := doReq(t, mux, http.MethodGet, "/api/v1/api-security/policy", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodePolicyData(t, rr)
	if data["mode"] != "OBSERVE" || data["mode_source"] != "default" {
		t.Fatalf("default view: %v", data)
	}
	if data["edition"] != "wdsp" || data["api_dynamic_protection"] != true {
		t.Fatalf("edition/capability: %v", data)
	}
	limits, ok := data["limits"].(map[string]any)
	if !ok || limits["max_body_parse_bytes"].(float64) != float64(1<<20) || limits["max_json_depth"].(float64) != 32 {
		t.Fatalf("limits: %v", data["limits"])
	}

	// ModeFromEnv=true → env
	h.SetPolicySource(PolicySource{Edition: "wdsp", APIDynamicProtection: true, Mode: "PROTECT", ModeFromEnv: true})
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/policy", nil)
	data = decodePolicyData(t, rr)
	if data["mode"] != "PROTECT" || data["mode_source"] != "env" {
		t.Fatalf("env view: %v", data)
	}

	// settings 表合法覆盖 → db
	fs.values[PolicySettingsGroup+":"+PolicyModeKey] = "OFF"
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/policy", nil)
	data = decodePolicyData(t, rr)
	if data["mode"] != "OFF" || data["mode_source"] != "db" {
		t.Fatalf("db view: %v", data)
	}

	// 覆盖值非法 → 回退 env（fail-safe）
	fs.values[PolicySettingsGroup+":"+PolicyModeKey] = "garbage"
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/policy", nil)
	data = decodePolicyData(t, rr)
	if data["mode"] != "PROTECT" || data["mode_source"] != "env" {
		t.Fatalf("invalid override fallback: %v", data)
	}

	// 读库错误 → 500（不静默回退）
	fs.getErr = errors.New("db down")
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/policy", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("get err status=%d", rr.Code)
	}
}

// TestPutPolicy 模式覆盖：校验层 400；合法值（大小写归一）写库并返回新视图；未配置设置服务 503。
func TestPutPolicy(t *testing.T) {
	fs := &fakePolicySettings{values: map[string]string{}}
	h := NewHandler(nil, nil) // 无审计服务：recordAudit 应安全跳过
	h.SetPolicySource(testPolicySource())
	h.SetPolicySettings(fs)
	mux := newPolicyTestMux(h)

	// 非法 mode → 400
	rr := doReq(t, mux, http.MethodPut, "/api/v1/api-security/policy", map[string]any{"mode": "BLOCK"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad mode status=%d", rr.Code)
	}
	// 空 mode → 400
	rr = doReq(t, mux, http.MethodPut, "/api/v1/api-security/policy", map[string]any{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty mode status=%d", rr.Code)
	}
	// 非 JSON body → 400
	req := httptest.NewRequest(http.MethodPut, "/api/v1/api-security/policy", bytes.NewReader([]byte("not-json")))
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
	if fs.upsertCalls != 0 {
		t.Fatalf("invalid requests must not write settings: %d", fs.upsertCalls)
	}

	// 合法值（小写归一为大写）→ 200 + 覆盖写库 + 返回新视图
	rr = doReq(t, mux, http.MethodPut, "/api/v1/api-security/policy", map[string]any{"mode": "protect"})
	if rr.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.upsertCalls != 1 || fs.lastUpserted != "PROTECT" {
		t.Fatalf("upsert calls=%d value=%s", fs.upsertCalls, fs.lastUpserted)
	}
	data := decodePolicyData(t, rr)
	policy, ok := data["policy"].(map[string]any)
	if !ok || policy["mode"] != "PROTECT" || policy["mode_source"] != "db" {
		t.Fatalf("put view: %v", data)
	}

	// 未注入设置服务 → 503
	hNoSettings := NewHandler(nil, nil)
	hNoSettings.SetPolicySource(testPolicySource())
	muxNoSettings := newPolicyTestMux(hNoSettings)
	rr = doReq(t, muxNoSettings, http.MethodPut, "/api/v1/api-security/policy", map[string]any{"mode": "OFF"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no settings status=%d", rr.Code)
	}
}

// TestPublishPolicy 发布触发：未配置 503；成功返回任务摘要；发布函数错误 500。
func TestPublishPolicy(t *testing.T) {
	h := NewHandler(nil, nil)
	h.SetPolicySource(testPolicySource())
	mux := newPolicyTestMux(h)

	// 未注入发布函数 → 503
	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/policy/publish", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no publish fn status=%d", rr.Code)
	}

	// 发布成功 → 200 + 任务摘要
	called := false
	h.SetPolicyPublishFunc(func(ctx context.Context, requestedBy uuid.UUID, requestID string) (*PolicyPublishResult, error) {
		called = true
		if requestID != "test-rid" {
			t.Fatalf("requestID=%s", requestID)
		}
		return &PolicyPublishResult{TaskID: uuid.New().String(), Status: "SUCCESS"}, nil
	})
	rr = doReq(t, mux, http.MethodPost, "/api/v1/api-security/policy/publish", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !called {
		t.Fatal("publish func not called")
	}
	data := decodePolicyData(t, rr)
	if data["status"] != "SUCCESS" || data["task_id"] == "" {
		t.Fatalf("publish result: %v", data)
	}

	// 发布函数错误 → 500
	h.SetPolicyPublishFunc(func(ctx context.Context, requestedBy uuid.UUID, requestID string) (*PolicyPublishResult, error) {
		return nil, errors.New("gateway unreachable")
	})
	rr = doReq(t, mux, http.MethodPost, "/api/v1/api-security/policy/publish", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("publish err status=%d", rr.Code)
	}
}
