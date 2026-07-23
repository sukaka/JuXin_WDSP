package apiassets

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

// allPerms 任务书五十二章本端点组全部权限点。
var allPerms = []string{
	"api_asset.read", "api_asset.confirm", "api_asset.edit",
	"api_asset.merge", "api_asset.split", "api_asset.ignore",
	"api_learning.read", "api_learning.start", "api_learning.stop",
}

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

// TestRegisterRoutesPermission 未登录 401、无权限 403。
func TestRegisterRoutesPermission(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)

	// 无主体：RequirePermission 返回 401
	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := doJSON(t, muxNoAuth, http.MethodGet, "/api/v1/api-security/endpoints", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status=%d", rr.Code)
	}

	// 有主体无权限：403
	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	rr = doJSON(t, muxNoPerm, http.MethodGet, "/api/v1/api-security/endpoints", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm status=%d", rr.Code)
	}
}

// TestEndpointGroupHTTP 覆盖 51.1 端点组 + 学习启停的主流程与校验层。
func TestEndpointGroupHTTP(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	h := NewHandler(store, nil) // 无审计服务：recordAudit 应安全跳过
	mux := newTestMux(h)

	login, err := store.UpsertDiscovery(ctx, "POST", "/api/login/{id}", 0.7, true)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.UpsertDiscovery(ctx, "GET", "/api/login/{id}/logs", 0.6, true)
	if err != nil {
		t.Fatal(err)
	}

	// ---- 列表（keyword 过滤）----
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints?keyword=login", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var listEnv struct {
		Data struct {
			Items []Endpoint `json:"items"`
			Total int64      `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listEnv); err != nil {
		t.Fatal(err)
	}
	if listEnv.Data.Total != 2 {
		t.Fatalf("list total=%d", listEnv.Data.Total)
	}
	if !strings.Contains(rr.Body.String(), "\"http_method\"") || !strings.Contains(rr.Body.String(), "\"normalized_path\"") {
		t.Fatalf("json tags not aligned: %s", rr.Body.String())
	}
	// application_id 非法 → 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints?application_id=bad", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad application_id status=%d", rr.Code)
	}

	// ---- 详情（错误 id → 400，不存在 → 404）----
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/not-a-uuid", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+uuid.New().String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+login.ID.String(), nil)
	data := decodeData(t, rr)
	epRaw, _ := json.Marshal(data["endpoint"])
	var ep Endpoint
	if err := json.Unmarshal(epRaw, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.ID != login.ID || ep.Asset != nil {
		t.Fatalf("endpoint: %+v", ep)
	}

	// ---- PATCH 资产扩展（空 body / 非法 exposure → 400）----
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/endpoints/"+login.ID.String(), map[string]any{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty patch status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/endpoints/"+login.ID.String(), map[string]any{"exposure": "BAD"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad exposure status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/endpoints/"+login.ID.String(),
		map[string]any{"purpose": "登录认证", "exposure": "PUBLIC", "owner": "安全组", "tags": []string{"core"}})
	data = decodeData(t, rr)
	epRaw, _ = json.Marshal(data["endpoint"])
	ep = Endpoint{}
	if err := json.Unmarshal(epRaw, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Asset == nil || ep.Asset.Purpose != "登录认证" || ep.Asset.Exposure != "PUBLIC" || len(ep.Asset.Tags) != 1 {
		t.Fatalf("patched asset: %+v", ep.Asset)
	}

	// ---- 批量确认（空 ids → 400；部分不存在 → failed）----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{"ids": []string{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	missing := uuid.New()
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/confirm",
		map[string]any{"ids": []string{login.ID.String(), missing.String()}})
	data = decodeData(t, rr)
	if data["confirmed"].(float64) != 1 || len(data["failed"].([]any)) != 1 {
		t.Fatalf("confirm result: %v", data)
	}
	cur, err := store.GetByID(ctx, login.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.AssetStatus != "CONFIRMED" || cur.ConfirmedAt == nil {
		t.Fatalf("after confirm: %+v", cur)
	}

	// ---- 忽略 ----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/ignore", nil)
	data = decodeData(t, rr)
	epRaw, _ = json.Marshal(data["endpoint"])
	ep = Endpoint{}
	_ = json.Unmarshal(epRaw, &ep)
	if ep.AssetStatus != "IGNORED" {
		t.Fatalf("ignore: %+v", ep)
	}

	// ---- 自动分类（启发式 + 锁定冲突）----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/classify", nil)
	data = decodeData(t, rr)
	dimsRaw, _ := json.Marshal(data["dimensions"])
	var dims []ClassificationDimension
	if err := json.Unmarshal(dimsRaw, &dims); err != nil {
		t.Fatal(err)
	}
	foundAuth := false
	for _, d := range dims {
		if d.Dimension == "PURPOSE" && d.Value == "AUTH" && d.Source == "AUTO" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Fatalf("classify dims: %v", dims)
	}
	if err := store.SetClassificationLocked(ctx, login.ID, true); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/classify", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("locked classify status=%d", rr.Code)
	}

	// ---- 合并（自合并/非法 other_id → 400；不存在 → 404）----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/merge",
		map[string]any{"other_id": login.ID.String()})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("self merge status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/merge",
		map[string]any{"other_id": "not-a-uuid"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad other_id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/merge",
		map[string]any{"other_id": uuid.New().String()})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing merge status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/merge",
		map[string]any{"other_id": other.ID.String()})
	data = decodeData(t, rr)
	epRaw, _ = json.Marshal(data["endpoint"])
	ep = Endpoint{}
	_ = json.Unmarshal(epRaw, &ep)
	if ep.HitCount != login.HitCount+other.HitCount {
		t.Fatalf("merged hit_count=%d", ep.HitCount)
	}
	if _, err := store.GetByID(ctx, other.ID); err == nil {
		t.Fatal("other should be deleted after merge")
	}

	// ---- 拆分（空 paths → 400；冲突 → 409）----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/split",
		map[string]any{"paths": []string{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty split status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/split",
		map[string]any{"paths": []string{"/api/login/99/captcha"}})
	data = decodeData(t, rr)
	epsRaw, _ := json.Marshal(data["endpoints"])
	var created []Endpoint
	if err := json.Unmarshal(epsRaw, &created); err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0].NormalizedPath != "/api/login/{id}/captcha" || created[0].HTTPMethod != "POST" {
		t.Fatalf("split created: %+v", created)
	}
	// 重复拆分同一路径 → 409（端点键冲突）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/split",
		map[string]any{"paths": []string{"/api/login/99/captcha"}})
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict split status=%d body=%s", rr.Code, rr.Body.String())
	}

	// ---- 学习启停（状态机冲突 → 409）----
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/start", nil)
	data = decodeData(t, rr)
	jobRaw, _ := json.Marshal(data["job"])
	var job LearningJob
	if err := json.Unmarshal(jobRaw, &job); err != nil {
		t.Fatal(err)
	}
	if job.Status != "RUNNING" {
		t.Fatalf("job: %+v", job)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/start", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("double start status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/status", nil)
	data = decodeData(t, rr)
	if data["learning_status"] != "LEARNING" || data["job"] == nil {
		t.Fatalf("learning status: %v", data)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/stop", nil)
	data = decodeData(t, rr)
	jobRaw, _ = json.Marshal(data["job"])
	job = LearningJob{}
	_ = json.Unmarshal(jobRaw, &job)
	if job.Status != "STOPPED" || job.StoppedAt == nil {
		t.Fatalf("stopped job: %+v", job)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/stop", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("double stop status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+login.ID.String()+"/learning/status", nil)
	data = decodeData(t, rr)
	if data["learning_status"] != "PAUSED" {
		t.Fatalf("after stop: %v", data)
	}
	// 不存在端点的学习操作 → 404
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+uuid.New().String()+"/learning/start", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing start status=%d", rr.Code)
	}
}
