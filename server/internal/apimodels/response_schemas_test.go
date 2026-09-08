// response_schemas_test.go 响应 Schema 学习结果只读接口测试（httptest + fake，不依赖数据库）：
// 路由权限（401/403）、参数校验（400/404）、成功路径与存储错误（500）、未接线（503）。
package apimodels

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeRespSchemaReader 内存版只读存取（记录调用，可注入错误路径）。
type fakeRespSchemaReader struct {
	key     string
	keyErr  error
	list    []ResponseSchema
	listErr error
	lastKey string
}

func (f *fakeRespSchemaReader) EndpointKey(_ context.Context, _ uuid.UUID) (string, error) {
	return f.key, f.keyErr
}

func (f *fakeRespSchemaReader) ListResponseSchemas(_ context.Context, endpointKey string) ([]ResponseSchema, error) {
	f.lastKey = endpointKey
	return f.list, f.listErr
}

// injectRespSchemaPrincipal 注入持有 api_model.read 的主体（与运行时策略测试同一模式）。
func injectRespSchemaPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: map[string]bool{"api_model.read": true}}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func doRespSchemaReq(t *testing.T, mux http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestListResponseSchemasPermission 未登录 401、无权限 403。
func TestListResponseSchemasPermission(t *testing.T) {
	h := NewHandler(nil, nil)
	path := "/api/v1/api-security/endpoints/" + uuid.NewString() + "/response-schemas"

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	if rr := doRespSchemaReq(t, muxNoAuth, path); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status=%d", rr.Code)
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	if rr := doRespSchemaReq(t, muxNoPerm, path); rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm status=%d", rr.Code)
	}
}

// TestListResponseSchemas 参数校验与成功路径：非法 ID 400；端点不存在 404；
// 成功返回 items（按状态码一行一项）；存储错误 500；未接线 503。
func TestListResponseSchemas(t *testing.T) {
	newMux := func(fr *fakeRespSchemaReader) *http.ServeMux {
		h := NewHandler(nil, nil)
		h.SetResponseSchemaReader(fr)
		mux := http.NewServeMux()
		RegisterRoutes(mux, injectRespSchemaPrincipal, h)
		return mux
	}

	// 非法接口 ID → 400
	if rr := doRespSchemaReq(t, newMux(&fakeRespSchemaReader{}), "/api/v1/api-security/endpoints/bad/response-schemas"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	// 端点不存在 → 404
	mux := newMux(&fakeRespSchemaReader{keyErr: ErrEndpointNotFound})
	if rr := doRespSchemaReq(t, mux, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas"); rr.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d", rr.Code)
	}
	// 成功：透传端点键，返回 items
	now := time.Now()
	fr := &fakeRespSchemaReader{key: "GET /v1/users/{id}", list: []ResponseSchema{{
		ID: uuid.New(), EndpointKey: "GET /v1/users/{id}", StatusCode: 200,
		Fields: map[string]string{"id": "number"}, ContentHash: "h", SampleCount: 3,
		FirstSeen: now, LastSeen: now, UpdatedAt: now,
	}}}
	rr := doRespSchemaReq(t, newMux(fr), "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas")
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fr.lastKey != "GET /v1/users/{id}" {
		t.Fatalf("endpoint key not propagated: %q", fr.lastKey)
	}
	data := decodeRuntimeData(t, rr)
	items, ok := data["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", data)
	}
	item := items[0].(map[string]any)
	if item["status_code"].(float64) != 200 || item["sample_count"].(float64) != 3 {
		t.Fatalf("item = %v", item)
	}
	if item["fields"].(map[string]any)["id"] != "number" {
		t.Fatalf("fields = %v", item["fields"])
	}
	// 空结果：items 为 [] 而非 null
	fr2 := &fakeRespSchemaReader{key: "GET /v1/empty", list: []ResponseSchema{}}
	rr = doRespSchemaReq(t, newMux(fr2), "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas")
	if rr.Code != http.StatusOK {
		t.Fatalf("empty status=%d", rr.Code)
	}
	if items := decodeRuntimeData(t, rr)["items"].([]any); len(items) != 0 {
		t.Fatalf("empty items = %v", items)
	}
	// 存储错误 → 500（不静默）
	mux = newMux(&fakeRespSchemaReader{key: "k", listErr: errors.New("db down")})
	if rr := doRespSchemaReq(t, mux, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("list err status=%d", rr.Code)
	}
	// 未接线 → 503
	h := NewHandler(nil, nil)
	muxBare := http.NewServeMux()
	RegisterRoutes(muxBare, injectRespSchemaPrincipal, h)
	if rr := doRespSchemaReq(t, muxBare, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired status=%d", rr.Code)
	}
}
