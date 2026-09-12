package sitediscovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

var siteDiscoveryPerms = []string{"site_discovery.read", "site_discovery.manage"}

// injectPrincipal 模拟认证链：注入持有站点发现权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range siteDiscoveryPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newTestMux(h *Handler, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, h)
	return mux
}

func seedOne(t *testing.T, store *MemStore) *Discovery {
	t.Helper()
	d, err := store.Upsert(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// 未登录 401、无权限 403（读/写端点各一）。
func TestRoutesPermission(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)

	muxNoAuth := newTestMux(h, func(next http.Handler) http.Handler { return next })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/site-discoveries", nil)
	rr := httptest.NewRecorder()
	muxNoAuth.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth GET status=%d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/site-discoveries/"+uuid.NewString()+"/confirm", nil)
	rr = httptest.NewRecorder()
	muxNoAuth.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth POST status=%d", rr.Code)
	}

	muxNoPerm := newTestMux(h, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/site-discoveries", nil)
	rr = httptest.NewRecorder()
	muxNoPerm.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm GET status=%d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/site-discoveries/"+uuid.NewString()+"/ignore", nil)
	rr = httptest.NewRecorder()
	muxNoPerm.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm POST status=%d", rr.Code)
	}
}

// List 过滤参数校验与分页响应结构。
func TestHandlerList(t *testing.T) {
	store := NewMemStore()
	seedOne(t, store)
	h := NewHandler(store, nil)
	mux := newTestMux(h, injectPrincipal)

	// 非法过滤值 400
	for _, q := range []string{"status=BOGUS", "protocol=FTP", "source_mode=SNIFF"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/site-discoveries?"+q, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d, want 400", q, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/site-discoveries?status=NEW&keyword=example.com", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Code string `json:"code"`
		Data struct {
			Items    []Discovery `json:"items"`
			Page     int         `json:"page"`
			PageSize int         `json:"page_size"`
			Total    int64       `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != "SUCCESS" || env.Data.Total != 1 || len(env.Data.Items) != 1 {
		t.Fatalf("list env: %+v", env)
	}
	it := env.Data.Items[0]
	if it.Domain != "example.com" || it.Protocol != "HTTPS" || it.SourceMode == "" ||
		it.Status != StatusNew || it.FirstSeen.IsZero() || it.LastSeen.IsZero() {
		t.Fatalf("list item fields: %+v", it)
	}
}

// Confirm/Ignore/Restore 成功路径：返回更新后条目；审计服务为 nil 不 panic。
func TestHandlerTransitions(t *testing.T) {
	store := NewMemStore()
	d := seedOne(t, store)
	h := NewHandler(store, nil)
	mux := newTestMux(h, injectPrincipal)

	do := func(action string, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/site-discoveries/"+id+"/"+action, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	decode := func(rr *httptest.ResponseRecorder) Discovery {
		t.Helper()
		var env struct {
			Code string    `json:"code"`
			Data Discovery `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v body=%s", err, rr.Body.String())
		}
		return env.Data
	}

	rr := do("confirm", d.ID.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := decode(rr)
	if got.Status != StatusConfirmed || got.ConfirmedBy != "tester" || got.ConfirmedAt == nil {
		t.Fatalf("confirm result: %+v", got)
	}

	rr = do("ignore", d.ID.String())
	if rr.Code != http.StatusOK || decode(rr).Status != StatusIgnored {
		t.Fatalf("ignore: %d %+v", rr.Code, decode(rr))
	}

	// IGNORED 上 confirm → 409
	rr = do("confirm", d.ID.String())
	if rr.Code != http.StatusConflict {
		t.Fatalf("confirm on IGNORED status=%d, want 409", rr.Code)
	}

	rr = do("restore", d.ID.String())
	if rr.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", rr.Code, rr.Body.String())
	}
	got = decode(rr)
	if got.Status != StatusNew || got.ConfirmedBy != "" || got.ConfirmedAt != nil {
		t.Fatalf("restore result: %+v", got)
	}

	// 不存在 → 404；非法 ID → 400
	rr = do("confirm", uuid.NewString())
	if rr.Code != http.StatusNotFound {
		t.Fatalf("confirm missing status=%d, want 404", rr.Code)
	}
	rr = do("ignore", "not-a-uuid")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status=%d, want 400", rr.Code)
	}
}

// 采集 → HTTP 全链路（等价网关 JSONL 喂入后管理面可见可处置）。
func TestCollectThenServeHTTP(t *testing.T) {
	dir := t.TempDir()
	logPath := writeLog(t, dir,
		validLine(t, map[string]interface{}{"domain": "shop.example.com", "hits": 99, "client_count": 21,
			"window_start": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
			"window_end":   time.Now().UTC().Format(time.RFC3339)}))
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "gw-1")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	h := NewHandler(store, nil)
	mux := newTestMux(h, injectPrincipal)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/site-discoveries?keyword=shop", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Data struct {
			Items []Discovery `json:"items"`
			Total int64       `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 1 || env.Data.Items[0].SeenCount != 99 || env.Data.Items[0].ClientCount != 21 {
		t.Fatalf("collected item: %+v", env.Data)
	}
}
