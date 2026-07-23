package apiassets

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// TestLifecycleSamplesPermission 新端点组未登录 401、无权限 403。
func TestLifecycleSamplesPermission(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	id := uuid.New().String()
	paths := []string{
		"/api/v1/api-security/endpoints/" + id + "/lifecycle-events",
		"/api/v1/api-security/endpoints/" + id + "/learning/samples",
	}

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, p := range paths {
		rr := doJSON(t, muxNoAuth, http.MethodGet, p, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s status=%d", p, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	for _, p := range paths {
		rr := doJSON(t, muxNoPerm, http.MethodGet, p, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s status=%d", p, rr.Code)
		}
	}
}

// TestLifecycleEventsHTTP 生命周期事件：校验层（400/404）+ 事件轨迹（忽略/学习停止）+ 分页。
func TestLifecycleEventsHTTP(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	ep, err := store.UpsertDiscovery(context.Background(), "GET", "/api/orders/{id}", 0.7, true)
	if err != nil {
		t.Fatal(err)
	}

	// 非法 id → 400；不存在端点 → 404
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/not-a-uuid/lifecycle-events", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+uuid.New().String()+"/lifecycle-events", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}

	// 无事件时返回空页
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/lifecycle-events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Data struct {
			Items []LifecycleEvent `json:"items"`
			Total int64            `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 0 || len(env.Data.Items) != 0 {
		t.Fatalf("empty events: %+v", env.Data)
	}

	// 触发两条事件：忽略（资产状态变更）+ 学习启停（停止学习）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/ignore", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ignore status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/start", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("start status=%d", rr.Code)
	}
	// 等待纳秒级时间戳区分，保证 created_at DESC 次序确定
	time.Sleep(time.Millisecond)
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/stop", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop status=%d", rr.Code)
	}

	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/lifecycle-events", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 2 || len(env.Data.Items) != 2 {
		t.Fatalf("events total=%d items=%d", env.Data.Total, len(env.Data.Items))
	}
	// created_at DESC：最新的是停止学习（LEARNING→PAUSED）
	first, second := env.Data.Items[0], env.Data.Items[1]
	if first.ToStatus != "PAUSED" || first.FromStatus != "LEARNING" || first.Actor != "tester" {
		t.Fatalf("first event: %+v", first)
	}
	if second.ToStatus != "IGNORED" || second.Reason != "资产状态变更" {
		t.Fatalf("second event: %+v", second)
	}
	if first.CreatedAt.Before(second.CreatedAt) {
		t.Fatal("events not ordered by created_at DESC")
	}

	// 分页：page_size=1 第二页应取到较旧一条
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/lifecycle-events?page=2&page_size=1", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 2 || len(env.Data.Items) != 1 || env.Data.Items[0].ToStatus != "IGNORED" {
		t.Fatalf("paged events: %+v", env.Data)
	}
}

// TestLearningSamplesHTTP 学习样本：校验层（400/404）+ accepted 过滤 + 分页。
func TestLearningSamplesHTTP(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	ep, err := store.UpsertDiscovery(context.Background(), "POST", "/api/pay/{id}", 0.8, true)
	if err != nil {
		t.Fatal(err)
	}

	// 非法 id → 400；不存在端点 → 404；非法 accepted → 400
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/not-a-uuid/learning/samples", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+uuid.New().String()+"/learning/samples", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/samples?accepted=maybe", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad accepted status=%d", rr.Code)
	}

	// 置样本：2 采纳 + 1 排除（生产样本由网关侧写库，此处回放）
	base := time.Now().UTC()
	store.AddLearningSample(LearningSample{EndpointID: ep.ID, RequestID: "r1", SampleHash: "h1", Accepted: true, CollectedAt: base})
	store.AddLearningSample(LearningSample{EndpointID: ep.ID, RequestID: "r2", SampleHash: "h2", Accepted: true, CollectedAt: base.Add(time.Second)})
	store.AddLearningSample(LearningSample{EndpointID: ep.ID, RequestID: "r3", SampleHash: "h3", Accepted: false, ExcludeReason: "响应非JSON", CollectedAt: base.Add(2 * time.Second)})

	var env struct {
		Data struct {
			Items []LearningSample `json:"items"`
			Total int64            `json:"total"`
		} `json:"data"`
	}
	// 不过滤 → 3 条，collected_at DESC
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/samples", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 3 || len(env.Data.Items) != 3 {
		t.Fatalf("samples total=%d items=%d", env.Data.Total, len(env.Data.Items))
	}
	if env.Data.Items[0].RequestID != "r3" || env.Data.Items[0].ExcludeReason != "响应非JSON" {
		t.Fatalf("desc order: %+v", env.Data.Items[0])
	}
	// accepted=true → 2；accepted=false → 1
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/samples?accepted=true", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 2 {
		t.Fatalf("accepted=true total=%d", env.Data.Total)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/samples?accepted=false", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 1 || env.Data.Items[0].RequestID != "r3" {
		t.Fatalf("accepted=false: %+v", env.Data)
	}
	// 分页
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/learning/samples?page=2&page_size=2", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 3 || len(env.Data.Items) != 1 || env.Data.Items[0].RequestID != "r1" {
		t.Fatalf("paged samples: %+v", env.Data)
	}
}
