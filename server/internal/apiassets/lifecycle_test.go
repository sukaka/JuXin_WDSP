// lifecycle_test.go 资产生命周期增强单测（P0-10/P0-11）：
// deprecate/restore 状态机与 HTTP 入口、ZOMBIE 判定作业（SweepOnce）、
// 生命周期事件轨迹、服务资产接口与权限层。
package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// mustSeed 发现登记一个端点（测试辅助）。
func mustSeed(t *testing.T, store *MemStore, method, path string) *Endpoint {
	t.Helper()
	ep, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{Method: method, PathTemplate: path, Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

// TestDeprecateRestoreHTTP 人工下线/恢复：状态机流转、409/404/400 校验层、生命周期事件。
func TestDeprecateRestoreHTTP(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	ep := mustSeed(t, store, "GET", "/api/legacy/"+uuid.NewString()[:8]+"/{id}")

	// 非法 id → 400；不存在 → 404（deprecate 与 restore 同口径）
	for _, op := range []string{"deprecate", "restore"} {
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/not-a-uuid/"+op, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s bad id status=%d", op, rr.Code)
		}
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/"+op, nil)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s missing id status=%d", op, rr.Code)
		}
	}

	// DISCOVERED → DEPRECATED
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/deprecate", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("deprecate status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["message"] != "接口已标记下线" {
		t.Fatalf("deprecate message=%v", data["message"])
	}
	got, err := store.GetByID(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetStatus != "DEPRECATED" {
		t.Fatalf("asset_status=%s, want DEPRECATED", got.AssetStatus)
	}

	// 重复下线 → 409（DEPRECATED 不在合法起点）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/deprecate", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-deprecate status=%d, want 409", rr.Code)
	}

	// DEPRECATED → CONFIRMED（恢复）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/restore", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", rr.Code, rr.Body.String())
	}
	got, err = store.GetByID(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetStatus != "CONFIRMED" || got.ConfirmedAt == nil {
		t.Fatalf("restore: status=%s confirmed_at=%v, want CONFIRMED + confirmed_at", got.AssetStatus, got.ConfirmedAt)
	}

	// CONFIRMED 恢复 → 409（仅 DEPRECATED/ZOMBIE 可恢复）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/restore", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-restore status=%d, want 409", rr.Code)
	}

	// IGNORED 端点下线 → 409
	ignored := mustSeed(t, store, "GET", "/api/ignored-"+uuid.NewString()[:8])
	if _, err := store.SetAssetStatus(ctx, ignored.ID, "IGNORED", "tester"); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/"+ignored.ID.String()+"/deprecate", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("deprecate IGNORED status=%d, want 409", rr.Code)
	}

	// 生命周期事件轨迹：DEPRECATED→CONFIRMED 两条（含原因与操作者）
	events, total, err := store.ListLifecycleEvents(ctx, ep.ID, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("events total=%d, want 2", total)
	}
	if events[0].FromStatus != "DEPRECATED" || events[0].ToStatus != "CONFIRMED" || events[0].Actor != "tester" {
		t.Fatalf("restore event: %+v", events[0])
	}
	if events[1].FromStatus != "DISCOVERED" || events[1].ToStatus != "DEPRECATED" || events[1].Reason != "人工标记下线" {
		t.Fatalf("deprecate event: %+v", events[1])
	}
}

// TestLifecycleHTTPPermission 新端点未登录 401、无权限 403。
func TestLifecycleHTTPPermission(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	id := uuid.NewString()
	checks := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/api-security/endpoints/" + id + "/deprecate"},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + id + "/restore"},
		{http.MethodGet, "/api/v1/api-security/service-assets"},
	}

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, c := range checks {
		rr := doJSON(t, muxNoAuth, c.method, c.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", c.method, c.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	for _, c := range checks {
		rr := doJSON(t, muxNoPerm, c.method, c.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", c.method, c.path, rr.Code)
		}
	}
}

// TestZombieSweepOnce 僵尸判定作业：DEPRECATED 近 7 天仍有流量 → ZOMBIE；
// 其余状态不动；僵尸判定写生命周期事件；同轮完成价值评分回填；重复清扫幂等。
func TestZombieSweepOnce(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now().UTC()

	// A：DEPRECATED + 近窗口流量 → 应迁移 ZOMBIE
	a := mustSeed(t, store, "GET", "/api/zom-a-"+uuid.NewString()[:8])
	// B：DEPRECATED + 8 天前流量（出窗口）→ 保持 DEPRECATED
	b := mustSeed(t, store, "GET", "/api/zom-b-"+uuid.NewString()[:8])
	// C：DEPRECATED 无流量 → 保持 DEPRECATED
	c := mustSeed(t, store, "POST", "/api/zom-c-"+uuid.NewString()[:8])
	// D：DISCOVERED + 流量 → 保持 DISCOVERED（非候选）
	d := mustSeed(t, store, "GET", "/api/zom-d-"+uuid.NewString()[:8])
	for _, id := range []uuid.UUID{a.ID, b.ID, c.ID} {
		if _, err := store.Deprecate(ctx, id, "tester"); err != nil {
			t.Fatal(err)
		}
	}
	// 造流量：A 昨天 2 桶；B 8 天前 1 桶；D 当前 1 桶
	for i := 0; i < 2; i++ {
		if err := store.RecordTrafficBucket(ctx, a.ID, now.Add(-24*time.Hour).Add(time.Duration(i)*5*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordTrafficBucket(ctx, b.ID, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTrafficBucket(ctx, d.ID, now); err != nil {
		t.Fatal(err)
	}

	sweeper := NewSweeper(store, SweepOptions{})
	res, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.ZombieCandidates != 1 || res.Zombied != 1 {
		t.Fatalf("sweep result: %+v, want candidates=1 zombied=1", res)
	}
	if res.ValueRefreshed != 4 {
		t.Fatalf("value refreshed=%d, want 4（全部非 IGNORED 端点首轮评分）", res.ValueRefreshed)
	}

	ea, _ := store.GetByID(ctx, a.ID)
	if ea.AssetStatus != "ZOMBIE" || ea.ZombieSince == nil {
		t.Fatalf("A: status=%s zombie_since=%v, want ZOMBIE + zombie_since", ea.AssetStatus, ea.ZombieSince)
	}
	eb, _ := store.GetByID(ctx, b.ID)
	if eb.AssetStatus != "DEPRECATED" || eb.ZombieSince != nil {
		t.Fatalf("B: status=%s, want DEPRECATED（窗口外流量不判僵尸）", eb.AssetStatus)
	}
	ec, _ := store.GetByID(ctx, c.ID)
	if ec.AssetStatus != "DEPRECATED" {
		t.Fatalf("C: status=%s, want DEPRECATED（无流量不判僵尸）", ec.AssetStatus)
	}
	ed, _ := store.GetByID(ctx, d.ID)
	if ed.AssetStatus != "DISCOVERED" {
		t.Fatalf("D: status=%s, want DISCOVERED（非 DEPRECATED 不判僵尸）", ed.AssetStatus)
	}

	// 僵尸判定写生命周期事件（actor=system，原因含观察窗口）
	events, _, err := store.ListLifecycleEvents(ctx, a.ID, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	var zombieEv *LifecycleEvent
	for i := range events {
		if events[i].ToStatus == "ZOMBIE" {
			zombieEv = &events[i]
		}
	}
	if zombieEv == nil || zombieEv.FromStatus != "DEPRECATED" || zombieEv.Actor != "system" ||
		!strings.Contains(zombieEv.Reason, "僵尸判定") {
		t.Fatalf("zombie lifecycle event: %+v", events)
	}

	// 价值评分回填：四端点均有 asset_value 与可解析 explain
	for _, id := range []uuid.UUID{a.ID, b.ID, c.ID, d.ID} {
		e, err := store.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if e.AssetValue == "" || len(e.AssetValueExplain) == 0 {
			t.Fatalf("endpoint %s asset_value=%q explain empty", id, e.AssetValue)
		}
		var score AssetValueScore
		if err := json.Unmarshal(e.AssetValueExplain, &score); err != nil {
			t.Fatalf("explain not json: %v", err)
		}
		if score.Level != e.AssetValue || score.ComputedAt == nil || len(score.Dimensions) != 9 {
			t.Fatalf("explain mismatch: level=%s computed=%v dims=%d", score.Level, score.ComputedAt, len(score.Dimensions))
		}
	}

	// 幂等：A 已是 ZOMBIE 不再候选；无新流量价值不重算
	res2, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res2.ZombieCandidates != 0 || res2.Zombied != 0 || res2.ValueRefreshed != 0 {
		t.Fatalf("second sweep: %+v, want 全零（幂等）", res2)
	}

	// ZOMBIE 人工恢复：zombie_since 清空、状态 CONFIRMED
	restored, err := store.Restore(ctx, a.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if restored.AssetStatus != "CONFIRMED" || restored.ZombieSince != nil {
		t.Fatalf("restore zombie: status=%s zombie_since=%v", restored.AssetStatus, restored.ZombieSince)
	}
}

// TestZombieSweepOptions 窗口可配：缩短窗口后旧流量不再命中僵尸判定。
func TestZombieSweepOptions(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now().UTC()

	ep := mustSeed(t, store, "GET", "/api/zom-win-"+uuid.NewString()[:8])
	if _, err := store.Deprecate(ctx, ep.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	// 3 天前流量：默认 7 天窗口命中，1 天窗口不命中
	if err := store.RecordTrafficBucket(ctx, ep.ID, now.Add(-3*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	res, err := NewSweeper(store, SweepOptions{ZombieWindowDays: 1}).SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.ZombieCandidates != 0 {
		t.Fatalf("window=1d candidates=%d, want 0", res.ZombieCandidates)
	}
	res, err = NewSweeper(store, SweepOptions{ZombieWindowDays: 7}).SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Zombied != 1 {
		t.Fatalf("window=7d zombied=%d, want 1", res.Zombied)
	}
}

// TestMarkZombieConcurrent 并发安全语义：端点已非 DEPRECATED 时 MarkZombie 跳过不报错。
func TestMarkZombieConcurrent(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ep := mustSeed(t, store, "GET", "/api/zom-race-"+uuid.NewString()[:8])

	// 未 DEPRECATED：返回 false（调用方跳过）
	marked, err := store.MarkZombie(ctx, ep.ID, time.Now().UTC(), "测试")
	if err != nil || marked {
		t.Fatalf("mark zombie on DISCOVERED: marked=%v err=%v, want false/nil", marked, err)
	}
	// 不存在端点：ErrNotFound
	if _, err := store.MarkZombie(ctx, uuid.New(), time.Now().UTC(), "测试"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark zombie missing: err=%v, want ErrNotFound", err)
	}
}

// TestZombieSinceInvariant zombie_since 不变式：仅 ZOMBIE 态持有时间戳，
// 任何离开 ZOMBIE 的路径（restore / SetAssetStatus 忽略）都清空。
func TestZombieSinceInvariant(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	ep := mustSeed(t, store, "GET", "/api/zom-inv-"+uuid.NewString()[:8])
	if _, err := store.Deprecate(ctx, ep.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTrafficBucket(ctx, ep.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	marked, err := store.MarkZombie(ctx, ep.ID, time.Now().UTC(), "僵尸判定")
	if err != nil || !marked {
		t.Fatalf("mark zombie: marked=%v err=%v", marked, err)
	}
	got, _ := store.GetByID(ctx, ep.ID)
	if got.ZombieSince == nil {
		t.Fatal("ZOMBIE 态 zombie_since 应为非空")
	}

	// 通用状态变更路径（忽略 ZOMBIE 端点）也清空
	if _, err := store.SetAssetStatus(ctx, ep.ID, "IGNORED", "tester"); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetByID(ctx, ep.ID)
	if got.AssetStatus != "IGNORED" || got.ZombieSince != nil {
		t.Fatalf("ignore zombie: status=%s zombie_since=%v, want IGNORED + 清空", got.AssetStatus, got.ZombieSince)
	}
}

// TestServiceAssetsHTTP 服务资产接口：分页返回 + 校验层（聚合 SQL 语义由集成测试覆盖）。
func TestServiceAssetsHTTP(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	store.AddServiceAsset(ServiceAsset{ServerIP: "10.0.0.1", Port: 8080, ApplicationCount: 2, APICount: 5, Traffic7d: 1200, SensitiveAPICount: 1, RiskCount: 3})
	store.AddServiceAsset(ServiceAsset{ServerIP: "10.0.0.2", Port: 9090, ApplicationCount: 1, APICount: 2})

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/service-assets", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("service-assets status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Data struct {
			Items []ServiceAsset `json:"items"`
			Total int64          `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 2 || len(env.Data.Items) != 2 {
		t.Fatalf("service-assets total=%d items=%d", env.Data.Total, len(env.Data.Items))
	}
	first := env.Data.Items[0]
	if first.ServerIP != "10.0.0.1" || first.Port != 8080 || first.ApplicationCount != 2 ||
		first.APICount != 5 || first.Traffic7d != 1200 || first.SensitiveAPICount != 1 || first.RiskCount != 3 {
		t.Fatalf("service-assets[0]: %+v", first)
	}

	// 分页：page_size=1 第二页
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/service-assets?page=2&page_size=1", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Total != 2 || len(env.Data.Items) != 1 || env.Data.Items[0].ServerIP != "10.0.0.2" {
		t.Fatalf("paged service-assets: %+v", env.Data)
	}
}
