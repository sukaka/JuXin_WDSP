package apiassets

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestMemStoreMerge 验证合并：命中数累加、other 删除、历史键归档别名。
func TestMemStoreMerge(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	primary, err := store.UpsertDiscovery(ctx, "GET", "/users/{id}", 0.7, true)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.UpsertDiscovery(ctx, "GET", "/users/{id}/detail", 0.6, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertDiscovery(ctx, "GET", "/users/{id}/detail", 0.6, true); err != nil {
		t.Fatal(err)
	}
	merged, err := store.Merge(ctx, primary.ID, other.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if merged.HitCount != primary.HitCount+2 {
		t.Fatalf("hit_count=%d, want %d", merged.HitCount, primary.HitCount+2)
	}
	if _, err := store.GetByID(ctx, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other should be deleted, err=%v", err)
	}
	if owner, ok := store.aliases["GET /users/{id}/detail"]; !ok || owner != primary.ID {
		t.Fatalf("alias not archived: %v", store.aliases)
	}
	// 自身合并与非存在端点
	if _, err := store.Merge(ctx, primary.ID, primary.ID, "tester"); err == nil {
		t.Fatal("merge self should fail")
	}
	if _, err := store.Merge(ctx, primary.ID, uuid.New(), "tester"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("merge missing other err=%v", err)
	}
}

// TestMemStoreSplit 验证拆分：继承方法/置信度、冲突检测、空路径拒绝。
func TestMemStoreSplit(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	src, err := store.UpsertDiscovery(ctx, "POST", "/orders/{id}", 0.8, true)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Split(ctx, src.ID, []string{"/orders/{id}/items", "/orders/{id}/refund"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 {
		t.Fatalf("created=%d", len(created))
	}
	for _, e := range created {
		if e.HTTPMethod != "POST" || e.APIConfidence != 0.8 || e.AssetStatus != "DISCOVERED" {
			t.Fatalf("split child: %+v", e)
		}
	}
	// 与现有端点键冲突（包含与本次新建冲突）
	if _, err := store.Split(ctx, src.ID, []string{"/orders/{id}/items"}, "tester"); !errors.Is(err, ErrEndpointConflict) {
		t.Fatalf("split conflict err=%v", err)
	}
	// 空路径列表 / 空白路径
	if _, err := store.Split(ctx, src.ID, nil, "tester"); err == nil {
		t.Fatal("empty paths should fail")
	}
	if _, err := store.Split(ctx, src.ID, []string{"  "}, "tester"); err == nil {
		t.Fatal("blank path should fail")
	}
	// 源端点不存在
	if _, err := store.Split(ctx, uuid.New(), []string{"/a"}, "tester"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("split missing src err=%v", err)
	}
}

// TestMemStoreSetAssetStatus 验证状态机与白名单。
func TestMemStoreSetAssetStatus(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e, err := store.UpsertDiscovery(ctx, "GET", "/health", 0.5, true)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.SetAssetStatus(ctx, e.ID, "ignored", "tester")
	if err != nil {
		t.Fatal(err)
	}
	if updated.AssetStatus != "IGNORED" {
		t.Fatalf("asset_status=%s", updated.AssetStatus)
	}
	if _, err := store.SetAssetStatus(ctx, e.ID, "BAD_STATUS", "tester"); err == nil {
		t.Fatal("invalid status should fail")
	}
	if _, err := store.SetAssetStatus(ctx, uuid.New(), "IGNORED", "tester"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing endpoint err=%v", err)
	}
}

// TestMemStoreUpsertAsset 验证资产扩展 upsert 与读取。
func TestMemStoreUpsertAsset(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e, err := store.UpsertDiscovery(ctx, "GET", "/pay/orders", 0.9, true)
	if err != nil {
		t.Fatal(err)
	}
	// 无记录时 GetAsset 返回 (nil, nil)
	if a, err := store.GetAsset(ctx, e.ID); err != nil || a != nil {
		t.Fatalf("empty asset: %v %v", a, err)
	}
	a, err := store.UpsertAsset(ctx, e.ID, "订单支付", "public", "支付组", []string{"core", "pci"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Purpose != "订单支付" || a.Exposure != "PUBLIC" || a.Owner != "支付组" || len(a.Tags) != 2 {
		t.Fatalf("asset: %+v", a)
	}
	// 再次 upsert 为全量替换
	a2, err := store.UpsertAsset(ctx, e.ID, "订单查询", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if a2.Purpose != "订单查询" || a2.Exposure != "INTERNAL" || a2.Tags == nil || len(a2.Tags) != 0 {
		t.Fatalf("asset replace: %+v", a2)
	}
	got, err := store.GetAsset(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != "订单查询" {
		t.Fatalf("get asset: %+v", got)
	}
	// 端点不存在
	if _, err := store.UpsertAsset(ctx, uuid.New(), "x", "", "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing endpoint err=%v", err)
	}
}

// TestMemStoreLearningLifecycle 验证学习启停状态机。
func TestMemStoreLearningLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e, err := store.UpsertDiscovery(ctx, "GET", "/users/{id}", 0.7, true)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	job, err := store.StartLearning(ctx, e.ID, &uid)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "RUNNING" || job.CreatedBy == nil || *job.CreatedBy != uid {
		t.Fatalf("job: %+v", job)
	}
	cur, err := store.GetByID(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.LearningStatus != "LEARNING" {
		t.Fatalf("learning_status=%s", cur.LearningStatus)
	}
	// 状态机冲突：重复启动
	if _, err := store.StartLearning(ctx, e.ID, nil); !errors.Is(err, ErrLearningRunning) {
		t.Fatalf("double start err=%v", err)
	}
	// 状态查询
	latest, stats, err := store.LearningStatus(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != job.ID || stats.Total != 0 {
		t.Fatalf("status: %+v %+v", latest, stats)
	}
	// 停止
	stopped, err := store.StopLearning(ctx, e.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != "STOPPED" || stopped.StoppedAt == nil {
		t.Fatalf("stopped: %+v", stopped)
	}
	cur, _ = store.GetByID(ctx, e.ID)
	if cur.LearningStatus != "PAUSED" {
		t.Fatalf("learning_status=%s", cur.LearningStatus)
	}
	// 状态机冲突：重复停止
	if _, err := store.StopLearning(ctx, e.ID, "tester"); !errors.Is(err, ErrLearningNotRunning) {
		t.Fatalf("double stop err=%v", err)
	}
	// 端点不存在
	if _, err := store.StartLearning(ctx, uuid.New(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("start missing err=%v", err)
	}
	if _, err := store.StopLearning(ctx, uuid.New(), "tester"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stop missing err=%v", err)
	}
	// 从未学习的端点状态
	e2, err := store.UpsertDiscovery(ctx, "GET", "/never-learned", 0.5, true)
	if err != nil {
		t.Fatal(err)
	}
	job2, stats2, err := store.LearningStatus(ctx, e2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job2 != nil || stats2.Total != 0 {
		t.Fatalf("never learned: %+v %+v", job2, stats2)
	}
}

// TestMemStoreAutoClassify 验证启发式分类与锁定冲突。
func TestMemStoreAutoClassify(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e, err := store.UpsertDiscovery(ctx, "POST", "/api/login/{id}", 0.7, true)
	if err != nil {
		t.Fatal(err)
	}
	dims, err := store.AutoClassify(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	var purpose, access string
	for _, d := range dims {
		if d.Source != "AUTO" || d.EndpointID != e.ID {
			t.Fatalf("dim: %+v", d)
		}
		switch d.Dimension {
		case "PURPOSE":
			purpose = d.Value
		case "ACCESS":
			access = d.Value
		}
	}
	if purpose != "AUTH" || access != "WRITE" {
		t.Fatalf("dims=%v purpose=%s access=%s", dims, purpose, access)
	}
	// 锁定后拒绝自动分类
	if err := store.SetClassificationLocked(ctx, e.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AutoClassify(ctx, e.ID); !errors.Is(err, ErrClassificationLocked) {
		t.Fatalf("locked err=%v", err)
	}
	if _, err := store.AutoClassify(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing err=%v", err)
	}
}

// TestMemStoreListFilters 验证新过滤条件。
func TestMemStoreListFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	e1, _ := store.UpsertDiscovery(ctx, "GET", "/users/{id}", 0.7, true)
	_, _ = store.UpsertDiscovery(ctx, "POST", "/orders", 0.8, true)
	if _, err := store.SetAssetStatus(ctx, e1.ID, "IGNORED", "tester"); err != nil {
		t.Fatal(err)
	}
	list, total, err := store.List(ctx, ListFilter{AssetStatus: "IGNORED", Page: 1, PageSize: 20})
	if err != nil || total != 1 || list[0].ID != e1.ID {
		t.Fatalf("asset_status filter: total=%d err=%v", total, err)
	}
	_, total, err = store.List(ctx, ListFilter{Keyword: "ORDERS", Page: 1, PageSize: 20})
	if err != nil || total != 1 {
		t.Fatalf("keyword filter: total=%d err=%v", total, err)
	}
	_, total, err = store.List(ctx, ListFilter{LearningStatus: "NOT_STARTED", Page: 1, PageSize: 20})
	if err != nil || total != 2 {
		t.Fatalf("learning filter: total=%d err=%v", total, err)
	}
	appID := uuid.New()
	_, total, err = store.List(ctx, ListFilter{ApplicationID: &appID, Page: 1, PageSize: 20})
	if err != nil || total != 0 {
		t.Fatalf("application filter: total=%d err=%v", total, err)
	}
}
