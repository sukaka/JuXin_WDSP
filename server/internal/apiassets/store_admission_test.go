// store_admission_test.go ListConfirmedByApplication 确认集查询测试（API 准入 P1）：
// 仅 CONFIRMED 入选、按应用过滤、endpoint_key 升序确定（内存仓储驱动，
// 与 SQL 实现同口径——排序/过滤语义一致性由本测试冻结）。
package apiassets

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestMemStoreListConfirmedByApplication(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	appA := uuid.New()
	appB := uuid.New()

	mustDiscover := func(appID *uuid.UUID, method, path string) *Endpoint {
		t.Helper()
		e, err := store.UpsertDiscovery(ctx, DiscoveryInput{
			Method: method, PathTemplate: path, Confidence: 0.7, IsAPI: true, ApplicationID: appID,
		})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	// 应用 A：三个端点——一个确认、一个保持 DISCOVERED、一个转 IGNORED
	ea1 := mustDiscover(&appA, "POST", "/v1/login")
	mustDiscover(&appA, "GET", "/v1/orders/{id}")
	ea3 := mustDiscover(&appA, "GET", "/v1/coupon")
	// 应用 B：一个确认端点（同键不同应用，验证按应用过滤）
	eb1 := mustDiscover(&appB, "POST", "/v1/login")
	// 未归属端点（application_id 为 nil）不得混入
	mustDiscover(nil, "GET", "/v1/orphan")

	if _, err := store.Confirm(ctx, ea1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(ctx, eb1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetAssetStatus(ctx, ea3.ID, "IGNORED", "tester"); err != nil {
		t.Fatal(err)
	}

	got, err := store.ListConfirmedByApplication(ctx, appA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "POST /v1/login" {
		t.Fatalf("应用 A 确认集应为 [POST /v1/login]，got %v", got)
	}
	gotB, err := store.ListConfirmedByApplication(ctx, appB)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotB) != 1 || gotB[0] != "POST /v1/login" {
		t.Fatalf("应用 B 确认集应为 [POST /v1/login]，got %v", gotB)
	}
	// 无确认端点的应用：非 nil 空切片（下发 JSON 为 [] 而非 null）
	gotEmpty, err := store.ListConfirmedByApplication(ctx, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if gotEmpty == nil || len(gotEmpty) != 0 {
		t.Fatalf("空确认集应为非 nil 空切片，got %#v", gotEmpty)
	}

	// 排序确定：多确认端点按 endpoint_key 升序
	ea4 := mustDiscover(&appA, "GET", "/v1/zeta")
	ea5 := mustDiscover(&appA, "DELETE", "/v1/alpha")
	if _, err := store.Confirm(ctx, ea4.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(ctx, ea5.ID); err != nil {
		t.Fatal(err)
	}
	gotSorted, err := store.ListConfirmedByApplication(ctx, appA)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DELETE /v1/alpha", "GET /v1/zeta", "POST /v1/login"}
	if len(gotSorted) != len(want) {
		t.Fatalf("确认集长度 %d，want %d: %v", len(gotSorted), len(want), gotSorted)
	}
	for i := range want {
		if gotSorted[i] != want[i] {
			t.Fatalf("确认集排序不符: got %v, want %v", gotSorted, want)
		}
	}
}
