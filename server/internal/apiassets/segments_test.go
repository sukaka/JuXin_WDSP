// segments_test.go 段形派生与发现链路生产方测试（内存仓储，语义同 SQL）。
package apiassets

import (
	"context"
	"testing"
)

// TestDerivePathSegments 段形派生（纯函数矩阵）：位置序号、静态/变量段、根路径与退化段。
func TestDerivePathSegments(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []PathSegment
	}{
		{"静态加占位", "/v1/users/{id}", []PathSegment{
			{Position: 0, LiteralValue: "v1"},
			{Position: 1, LiteralValue: "users"},
			{Position: 2, IsVariable: true, VariableName: "id"},
		}},
		{"uuid/hex 占位", "/files/{uuid}/raw/{hex}", []PathSegment{
			{Position: 0, LiteralValue: "files"},
			{Position: 1, IsVariable: true, VariableName: "uuid"},
			{Position: 2, LiteralValue: "raw"},
			{Position: 3, IsVariable: true, VariableName: "hex"},
		}},
		{"自定义占位名亦为变量段", "/a/{order_id}", []PathSegment{
			{Position: 0, LiteralValue: "a"},
			{Position: 1, IsVariable: true, VariableName: "order_id"},
		}},
		{"根路径无段", "/", nil},
		{"空路径无段", "", nil},
		{"单静态段", "/health", []PathSegment{{Position: 0, LiteralValue: "health"}}},
		{"无前导斜杠同口径", "v1/{id}", []PathSegment{
			{Position: 0, LiteralValue: "v1"},
			{Position: 1, IsVariable: true, VariableName: "id"},
		}},
		{"退化空段按静态空串保留", "/v1//x", []PathSegment{
			{Position: 0, LiteralValue: "v1"},
			{Position: 1, LiteralValue: ""},
			{Position: 2, LiteralValue: "x"},
		}},
		{"空花括号非占位", "/a/{}", []PathSegment{
			{Position: 0, LiteralValue: "a"},
			{Position: 1, LiteralValue: "{}"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := derivePathSegments(tc.path)
			if len(got) != len(tc.want) {
				t.Fatalf("segs=%+v want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("segs[%d]=%+v want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestMemStorePathSegmentsLifecycle 发现链路生产方：首插派生、命中重放不改写（幂等）、
// 拆分派生新端点段形、合并删除对方段形。
func TestMemStorePathSegmentsLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	// 首插派生
	ep, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/users/{id}/orders/{uuid}", Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []PathSegment{
		{EndpointID: ep.ID, Position: 0, LiteralValue: "v1"},
		{EndpointID: ep.ID, Position: 1, LiteralValue: "users"},
		{EndpointID: ep.ID, Position: 2, IsVariable: true, VariableName: "id"},
		{EndpointID: ep.ID, Position: 3, LiteralValue: "orders"},
		{EndpointID: ep.ID, Position: 4, IsVariable: true, VariableName: "uuid"},
	}
	assertSegments := func(who string, got []PathSegment, want []PathSegment) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s segs=%+v want %+v", who, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s segs[%d]=%+v want %+v", who, i, got[i], want[i])
			}
		}
	}
	segs, err := store.ListPathSegments(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertSegments("首插", segs, want)

	// 命中重放：hit_count 累加但段形不重写（幂等）
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "get", PathTemplate: "/v1/users/{id}/orders/{uuid}", Confidence: 0.9, IsAPI: true}); err != nil {
		t.Fatal(err)
	}
	segs, err = store.ListPathSegments(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertSegments("重放", segs, want)

	// 拆分：新端点派生段形
	created, err := store.Split(ctx, ep.ID, []string{"/v1/users/{id}/detail"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("split=%+v", created)
	}
	segs, err = store.ListPathSegments(ctx, created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	assertSegments("拆分", segs, []PathSegment{
		{EndpointID: created[0].ID, Position: 0, LiteralValue: "v1"},
		{EndpointID: created[0].ID, Position: 1, LiteralValue: "users"},
		{EndpointID: created[0].ID, Position: 2, IsVariable: true, VariableName: "id"},
		{EndpointID: created[0].ID, Position: 3, LiteralValue: "detail"},
	})

	// 合并：对方端点段形随删除清理
	if _, err := store.Merge(ctx, ep.ID, created[0].ID, "tester"); err != nil {
		t.Fatal(err)
	}
	segs, err = store.ListPathSegments(ctx, created[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("合并后对方段形未清理: %+v", segs)
	}
	// 主端点段形不受影响
	segs, err = store.ListPathSegments(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertSegments("合并后主端点", segs, want)

	// 根路径端点无段
	root, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/", Confidence: 0.5, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	segs, err = store.ListPathSegments(ctx, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("根路径段形: %+v", segs)
	}
}
