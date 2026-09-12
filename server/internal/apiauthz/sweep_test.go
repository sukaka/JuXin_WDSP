// sweep_test.go SweepOnce 权属清扫与模板提取测试（内存仓储，语义同 SQL）。
package apiauthz

import (
	"context"
	"testing"
	"time"
)

// TestExtractObjectRefs 模板/原始路径段对齐提取（纯函数矩阵）。
func TestExtractObjectRefs(t *testing.T) {
	cases := []struct {
		name     string
		template string
		rawPath  string
		want     []objectRef
	}{
		{"id 段提取", "/v1/users/{id}", "/v1/users/123", []objectRef{{"users", "123"}}},
		{"uuid 段提取", "/v1/orders/{uuid}", "/v1/orders/9f0a-bb", []objectRef{{"orders", "9f0a-bb"}}},
		{"多占位符", "/users/{user_id}/orders/{order_id}", "/users/u1/orders/o2",
			[]objectRef{{"users", "u1"}, {"orders", "o2"}}},
		{"占位符名兜底", "/{id}", "/42", []objectRef{{"id", "42"}}},
		{"连续占位符退化", "/a/{x}/{y}", "/a/1/2", []objectRef{{"a", "1"}, {"y", "2"}}},
		{"查询串截断", "/v1/users/{id}", "/v1/users/123?verbose=1", []objectRef{{"users", "123"}}},
		{"静态段不匹配", "/v1/users/{id}", "/v1/orders/123", nil},
		{"段数不符", "/v1/users/{id}", "/v1/users", nil},
		{"无占位符", "/v1/ping", "/v1/ping", nil},
		{"空捕获跳过", "/v1/users/{id}", "/v1/users/", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractObjectRefs(tc.template, tc.rawPath)
			if len(got) != len(tc.want) {
				t.Fatalf("refs=%+v want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("refs[%d]=%+v want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestSweepOnceUpsert 首次全量回填 upsert；连续清扫不重复计数（水位幂等）；
// 新事件到达后 access_count 累加、last_seen 前移。
func TestSweepOnceUpsert(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")

	base := time.Now().UTC().Add(-time.Hour)
	// 事件1：fp-a 访问对象 1001
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
	// 事件2：fp-a 再访问对象 1001（累计）
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base.Add(time.Minute))
	// 事件3：fp-b 访问对象 1001（同对象不同身份 → 独立权属行）
	store.addRuntimeEvent(epKey, "fp-b", "/v1/users/1001", base.Add(2*time.Minute))
	// 匿名事件不产权属（SweepOnce 扫描时按身份过滤，与 SQL WHERE 口径一致）
	store.addRuntimeEvent(epKey, "", "/v1/users/1002", base.Add(3*time.Minute))

	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 3 || res.ObjectsExtracted != 3 || res.OwnershipUpserted != 3 ||
		res.SkippedNoEndpoint != 0 || res.SkippedNoMatch != 0 {
		t.Fatalf("result=%+v", res)
	}
	rows := store.ownershipRows()
	if len(rows) != 2 {
		t.Fatalf("ownership=%d rows=%+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.EndpointID != endpointID || r.ObjectType != "users" || r.ObjectID != "1001" {
			t.Fatalf("row=%+v", r)
		}
		switch r.IdentityFingerprint {
		case "fp-a":
			if r.AccessCount != 2 || !r.LastSeen.Equal(base.Add(time.Minute)) || !r.FirstSeen.Equal(base) {
				t.Fatalf("fp-a row=%+v", r)
			}
		case "fp-b":
			if r.AccessCount != 1 {
				t.Fatalf("fp-b row=%+v", r)
			}
		default:
			t.Fatalf("unexpected identity row=%+v", r)
		}
	}

	// 连续清扫：水位已前移，无新事件 → 全零结果，计数不变（幂等）
	res2, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if res2.EventsScanned != 0 || res2.OwnershipUpserted != 0 || res2.HasMore {
		t.Fatalf("second sweep=%+v", res2)
	}
	for _, r := range store.ownershipRows() {
		if r.IdentityFingerprint == "fp-a" && r.AccessCount != 2 {
			t.Fatalf("count changed after idle sweep: %+v", r)
		}
	}

	// 新事件（更晚时间）→ access_count 累加、last_seen 前移
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base.Add(4*time.Minute))
	res3, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep3: %v", err)
	}
	if res3.EventsScanned != 1 || res3.OwnershipUpserted != 1 {
		t.Fatalf("third sweep=%+v", res3)
	}
	for _, r := range store.ownershipRows() {
		if r.IdentityFingerprint == "fp-a" {
			if r.AccessCount != 3 || !r.LastSeen.Equal(base.Add(4*time.Minute)) {
				t.Fatalf("fp-a after new event=%+v", r)
			}
		}
	}
}

// TestSweepOnceEmpty 空表/无命中安全。
func TestSweepOnceEmpty(t *testing.T) {
	store := NewMemStore()
	res, err := store.SweepOnce(context.Background())
	if err != nil || res.EventsScanned != 0 || res.Watermark != nil {
		t.Fatalf("empty sweep=%+v err=%v", res, err)
	}
	// 有事件但模板无占位符（无对象段）
	store.addEndpoint("GET /ping", "/ping")
	store.addRuntimeEvent("GET /ping", "fp-a", "/ping", time.Now().UTC())
	res, err = store.SweepOnce(context.Background())
	if err != nil || res.EventsScanned != 1 || res.SkippedNoMatch != 1 || res.OwnershipUpserted != 0 {
		t.Fatalf("no-match sweep=%+v err=%v", res, err)
	}
	if len(store.ownershipRows()) != 0 {
		t.Fatalf("ownership=%+v", store.ownershipRows())
	}
}

// TestSweepOnceUnknownEndpoint endpoint_key 未匹配资产的事件跳过并计数；
// raw_path 与模板静态段不符的事件按不匹配跳过。
func TestSweepOnceUnknownEndpoint(t *testing.T) {
	store := NewMemStore()
	store.addEndpoint("GET /v1/users/{id}", "/v1/users/{id}")
	store.addRuntimeEvent("GET /ghost/{id}", "fp-a", "/ghost/1", time.Now().UTC())
	store.addRuntimeEvent("GET /v1/users/{id}", "fp-a", "/v1/orders/1", time.Now().UTC().Add(time.Minute))
	res, err := store.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 2 || res.SkippedNoEndpoint != 1 || res.SkippedNoMatch != 1 || res.OwnershipUpserted != 0 {
		t.Fatalf("result=%+v", res)
	}
	if len(store.ownershipRows()) != 0 {
		t.Fatalf("ownership=%+v", store.ownershipRows())
	}
}
