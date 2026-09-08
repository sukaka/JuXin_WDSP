// objectmodels_test.go 对象模型段提取与 SweepObjectModelsOnce 测试（内存仓储，语义同 SQL）。
package apiauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

const testUUID = "9f0a1b2c-3d4e-5f60-7a8b-9c0d1e2f3041"

// TestExtractObjectSegmentRefs 段引用提取（纯函数矩阵）：路径占位段位置/形态、
// Query 对象参数形态、不匹配与边界。
func TestExtractObjectSegmentRefs(t *testing.T) {
	cases := []struct {
		name     string
		template string
		rawPath  string
		want     []objectSegmentRef
	}{
		{"id 段提取", "/v1/users/{id}", "/v1/users/123",
			[]objectSegmentRef{{"path:2", "users", "123", "numeric"}}},
		{"uuid 段提取", "/v1/orders/{uuid}", "/v1/orders/" + testUUID,
			[]objectSegmentRef{{"path:2", "orders", testUUID, "uuid"}}},
		{"hex 段提取", "/files/{hex}", "/files/0123456789abcdef",
			[]objectSegmentRef{{"path:1", "files", "0123456789abcdef", "hex"}}},
		{"未知形态", "/users/{id}", "/users/abc",
			[]objectSegmentRef{{"path:1", "users", "abc", ""}}},
		{"多占位符位置", "/users/{user_id}/orders/{order_id}", "/users/u1/orders/o2",
			[]objectSegmentRef{{"path:1", "users", "u1", ""}, {"path:3", "orders", "o2", ""}}},
		{"占位符名兜底", "/{id}", "/42",
			[]objectSegmentRef{{"path:0", "id", "42", "numeric"}}},
		{"查询串截断", "/v1/users/{id}", "/v1/users/123?verbose=true",
			[]objectSegmentRef{{"path:2", "users", "123", "numeric"}}},
		{"query 对象参数", "/search", "/search?account_id=123&q=abc",
			[]objectSegmentRef{{"query:account_id", "account_id", "123", "numeric"}}},
		{"query uuid 参数", "/search", "/search?org=" + testUUID,
			[]objectSegmentRef{{"query:org", "org", testUUID, "uuid"}}},
		{"重复 query 参数取首次", "/s", "/s?id=1&id=2",
			[]objectSegmentRef{{"query:id", "id", "1", "numeric"}}},
		{"路径占位加 query", "/users/{id}", "/users/123?org=" + testUUID,
			[]objectSegmentRef{{"path:1", "users", "123", "numeric"}, {"query:org", "org", testUUID, "uuid"}}},
		{"query fragment 截断", "/s", "/s?id=123#frag",
			[]objectSegmentRef{{"query:id", "id", "123", "numeric"}}},
		{"fragment 截断", "/users/{id}", "/users/123#x",
			[]objectSegmentRef{{"path:1", "users", "123", "numeric"}}},
		{"静态段不匹配", "/v1/users/{id}", "/v1/orders/123", nil},
		{"段数不符 query 不补偿", "/users/{id}", "/users/123/extra?x=1", nil},
		{"无占位符无 query", "/v1/ping", "/v1/ping", nil},
		{"空捕获跳过", "/v1/users/{id}", "/v1/users/", nil},
		{"query 值非标识", "/s", "/s?q=abc-def", nil},
		{"无等号参数跳过", "/s", "/s?flag", nil},
		{"空查询串", "/s", "/s?", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractObjectSegmentRefs(tc.template, tc.rawPath)
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

// TestIdentifierTypeMerge 形态映射与合并口径（与 SQL upsert CASE 一致）。
func TestIdentifierTypeMerge(t *testing.T) {
	if got := identifierTypeOf("numeric"); got != "numeric" {
		t.Fatal(got)
	}
	if got := identifierTypeOf("uuid"); got != "uuid" {
		t.Fatal(got)
	}
	if got := identifierTypeOf("hex"); got != "hash" { // hex 落列口径 hash
		t.Fatal(got)
	}
	if got := identifierTypeOf(""); got != "unknown" {
		t.Fatal(got)
	}
	mergeCases := []struct{ old, new, want string }{
		{"numeric", "numeric", "numeric"},
		{"numeric", "unknown", "numeric"}, // unknown 不覆盖已知
		{"unknown", "uuid", "uuid"},       // 已知 refine unknown
		{"numeric", "uuid", "mixed"},      // 已知不一致 → mixed
		{"mixed", "hash", "mixed"},        // mixed 保持
		{"unknown", "unknown", "unknown"},
	}
	for _, tc := range mergeCases {
		if got := mergeIdentifierType(tc.old, tc.new); got != tc.want {
			t.Fatalf("merge(%s,%s)=%s want %s", tc.old, tc.new, got, tc.want)
		}
	}
}

// TestSweepObjectModelsOnce 首次全量回填 upsert（含匿名事件与 Query 参数形态）；
// 连续清扫不重复计数（水位幂等）；新事件到达后 sample_count 累加、last_seen 前移、
// 形态合并为 mixed；示例哈希只留首个。
func TestSweepObjectModelsOnce(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
	searchKey := "GET /search"
	searchID := store.addEndpoint(searchKey, "/search")

	base := time.Now().UTC().Add(-time.Hour)
	// 事件1：实名访问数字对象
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
	// 事件2：匿名事件也入对象模型（与权属按身份切分不同）
	store.addRuntimeEvent(epKey, "", "/v1/users/1002", base.Add(time.Minute))
	// 事件3：同段 uuid 形态 → 与 numeric 合并为 mixed
	store.addRuntimeEvent(epKey, "fp-b", "/v1/users/"+testUUID, base.Add(2*time.Minute))
	// 事件4：未知形态不改已知形态
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/abc", base.Add(3*time.Minute))
	// 事件5：无占位符端点的 Query 对象参数（匿名）
	store.addRuntimeEvent(searchKey, "", "/search?account_id="+testUUID, base.Add(4*time.Minute))

	res, err := store.SweepObjectModelsOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 5 || res.SegmentsExtracted != 5 || res.ModelsUpserted != 5 ||
		res.SkippedNoEndpoint != 0 || res.SkippedNoMatch != 0 {
		t.Fatalf("result=%+v", res)
	}
	rows := store.objectModelRows()
	if len(rows) != 2 {
		t.Fatalf("models=%d rows=%+v", len(rows), rows)
	}
	// objectModelRows 按 endpoint|segment 排序：search 端点 id 与 users 端点 id 字典序不定，按段键找
	var pathRow, queryRow *ObjectModel
	for i := range rows {
		switch rows[i].ObjectSegment {
		case "path:2":
			pathRow = &rows[i]
		case "query:account_id":
			queryRow = &rows[i]
		}
	}
	if pathRow == nil || queryRow == nil {
		t.Fatalf("rows=%+v", rows)
	}
	if pathRow.EndpointID != endpointID || pathRow.SampleCount != 4 || pathRow.IdentifierType != "mixed" {
		t.Fatalf("path row=%+v", pathRow)
	}
	if !pathRow.FirstSeen.Equal(base) || !pathRow.LastSeen.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("path row time=%+v", pathRow)
	}
	wantHash := sha256.Sum256([]byte("1001"))
	if pathRow.ExampleHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("example_hash=%s want first observed", pathRow.ExampleHash)
	}
	if queryRow.EndpointID != searchID || queryRow.SampleCount != 1 || queryRow.IdentifierType != "uuid" {
		t.Fatalf("query row=%+v", queryRow)
	}

	// 连续清扫：水位已前移，无新事件 → 全零结果，计数/形态不变（幂等）
	res2, err := store.SweepObjectModelsOnce(ctx)
	if err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if res2.EventsScanned != 0 || res2.ModelsUpserted != 0 || res2.HasMore {
		t.Fatalf("second sweep=%+v", res2)
	}
	for _, r := range store.objectModelRows() {
		if r.ObjectSegment == "path:2" && (r.SampleCount != 4 || r.IdentifierType != "mixed") {
			t.Fatalf("row changed after idle sweep: %+v", r)
		}
	}

	// 新事件（更晚时间）→ sample_count 累加、last_seen 前移、形态保持 mixed
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1003", base.Add(5*time.Minute))
	res3, err := store.SweepObjectModelsOnce(ctx)
	if err != nil {
		t.Fatalf("sweep3: %v", err)
	}
	if res3.EventsScanned != 1 || res3.ModelsUpserted != 1 {
		t.Fatalf("third sweep=%+v", res3)
	}
	for _, r := range store.objectModelRows() {
		if r.ObjectSegment == "path:2" {
			if r.SampleCount != 5 || r.IdentifierType != "mixed" || !r.LastSeen.Equal(base.Add(5*time.Minute)) {
				t.Fatalf("path row after new event=%+v", r)
			}
		}
	}
}

// TestSweepObjectModelsOnceEmpty 空表/无命中安全；未知端点与模板不匹配按跳过计数。
func TestSweepObjectModelsOnceEmpty(t *testing.T) {
	store := NewMemStore()
	res, err := store.SweepObjectModelsOnce(context.Background())
	if err != nil || res.EventsScanned != 0 || res.Watermark != nil {
		t.Fatalf("empty sweep=%+v err=%v", res, err)
	}
	// 未知端点事件跳过
	store.addRuntimeEvent("GET /ghost/{id}", "fp-a", "/ghost/1", time.Now().UTC())
	// 模板无占位段且无 Query 参数 → 无对象段
	store.addEndpoint("GET /ping", "/ping")
	store.addRuntimeEvent("GET /ping", "fp-a", "/ping", time.Now().UTC().Add(time.Minute))
	// 模板与 raw_path 静态段不符
	store.addEndpoint("GET /v1/users/{id}", "/v1/users/{id}")
	store.addRuntimeEvent("GET /v1/users/{id}", "fp-a", "/v1/orders/1", time.Now().UTC().Add(2*time.Minute))
	res, err = store.SweepObjectModelsOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 3 || res.SkippedNoEndpoint != 1 || res.SkippedNoMatch != 2 || res.ModelsUpserted != 0 {
		t.Fatalf("result=%+v", res)
	}
	if len(store.objectModelRows()) != 0 {
		t.Fatalf("models=%+v", store.objectModelRows())
	}
}

// TestExtractObjectRefsStillPathOnly 权属提取只取路径占位段（Query 参数不入权属），
// 保障 extractObjectRefs 重构后语义不变（补充既有矩阵用例）。
func TestExtractObjectRefsStillPathOnly(t *testing.T) {
	got := extractObjectRefs("/users/{id}", "/users/123?account_id="+testUUID)
	if len(got) != 1 || got[0] != (objectRef{ObjectType: "users", ObjectID: "123"}) {
		t.Fatalf("refs=%+v", got)
	}
}
