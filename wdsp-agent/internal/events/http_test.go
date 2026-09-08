// HTTPBatcher 分批上限测试（Phase 3 契约 §3：≤100 条且 ≤8MB；
// P1-03 批次预算统一：单条超限先缩减标记截断，仍超限丢弃计数）。
package events

import (
	"strings"
	"testing"
)

func mkRecord(bodyLen int) HTTPRecord {
	return HTTPRecord{
		FlowID: "a-1.1.1.1-80-2.2.2.2-8080-1",
		Request: &HTTPMessage{
			Method: "POST", Host: "h", URI: "/",
			Body: strings.Repeat("x", bodyLen),
		},
	}
}

func TestHTTPBatcherCountLimit(t *testing.T) {
	b := NewHTTPBatcher(nil)
	for i := 0; i < MaxHTTPRecordsPerBatch; i++ {
		if !b.Add(mkRecord(10)) {
			t.Fatalf("第 %d 条应可入批", i+1)
		}
	}
	if b.Len() != MaxHTTPRecordsPerBatch {
		t.Fatalf("批内条数错误: %d", b.Len())
	}
	// 第 101 条：批满返回 false；Flush 后新批可入
	if b.Add(mkRecord(10)) {
		t.Fatal("超 100 条应返回 false")
	}
	recs := b.Flush()
	if len(recs) != MaxHTTPRecordsPerBatch {
		t.Fatalf("Flush 条数错误: %d", len(recs))
	}
	if b.Len() != 0 || b.Flush() != nil {
		t.Fatal("空批 Flush 应为 nil")
	}
	if !b.Add(mkRecord(10)) {
		t.Fatal("新批首条必成功")
	}
}

func TestHTTPBatcherSizeLimit(t *testing.T) {
	b := NewHTTPBatcher(nil)
	// 单条 ~1MB：9 条必然触发 8MB 上限前返回 false
	added := 0
	for b.Add(mkRecord(1 << 20)) {
		added++
		if added > MaxHTTPRecordsPerBatch {
			t.Fatal("条数上限应先于字节上限触发")
		}
	}
	if added == 0 || added >= 9 {
		t.Fatalf("8MB 上限切批异常: added=%d", added)
	}
}

// P1-03：单条超 8MB 预算 → 清空 Body 并标记截断后入批（不再独占批放行）。
func TestHTTPBatcherOversizeShrunk(t *testing.T) {
	var drops []string
	b := NewHTTPBatcher(func(reason string) { drops = append(drops, reason) })
	if !b.Add(mkRecord(9 << 20)) {
		t.Fatal("超大单条经缩减后应可入批")
	}
	recs := b.Flush()
	if len(recs) != 1 {
		t.Fatalf("批应含 1 条: %d", len(recs))
	}
	r := recs[0]
	if r.Request.Body != "" || !r.Request.BodyTruncated ||
		r.Request.BodySkippedReason != BodySkippedBudgetExceeded {
		t.Fatalf("缩减标记错误: %+v", r.Request)
	}
	if len(drops) != 0 {
		t.Fatalf("缩减成功不应丢弃: %v", drops)
	}
	// 缩减后的记录与后续小记录可同批（不再独占一批）
	if !b.Add(recs[0]) || !b.Add(mkRecord(1)) {
		t.Fatal("缩减后的记录与小记录应可同批")
	}
	if b.Len() != 2 {
		t.Fatalf("批内条数错误: %d", b.Len())
	}
}

// P1-03：缩减后仍超限（无 Body、单条 Header 即超预算）→ 丢弃计数 oversize。
func TestHTTPBatcherOversizeDropped(t *testing.T) {
	var drops []string
	b := NewHTTPBatcher(func(reason string) { drops = append(drops, reason) })
	r := HTTPRecord{
		FlowID:  "a-1.1.1.1-80-2.2.2.2-8080-1",
		Request: &HTTPMessage{Method: "GET", Host: "h", URI: "/"},
	}
	// 构造无法靠缩减修复的超大记录：URI 本身超 8MB（URI 不是可选内容，不缩减）
	r.Request.URI = "/" + strings.Repeat("u", MaxHTTPRecordBytes)
	if !b.Add(r) {
		t.Fatal("丢弃的记录已消费，Add 应返回 true")
	}
	if b.Len() != 0 || b.Flush() != nil {
		t.Fatal("仍超限的记录应丢弃，不入批")
	}
	if len(drops) != 1 || drops[0] != DropOversize {
		t.Fatalf("应计数 oversize 一次: %v", drops)
	}
}

// P1-03：超大记录缩减顺序——先正文（双向），再 Header 从大到小。
func TestShrinkHTTPRecordOrder(t *testing.T) {
	r := HTTPRecord{
		FlowID: "f1",
		Request: &HTTPMessage{
			Method: "POST", Host: "h", URI: "/",
			Headers: map[string]string{"x-big": strings.Repeat("h", 2<<20)},
			Body:    strings.Repeat("x", 9<<20),
		},
		Response: &HTTPMessage{
			Status: 200,
			Body:   strings.Repeat("y", 2<<20),
		},
	}
	shrinkHTTPRecord(&r)
	if r.Request.Body != "" || r.Response.Body != "" {
		t.Fatal("双向 Body 应被清空")
	}
	if !r.Request.BodyTruncated || !r.Response.BodyTruncated {
		t.Fatal("双向 Body 应标记截断")
	}
	if r.Request.BodySkippedReason != BodySkippedBudgetExceeded ||
		r.Response.BodySkippedReason != BodySkippedBudgetExceeded {
		t.Fatal("应标记 budget_exceeded")
	}
	if recordBytes(&r) > MaxHTTPRecordBytes {
		t.Fatalf("缩减后仍超预算: %d", recordBytes(&r))
	}
	if _, ok := r.Request.Headers["x-big"]; !ok {
		t.Fatal("Body 缩减已足够时不应移除 Header")
	}
}

// P1-03：8MB 边界——含 JSON 转义的正文计入预算（转义膨胀不得绕过上限制）。
func TestHTTPBatcherEscapedBoundary(t *testing.T) {
	b := NewHTTPBatcher(nil)
	// 全为需转义字符（引号）：JSON 序列化后体积翻倍
	rec := mkRecord(0)
	rec.Request.Body = strings.Repeat(`"`, 5<<20) // 线上 5MB → 序列化 ~10MB
	if !b.Add(rec) {
		t.Fatal("首条应消费（入批或缩减入批）")
	}
	recs := b.Flush()
	if len(recs) != 1 {
		t.Fatalf("批应含 1 条: %d", len(recs))
	}
	if recs[0].Request.Body != "" {
		t.Fatal("转义后超预算应缩减 Body")
	}
	// 逐字节逼近上限：9 条各 ~0.9MB 序列化正文应触发切批
	b2 := NewHTTPBatcher(nil)
	small := mkRecord(0)
	small.Request.Body = strings.Repeat("x", 900<<10)
	added := 0
	for b2.Add(small) {
		added++
		if added > MaxHTTPRecordsPerBatch {
			t.Fatal("条数上限应先于字节上限触发")
		}
	}
	if added == 0 || added >= 10 {
		t.Fatalf("8MB 边界切批异常: added=%d", added)
	}
}
