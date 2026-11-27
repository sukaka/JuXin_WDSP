package jiuzhang_guard

import (
	"bytes"
	"net/http/httptest"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
)

// TestMCPSSEWriterDegradeWriteContractAndCRLFBoundaries 验证：
// 1) 当缓冲中已有待发送前缀且本次 Write 触发预算降级时，Write 返回 n == len(p)（绝不违反 io.Writer 返回 n > len(p)）；
// 2) hasMCPSSEEventBoundary 同样识别 \r\n\r\n 与 \r\r 两种合法 SSE 事件分隔符。
func TestMCPSSEWriterDegradeWriteContractAndCRLFBoundaries(t *testing.T) {
	if !hasMCPSSEEventBoundary([]byte("data: 1\r\n\r\n")) {
		t.Fatal("expected CRLF CRLF boundary to be recognized")
	}
	if !hasMCPSSEEventBoundary([]byte("data: 1\r\r")) {
		t.Fatal("expected CR CR boundary to be recognized")
	}
	if hasMCPSSEEventBoundary([]byte("data: partial\r\n")) {
		t.Fatal("single CRLF must not be treated as complete event boundary")
	}

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/event-stream")
	rc := dsctx.New("req-sse-1", dsctx.DefaultParseLimits())
	mw := &mcpSSEWriter{
		base: rec,
		rc:   rc,
		call: &mcpguard.CallContext{Method: "tools/call"},
	}
	// 先写入半个事件进入 pending
	chunk1 := bytes.Repeat([]byte("a"), 1024)
	n1, err := mw.Write(chunk1)
	if err != nil || n1 != len(chunk1) {
		t.Fatalf("chunk1 write = (%d, %v), want (%d, nil)", n1, err, len(chunk1))
	}
	// 第二片触发 event_bytes 预算降级：总 pending = 1024 + (1MiB) > 1MiB，但 Write 必须返回 len(chunk2) 而非 len(pending)
	chunk2 := bytes.Repeat([]byte("b"), mcpSSEMaxEventBytes)
	n2, err := mw.Write(chunk2)
	if err != nil {
		t.Fatalf("chunk2 write err = %v", err)
	}
	if n2 != len(chunk2) {
		t.Fatalf("io.Writer contract violated: Write returned n=%d, len(p)=%d (n must equal len(p))", n2, len(chunk2))
	}
	if !mw.degraded {
		t.Fatal("expected writer to degrade on event_bytes overflow")
	}
	if rec.Body.Len() != len(chunk1)+len(chunk2) {
		t.Fatalf("flushed body len = %d, want %d", rec.Body.Len(), len(chunk1)+len(chunk2))
	}
}
