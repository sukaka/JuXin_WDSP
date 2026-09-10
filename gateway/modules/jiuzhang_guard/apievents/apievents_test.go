package apievents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// emitAndRead 输出一条记录并读回最后一行 JSON。
func emitAndRead(t *testing.T, rec Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api-events.jsonl")
	l, err := NewLogger(path, "node-t")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer l.Close()
	if rec.RequestID == "" {
		rec.RequestID = "rid-t"
	}
	rec.OccurredAt = time.Now().UTC()
	if err := l.Emit(rec); err != nil {
		t.Fatalf("emit: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// 携带响应结构观测：response_observations 键存在且形态完整（不落值）。
func TestEmit_WithResponseObservations(t *testing.T) {
	line := emitAndRead(t, Record{
		EndpointKey: "GET /v1/users/{id}",
		FinalAction: "ALLOW",
		ResponseObservations: []dsctx.ResponseObservation{{
			StatusCode:  200,
			ContentType: "application/json",
			BodySize:    64,
			Fields:      map[string]string{"id": "number", "name": "string"},
			FieldCount:  2,
		}},
	})
	if !strings.Contains(line, `"response_observations"`) {
		t.Fatalf("key missing: %s", line)
	}
	var got struct {
		Obs []struct {
			StatusCode int               `json:"status_code"`
			Fields     map[string]string `json:"fields"`
			FieldCount int               `json:"field_count"`
		} `json:"response_observations"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Obs) != 1 || got.Obs[0].StatusCode != 200 || got.Obs[0].Fields["id"] != "number" || got.Obs[0].FieldCount != 2 {
		t.Fatalf("obs roundtrip = %+v", got.Obs)
	}
}

// 无观测：response_observations 键省略（omitempty），事件较旧版零变化。
func TestEmit_WithoutResponseObservations(t *testing.T) {
	line := emitAndRead(t, Record{EndpointKey: "GET /v1/ping", FinalAction: "ALLOW"})
	if strings.Contains(line, "response_observations") {
		t.Fatalf("key must be omitted when no observation: %s", line)
	}
}

func TestEmit_AuthzDecisionContainsOnlyHMACObjectRef(t *testing.T) {
	ref := detectors.ObjectRefHMAC([]byte("event-test-key"), "order-123")
	line := emitAndRead(t, Record{
		EndpointKey: "GET /v1/orders/{id}",
		AuthzDecision: &dsevents.AuthorizationDecisionGroup{
			DecisionID: "az-test",
			Decision:   dsevents.AuthorizationObserveViolation,
			Checks: []dsevents.AuthorizationCheck{
				{Type: "BOLA", Decision: dsevents.AuthorizationObserveViolation, ObjectRef: "order-123", Role: "admin"},
				{Type: "BOLA", Decision: dsevents.AuthorizationAllow, ObjectRef: ref},
			},
		},
	})
	if strings.Contains(line, "order-123") || strings.Contains(line, `"role":"admin"`) {
		t.Fatalf("raw object ID or role claim leaked: %s", line)
	}
	if !strings.Contains(line, ref) {
		t.Fatalf("HMAC object ref missing: %s", line)
	}
}

// 后台写失败必须由 Close 上报，即使文件关闭本身也返回错误，避免先返回 close
// 错误而遮蔽异步写错误。
func TestCloseReportsBackgroundWriteFailureWhenFileCloseAlsoFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-events.jsonl")
	l, err := NewLogger(path, "node-t")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	// 暂停 writer，使事件稳定进入后台队列；随后从 Logger 外部关闭文件，模拟
	// 后台落盘失败，并重新交还令牌让 writer 处理队列。
	<-l.writeTok
	if err := l.Emit(Record{RequestID: "queued-write-failure"}); err != nil {
		t.Fatalf("queue emit: %v", err)
	}
	if err := l.f.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}
	l.writeTok <- struct{}{}
	l.notify <- struct{}{}

	err = l.Close()
	if err == nil || !strings.Contains(err.Error(), "background write") {
		t.Fatalf("Close error = %v, want background write failure", err)
	}
	if again := l.Close(); again == nil || again.Error() != err.Error() {
		t.Fatalf("second Close error = %v, want same close result", again)
	}
}

func TestQueueFullIsReportedByCloseWithoutDeadlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-events.jsonl")
	l, err := NewLogger(path, "node-t")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	// Hold the write token so the queue cannot drain while it is being filled.
	<-l.writeTok
	for i := 0; i < eventQueueSize; i++ {
		if err := l.Emit(Record{RequestID: fmt.Sprintf("queued-%d", i)}); err != nil {
			t.Fatalf("queue emit %d: %v", i, err)
		}
	}
	l.mu.Lock()
	l.lastReport = time.Now()
	l.mu.Unlock()
	if err := l.Emit(Record{RequestID: "dropped"}); err != nil {
		t.Fatalf("queue-full error should be deferred to Close: %v", err)
	}

	l.writeTok <- struct{}{}
	l.notify <- struct{}{}
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "queue full") {
			t.Fatalf("Close error = %v, want queue-full report", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked while draining queue")
	}
}
