package apievents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
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
