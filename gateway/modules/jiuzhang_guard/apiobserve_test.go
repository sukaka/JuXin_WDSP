package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// 响应结构观测端到端（P0-06）：API 流量 + 合法 JSON 响应 → 事件携带 response_observations
// （一级字段+类型+元信息）；不落值；非 JSON 响应零产出（事件零变化）。
func TestServeNext_ResponseObservationEmitted(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	upstreamBody := `{"code":0,"data":{"items":[1,2]},"msg":"ok","token":"secret-value-123"}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-obs-1")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	ev := recs[0]
	if len(ev.ResponseObservations) != 1 {
		t.Fatalf("response_observations = %+v", ev.ResponseObservations)
	}
	obs := ev.ResponseObservations[0]
	if obs.StatusCode != http.StatusOK || obs.ContentType != "application/json; charset=utf-8" || obs.BodySize != int64(len(upstreamBody)) {
		t.Fatalf("obs meta = %+v", obs)
	}
	want := map[string]string{"code": "number", "data": "object", "msg": "string", "token": "string"}
	for k, v := range want {
		if obs.Fields[k] != v {
			t.Fatalf("field %s = %q, want %q (obs=%+v)", k, obs.Fields[k], v, obs)
		}
	}
	if _, ok := obs.Fields["data.items"]; ok {
		t.Fatalf("nested path must not be observed: %+v", obs.Fields)
	}
	if obs.Truncated || obs.FieldCount != len(want) {
		t.Fatalf("count=%d truncated=%v", obs.FieldCount, obs.Truncated)
	}
	// 不落值：整条事件行不含响应明文值
	data, _ := os.ReadFile(logPath)
	if strings.Contains(string(data), "secret-value-123") {
		t.Fatalf("event must not contain response value: %s", data)
	}
}

// 非 JSON 响应：观测不产出，事件其余字段不变（零变化纪律）。
func TestServeNext_ResponseObservationSkippedNonJSON(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "plain-ok")
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5001"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if len(recs[0].ResponseObservations) != 0 {
		t.Fatalf("non-JSON must not produce observation: %+v", recs[0].ResponseObservations)
	}
	if recs[0].ResponseStatus != http.StatusOK || recs[0].FinalAction == "" {
		t.Fatalf("event fields regressed: %+v", recs[0])
	}
}
