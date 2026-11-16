package jiuzhang_guard

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func responseBodySSEGuard(t *testing.T) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = responseBodySensitiveGuardRules()
	return g, logPath
}

func responseBodySSEUnchecked(records []apievents.Record, reason string) bool {
	for _, record := range records {
		for _, detail := range record.Details {
			if detail.RuleID == "sensitive.response_body_unchecked" &&
				detail.Evidence["completion"] == "partial" && detail.Evidence["skip_reason"] == reason {
				return true
			}
		}
	}
	return false
}

func TestServeNextSSESensitiveValuesAcrossChunksAndEvents(t *testing.T) {
	g, logPath := responseBodySSEGuard(t)
	chunks := []string{
		": keepalive\n\n",
		"data: {\"ok\":", "true}\n\n",
		"data: {\"contact\":\"138001", "38000\"}\n\n",
		"data: 13912345678\n\n",
	}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, chunk := range chunks {
			if _, err := io.WriteString(w, chunk); err != nil {
				return err
			}
		}
		return nil
	})
	req := compressedResponseRequest("response-sse-chunks")
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if got, want := recorder.Body.String(), strings.Join(chunks, ""); got != want {
		t.Fatalf("SSE bytes changed:\n%q\nwant:\n%q", got, want)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 || records[0].FinalAction != "OBSERVE" {
		t.Fatalf("SSE value observations must not block: %+v", records)
	}
	var firstHit, secondHit bool
	for _, detail := range records[0].Details {
		if detail.RuleID != "sensitive.response_value" {
			continue
		}
		switch detail.Evidence["field"] {
		case "sse.event[3].data.contact":
			firstHit = true
		case "sse.event[4].data.line[1]":
			secondHit = true
		}
	}
	if !firstHit || !secondHit {
		t.Fatalf("JSON/text event hits missing: first=%v second=%v details=%+v", firstHit, secondHit, records[0].Details)
	}
	if responseBodySSEUnchecked(records, "") {
		t.Fatalf("complete in-budget stream must not be partial: %+v", records[0].Details)
	}
	rc := RequestContextFrom(req).GetResponse()
	if rc == nil || len(rc.SensitiveFields) != 2 {
		t.Fatalf("stream SensitiveFields were not preserved: %+v", rc)
	}
	assertCompressedResponseEventRedacted(t, records, "13800138000")
	assertCompressedResponseEventRedacted(t, records, "13912345678")
}

func TestServeNextSSEEventByteBudgetPassesOriginalBytes(t *testing.T) {
	g, logPath := responseBodySSEGuard(t)
	payload := "data: " + strings.Repeat("x", mcpSSEMaxEventBytes) + "\ndata: 13800138000\n\n"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
		return nil
	})
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, compressedResponseRequest("response-sse-event-budget"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Body.String() != payload {
		t.Fatal("over-budget event must be delivered byte-for-byte")
	}
	records := readAPIRecords(t, logPath)
	if !responseBodySSEUnchecked(records, "SSE_EVENT_BYTES_EXCEEDED") {
		t.Fatalf("event budget partial missing: %+v", records[0].Details)
	}
	if compressedResponseRuleExists(records, "sensitive.response_value") {
		t.Fatal("over-budget event must not be scanned")
	}
	assertCompressedResponseEventRedacted(t, records, "13800138000")
}

func TestServeNextSSEEventCountBudgetUsesKeepaliveBoundaries(t *testing.T) {
	g, logPath := responseBodySSEGuard(t)
	var stream strings.Builder
	for i := 0; i < mcpSSEMaxEvents; i++ {
		stream.WriteString(": keepalive\n\n")
	}
	stream.WriteString("data: 13800138000\n\n")
	payload := stream.String()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
		return nil
	})
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, compressedResponseRequest("response-sse-count-budget"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Body.String() != payload {
		t.Fatal("event-count degradation must preserve every byte")
	}
	records := readAPIRecords(t, logPath)
	if !responseBodySSEUnchecked(records, "SSE_EVENT_COUNT_EXCEEDED") {
		t.Fatalf("event count partial missing: %+v", records[0].Details)
	}
	if compressedResponseRuleExists(records, "sensitive.response_value") {
		t.Fatal("event after the 4096-event budget must not be scanned")
	}
}

func TestResponseSSEWriterStreamByteBudget(t *testing.T) {
	g, _ := responseBodySSEGuard(t)
	ctx := dsctx.New("response-sse-stream-budget", dsctx.DefaultParseLimits())
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Content-Type", "text/event-stream")
	_, writer := g.wrapResponseBodySSEResponse(recorder, ctx, false)
	writer.streamBytes = mcpSSEMaxStreamBytes
	writer.WriteHeader(http.StatusOK)
	payload := []byte("data: 13800138000\n\n")
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	writer.Finish()
	if !bytes.Equal(recorder.Body.Bytes(), payload) {
		t.Fatal("stream-budget bytes changed")
	}
	matches := ctx.CopyMatches()
	if !responseBodySSEUnchecked([]apievents.Record{{Details: matches}}, "SSE_STREAM_BYTES_EXCEEDED") {
		t.Fatalf("stream budget partial missing: %+v", matches)
	}
	for _, match := range matches {
		if match.RuleID == "sensitive.response_value" {
			t.Fatal("stream after the byte budget must not be scanned")
		}
	}
}

func TestServeNextSSEIncompleteTailPassesWithPartial(t *testing.T) {
	g, logPath := responseBodySSEGuard(t)
	const payload = "data: 13800138000"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
		return nil
	})
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, compressedResponseRequest("response-sse-incomplete"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Body.String() != payload {
		t.Fatal("incomplete tail must be forwarded unchanged")
	}
	records := readAPIRecords(t, logPath)
	if !responseBodySSEUnchecked(records, "SSE_INCOMPLETE_EVENT") {
		t.Fatalf("incomplete tail partial missing: %+v", records[0].Details)
	}
	if compressedResponseRuleExists(records, "sensitive.response_value") {
		t.Fatal("incomplete event must not be scanned")
	}
	assertCompressedResponseEventRedacted(t, records, "13800138000")
}

func TestServeNextMCPDoesNotDuplicateGenericSSEValueDetection(t *testing.T) {
	g, logPath := newMCPGuardWithValueRules(t, "OBSERVE")
	g.APISensitiveValueRules[0].Locations = []string{"json", "response_body"}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseSecondBad)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Body.String() != sseSecondBad {
		t.Fatal("MCP OBSERVE event must pass unchanged")
	}
	records := readAPIRecords(t, logPath)
	if !compressedResponseRuleExists(records, "mcp.result_sensitive_value") {
		t.Fatalf("MCP-specific value detail missing: %+v", records[0].Details)
	}
	if compressedResponseRuleExists(records, "sensitive.response_value") {
		t.Fatalf("MCP data must not be scanned again by the generic SSE writer: %+v", records[0].Details)
	}
}
