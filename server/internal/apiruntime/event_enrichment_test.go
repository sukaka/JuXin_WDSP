// event_enrichment_test.go 事件审计维度字段（迁移 000035）解析与传播测试。
package apiruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// 新字段按 JSON 名解析；旧版网关事件（缺字段）解析为零值不报错（缺失容忍）。
func TestParseRecordLine_EnrichmentFields(t *testing.T) {
	rec, err := parseRecordLine([]byte(`{
		"request_id":"r-e1","endpoint_key":"GET /v1/users/{id}",
		"client_ip":"203.0.113.9","method":"GET","raw_path":"/v1/users/42",
		"latency_ms":137,"model_version":"v3","policy_version":"p-12"
	}`))
	if err != nil {
		t.Fatalf("valid enriched record rejected: %v", err)
	}
	if rec.ClientIP != "203.0.113.9" || rec.Method != "GET" || rec.RawPath != "/v1/users/42" ||
		rec.LatencyMs != 137 || rec.ModelVersion != "v3" || rec.PolicyVersion != "p-12" {
		t.Fatalf("enrichment fields not parsed: %+v", rec)
	}

	// 旧版记录：无新字段键，仍可采集（零值）
	old, err := parseRecordLine([]byte(`{"request_id":"r-e2","endpoint_key":"GET /a","method":"GET"}`))
	if err != nil {
		t.Fatalf("legacy record rejected: %v", err)
	}
	if old.ClientIP != "" || old.RawPath != "" || old.LatencyMs != 0 || old.ModelVersion != "" || old.PolicyVersion != "" {
		t.Fatalf("legacy record must keep zero values: %+v", old)
	}
}

// 审计维度字段随 notable 记录进入待入库主事件；缺失时保持零值（落库侧转 NULL）。
func TestCollectOnce_EnrichmentFieldsPropagate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")

	enriched := Record{
		RequestID: "r-en-1", EndpointKey: "GET /v1/orders/{id}", Method: "GET", PathTemplate: "/v1/orders/{id}",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "HIGH", RiskScore: 90,
		ClientIP: "198.51.100.7", RawPath: "/v1/orders/991", LatencyMs: 42,
		ModelVersion: "v7", PolicyVersion: "p-3",
		OccurredAt: time.Now().UTC(),
	}
	legacy := Record{
		RequestID: "r-en-2", EndpointKey: "GET /v1/legacy", Method: "GET", PathTemplate: "/v1/legacy",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "MEDIUM", RiskScore: 40,
		OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, enriched), mustJSON(t, legacy)})

	saver := &fakeSaver{}
	c := NewCollector(saver, "test-enrich", logPath, filepath.Join(dir, "cp"), "node-1")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(saver.saved) != 2 {
		t.Fatalf("want 2 primary saved, got %d", len(saver.saved))
	}
	ev := saver.saved[0]
	if ev.ClientIP != "198.51.100.7" || ev.Method != "GET" || ev.RawPath != "/v1/orders/991" ||
		ev.LatencyMs != 42 || ev.ModelVersion != "v7" || ev.PolicyVersion != "p-3" {
		t.Fatalf("enrichment not propagated: %+v", ev)
	}
	legacyEv := saver.saved[1]
	if legacyEv.ClientIP != "" || legacyEv.RawPath != "" || legacyEv.LatencyMs != 0 ||
		legacyEv.ModelVersion != "" || legacyEv.PolicyVersion != "" {
		t.Fatalf("legacy event must keep zero values: %+v", legacyEv)
	}
}

// NULL 转换纪律：空串/非正耗时转 nil（落 NULL），有效值原样通过。
func TestNullConversions(t *testing.T) {
	if nullIfEmpty("") != nil || nullIfEmpty("x") != "x" {
		t.Fatal("nullIfEmpty broken")
	}
	if nullIfNonPositive(0) != nil || nullIfNonPositive(-5) != nil || nullIfNonPositive(12) != int64(12) {
		t.Fatal("nullIfNonPositive broken")
	}
}
