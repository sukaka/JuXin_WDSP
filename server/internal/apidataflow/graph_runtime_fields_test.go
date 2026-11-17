package apidataflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apm"
)

type runtimeFieldFakeReader struct {
	records []RuntimeFieldRecord
	queries []RuntimeFieldQuery
	err     error
}

func (f *runtimeFieldFakeReader) ReadRuntimeFields(_ context.Context, query RuntimeFieldQuery) ([]RuntimeFieldRecord, error) {
	query.References = append([]RuntimeFieldReference(nil), query.References...)
	f.queries = append(f.queries, query)
	return append([]RuntimeFieldRecord(nil), f.records...), f.err
}

func runtimeCHReference(t *testing.T, reference RuntimeFieldReference) string {
	t.Helper()
	application := ""
	if reference.ApplicationID != nil {
		application = reference.ApplicationID.String()
	}
	data, err := json.Marshal([]string{reference.TraceID, reference.Method, reference.PathTemplate, application})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func runtimeGraphRow(edgeID, source, target, api string, calls uint64, dataTypes, fields, samples, references []string, referenceCount uint64) []any {
	now := time.Now().UTC()
	return []any{
		edgeID, source, "SERVICE", target, "SERVICE", "HTTP",
		calls, uint64(0), float64(12.5), uint32(20), now.Add(-time.Second), now,
		"OBSERVED_TRACE", float32(0.98), []string{api}, dataTypes, fields, samples,
		"INTERNAL", "INTERNAL", "UNKNOWN", "",
		references, referenceCount,
	}
}

func TestCHReaderRuntimeFieldsDoNotContaminateSameTraceHop(t *testing.T) {
	applicationID := uuid.New()
	traceID := strings.Repeat("a", 32)
	login := RuntimeFieldReference{TraceID: traceID, Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	verify := RuntimeFieldReference{TraceID: traceID, Method: "POST", PathTemplate: "/verify", ApplicationID: &applicationID}
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 2, []string{`[]`}, []string{`[]`}, []string{traceID}, []string{runtimeCHReference(t, login)}, 1),
		runtimeGraphRow("edge-verify", "auth", "profile", "POST /verify", 1, []string{`[]`}, []string{`[]`}, []string{traceID}, []string{runtimeCHReference(t, verify)}, 1),
	}}}}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{{
		Reference: login,
		Fields:    []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}},
	}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	graph, err := reader.Graph(context.Background(), GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour), ApplicationID: &applicationID, View: "service", MaxEdges: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 2 || len(runtime.queries) != 1 || len(runtime.queries[0].References) != 2 {
		t.Fatalf("unexpected graph or runtime query: graph=%+v queries=%+v", graph.Edges, runtime.queries)
	}
	if graph.Edges[0].ID != "edge-login" || len(graph.Edges[0].Fields) != 1 || graph.Edges[0].Fields[0].Path != "form.pwd" ||
		len(graph.Edges[0].DataTypes) != 1 || graph.Edges[0].DataTypes[0] != "CREDENTIAL" {
		t.Fatalf("matching contribution was not enriched: %+v", graph.Edges[0])
	}
	if len(graph.Edges[1].Fields) != 0 || len(graph.Edges[1].DataTypes) != 0 {
		t.Fatalf("same trace contaminated another real hop: %+v", graph.Edges[1])
	}
	if graph.Edges[0].Calls != 2 || graph.Edges[0].EvidenceType != "OBSERVED_TRACE" || graph.Edges[0].Confidence != float64(float32(0.98)) ||
		graph.Edges[0].AvgLatencyMS != 12.5 || graph.Edges[0].MaxLatencyMS != 20 || len(graph.Edges[0].SampleTraceIDs) != 1 {
		t.Fatalf("enrichment changed edge facts: %+v", graph.Edges[0])
	}
}

func TestCHReaderRuntimeFieldsUseAllBoundedTraceReferences(t *testing.T) {
	applicationID := uuid.New()
	references := make([]RuntimeFieldReference, 5)
	encoded := make([]string, 5)
	for i := range references {
		references[i] = RuntimeFieldReference{TraceID: fmt.Sprintf("%032x", i+1), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
		encoded[i] = runtimeCHReference(t, references[i])
	}
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 5, []string{`[]`}, []string{`[]`}, []string{references[0].TraceID}, encoded, 5),
	}}}}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{{
		Reference: references[4], Fields: []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}},
	}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	graph, err := reader.Graph(context.Background(), GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, MaxEdges: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.queries) != 1 || len(runtime.queries[0].References) != 5 || len(graph.Edges) != 1 || len(graph.Edges[0].Fields) != 1 {
		t.Fatalf("sample_trace_ids replaced full contribution references: queries=%+v graph=%+v", runtime.queries, graph.Edges)
	}
}

func TestCHReaderRuntimeDataTypeFilterPrecedesMaxEdges(t *testing.T) {
	applicationID := uuid.New()
	login := RuntimeFieldReference{TraceID: strings.Repeat("b", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	logout := RuntimeFieldReference{TraceID: strings.Repeat("c", 32), Method: "POST", PathTemplate: "/logout", ApplicationID: &applicationID}
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-phone-1", "a", "b", "GET /one", 100, []string{`["PHONE"]`}, []string{`[{"side":"REQUEST","path":"json.phone","data_type":"PHONE","match":"OBSERVED"}]`}, nil, nil, 0),
		runtimeGraphRow("edge-phone-2", "b", "c", "GET /two", 90, []string{`["PHONE"]`}, []string{`[{"side":"REQUEST","path":"json.phone","data_type":"PHONE","match":"OBSERVED"}]`}, nil, nil, 0),
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 80, []string{`[]`}, []string{`[]`}, []string{login.TraceID}, []string{runtimeCHReference(t, login)}, 1),
		runtimeGraphRow("edge-logout", "gateway", "auth", "POST /logout", 70, []string{`[]`}, []string{`[]`}, []string{logout.TraceID}, []string{runtimeCHReference(t, logout)}, 1),
	}}}}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{
		{Reference: login, Fields: []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}}},
		{Reference: logout, Fields: []FieldEvidence{{Side: "REQUEST", Path: "form.password", DataType: "CREDENTIAL", Match: "OBSERVED"}}},
	}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	graph, err := reader.Graph(context.Background(), GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, DataType: "credential", MaxEdges: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].ID != "edge-login" || !graph.Truncated {
		t.Fatalf("data_type was applied after max_edges: %+v", graph)
	}
	if strings.Contains(querier.queries[0], "data_types_json LIKE") {
		t.Fatalf("ClickHouse filter discarded runtime-only fields before enrichment: %s", querier.queries[0])
	}
}

func runtimeEvidenceRow(t *testing.T, eventID string, occurredAt time.Time, dataTypes, fields string, reference RuntimeFieldReference) []any {
	return []any{
		uuid.New(), eventID, "edge-login", occurredAt, "gateway", reference.TraceID, "span-1", fields,
		"OBSERVED_TRACE", float32(0.98), "10.0.0.1", "8.8.8.8", "TRUSTED_PROXY", "10.0.0.2",
		"PUBLIC", "INTERNAL", "PUBLIC_TO_INTERNAL", "TRUSTED_PROXY", dataTypes, runtimeCHReference(t, reference),
	}
}

func TestCHReaderRuntimeEvidenceMatchesGraphAndFiltersBeforeLimit(t *testing.T) {
	applicationID := uuid.New()
	now := time.Now().UTC()
	login := RuntimeFieldReference{TraceID: strings.Repeat("d", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	phone1 := RuntimeFieldReference{TraceID: strings.Repeat("e", 32), Method: "GET", PathTemplate: "/one", ApplicationID: &applicationID}
	phone2 := RuntimeFieldReference{TraceID: strings.Repeat("f", 32), Method: "GET", PathTemplate: "/two", ApplicationID: &applicationID}
	phoneFields := `[{"side":"REQUEST","path":"json.phone","data_type":"PHONE","match":"OBSERVED"}]`
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeEvidenceRow(t, "phone-1", now, `["PHONE"]`, phoneFields, phone1),
		runtimeEvidenceRow(t, "phone-2", now.Add(-time.Second), `["PHONE"]`, phoneFields, phone2),
		runtimeEvidenceRow(t, "runtime-login", now.Add(-2*time.Second), `[]`, `[]`, login),
	}}}}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{{
		Reference: login, Fields: []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}},
	}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	records, err := reader.Evidence(context.Background(), "edge-login", GraphFilter{
		Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, DataType: "CREDENTIAL",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].EventID != "runtime-login" || len(records[0].Fields) != 1 || records[0].Fields[0].Path != "form.pwd" {
		t.Fatalf("evidence and graph runtime fields diverged: %+v", records)
	}
	if len(runtime.queries) != 1 || len(runtime.queries[0].References) != 3 {
		t.Fatalf("evidence limit was applied before runtime data_type filtering: %+v", runtime.queries)
	}
	if strings.Contains(querier.queries[0], "data_types_json LIKE") {
		t.Fatalf("evidence CH filter discarded runtime-only fields: %s", querier.queries[0])
	}
	if records[0].EvidenceType != "OBSERVED_TRACE" || records[0].Confidence != float64(float32(0.98)) || records[0].TraceID != login.TraceID {
		t.Fatalf("evidence facts changed during enrichment: %+v", records[0])
	}
}

func TestCHReaderRuntimeReferenceTruncationDegradesWithoutDataType(t *testing.T) {
	applicationID := uuid.New()
	reference := RuntimeFieldReference{TraceID: strings.Repeat("a", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	agentFields := `[{"side":"REQUEST","path":"json.phone","data_type":"PHONE","match":"OBSERVED"}]`
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 7, []string{`["PHONE"]`}, []string{agentFields}, []string{reference.TraceID}, []string{runtimeCHReference(t, reference)}, 2),
	}}}}
	runtime := &runtimeFieldFakeReader{}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	graph, err := reader.Graph(context.Background(), GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, MaxEdges: 10})
	if err != nil {
		t.Fatalf("unfiltered graph must preserve real edges during enrichment degradation: %v", err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].Calls != 7 || len(graph.Edges[0].Fields) != 1 || graph.Edges[0].Fields[0].DataType != "PHONE" ||
		len(graph.Edges[0].DataTypes) != 1 || graph.Edges[0].DataTypes[0] != "PHONE" {
		t.Fatalf("degradation changed existing edge or Agent fields: %+v", graph.Edges)
	}
	if graph.RuntimeFieldsWarning == "" || !graph.Truncated || len(runtime.queries) != 0 {
		t.Fatalf("reference truncation was not exposed as a bounded degradation: graph=%+v queries=%d", graph, len(runtime.queries))
	}
}
