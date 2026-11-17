package apidataflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apm"
)

func TestCHReaderRuntimeReferenceQueryDeduplicatesFullKey(t *testing.T) {
	querier := &dataflowFakeQuerier{}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(&runtimeFieldFakeReader{})
	_, err := reader.Graph(context.Background(), GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), MaxEdges: 10})
	if err != nil {
		t.Fatal(err)
	}
	query := querier.queries[0]
	if !strings.Contains(query, "groupUniqArrayIf") || !strings.Contains(query, "AS runtime_refs") {
		t.Fatalf("runtime references are not deduplicated in ClickHouse: %s", query)
	}
	fullKey := "tuple(latest_trace_id,latest_method,latest_path_template,ifNull(toString(app_id),''))"
	if !strings.Contains(query, "uniqExactIf("+fullKey+",latest_trace_id != '')") {
		t.Fatalf("reference count is not the distinct full association key: %s", query)
	}
	if strings.Contains(query, "groupArrayIf") || strings.Contains(query, "countIf(latest_trace_id != '') AS runtime_ref_count") {
		t.Fatalf("raw event count can still exhaust the reference budget: %s", query)
	}
}

func TestCHReaderRepeatedRuntimeReferencesDoNotExhaustBudget(t *testing.T) {
	applicationID := uuid.New()
	reference := RuntimeFieldReference{TraceID: strings.Repeat("a", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	encoded := runtimeCHReference(t, reference)
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 3000, []string{`[]`}, []string{`[]`}, []string{reference.TraceID}, []string{encoded, encoded, encoded}, 1),
	}}}}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{{
		Reference: reference, Fields: []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}},
	}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	graph, err := reader.Graph(context.Background(), GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, MaxEdges: 10})
	if err != nil {
		t.Fatal(err)
	}
	if graph.RuntimeFieldsWarning != "" || len(graph.Edges) != 1 || graph.Edges[0].Calls != 3000 || len(graph.Edges[0].Fields) != 1 ||
		len(runtime.queries) != 1 || len(runtime.queries[0].References) != 1 {
		t.Fatalf("duplicate requests consumed distinct-reference budget: graph=%+v queries=%+v", graph, runtime.queries)
	}
}

func TestCHReaderRuntimeReadFailureDegradationBoundary(t *testing.T) {
	injected := errors.New("injected runtime read failure")
	for _, test := range []struct {
		name     string
		dataType string
	}{
		{name: "unfiltered graph degrades"},
		{name: "data type filter fails", dataType: "CREDENTIAL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			applicationID := uuid.New()
			reference := RuntimeFieldReference{TraceID: strings.Repeat("b", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
			agentFields := `[{"side":"REQUEST","path":"json.phone","data_type":"PHONE","match":"OBSERVED"}]`
			querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
				runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 9, []string{`["PHONE"]`}, []string{agentFields}, []string{reference.TraceID}, []string{runtimeCHReference(t, reference)}, 1),
			}}}}
			runtime := &runtimeFieldFakeReader{err: injected}
			reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
			graph, err := reader.Graph(context.Background(), GraphFilter{
				Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, MaxEdges: 10, DataType: test.dataType,
			})
			if test.dataType != "" {
				if !errors.Is(err, injected) || graph != nil {
					t.Fatalf("filtered graph returned incomplete results: graph=%+v err=%v", graph, err)
				}
				return
			}
			if err != nil || graph == nil {
				t.Fatalf("unfiltered graph lost existing edges: graph=%+v err=%v", graph, err)
			}
			if graph.RuntimeFieldsWarning == "" || !graph.Truncated || len(graph.Edges) != 1 || graph.Edges[0].Calls != 9 ||
				len(graph.Edges[0].Fields) != 1 || graph.Edges[0].Fields[0].DataType != "PHONE" || graph.Edges[0].DataTypes[0] != "PHONE" {
				t.Fatalf("unsafe or silent degradation: %+v", graph)
			}
		})
	}
}

func TestCHReaderRuntimeReferenceTruncationFailsWithDataType(t *testing.T) {
	applicationID := uuid.New()
	reference := RuntimeFieldReference{TraceID: strings.Repeat("c", 32), Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		runtimeGraphRow("edge-login", "gateway", "auth", "POST /login", 1, []string{`[]`}, []string{`[]`}, []string{reference.TraceID}, []string{runtimeCHReference(t, reference)}, 2),
	}}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(&runtimeFieldFakeReader{})
	graph, err := reader.Graph(context.Background(), GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(), ApplicationID: &applicationID, MaxEdges: 10, DataType: "CREDENTIAL",
	})
	if !errors.Is(err, ErrRuntimeFieldReferenceLimit) || graph != nil {
		t.Fatalf("filtered graph hid incomplete runtime association: graph=%+v err=%v", graph, err)
	}
}

func TestCHReaderRuntimeDataTypeCandidateLimitFails(t *testing.T) {
	rows := make([][]any, runtimeGraphCandidateLimit+1)
	for i := range rows {
		rows[i] = runtimeGraphRow("edge-phone", "a", "b", "GET /phone", uint64(i+1), []string{`["PHONE"]`}, []string{`[]`}, nil, nil, 0)
	}
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: rows}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(&runtimeFieldFakeReader{})
	graph, err := reader.Graph(context.Background(), GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(), MaxEdges: 10, DataType: "CREDENTIAL",
	})
	if !errors.Is(err, ErrRuntimeFieldGraphLimit) || graph != nil {
		t.Fatalf("candidate limit returned an incomplete filtered graph: graph=%+v err=%v", graph, err)
	}
}
