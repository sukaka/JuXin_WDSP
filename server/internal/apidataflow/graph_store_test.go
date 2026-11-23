package apidataflow

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apm"
)

type dataflowFakeRows struct {
	rows  [][]any
	index int
}

func (r *dataflowFakeRows) Next() bool { return r.index < len(r.rows) }

func (r *dataflowFakeRows) Scan(dest ...any) error {
	if r.index >= len(r.rows) {
		return fmt.Errorf("scan past end")
	}
	row := r.rows[r.index]
	r.index++
	if len(dest) != len(row) {
		return fmt.Errorf("scan arity = %d, want %d", len(dest), len(row))
	}
	for i, value := range row {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		case *time.Time:
			*target = value.(time.Time)
		case *uuid.UUID:
			*target = value.(uuid.UUID)
		case *uint64:
			*target = value.(uint64)
		case *uint32:
			*target = value.(uint32)
		case *float64:
			*target = value.(float64)
		case *float32:
			*target = value.(float32)
		case *[]string:
			*target = value.([]string)
		default:
			return fmt.Errorf("unsupported scan destination %T", dest[i])
		}
	}
	return nil
}

func (r *dataflowFakeRows) Close() error { return nil }
func (r *dataflowFakeRows) Err() error   { return nil }

type dataflowFakeQuerier struct {
	results []*dataflowFakeRows
	queries []string
	args    [][]any
}

func (q *dataflowFakeQuerier) Query(_ context.Context, query string, args ...any) (apm.CHRows, error) {
	q.queries = append(q.queries, query)
	q.args = append(q.args, args)
	if len(q.results) == 0 {
		return &dataflowFakeRows{}, nil
	}
	rows := q.results[0]
	q.results = q.results[1:]
	return rows, nil
}

func TestGraphWhereQualifiesContributionColumns(t *testing.T) {
	filter := GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(), View: "service",
		Method: "POST", DataType: " phone ",
	}
	where, args := graphWhere(filter, false)
	for _, column := range []string{"occurred_at", "protocol", "source_type", "evidence_type", "method", "data_types_json"} {
		if !strings.Contains(where, "wdsp.data_flow_contributions."+column) {
			t.Errorf("column %s is not table-qualified: %s", column, where)
		}
	}
	if len(args) != 4 || args[3] != `%"PHONE"%` {
		t.Fatalf("unexpected argument count or normalized data_type: %#v", args)
	}
	for _, predicate := range []string{"protocol = 'HTTP'", "source_type = 'SERVICE'", "target_type = 'SERVICE'", "evidence_type = 'OBSERVED_TRACE'"} {
		if !strings.Contains(where, predicate) {
			t.Errorf("service graph must contain %q: %s", predicate, where)
		}
	}
	if strings.Contains(where, "boundary_type") {
		t.Fatalf("service graph must not use boundary filters: %s", where)
	}
	filter.View = "network"
	networkWhere, _ := graphWhere(filter, false)
	if strings.Contains(networkWhere, "source_type") || strings.Contains(networkWhere, "target_type") || strings.Contains(networkWhere, "OBSERVED_TRACE") || strings.Contains(networkWhere, "boundary_type") {
		t.Fatalf("network view must preserve observation endpoints: %s", networkWhere)
	}

	filter.View = "service"
	observationWhere, _ := graphWhere(filter, true)
	if !strings.Contains(observationWhere, "wdsp.api_observations.occurred_at") || strings.Contains(observationWhere, "protocol") {
		t.Fatalf("unexpected observation filter: %s", observationWhere)
	}
}

func TestGraphWhereBoundary(t *testing.T) {
	applicationID := uuid.New()
	filter := GraphFilter{
		Start: time.Now().Add(-time.Hour), End: time.Now(), View: "boundary",
		ApplicationID: &applicationID, Method: "GET", DataType: "PHONE",
	}
	where, args := graphWhere(filter, false)
	for _, column := range []string{"occurred_at", "application_id", "protocol", "source_type", "target_type", "boundary_type", "method", "data_types_json"} {
		if !strings.Contains(where, "wdsp.data_flow_contributions."+column) {
			t.Errorf("column %s is not table-qualified: %s", column, where)
		}
	}
	for _, predicate := range []string{
		"protocol = 'HTTP'", "source_type IN ('CLIENT','EXTERNAL')", "target_type = 'SERVICE'",
		"boundary_type IN ('PUBLIC_TO_INTERNAL','UNKNOWN')",
	} {
		if !strings.Contains(where, predicate) {
			t.Errorf("boundary graph must contain %q: %s", predicate, where)
		}
	}
	if strings.Contains(where, "source_type = 'SERVICE'") || strings.Contains(where, "OBSERVED_TRACE") {
		t.Fatalf("boundary graph must not inherit service-only filters: %s", where)
	}
	if len(args) != 5 || args[2] != applicationID || args[3] != "GET" || args[4] != "%\"PHONE\"%" {
		t.Fatalf("boundary filters were not preserved: %#v", args)
	}
	observationWhere, observationArgs := graphWhere(filter, true)
	if strings.Contains(observationWhere, "boundary_type") || strings.Contains(observationWhere, "protocol") || len(observationArgs) != 3 {
		t.Fatalf("unexpected boundary observation filter: %s %#v", observationWhere, observationArgs)
	}
}

func TestValidateGraphFilterBoundary(t *testing.T) {
	filter := GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), View: "boundary"}
	if err := validateGraphFilter(&filter); err != nil {
		t.Fatal(err)
	}
	if filter.View != "boundary" || filter.MaxEdges != 50 {
		t.Fatalf("unexpected normalized filter: %+v", filter)
	}
	filter.View = "invalid"
	if err := validateGraphFilter(&filter); err == nil {
		t.Fatal("expected invalid view error")
	}
}

func TestGraphQueryUsesNonConflictingLatestAliases(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		view         string
		wantFilters  []string
		avoidFilters []string
	}{
		{
			view: "service",
			wantFilters: []string{
				"wdsp.data_flow_contributions.protocol = 'HTTP'",
				"wdsp.data_flow_contributions.source_type = 'SERVICE'",
				"wdsp.data_flow_contributions.target_type = 'SERVICE'",
				"wdsp.data_flow_contributions.evidence_type = 'OBSERVED_TRACE'",
			},
			avoidFilters: []string{"wdsp.data_flow_contributions.boundary_type IN"},
		},
		{
			view: "network",
			avoidFilters: []string{
				"wdsp.data_flow_contributions.source_type =",
				"wdsp.data_flow_contributions.target_type =",
				"wdsp.data_flow_contributions.evidence_type =",
				"wdsp.data_flow_contributions.boundary_type IN",
			},
		},
		{
			view: "boundary",
			wantFilters: []string{
				"wdsp.data_flow_contributions.protocol = 'HTTP'",
				"wdsp.data_flow_contributions.source_type IN ('CLIENT','EXTERNAL')",
				"wdsp.data_flow_contributions.target_type = 'SERVICE'",
				"wdsp.data_flow_contributions.boundary_type IN ('PUBLIC_TO_INTERNAL','UNKNOWN')",
			},
			avoidFilters: []string{
				"wdsp.data_flow_contributions.source_type = 'SERVICE'",
				"wdsp.data_flow_contributions.evidence_type = 'OBSERVED_TRACE'",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.view, func(t *testing.T) {
			querier := &dataflowFakeQuerier{}
			reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
			graph, err := reader.Graph(context.Background(), GraphFilter{
				Start: now.Add(-time.Hour), End: now, View: test.view, MaxEdges: 10,
				Method: "POST", DataType: "PHONE",
			})
			if err != nil {
				t.Fatal(err)
			}
			if graph.View != test.view || len(querier.queries) != 2 {
				t.Fatalf("unexpected graph or query count: view=%q queries=%d", graph.View, len(querier.queries))
			}
			query := querier.queries[0]
			for _, column := range []string{"source_type", "target_type", "protocol", "method", "data_types_json", "evidence_type", "boundary_type"} {
				if strings.Contains(query, "argMax("+column+",received_at) AS "+column) {
					t.Errorf("filtered column %s retains a conflicting alias: %s", column, query)
				}
				if !strings.Contains(query, "argMax("+column+",received_at) AS latest_"+column) {
					t.Errorf("filtered column %s lacks an intermediate alias: %s", column, query)
				}
			}
			for _, mapping := range []string{
				"latest_source_type AS source_type",
				"latest_target_type AS target_type",
				"latest_protocol AS protocol",
				"argMax(latest_evidence_type,event_time) AS evidence_type",
				"argMax(latest_boundary_type,event_time) AS boundary_type",
			} {
				if !strings.Contains(query, mapping) {
					t.Errorf("outer query does not restore API field with %q: %s", mapping, query)
				}
			}
			if strings.Contains(query, "WHERE evidence_type NOT IN") || !strings.Contains(query, "WHERE latest_evidence_type NOT IN ('PAIRED_CLIENT','PAIRED_SERVER')") {
				t.Errorf("paired evidence filter uses a conflicting scope: %s", query)
			}
			for _, filter := range []string{"wdsp.data_flow_contributions.method = ?", "wdsp.data_flow_contributions.data_types_json LIKE ?"} {
				if !strings.Contains(query, filter) {
					t.Errorf("query lost filter %q: %s", filter, query)
				}
			}
			for _, filter := range test.wantFilters {
				if !strings.Contains(query, filter) {
					t.Errorf("query lost view filter %q: %s", filter, query)
				}
			}
			for _, filter := range test.avoidFilters {
				if strings.Contains(query, filter) {
					t.Errorf("query acquired foreign view filter %q: %s", filter, query)
				}
			}
		})
	}
}

func TestEvidenceQueryUsesNonConflictingLatestAliases(t *testing.T) {
	now := time.Now().UTC()
	querier := &dataflowFakeQuerier{}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	_, err := reader.Evidence(context.Background(), "edge-1", GraphFilter{
		Start: now.Add(-time.Hour), End: now, View: "boundary", MaxEdges: 10,
		Method: "POST", DataType: "PHONE",
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(querier.queries) != 1 {
		t.Fatalf("unexpected evidence query count: %d", len(querier.queries))
	}
	query := querier.queries[0]
	for _, column := range []string{"evidence_type", "boundary_type"} {
		if strings.Contains(query, "argMax("+column+",received_at) AS "+column) {
			t.Errorf("filtered column %s retains a conflicting alias: %s", column, query)
		}
		for _, fragment := range []string{
			"argMax(" + column + ",received_at) AS latest_" + column,
			"latest_" + column + " AS " + column,
		} {
			if !strings.Contains(query, fragment) {
				t.Errorf("evidence query lacks %q: %s", fragment, query)
			}
		}
	}
	for _, filter := range []string{
		"wdsp.data_flow_contributions.source_type IN ('CLIENT','EXTERNAL')",
		"wdsp.data_flow_contributions.target_type = 'SERVICE'",
		"wdsp.data_flow_contributions.boundary_type IN ('PUBLIC_TO_INTERNAL','UNKNOWN')",
		"wdsp.data_flow_contributions.method = ?",
		"wdsp.data_flow_contributions.data_types_json LIKE ?",
	} {
		if !strings.Contains(query, filter) {
			t.Errorf("evidence query lost boundary filter %q: %s", filter, query)
		}
	}
	if strings.Contains(query, "HAVING evidence_type NOT IN") || !strings.Contains(query, "WHERE latest_evidence_type NOT IN ('PAIRED_CLIENT','PAIRED_SERVER')") {
		t.Errorf("evidence paired filter uses a conflicting scope: %s", query)
	}
}

func TestCHReaderBoundaryGraphMapping(t *testing.T) {
	now := time.Now().UTC()
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{
		{rows: [][]any{{
			"edge-1", "8.8.8.8", "CLIENT", "orders", "SERVICE", "HTTP",
			uint64(2), uint64(0), float64(12.5), uint32(20), now.Add(-time.Second), now,
			"OBSERVED_SERVER", float32(0.8), []string{"GET /orders/{id}"}, []string{`["PHONE"]`}, []string{`[]`}, []string{"trace-1"},
			"PUBLIC", "INTERNAL", "PUBLIC_TO_INTERNAL", "TRUSTED_PROXY",
		}}},
		{},
		{},
	}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	graph, err := reader.Graph(context.Background(), GraphFilter{
		Start: now.Add(-time.Hour), End: now.Add(time.Hour), View: "boundary", MaxEdges: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if graph.View != "boundary" || len(graph.Edges) != 1 {
		t.Fatalf("unexpected boundary graph: %+v", graph)
	}
	edge := graph.Edges[0]
	if edge.SourceZone != "PUBLIC" || edge.TargetZone != "INTERNAL" || edge.BoundaryType != "PUBLIC_TO_INTERNAL" || edge.BoundaryEvidence != "TRUSTED_PROXY" {
		t.Fatalf("boundary fields were not mapped: %+v", edge)
	}
	zones := map[string]string{}
	for _, node := range graph.Nodes {
		zones[node.ID] = node.NetworkZone
	}
	if zones["client:8.8.8.8"] != "PUBLIC" || zones["service:orders"] != "INTERNAL" {
		t.Fatalf("node network zones were not propagated: %+v", zones)
	}
	if len(querier.queries) != 3 || !strings.Contains(querier.queries[0], "argMax(latest_boundary_evidence,event_time)") {
		t.Fatalf("unexpected graph queries: %+v", querier.queries)
	}
}

func TestCHReaderBoundaryEvidenceMapping(t *testing.T) {
	now := time.Now().UTC()
	agentID := uuid.New()
	querier := &dataflowFakeQuerier{results: []*dataflowFakeRows{{rows: [][]any{
		{
			agentID, "event-public", "edge-1", now, "orders", "trace-1", "span-1", `[]`, "OBSERVED_SERVER", float32(0.8),
			"10.0.0.8", "8.8.8.8", "TRUSTED_PROXY", "10.20.0.30", "PUBLIC", "INTERNAL", "PUBLIC_TO_INTERNAL", "TRUSTED_PROXY",
		},
		{
			agentID, "event-unknown", "edge-2", now.Add(-time.Second), "billing", "trace-2", "span-2", `[]`, "OBSERVED_SERVER", float32(0.8),
			"10.0.0.9", "", "UNKNOWN", "10.20.0.31", "UNKNOWN", "INTERNAL", "UNKNOWN", "MISSING_CLIENT_ADDRESS",
		},
	}}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	records, err := reader.Evidence(context.Background(), "edge-1", GraphFilter{
		Start: now.Add(-time.Hour), End: now.Add(time.Hour), View: "boundary", MaxEdges: 10,
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("unexpected evidence records: %+v", records)
	}
	public := records[0]
	if public.ServiceName != "orders" || public.PeerAddress != "10.0.0.8" || public.ClientAddress != "8.8.8.8" || public.ClientAddressSource != "TRUSTED_PROXY" || public.ServerAddress != "10.20.0.30" {
		t.Fatalf("target service or observed addresses were not preserved: %+v", public)
	}
	if public.SourceZone != "PUBLIC" || public.TargetZone != "INTERNAL" || public.BoundaryType != "PUBLIC_TO_INTERNAL" || public.BoundaryEvidence != "TRUSTED_PROXY" {
		t.Fatalf("public boundary evidence was not mapped: %+v", public)
	}
	unknown := records[1]
	if unknown.ServiceName != "billing" || unknown.ClientAddress != "" || unknown.ClientAddressSource != "UNKNOWN" || unknown.SourceZone != "UNKNOWN" || unknown.BoundaryType != "UNKNOWN" || unknown.BoundaryEvidence != "MISSING_CLIENT_ADDRESS" {
		t.Fatalf("unknown boundary target or certainty was not preserved: %+v", unknown)
	}
	if len(querier.queries) != 1 || !strings.Contains(querier.queries[0], "argMax(peer_address,received_at)") || !strings.Contains(querier.queries[0], "boundary_type IN ('PUBLIC_TO_INTERNAL','UNKNOWN')") ||
		!strings.Contains(querier.queries[0], "if(latest_evidence_type = 'OBSERVED_SERVER',latest_target_node,latest_source_node) AS service_name") {
		t.Fatalf("unexpected evidence query: %+v", querier.queries)
	}
}

func TestGraphNodeUsesCallWeightedLatency(t *testing.T) {
	nodes := map[string]*Node{}
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 2, AvgLatencyMS: 10, MaxLatencyMS: 15}, true)
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 1, AvgLatencyMS: 30, MaxLatencyMS: 40}, false)
	node := nodes["service:orders"]
	if node.Calls != 3 || node.AvgLatencyMS < 16.666 || node.AvgLatencyMS > 16.667 || node.MaxLatencyMS != 40 {
		t.Fatalf("unexpected node metrics: %+v", node)
	}
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 3, AvgLatencyMS: 20, MaxLatencyMS: 20}, true)
	if node.Calls != 6 || node.AvgLatencyMS < 18.333 || node.AvgLatencyMS > 18.334 || node.AvgLatencyMS > float64(node.MaxLatencyMS) {
		t.Fatalf("weighted latency regressed: %+v", node)
	}
}

func TestGraphNodeNetworkZoneConflictRemainsUnknown(t *testing.T) {
	nodes := map[string]*Node{}
	upsertGraphNode(nodes, "client:source", "source", "CLIENT", Edge{SourceZone: "PUBLIC", TargetZone: "INTERNAL"}, true)
	upsertGraphNode(nodes, "service:target", "target", "SERVICE", Edge{SourceZone: "PUBLIC", TargetZone: "INTERNAL"}, false)
	upsertGraphNode(nodes, "client:source", "source", "CLIENT", Edge{SourceZone: "UNKNOWN", TargetZone: "INTERNAL"}, true)
	upsertGraphNode(nodes, "client:source", "source", "CLIENT", Edge{SourceZone: "PUBLIC", TargetZone: "INTERNAL"}, true)
	if nodes["client:source"].NetworkZone != "UNKNOWN" || nodes["service:target"].NetworkZone != "INTERNAL" {
		t.Fatalf("unexpected network zones: %+v", nodes)
	}
}

func TestGraphNodeComputesCumulativeErrorRateAndHealth(t *testing.T) {
	nodes := map[string]*Node{}
	// Edge 1: 100 calls, 20 errors -> 20% (ERROR)
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 100, Errors: 20}, true)
	node := nodes["service:orders"]
	if node.ErrorRate < 0.1999 || node.ErrorRate > 0.2001 || node.Health != "ERROR" {
		t.Fatalf("after edge 1: rate=%v health=%s, want 0.20 ERROR", node.ErrorRate, node.Health)
	}
	// Edge 2: 100 calls, 0 errors -> cumulative 20/200 = 10% (DEGRADED, NOT 0% from last edge!)
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 100, Errors: 0}, false)
	if node.Calls != 200 || node.ErrorRate < 0.0999 || node.ErrorRate > 0.1001 || node.Health != "DEGRADED" {
		t.Fatalf("after edge 2: calls=%d rate=%v health=%s, want 200 0.10 DEGRADED", node.Calls, node.ErrorRate, node.Health)
	}
	// Edge 3: 100 calls, 15 errors -> cumulative 35/300 = 11.67% (ERROR)
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 100, Errors: 15}, true)
	if node.Calls != 300 || node.ErrorRate < 0.116 || node.ErrorRate > 0.117 || node.Health != "ERROR" {
		t.Fatalf("after edge 3: calls=%d rate=%v health=%s, want 300 ~0.1167 ERROR", node.Calls, node.ErrorRate, node.Health)
	}
	// Edge 4: 700 calls, 0 errors -> cumulative 35/1000 = 3.5% (HEALTHY)
	upsertGraphNode(nodes, "service:orders", "orders", "SERVICE", Edge{Calls: 700, Errors: 0}, false)
	if node.Calls != 1000 || node.ErrorRate < 0.0349 || node.ErrorRate > 0.0351 || node.Health != "HEALTHY" {
		t.Fatalf("after edge 4: calls=%d rate=%v health=%s, want 1000 0.035 HEALTHY", node.Calls, node.ErrorRate, node.Health)
	}
}
