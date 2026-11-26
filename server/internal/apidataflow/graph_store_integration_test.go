package apidataflow

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
)

func TestCHReaderIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	applicationID := uuid.New()
	client := observationForTest("orders", "CLIENT", now.Add(-time.Second))
	client.ApplicationID = &applicationID
	client.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-graph-integration")}
	server := observationForTest("profile", "SERVER", now.Add(-time.Second+5*time.Millisecond))
	server.ApplicationID = &applicationID
	server.Service.Environment = "prod"
	server.Service.Namespace = "shop"
	server.HTTP.Host = "10.20.0.30"
	server.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-graph-integration")}
	records := []agents.APIObservationEnvelope{client, server}
	contributions := BuildContributions(records)
	writer := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	if err := writer.SaveContributions(ctx, contributions); err != nil {
		t.Fatal(err)
	}
	if err := writer.SaveContributions(ctx, contributions); err != nil {
		t.Fatal(err)
	}
	observationWriter := NewCHObservationStore(func(context.Context) apm.CHQuerier { return querier })
	if err := observationWriter.SaveBatch(ctx, records); err != nil {
		t.Fatal(err)
	}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	filter := GraphFilter{Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, MaxEdges: 10}
	graph, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].Calls != 1 {
		t.Fatalf("duplicate replay inflated graph: %+v", graph.Edges)
	}
	edge := graph.Edges[0]
	if edge.SourceName != "orders" || edge.TargetName != "profile" || len(edge.DataTypes) == 0 || edge.DataTypes[0] != "PHONE" {
		t.Fatalf("unexpected graph edge: %+v", edge)
	}
	evidence, err := reader.Evidence(ctx, edge.ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].ServiceName != "orders" || len(evidence[0].Fields) == 0 || evidence[0].Fields[0].Match != "CORRELATED_FIELD" {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
	quality, err := reader.Quality(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if quality.Observations != 2 || quality.TraceLinked != 2 || quality.TraceCoverage != 1 {
		t.Fatalf("unexpected quality: %+v", quality)
	}
	for _, node := range graph.Nodes {
		if node.Name == "profile" && (node.GroupName != "prod / shop" || len(node.Addresses) != 1 || node.Addresses[0] != "10.20.0.30") {
			t.Fatalf("missing real node metadata: %+v", node)
		}
	}
	filter.View = "network"
	network, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if network.View != "network" || len(network.Edges) != 1 || network.Edges[0].ID != edge.ID || network.Edges[0].TargetName != "10.20.0.30" {
		t.Fatalf("unexpected network graph: %+v", network)
	}
}

func TestCHReaderBoundaryIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	applicationID := uuid.New()
	public := observationForTest("orders", "SERVER", now.Add(-time.Second))
	public.ApplicationID = &applicationID
	public.HTTP.PeerService = ""
	public.HTTP.PeerAddress = "10.0.0.8"
	public.HTTP.ClientAddress = "8.8.8.8"
	public.HTTP.ClientAddressSource = "TRUSTED_PROXY"
	public.HTTP.ServerAddress = "10.20.0.30"
	unknown := observationForTest("billing", "SERVER", now)
	unknown.ApplicationID = &applicationID
	unknown.HTTP.PeerService = ""
	unknown.HTTP.PeerAddress = "10.0.0.9"
	unknown.HTTP.ClientAddressSource = "UNKNOWN"
	unknown.HTTP.ServerAddress = "10.20.0.31"
	contributions := BuildContributions([]agents.APIObservationEnvelope{public, unknown})
	if len(contributions) != 2 {
		t.Fatalf("unexpected boundary contributions: %+v", contributions)
	}
	writer := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	if err := writer.SaveContributions(ctx, contributions); err != nil {
		t.Fatal(err)
	}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	filter := GraphFilter{Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, MaxEdges: 10, View: "boundary"}
	graph, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if graph.View != "boundary" || len(graph.Edges) != 2 {
		t.Fatalf("unexpected boundary graph: %+v", graph)
	}
	edges := map[string]Edge{}
	for _, edge := range graph.Edges {
		edges[edge.TargetName] = edge
	}
	publicEdge := edges["orders"]
	if publicEdge.SourceZone != "PUBLIC" || publicEdge.TargetZone != "INTERNAL" || publicEdge.BoundaryType != "PUBLIC_TO_INTERNAL" || publicEdge.BoundaryEvidence != "TRUSTED_PROXY" {
		t.Fatalf("unexpected public boundary edge: %+v", publicEdge)
	}
	unknownEdge := edges["billing"]
	if unknownEdge.SourceZone != "UNKNOWN" || unknownEdge.TargetZone != "INTERNAL" || unknownEdge.BoundaryType != "UNKNOWN" || unknownEdge.BoundaryEvidence != "MISSING_CLIENT_ADDRESS" {
		t.Fatalf("unknown boundary became certain: %+v", unknownEdge)
	}
	zones := map[string]string{}
	for _, node := range graph.Nodes {
		zones[node.Name] = node.NetworkZone
	}
	if zones["10.0.0.8"] != "PUBLIC" || zones["orders"] != "INTERNAL" || zones["10.0.0.9"] != "UNKNOWN" || zones["billing"] != "INTERNAL" {
		t.Fatalf("unexpected boundary node zones: %+v", zones)
	}
	publicEvidence, err := reader.Evidence(ctx, publicEdge.ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicEvidence) != 1 || publicEvidence[0].ServiceName != "orders" || publicEvidence[0].PeerAddress != "10.0.0.8" || publicEvidence[0].ClientAddress != "8.8.8.8" || publicEvidence[0].ClientAddressSource != "TRUSTED_PROXY" || publicEvidence[0].ServerAddress != "10.20.0.30" || publicEvidence[0].BoundaryType != "PUBLIC_TO_INTERNAL" {
		t.Fatalf("unexpected public boundary evidence: %+v", publicEvidence)
	}
	unknownEvidence, err := reader.Evidence(ctx, unknownEdge.ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknownEvidence) != 1 || unknownEvidence[0].ServiceName != "billing" || unknownEvidence[0].ClientAddress != "" || unknownEvidence[0].ClientAddressSource != "UNKNOWN" || unknownEvidence[0].BoundaryType != "UNKNOWN" || unknownEvidence[0].BoundaryEvidence != "MISSING_CLIENT_ADDRESS" {
		t.Fatalf("unexpected unknown boundary evidence: %+v", unknownEvidence)
	}
	filter.View = "service"
	service, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(service.Edges) != 0 {
		t.Fatalf("service graph includes non-service boundary edges: %+v", service.Edges)
	}
}

func TestCHContributionStorePersistentTraceIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	applicationID := uuid.New()
	traceID := strings.ReplaceAll(uuid.NewString(), "-", "")
	agentA, agentB := uuid.New(), uuid.New()

	client1 := observationForTest("orders", "CLIENT", now.Add(-3*time.Second))
	client1.AgentID = agentA
	client1.EventID = "client-1-" + uuid.NewString()
	client1.ApplicationID = &applicationID
	client1.Trace.TraceID = traceID
	client1.Trace.SpanID = strings.Repeat("1", 16)
	client1.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-1-"+traceID)}
	client2 := observationForTest("orders", "CLIENT", now.Add(-2*time.Second))
	client2.AgentID = agentA
	client2.EventID = "client-2-" + uuid.NewString()
	client2.ApplicationID = &applicationID
	client2.Trace.TraceID = traceID
	client2.Trace.SpanID = strings.Repeat("2", 16)
	client2.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-2-"+traceID)}

	server1 := observationForTest("profile", "SERVER", now.Add(-2500*time.Millisecond))
	server1.AgentID = agentB
	server1.EventID = "server-1-" + uuid.NewString()
	server1.ApplicationID = &applicationID
	server1.Trace.TraceID = traceID
	server1.Trace.SpanID = strings.Repeat("a", 16)
	server1.Trace.ParentSpanID = client1.Trace.SpanID
	server1.HTTP.Host = "10.20.0.30"
	server1.HTTP.PeerService = ""
	server1.HTTP.PeerAddress = "8.8.8.8"
	server1.HTTP.ServerAddress = "10.20.0.30"
	server1.Fields = []agents.APIObservationField{
		sensitiveField("REQUEST", "request-1-"+traceID),
		sensitiveField("RESPONSE", "response-1-"+traceID),
	}
	server2 := observationForTest("profile", "SERVER", now.Add(-1500*time.Millisecond))
	server2.AgentID = agentB
	server2.EventID = "server-2-" + uuid.NewString()
	server2.ApplicationID = &applicationID
	server2.Trace.TraceID = traceID
	server2.Trace.SpanID = strings.Repeat("b", 16)
	server2.Trace.ParentSpanID = client2.Trace.SpanID
	server2.HTTP.Host = "10.20.0.30"
	server2.HTTP.PeerService = ""
	server2.HTTP.PeerAddress = "8.8.8.8"
	server2.HTTP.ServerAddress = "10.20.0.30"
	server2.Fields = []agents.APIObservationField{
		sensitiveField("REQUEST", "request-2-"+traceID),
		sensitiveField("RESPONSE", "response-2-"+traceID),
	}

	writerA := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	writerB := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	filter := GraphFilter{Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, MaxEdges: 10, View: "service"}
	readGraph := func(view string) *Graph {
		t.Helper()
		filter.View = view
		graph, err := reader.Graph(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return graph
	}

	if err := writerA.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{client1, client2}); err != nil {
		t.Fatal(err)
	}
	if graph := readGraph("service"); len(graph.Edges) != 0 {
		t.Fatalf("unpaired clients produced a service edge: %+v", graph.Edges)
	}
	if graph := readGraph("network"); len(graph.Edges) != 1 || graph.Edges[0].Calls != 2 {
		t.Fatalf("single-sided network observations were not preserved: %+v", graph.Edges)
	}

	if err := writerB.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{server2}); err != nil {
		t.Fatal(err)
	}
	graph := readGraph("service")
	if len(graph.Edges) != 1 || graph.Edges[0].Calls != 1 {
		t.Fatalf("cross-batch second call was not paired exactly once: %+v", graph.Edges)
	}
	evidence, err := reader.Evidence(ctx, graph.Edges[0].ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].EventID != client2.EventID {
		t.Fatalf("parent-span pairing selected the wrong repeated call: %+v", evidence)
	}

	if err := writerA.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{server1}); err != nil {
		t.Fatal(err)
	}
	if err := writerB.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{server1}); err != nil {
		t.Fatal(err)
	}
	graph = readGraph("service")
	if len(graph.Edges) != 1 || graph.Edges[0].Calls != 2 {
		t.Fatalf("multi-consumer replay or cross-batch pairing inflated calls: %+v", graph.Edges)
	}
	evidence, err = reader.Evidence(ctx, graph.Edges[0].ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		t.Fatalf("expected one evidence record per repeated call: %+v", evidence)
	}
	for _, record := range evidence {
		suffix := ""
		switch record.EventID {
		case client1.EventID:
			suffix = "1"
		case client2.EventID:
			suffix = "2"
		default:
			t.Fatalf("unexpected client evidence: %+v", record)
		}
		if len(record.Fields) != 2 || record.Fields[0].ValueHMAC != "request-"+suffix+"-"+traceID ||
			record.Fields[0].Match != "CORRELATED_FIELD" || record.Fields[1].ValueHMAC != "response-"+suffix+"-"+traceID {
			t.Fatalf("repeated call has mismatched fields: %+v", record)
		}
	}
	if network := readGraph("network"); len(network.Edges) != 1 || network.Edges[0].Calls != 2 || network.Edges[0].EvidenceType != "OBSERVED_TRACE" {
		t.Fatalf("superseded single-sided edges remained in network view: %+v", network.Edges)
	}
	if boundary := readGraph("boundary"); len(boundary.Edges) != 0 {
		t.Fatalf("paired server observations remained as external boundaries: %+v", boundary.Edges)
	}
}

func TestCHContributionStoreLateClientReplacesBoundaryIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	applicationID := uuid.New()
	traceID := strings.ReplaceAll(uuid.NewString(), "-", "")
	server := observationForTest("profile", "SERVER", now.Add(-2*time.Second))
	server.AgentID = uuid.New()
	server.EventID = "server-first-" + uuid.NewString()
	server.ApplicationID = &applicationID
	server.Trace.TraceID = traceID
	server.Trace.SpanID = strings.Repeat("a", 16)
	server.HTTP.PeerService = ""
	server.HTTP.PeerAddress = "8.8.8.8"
	server.HTTP.ServerAddress = "10.20.0.30"
	client := observationForTest("orders", "CLIENT", now.Add(-time.Second))
	client.AgentID = uuid.New()
	client.EventID = "client-late-" + uuid.NewString()
	client.ApplicationID = &applicationID
	client.Trace.TraceID = traceID
	client.Trace.SpanID = strings.Repeat("1", 16)
	server.Trace.ParentSpanID = client.Trace.SpanID

	writerA := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	writerB := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	filter := GraphFilter{Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, MaxEdges: 10, View: "boundary"}
	if err := writerA.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{server}); err != nil {
		t.Fatal(err)
	}
	boundary, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(boundary.Edges) != 1 || boundary.Edges[0].Calls != 1 {
		t.Fatalf("server-first observation did not form its boundary: %+v", boundary.Edges)
	}
	oldEdgeID := boundary.Edges[0].ID

	if err := writerB.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{client}); err != nil {
		t.Fatal(err)
	}
	boundary, err = reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(boundary.Edges) != 0 {
		t.Fatalf("late CLIENT did not replace the standalone boundary: %+v", boundary.Edges)
	}
	evidence, err := reader.Evidence(ctx, oldEdgeID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 0 {
		t.Fatalf("superseded boundary evidence remained visible: %+v", evidence)
	}
	filter.View = "service"
	service, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(service.Edges) != 1 || service.Edges[0].Calls != 1 || service.Edges[0].SourceName != "orders" || service.Edges[0].TargetName != "profile" {
		t.Fatalf("late CLIENT did not form the service edge: %+v", service.Edges)
	}
}

func TestCHReaderRuntimeFieldEnrichmentIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	applicationID := uuid.New()
	traceID := strings.ReplaceAll(uuid.NewString(), "-", "")
	client := observationForTest("orders", "CLIENT", now.Add(-time.Second))
	client.AgentID = uuid.New()
	client.EventID = "runtime-client-" + uuid.NewString()
	client.ApplicationID = &applicationID
	client.Trace.TraceID = traceID
	client.Trace.SpanID = strings.Repeat("1", 16)
	client.HTTP.Method = "POST"
	client.HTTP.PathTemplate = "/login"
	client.Fields = nil
	server := observationForTest("profile", "SERVER", now.Add(-time.Second+5*time.Millisecond))
	server.AgentID = uuid.New()
	server.EventID = "runtime-server-" + uuid.NewString()
	server.ApplicationID = &applicationID
	server.Trace.TraceID = traceID
	server.Trace.SpanID = strings.Repeat("a", 16)
	server.Trace.ParentSpanID = client.Trace.SpanID
	server.HTTP.Method = "POST"
	server.HTTP.PathTemplate = "/login"
	server.Fields = nil
	writer := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	if err := writer.SaveContributions(ctx, BuildContributions([]agents.APIObservationEnvelope{client, server})); err != nil {
		t.Fatal(err)
	}
	reference := RuntimeFieldReference{TraceID: traceID, Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID}
	runtime := &runtimeFieldFakeReader{records: []RuntimeFieldRecord{{
		Reference: reference,
		Fields:    []FieldEvidence{{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}},
	}}}
	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier }).WithRuntimeFields(runtime)
	filter := GraphFilter{Start: now.Add(-time.Hour), End: now.Add(time.Hour), ApplicationID: &applicationID, DataType: "credential", MaxEdges: 10, View: "service"}
	graph, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || len(graph.Edges[0].Fields) != 1 || graph.Edges[0].Fields[0].Path != "form.pwd" || graph.Edges[0].DataTypes[0] != "CREDENTIAL" {
		t.Fatalf("runtime-only field did not survive ClickHouse graph filtering: %+v", graph.Edges)
	}
	evidence, err := reader.Evidence(ctx, graph.Edges[0].ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || len(evidence[0].Fields) != 1 || evidence[0].Fields[0].Path != "form.pwd" || evidence[0].Fields[0].Match != "OBSERVED" {
		t.Fatalf("runtime-only field did not survive ClickHouse evidence filtering: %+v", evidence)
	}
}

func TestCHContributionStoreCrossMidnightPartitionIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	applicationID := uuid.New()
	traceID := strings.ReplaceAll(uuid.NewString(), "-", "")

	client := observationForTest("orders", "CLIENT", midnight.Add(-5*time.Minute))
	client.AgentID = uuid.New()
	client.EventID = "midnight-client-" + uuid.NewString()
	client.ApplicationID = &applicationID
	client.Trace.TraceID = traceID
	client.Trace.SpanID = strings.Repeat("1", 16)
	client.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "midnight-req-"+traceID)}

	server := observationForTest("profile", "SERVER", midnight.Add(5*time.Minute))
	server.AgentID = uuid.New()
	server.EventID = "midnight-server-" + uuid.NewString()
	server.ApplicationID = &applicationID
	server.Trace.TraceID = traceID
	server.Trace.SpanID = strings.Repeat("a", 16)
	server.Trace.ParentSpanID = client.Trace.SpanID
	server.Fields = []agents.APIObservationField{
		sensitiveField("REQUEST", "midnight-req-"+traceID),
		sensitiveField("RESPONSE", "midnight-resp-"+traceID),
	}

	writerA := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	writerB := NewCHContributionStore(func(context.Context) apm.CHQuerier { return querier })
	if err := writerA.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{client}); err != nil {
		t.Fatal(err)
	}
	if err := writerB.SaveObservationContributions(ctx, []agents.APIObservationEnvelope{server}); err != nil {
		t.Fatal(err)
	}

	reader := NewCHReader(func(context.Context) apm.CHQuerier { return querier })
	filter := GraphFilter{
		Start:         midnight.Add(-time.Hour),
		End:           midnight.Add(time.Hour),
		ApplicationID: &applicationID,
		MaxEdges:      10,
		View:          "service",
	}
	graph, err := reader.Graph(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].Calls != 1 || graph.Edges[0].SourceName != "orders" || graph.Edges[0].TargetName != "profile" {
		t.Fatalf("cross-midnight multi-partition trace did not correlate: %+v", graph.Edges)
	}
	evidence, err := reader.Evidence(ctx, graph.Edges[0].ID, filter, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || len(evidence[0].Fields) != 2 || evidence[0].Fields[0].Match != "CORRELATED_FIELD" {
		t.Fatalf("cross-midnight field observations did not correlate: %+v", evidence)
	}
}
