package apidataflow

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
)

type traceFakeRows struct {
	rows  [][]any
	index int
}

func (r *traceFakeRows) Next() bool { return r.index < len(r.rows) }

func (r *traceFakeRows) Scan(dest ...any) error {
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
		case *uint16:
			*target = value.(uint16)
		case *uint32:
			*target = value.(uint32)
		case *bool:
			*target = value.(bool)
		default:
			return fmt.Errorf("unsupported scan destination %T", dest[i])
		}
	}
	return nil
}

func (r *traceFakeRows) Close() error { return nil }
func (r *traceFakeRows) Err() error   { return nil }

type traceFakeCH struct {
	results []*traceFakeRows
	queries []string
	args    [][]any
	execs   []string
	execArg [][]any
}

func (f *traceFakeCH) Query(_ context.Context, query string, args ...any) (apm.CHRows, error) {
	f.queries = append(f.queries, query)
	f.args = append(f.args, args)
	if len(f.results) == 0 {
		return &traceFakeRows{}, nil
	}
	rows := f.results[0]
	f.results = f.results[1:]
	return rows, nil
}

func (f *traceFakeCH) Exec(_ context.Context, query string, args ...any) error {
	f.execs = append(f.execs, query)
	f.execArg = append(f.execArg, args)
	return nil
}

func traceObservationRow(record agents.APIObservationEnvelope) []any {
	appID := uuid.Nil
	if record.ApplicationID != nil {
		appID = *record.ApplicationID
	}
	return []any{
		record.AgentID,
		record.EventID,
		record.OccurredAt.UTC(),
		appID,
		record.Service.Name,
		record.Trace.TraceID,
		record.Trace.SpanID,
		record.Trace.ParentSpanID,
		record.HTTP.Direction,
		record.HTTP.Method,
		record.HTTP.Host,
		record.HTTP.PathTemplate,
		uint16(record.HTTP.Status),
		uint32(record.HTTP.LatencyMS),
		record.HTTP.PeerService,
		record.HTTP.PeerAddress,
		record.HTTP.ClientAddress,
		record.HTTP.ClientAddressSource,
		record.HTTP.ServerAddress,
		record.HTTP.MessagingSystem,
		record.HTTP.MessagingDestination,
	}
}

func traceFieldRow(agentID uuid.UUID, eventID string, f agents.APIObservationField) []any {
	return []any{
		agentID,
		eventID,
		f.Side,
		f.Location,
		f.Path,
		f.DataType,
		f.Level,
		f.ValueHMAC,
		f.HMACKeyID,
		f.ValuePresent,
		f.Truncated,
	}
}

func TestSaveObservationContributionsPrunesByTimeWindowAndEliminatesSubquery(t *testing.T) {
	base := time.Date(2026, 11, 25, 14, 30, 0, 0, time.UTC)
	appID := uuid.New()
	traceID := strings.Repeat("a", 32)

	client := observationForTest("orders", "CLIENT", base.Add(-2*time.Second))
	client.AgentID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	client.EventID = "ev-client-1"
	client.ApplicationID = &appID
	client.Trace.TraceID = traceID
	client.Trace.SpanID = strings.Repeat("1", 16)
	client.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-1")}

	server := observationForTest("profile", "SERVER", base)
	server.AgentID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	server.EventID = "ev-server-1"
	server.ApplicationID = &appID
	server.Trace.TraceID = traceID
	server.Trace.SpanID = strings.Repeat("2", 16)
	server.Trace.ParentSpanID = client.Trace.SpanID
	server.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-1")}

	otherAgent := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	fake := &traceFakeCH{
		results: []*traceFakeRows{
			{rows: [][]any{traceObservationRow(client), traceObservationRow(server)}},
			{rows: [][]any{
				traceFieldRow(client.AgentID, client.EventID, client.Fields[0]),
				// Mismatched (agent_id, event_id) pair must be ignored by Go index lookup.
				traceFieldRow(otherAgent, client.EventID, sensitiveField("REQUEST", "hmac-foreign")),
			}},
		},
	}

	store := NewCHContributionStore(func(context.Context) apm.CHQuerier { return fake })
	if err := store.SaveObservationContributions(context.Background(), []agents.APIObservationEnvelope{server}); err != nil {
		t.Fatal(err)
	}

	if len(fake.queries) != 2 {
		t.Fatalf("expected 2 CH queries, got %d: %#v", len(fake.queries), fake.queries)
	}
	q1, args1 := fake.queries[0], fake.args[0]
	if !strings.Contains(q1, "FROM wdsp.api_observations") || !strings.Contains(q1, "occurred_at >= ? AND occurred_at <= ? AND trace_id IN (?)") {
		t.Fatalf("Query 1 missing occurred_at pruning: %s", q1)
	}
	if len(args1) != 3 {
		t.Fatalf("Query 1 arg count = %d, want 3: %#v", len(args1), args1)
	}
	wantStart1, wantEnd1 := base.Add(-time.Hour), base.Add(time.Hour)
	if !args1[0].(time.Time).Equal(wantStart1) || !args1[1].(time.Time).Equal(wantEnd1) {
		t.Fatalf("Query 1 window = [%v, %v], want [%v, %v]", args1[0], args1[1], wantStart1, wantEnd1)
	}

	q2, args2 := fake.queries[1], fake.args[1]
	if strings.Contains(q2, "wdsp.api_observations") {
		t.Fatalf("Query 2 still contains redundant api_observations subquery: %s", q2)
	}
	if !strings.Contains(q2, "FROM wdsp.api_field_observations") ||
		!strings.Contains(q2, "occurred_at >= ? AND occurred_at <= ? AND agent_id IN (?) AND event_id IN (?)") {
		t.Fatalf("Query 2 missing direct occurred_at + key pruning: %s", q2)
	}
	if len(args2) != 4 {
		t.Fatalf("Query 2 arg count = %d, want 4: %#v", len(args2), args2)
	}
	wantFieldStart, wantFieldEnd := client.OccurredAt.UTC().Add(-time.Second), server.OccurredAt.UTC().Add(time.Second)
	if !args2[0].(time.Time).Equal(wantFieldStart) || !args2[1].(time.Time).Equal(wantFieldEnd) {
		t.Fatalf("Query 2 field window = [%v, %v], want [%v, %v]", args2[0], args2[1], wantFieldStart, wantFieldEnd)
	}
	gotAgents := args2[2].([]uuid.UUID)
	gotEvents := args2[3].([]string)
	if len(gotAgents) != 2 || gotAgents[0] != client.AgentID || gotAgents[1] != server.AgentID {
		t.Fatalf("Query 2 agent_ids = %v", gotAgents)
	}
	if len(gotEvents) != 2 || gotEvents[0] != client.EventID || gotEvents[1] != server.EventID {
		t.Fatalf("Query 2 event_ids = %v", gotEvents)
	}

	// Verify contributions were persisted with paired service edge + correlated field.
	if len(fake.execs) != 3 || !strings.Contains(fake.execs[2], "INSERT INTO wdsp.data_flow_contributions") {
		t.Fatalf("expected SaveBatch (2 execs) + SaveContributions (1 exec), got: %#v", fake.execs)
	}
}

func TestSaveObservationContributionsCrossMidnightMultiPartitionWindow(t *testing.T) {
	t1 := time.Date(2026, 11, 25, 23, 50, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 26, 0, 10, 0, 0, time.UTC)
	unrelatedWithoutTrace := observationForTest("health", "SERVER", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	unrelatedWithoutTrace.Trace.TraceID = ""

	rec1 := observationForTest("orders", "CLIENT", t1)
	rec1.Trace.TraceID = strings.Repeat("b", 32)
	rec1.Trace.SpanID = strings.Repeat("1", 16)
	rec2 := observationForTest("profile", "SERVER", t2)
	rec2.Trace.TraceID = rec1.Trace.TraceID
	rec2.Trace.SpanID = strings.Repeat("2", 16)
	rec2.Trace.ParentSpanID = rec1.Trace.SpanID

	fake := &traceFakeCH{
		results: []*traceFakeRows{
			{rows: [][]any{traceObservationRow(rec1), traceObservationRow(rec2)}},
			{},
		},
	}
	store := NewCHContributionStore(func(context.Context) apm.CHQuerier { return fake })
	if err := store.SaveObservationContributions(context.Background(), []agents.APIObservationEnvelope{unrelatedWithoutTrace, rec1, rec2}); err != nil {
		t.Fatal(err)
	}

	if len(fake.queries) != 2 {
		t.Fatalf("expected 2 queries, got %d", len(fake.queries))
	}
	args1 := fake.args[0]
	wantStart := time.Date(2026, 11, 25, 22, 50, 0, 0, time.UTC)
	wantEnd := time.Date(2026, 11, 26, 1, 10, 0, 0, time.UTC)
	if !args1[0].(time.Time).Equal(wantStart) || !args1[1].(time.Time).Equal(wantEnd) {
		t.Fatalf("cross-midnight window = [%v, %v], want [%v, %v]", args1[0], args1[1], wantStart, wantEnd)
	}
}

func TestSaveObservationContributionsZeroOccurredAtFallback(t *testing.T) {
	rec := observationForTest("orders", "SERVER", time.Time{})
	rec.OccurredAt = time.Time{}
	rec.Trace.TraceID = strings.Repeat("c", 32)
	rec.Fields = nil

	fake := &traceFakeCH{
		results: []*traceFakeRows{
			{rows: [][]any{traceObservationRow(rec)}},
			{},
		},
	}
	store := NewCHContributionStore(func(context.Context) apm.CHQuerier { return fake }).WithTraceWindow(30 * time.Minute)
	if err := store.SaveObservationContributions(context.Background(), []agents.APIObservationEnvelope{rec}); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 2 {
		t.Fatalf("expected 2 queries, got %d", len(fake.queries))
	}
	if !strings.Contains(fake.queries[0], "WHERE trace_id IN (?)") ||
		strings.Contains(fake.queries[0], "occurred_at >=") || len(fake.args[0]) != 1 {
		t.Fatalf("expected zero-timestamp fallback to omit occurred_at filter on Query 1: sql=%s args=%#v", fake.queries[0], fake.args[0])
	}
	if !strings.Contains(fake.queries[1], "WHERE agent_id IN (?) AND event_id IN (?)") ||
		strings.Contains(fake.queries[1], "occurred_at >=") || len(fake.args[1]) != 2 {
		t.Fatalf("expected zero-timestamp fallback to omit occurred_at filter on Query 2: sql=%s args=%#v", fake.queries[1], fake.args[1])
	}
}

func TestLoadTraceObservationsEmptyResultShortCircuitsFieldsQuery(t *testing.T) {
	rec := observationForTest("orders", "CLIENT", time.Now().UTC())
	rec.Trace.TraceID = strings.Repeat("d", 32)
	fake := &traceFakeCH{
		results: []*traceFakeRows{{}},
	}
	store := NewCHContributionStore(func(context.Context) apm.CHQuerier { return fake })
	if err := store.SaveObservationContributions(context.Background(), []agents.APIObservationEnvelope{rec}); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 1 {
		t.Fatalf("expected Query 2 to short-circuit when Query 1 returns 0 rows, got %d queries", len(fake.queries))
	}
}
