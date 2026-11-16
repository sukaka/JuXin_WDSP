package apidataflow

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
)

type fakeCH struct {
	queries []string
	args    [][]any
	err     error
}

func (f *fakeCH) Query(context.Context, string, ...any) (apm.CHRows, error) {
	return nil, f.err
}
func (f *fakeCH) Exec(_ context.Context, query string, args ...any) error {
	f.queries = append(f.queries, query)
	f.args = append(f.args, args)
	return f.err
}

func TestInsertValuesSQL(t *testing.T) {
	sql := insertValuesSQL("wdsp.api_observations", []string{"agent_id", "event_id"}, 2)
	if sql != "INSERT INTO wdsp.api_observations (agent_id,event_id) VALUES (?,?),(?,?)" {
		t.Fatalf("unexpected SQL: %s", sql)
	}
}

func TestCHObservationStoreSaveBatch(t *testing.T) {
	fake := &fakeCH{}
	store := NewCHObservationStore(func(context.Context) apm.CHQuerier { return fake })
	record := validProjectionEnvelope()
	record.HTTP.PeerAddress = "10.0.0.8"
	record.HTTP.ClientAddress = "8.8.8.8"
	record.HTTP.ClientAddressSource = "TRUSTED_PROXY"
	record.HTTP.ServerAddress = "10.20.0.30"
	if err := store.SaveBatch(context.Background(), []agents.APIObservationEnvelope{record}); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 2 || !strings.Contains(fake.queries[0], "wdsp.api_observations") || !strings.Contains(fake.queries[1], "wdsp.api_field_observations") {
		t.Fatalf("unexpected inserts: %#v", fake.queries)
	}
	if len(fake.args[0]) != 39 || len(fake.args[1]) != 12 {
		t.Fatalf("unexpected argument counts: %d %d", len(fake.args[0]), len(fake.args[1]))
	}
	for _, column := range []string{"peer_address", "client_address", "client_address_source", "server_address"} {
		if !strings.Contains(fake.queries[0], column) {
			t.Errorf("missing observation column %q: %s", column, fake.queries[0])
		}
	}
	if fake.args[0][32] != "10.0.0.8" || fake.args[0][33] != "8.8.8.8" ||
		fake.args[0][34] != "TRUSTED_PROXY" || fake.args[0][35] != "10.20.0.30" {
		t.Fatalf("observed addresses were not stored separately: %+v", fake.args[0][32:36])
	}
	for _, arg := range fake.args[0] {
		if s, ok := arg.(string); ok {
			for _, forbidden := range []string{"secret-value", "raw_body", "request_headers", "Bearer "} {
				if strings.Contains(s, forbidden) {
					t.Fatalf("raw body or header content leaked into observation: %q", forbidden)
				}
			}
		}
	}
}

func TestCHObservationStoreUnavailable(t *testing.T) {
	store := NewCHObservationStore(func(context.Context) apm.CHQuerier { return nil })
	if err := store.SaveBatch(context.Background(), []agents.APIObservationEnvelope{{}}); err == nil {
		t.Fatal("expected unavailable error")
	}
}

func TestCHContributionStoreSaveBoundaryEvidence(t *testing.T) {
	record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
	record.HTTP.PeerService = ""
	record.HTTP.PeerAddress = "10.0.0.8"
	record.HTTP.ClientAddress = "2001:4860:4860::8888"
	record.HTTP.ClientAddressSource = "GATEWAY"
	record.HTTP.ServerAddress = "fd00::30"
	contributions := BuildContributions([]agents.APIObservationEnvelope{record})
	if len(contributions) != 1 {
		t.Fatalf("unexpected contributions: %+v", contributions)
	}
	fake := &fakeCH{}
	store := NewCHContributionStore(func(context.Context) apm.CHQuerier { return fake })
	if err := store.SaveContributions(context.Background(), contributions); err != nil {
		t.Fatal(err)
	}
	if len(fake.queries) != 1 || len(fake.args) != 1 || len(fake.args[0]) != 31 {
		t.Fatalf("unexpected contribution insert: %#v %#v", fake.queries, fake.args)
	}
	for _, column := range []string{
		"peer_address", "client_address", "client_address_source", "server_address",
		"source_zone", "target_zone", "boundary_type", "boundary_evidence",
	} {
		if !strings.Contains(fake.queries[0], column) {
			t.Errorf("missing contribution column %q: %s", column, fake.queries[0])
		}
	}
	want := []any{"10.0.0.8", "2001:4860:4860::8888", "GATEWAY", "fd00::30", "PUBLIC", "INTERNAL", "PUBLIC_TO_INTERNAL", "GATEWAY"}
	for i, expected := range want {
		if actual := fake.args[0][23+i]; actual != expected {
			t.Errorf("boundary argument %d = %#v, want %#v", 23+i, actual, expected)
		}
	}
}

func TestEvidenceRecordOmitsEmptyBoundaryFields(t *testing.T) {
	payload, err := json.Marshal(EvidenceRecord{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"peer_address", "client_address", "client_address_source", "server_address",
		"source_zone", "target_zone", "boundary_type", "boundary_evidence",
	} {
		if strings.Contains(string(payload), `"`+field+`"`) {
			t.Errorf("empty optional field %q was not omitted: %s", field, payload)
		}
	}
}

func validProjectionEnvelope() agents.APIObservationEnvelope {
	return agents.APIObservationEnvelope{
		SchemaVersion: 1, AgentID: testAgentID, ReceivedAt: time.Now().UTC(),
		APIObservationRecord: agents.APIObservationRecord{
			EventID: "ev-1", OccurredAt: time.Now().UTC().Add(-time.Second),
			Source:  agents.APIObservationSource{Type: "IN_PROCESS", Language: "java", Framework: "spring", AgentVersion: "1", SourceEpoch: 1},
			Service: agents.APIObservationService{Name: "orders", InstanceID: "orders-1"},
			HTTP:    agents.APIObservationHTTP{Direction: "SERVER", Method: "POST", Host: "orders", PathTemplate: "/orders", Status: 201, LatencyMS: 5},
			Fields:  []agents.APIObservationField{{Side: "REQUEST", Location: "JSON_BODY", Path: "$.mobile", DataType: "PHONE", ValueHMAC: "hmac-sha256:" + strings.Repeat("a", 64), HMACKeyID: "k1", ValuePresent: true}},
			Quality: agents.APIObservationQuality{RouteSource: "FRAMEWORK", RequestBodyState: "ANALYZED"},
		},
	}
}
