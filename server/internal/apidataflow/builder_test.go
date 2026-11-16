package apidataflow

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
)

func observationForTest(service, direction string, occurredAt time.Time) agents.APIObservationEnvelope {
	return agents.APIObservationEnvelope{
		SchemaVersion: 1, AgentID: testAgentID, ReceivedAt: occurredAt,
		APIObservationRecord: agents.APIObservationRecord{
			EventID: uuid.NewString(), OccurredAt: occurredAt,
			Source:  agents.APIObservationSource{Type: "IN_PROCESS", Language: "java", Framework: "spring", AgentVersion: "1"},
			Service: agents.APIObservationService{Name: service, InstanceID: service + "-1"},
			Trace:   agents.APIObservationTrace{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16)},
			HTTP:    agents.APIObservationHTTP{Direction: direction, Method: "POST", Host: "profile", PeerService: "profile", PathTemplate: "/profiles/{id}", Status: 200, LatencyMS: 12},
			Quality: agents.APIObservationQuality{RouteSource: "FRAMEWORK"},
		},
	}
}

func sensitiveField(side, value string) agents.APIObservationField {
	return agents.APIObservationField{Side: side, Location: "JSON_BODY", Path: "$.mobile", DataType: "PHONE", ValueHMAC: value, HMACKeyID: "key-1", ValuePresent: true}
}

func TestBuildContributionsTraceAndFields(t *testing.T) {
	now := time.Now().UTC()
	client := observationForTest("orders", "CLIENT", now)
	client.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-1")}
	server := observationForTest("profile", "SERVER", now.Add(5*time.Millisecond))
	server.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-1")}
	edges := BuildContributions([]agents.APIObservationEnvelope{server, client})
	if len(edges) != 1 {
		t.Fatalf("expected one call edge: %+v", edges)
	}
	edge := edges[0]
	if edge.SourceNode != "orders" || edge.TargetNode != "profile" || edge.CountWeight != 1 || edge.EvidenceType != "OBSERVED_TRACE" {
		t.Fatalf("unexpected edge: %+v", edge)
	}
	if len(edge.Fields) != 1 || edge.Fields[0].Match != "CORRELATED_FIELD" || edge.DataTypes[0] != "PHONE" {
		t.Fatalf("unexpected field evidence: %+v", edge.Fields)
	}
}

func TestBuildContributionsKafka(t *testing.T) {
	now := time.Now().UTC()
	producer := observationForTest("orders", "PRODUCER", now)
	producer.HTTP.MessagingSystem = "kafka"
	producer.HTTP.MessagingDestination = "customer-events"
	consumer := observationForTest("notifications", "CONSUMER", now.Add(time.Second))
	consumer.HTTP.MessagingSystem = "kafka"
	consumer.HTTP.MessagingDestination = "customer-events"
	edges := BuildContributions([]agents.APIObservationEnvelope{producer, consumer})
	if len(edges) != 2 || edges[0].TargetNode != "kafka/customer-events" || edges[1].SourceNode != "kafka/customer-events" || edges[1].TargetNode != "notifications" {
		t.Fatalf("unexpected Kafka edges: %+v", edges)
	}
}

func TestBuildResponseToRequestCorrelationDoesNotIncreaseCalls(t *testing.T) {
	now := time.Now().UTC()
	upstream := observationForTest("identity", "SERVER", now)
	upstream.Fields = []agents.APIObservationField{sensitiveField("RESPONSE", "hmac-2")}
	downstream := observationForTest("orders", "CLIENT", now.Add(time.Second))
	downstream.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "hmac-2")}
	edges := BuildContributions([]agents.APIObservationEnvelope{upstream, downstream})
	found := false
	for _, edge := range edges {
		if edge.EvidenceType == "CORRELATED_FIELD" {
			found = true
			if edge.CountWeight != 0 || edge.SourceNode != "identity" || edge.TargetNode != "orders" {
				t.Fatalf("unexpected correlation edge: %+v", edge)
			}
		}
	}
	if !found {
		t.Fatalf("missing response-to-request correlation: %+v", edges)
	}
}

func TestBuildContributionsUsesObservedPeerAddress(t *testing.T) {
	server := observationForTest("orders", "SERVER", time.Now().UTC())
	server.HTTP.PeerService = ""
	server.HTTP.PeerAddress = "192.0.2.10"
	edges := BuildContributions([]agents.APIObservationEnvelope{server})
	if len(edges) != 1 || edges[0].SourceNode != "192.0.2.10" || edges[0].SourceType != "CLIENT" || edges[0].TargetNode != "orders" {
		t.Fatalf("unexpected observed source: %+v", edges)
	}
}

func TestBuildSystemAPIContributionsIncludeMultiHopDirectAndResponseFields(t *testing.T) {
	now := time.Now().UTC()
	pairs := [][2]string{{"orders", "profile"}, {"profile", "identity"}, {"orders", "identity"}}
	records := []agents.APIObservationEnvelope{}
	for i, pair := range pairs {
		traceID := strings.Repeat(string(rune('a'+i)), 32)
		requestHMAC := "request-" + traceID
		client := observationForTest(pair[0], "CLIENT", now.Add(time.Duration(i)*time.Second))
		client.Trace.TraceID = traceID
		client.HTTP.Host = pair[1]
		client.HTTP.PeerService = pair[1]
		client.HTTP.PathTemplate = "/" + pair[1] + "/{id}"
		client.Fields = []agents.APIObservationField{sensitiveField("REQUEST", requestHMAC)}
		server := observationForTest(pair[1], "SERVER", now.Add(time.Duration(i)*time.Second+5*time.Millisecond))
		server.Trace.TraceID = traceID
		server.HTTP.Host = pair[1]
		server.HTTP.PathTemplate = "/" + pair[1] + "/{id}"
		server.Fields = []agents.APIObservationField{
			sensitiveField("REQUEST", requestHMAC),
			{Side: "RESPONSE", Location: "JSON_BODY", Path: "$.identity_no", DataType: "CN_ID", ValueHMAC: "response-" + traceID, HMACKeyID: "key-1", ValuePresent: true},
		}
		records = append(records, client, server)
	}
	edges := BuildContributions(records)
	if len(edges) != len(pairs) {
		t.Fatalf("expected three system API relations, got %+v", edges)
	}
	found := map[string]bool{}
	for _, edge := range edges {
		found[edge.SourceNode+"->"+edge.TargetNode] = true
		hasRequest, hasResponse := false, false
		for _, field := range edge.Fields {
			hasRequest = hasRequest || field.Side == "REQUEST" && field.DataType == "PHONE"
			hasResponse = hasResponse || field.Side == "RESPONSE" && field.DataType == "CN_ID"
		}
		if !hasRequest || !hasResponse {
			t.Fatalf("request/response sensitive fields missing from %s -> %s: %+v", edge.SourceNode, edge.TargetNode, edge.Fields)
		}
	}
	for _, pair := range pairs {
		if !found[pair[0]+"->"+pair[1]] {
			t.Errorf("missing direct system relation %s -> %s", pair[0], pair[1])
		}
	}
}

func validateObservationForTest(t *testing.T, record agents.APIObservationEnvelope) agents.APIObservationEnvelope {
	t.Helper()
	batch := agents.APIObservationBatch{SchemaVersion: agents.APIObservationSchemaV1, Records: []agents.APIObservationRecord{record.APIObservationRecord}}
	if invalid := batch.Validate(time.Now().UTC()); len(invalid) != 0 {
		t.Fatalf("valid observation rejected: %+v", invalid)
	}
	record.APIObservationRecord = batch.Records[0]
	return record
}

func TestBuildContributionsNetworkBoundaries(t *testing.T) {
	tests := []struct {
		name                string
		peerAddress         string
		clientAddress       string
		clientAddressSource string
		serverAddress       string
		wantClientAddress   string
		wantSourceZone      string
		wantTargetZone      string
		wantBoundaryType    string
		wantEvidence        string
	}{
		{
			name: "direct public IPv4 to internal", peerAddress: "8.8.8.8", clientAddress: "8.8.8.8",
			clientAddressSource: "DIRECT_PEER", serverAddress: "10.20.0.30", wantClientAddress: "8.8.8.8",
			wantSourceZone: "PUBLIC", wantTargetZone: "INTERNAL", wantBoundaryType: "PUBLIC_TO_INTERNAL", wantEvidence: "DIRECT_PEER",
		},
		{
			name: "trusted proxy preserves separate peer", peerAddress: "10.0.0.8", clientAddress: "1.1.1.1",
			clientAddressSource: "TRUSTED_PROXY", serverAddress: "10.20.0.30", wantClientAddress: "1.1.1.1",
			wantSourceZone: "PUBLIC", wantTargetZone: "INTERNAL", wantBoundaryType: "PUBLIC_TO_INTERNAL", wantEvidence: "TRUSTED_PROXY",
		},
		{
			name: "gateway public IPv6 to internal", peerAddress: "fd00::8", clientAddress: "2001:4860:4860::8888",
			clientAddressSource: "GATEWAY", serverAddress: "fd00::30", wantClientAddress: "2001:4860:4860::8888",
			wantSourceZone: "PUBLIC", wantTargetZone: "INTERNAL", wantBoundaryType: "PUBLIC_TO_INTERNAL", wantEvidence: "GATEWAY",
		},
		{
			name: "missing server remains unknown", peerAddress: "8.8.8.8", clientAddress: "8.8.8.8",
			clientAddressSource: "DIRECT_PEER", wantClientAddress: "8.8.8.8",
			wantSourceZone: "PUBLIC", wantTargetZone: "UNKNOWN", wantBoundaryType: "UNKNOWN", wantEvidence: "MISSING_SERVER_ADDRESS",
		},
		{
			name: "unknown client source cannot form boundary", peerAddress: "10.0.0.8", clientAddress: "8.8.8.8",
			clientAddressSource: "UNKNOWN", serverAddress: "10.20.0.30", wantClientAddress: "8.8.8.8",
			wantSourceZone: "UNKNOWN", wantTargetZone: "INTERNAL", wantBoundaryType: "UNKNOWN", wantEvidence: "UNTRUSTED_CLIENT_SOURCE",
		},
		{
			name: "proxy peer is not promoted to missing client", peerAddress: "10.0.0.8",
			clientAddressSource: "TRUSTED_PROXY", serverAddress: "10.20.0.30",
			wantSourceZone: "UNKNOWN", wantTargetZone: "INTERNAL", wantBoundaryType: "UNKNOWN", wantEvidence: "MISSING_CLIENT_ADDRESS",
		},
		{
			name: "internal direct traffic is not a public boundary", peerAddress: "10.0.0.8", clientAddress: "10.0.0.8",
			clientAddressSource: "DIRECT_PEER", serverAddress: "10.20.0.30", wantClientAddress: "10.0.0.8",
			wantSourceZone: "INTERNAL", wantTargetZone: "INTERNAL", wantBoundaryType: "UNKNOWN", wantEvidence: "DIRECT_PEER",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
			record.HTTP.PeerService = ""
			record.HTTP.PeerAddress = tt.peerAddress
			record.HTTP.ClientAddress = tt.clientAddress
			record.HTTP.ClientAddressSource = tt.clientAddressSource
			record.HTTP.ServerAddress = tt.serverAddress
			record = validateObservationForTest(t, record)
			edges := BuildContributions([]agents.APIObservationEnvelope{record})
			if len(edges) != 1 {
				t.Fatalf("expected one server contribution: %+v", edges)
			}
			edge := edges[0]
			if edge.SourceZone != tt.wantSourceZone || edge.TargetZone != tt.wantTargetZone ||
				edge.BoundaryType != tt.wantBoundaryType || edge.BoundaryEvidence != tt.wantEvidence {
				t.Fatalf("unexpected boundary: %+v", edge)
			}
			if edge.PeerAddress != record.HTTP.PeerAddress || edge.ClientAddress != tt.wantClientAddress ||
				edge.ClientAddressSource != record.HTTP.ClientAddressSource || edge.ServerAddress != tt.serverAddress {
				t.Fatalf("observed addresses were not preserved separately: %+v", edge)
			}
		})
	}
}

func TestBuildContributionsLegacyPeerAddressDefaultsToDirectPeer(t *testing.T) {
	record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
	record.HTTP.PeerService = ""
	record.HTTP.PeerAddress = "192.0.2.10"
	record.HTTP.ServerAddress = "10.20.0.30"
	edges := BuildContributions([]agents.APIObservationEnvelope{record})
	if len(edges) != 1 || edges[0].ClientAddress != "192.0.2.10" || edges[0].ClientAddressSource != "DIRECT_PEER" ||
		edges[0].BoundaryType != "PUBLIC_TO_INTERNAL" || edges[0].BoundaryEvidence != "DIRECT_PEER" {
		t.Fatalf("legacy direct peer was not preserved: %+v", edges)
	}
	validated := validateObservationForTest(t, record)
	if validated.HTTP.ClientAddress != validated.HTTP.PeerAddress || validated.HTTP.ClientAddressSource != "DIRECT_PEER" {
		t.Fatalf("legacy observation was not normalized: %+v", validated.HTTP)
	}
}

func TestAPIObservationRejectsMismatchedDirectPeer(t *testing.T) {
	for _, tt := range []struct{ name, peer, client string }{
		{name: "IPv4", peer: "192.0.2.10", client: "192.0.2.11"},
		{name: "IPv6", peer: "2001:db8::10", client: "2001:db8::11"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
			record.HTTP.PeerAddress = tt.peer
			record.HTTP.ClientAddress = tt.client
			record.HTTP.ClientAddressSource = "DIRECT_PEER"
			batch := agents.APIObservationBatch{SchemaVersion: 1, Records: []agents.APIObservationRecord{record.APIObservationRecord}}
			if invalid := batch.Validate(time.Now().UTC()); len(invalid) != 1 || !strings.Contains(invalid[0].Reason, "client_address") {
				t.Fatalf("mismatched direct peer accepted: %+v", invalid)
			}
		})
	}
}

func TestAPIObservationCanonicalizesIPv6BeforeDirectPeerComparison(t *testing.T) {
	record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
	record.HTTP.PeerAddress = "2001:4860:4860:0:0:0:0:8888"
	record.HTTP.ClientAddress = "2001:4860:4860::8888"
	record.HTTP.ClientAddressSource = "DIRECT_PEER"
	record.HTTP.ServerAddress = "fd00:0:0:0::30"
	record = validateObservationForTest(t, record)
	if record.HTTP.PeerAddress != "2001:4860:4860::8888" || record.HTTP.ClientAddress != record.HTTP.PeerAddress || record.HTTP.ServerAddress != "fd00::30" {
		t.Fatalf("addresses were not canonicalized: %+v", record.HTTP)
	}
}

func TestAPIObservationRejectsInvalidAddressSource(t *testing.T) {
	record := observationForTest("orders", "SERVER", time.Now().UTC().Add(-time.Second))
	record.HTTP.ClientAddress = "8.8.8.8"
	record.HTTP.ClientAddressSource = "X_FORWARDED_FOR"
	batch := agents.APIObservationBatch{SchemaVersion: 1, Records: []agents.APIObservationRecord{record.APIObservationRecord}}
	if invalid := batch.Validate(time.Now().UTC()); len(invalid) != 1 || !strings.Contains(invalid[0].Reason, "client_address_source") {
		t.Fatalf("untrusted forwarding header source accepted: %+v", invalid)
	}
}

func TestBuildContributionsRepeatedCallsUseMatchingServer(t *testing.T) {
	for _, withParent := range []bool{true, false} {
		name := "parent span"
		if !withParent {
			name = "one-to-one temporal fallback"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			traceID := strings.Repeat("f", 32)
			client1 := observationForTest("orders", "CLIENT", now)
			client1.EventID = "client-1"
			client1.Trace.TraceID = traceID
			client1.Trace.SpanID = strings.Repeat("1", 16)
			client1.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-1")}
			client2 := observationForTest("orders", "CLIENT", now.Add(20*time.Millisecond))
			client2.EventID = "client-2"
			client2.Trace.TraceID = traceID
			client2.Trace.SpanID = strings.Repeat("2", 16)
			client2.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-2")}

			server1 := observationForTest("profile", "SERVER", now.Add(5*time.Millisecond))
			server1.EventID = "server-1"
			server1.Trace.TraceID = traceID
			server1.Trace.SpanID = strings.Repeat("a", 16)
			server1.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-1"), sensitiveField("RESPONSE", "response-1")}
			server2 := observationForTest("profile", "SERVER", now.Add(25*time.Millisecond))
			server2.EventID = "server-2"
			server2.Trace.TraceID = traceID
			server2.Trace.SpanID = strings.Repeat("b", 16)
			server2.Fields = []agents.APIObservationField{sensitiveField("REQUEST", "request-2"), sensitiveField("RESPONSE", "response-2")}
			if withParent {
				server1.Trace.ParentSpanID = client1.Trace.SpanID
				server2.Trace.ParentSpanID = client2.Trace.SpanID
			}

			contributions := BuildContributions([]agents.APIObservationEnvelope{server2, client2, server1, client1})
			byClient := map[string]Contribution{}
			for _, contribution := range contributions {
				if contribution.EvidenceType == "OBSERVED_TRACE" {
					byClient[contribution.EventID] = contribution
				}
			}
			if len(byClient) != 2 {
				t.Fatalf("expected two paired calls, got %+v", contributions)
			}
			for eventID, suffix := range map[string]string{"client-1": "1", "client-2": "2"} {
				contribution := byClient[eventID]
				if contribution.CountWeight != 1 || len(contribution.Fields) != 2 {
					t.Fatalf("unexpected contribution for %s: %+v", eventID, contribution)
				}
				request, response := contribution.Fields[0], contribution.Fields[1]
				if request.ValueHMAC != "request-"+suffix || request.Match != "CORRELATED_FIELD" ||
					response.ValueHMAC != "response-"+suffix {
					t.Fatalf("wrong SERVER fields selected for %s: %+v", eventID, contribution.Fields)
				}
			}
		})
	}
}

func TestPersistentContributionsSupersedeSingleSidedEdges(t *testing.T) {
	now := time.Now().UTC()
	client := observationForTest("orders", "CLIENT", now)
	server := observationForTest("profile", "SERVER", now.Add(time.Millisecond))
	server.Trace.ParentSpanID = client.Trace.SpanID
	clientOnly := BuildContributions([]agents.APIObservationEnvelope{client})
	serverOnly := BuildContributions([]agents.APIObservationEnvelope{server})
	if len(clientOnly) != 1 || len(serverOnly) != 1 {
		t.Fatalf("unexpected single-sided contributions: %+v %+v", clientOnly, serverOnly)
	}

	persisted := persistentContributions([]agents.APIObservationEnvelope{client, server})
	tombstones := map[string]Contribution{}
	paired := 0
	for _, contribution := range persisted {
		switch contribution.EvidenceType {
		case "OBSERVED_TRACE":
			paired++
		case "PAIRED_CLIENT", "PAIRED_SERVER":
			tombstones[contribution.EvidenceType] = contribution
		}
	}
	if paired != 1 || len(tombstones) != 2 {
		t.Fatalf("missing pair or replacement records: %+v", persisted)
	}
	if tombstones["PAIRED_CLIENT"].EdgeID != clientOnly[0].EdgeID || tombstones["PAIRED_SERVER"].EdgeID != serverOnly[0].EdgeID {
		t.Fatalf("replacement records do not address the original edges: %+v", tombstones)
	}
	for _, contribution := range tombstones {
		if contribution.CountWeight != 0 {
			t.Fatalf("replacement record must not add calls: %+v", contribution)
		}
	}
}

func TestBuildContributionsKeepsUnpairedRepeatedServer(t *testing.T) {
	now := time.Now().UTC()
	client := observationForTest("orders", "CLIENT", now)
	server1 := observationForTest("profile", "SERVER", now.Add(time.Millisecond))
	server1.EventID = "paired-server"
	server1.Trace.ParentSpanID = client.Trace.SpanID
	server2 := observationForTest("profile", "SERVER", now.Add(2*time.Millisecond))
	server2.EventID = "unpaired-server"
	server2.Trace.ParentSpanID = strings.Repeat("9", 16)

	contributions := BuildContributions([]agents.APIObservationEnvelope{server2, client, server1})
	paired, standalone := 0, 0
	for _, contribution := range contributions {
		switch contribution.EvidenceType {
		case "OBSERVED_TRACE":
			paired++
		case "OBSERVED_SERVER":
			standalone++
			if contribution.EventID != server2.EventID {
				t.Fatalf("wrong server was suppressed: %+v", contribution)
			}
		}
	}
	if paired != 1 || standalone != 1 {
		t.Fatalf("expected one paired and one standalone call: %+v", contributions)
	}
}
