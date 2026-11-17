package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	agentmodel "github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/product"
)

func TestCloudAPIDataFlowEndToEnd(t *testing.T) {
	kafkaAddr := os.Getenv("WDSP_KAFKA_TEST_ADDR")
	clickhouseDSN := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if kafkaAddr == "" || clickhouseDSN == "" {
		t.Skip("WDSP_KAFKA_TEST_ADDR and WDSP_CLICKHOUSE_TEST_DSN are required")
	}
	cfg := baseTestCfg()
	cfg.Product = product.Settings{Edition: product.EditionWDSP, APIDynamicProtection: true, WebWAFEnabled: true, APIProtectionMode: "OBSERVE"}
	cfg.APM = config.APMConfig{Enabled: true, ClickHouseDSN: clickhouseDSN}
	cfg.Kafka = config.KafkaConfig{Enabled: true, Brokers: []string{kafkaAddr}, Topic: "wdsp.api.observations.v1", DLQTopic: "wdsp.api.observations.dlq.v1", ProduceTimeout: 10 * time.Second, MaxBatchRecords: 100, MaxBatchBytes: 4 << 20}
	env := newTestEnv(t, cfg)
	env.importBaseLicense(t)
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	env.app.StartStage6Workers(workerCtx)

	token, err := agentmodel.GenerateEnrollmentToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO agent_enrollment_tokens (label,token_hash,expires_at,created_by)
VALUES ('cloud-dataflow-test',$1,$2,'integration-test')`, agentmodel.HashSecret(token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	enrollBody := fmt.Sprintf(`{"enrollment_token":%q,"hostname":"cloud-java-agent","ip":"10.20.0.10","capabilities":{"http_event_schema_versions":[1,2],"api_observation_schema_versions":[1]}}`, token)
	resp, err := http.Post(env.server.URL+"/api/v1/agents/enroll", "application/json", strings.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	var enrollment struct {
		AgentID    string `json:"agent_id"`
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || enrollment.AgentID == "" || enrollment.Credential == "" {
		t.Fatalf("enroll failed: %d", resp.StatusCode)
	}

	applicationID := uuid.New()
	if _, err := env.db.Exec(context.Background(), `INSERT INTO applications (id,code,name) VALUES ($1,$2,'Cloud Dataflow Test')`, applicationID, "cloud-dataflow-"+applicationID.String()); err != nil {
		t.Fatal(err)
	}
	bindings := map[string]uuid.UUID{}
	for _, serviceName := range []string{"orders", "profile", "identity"} {
		bindingID := uuid.New()
		bindings[serviceName] = bindingID
		if _, err := env.db.Exec(context.Background(), `
INSERT INTO agent_workload_bindings (id,traffic_agent_id,application_id,service_name,environment,binding_version)
VALUES ($1,$2,$3,$4,'prod',1)`, bindingID, enrollment.AgentID, applicationID, serviceName); err != nil {
			t.Fatal(err)
		}
	}
	batch := cloudObservationBatch(bindings)
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	postObservation := func(expectedAccepted, expectedDuplicates int) {
		req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/agents/"+enrollment.AgentID+"/api-observations", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+enrollment.Credential)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result struct {
			AcceptedCount  int `json:"accepted_count"`
			DuplicateCount int `json:"duplicate_count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted || result.AcceptedCount != expectedAccepted || result.DuplicateCount != expectedDuplicates {
			t.Fatalf("unexpected observation response: status=%d result=%+v", resp.StatusCode, result)
		}
	}
	postObservation(len(batch["records"].([]map[string]interface{})), 0)
	postObservation(0, len(batch["records"].([]map[string]interface{})))

	username := "cloudflow_" + s5Rand()
	password := "S5@Test2026!"
	env.createUserDirect(t, username, password, "SECURITY_ADMIN")
	cookies, _ := env.login(t, username, password)
	var graph map[string]interface{}
	deadline := time.Now().Add(40 * time.Second)
	for {
		resp := env.get(t, "/api/v1/api-security/data-flow/graph?max_edges=50&application_id="+applicationID.String(), cookies)
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("graph status=%d body=%s", resp.StatusCode, data)
		}
		var envelope struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		graph = envelope.Data
		edges, _ := graph["edges"].([]interface{})
		if len(edges) >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	edges, _ := graph["edges"].([]interface{})
	if len(edges) != 3 {
		t.Fatalf("expected exactly 3 system API relations, got %d: %+v", len(edges), graph)
	}
	foundCall, foundNext, foundDirect, foundPhone, foundID := false, false, false, false, false
	var callEdgeID string
	for _, raw := range edges {
		edge, _ := raw.(map[string]interface{})
		source, _ := edge["source_name"].(string)
		target, _ := edge["target_name"].(string)
		if source == "orders" && target == "profile" {
			foundCall = true
			callEdgeID, _ = edge["id"].(string)
			if calls, _ := edge["calls"].(float64); calls != 1 {
				t.Fatalf("duplicate observations inflated call count: %+v", edge)
			}
			if apis, _ := edge["apis"].([]interface{}); len(apis) != 1 || apis[0] != "POST /profiles/{id}" {
				t.Fatalf("system relation did not retain its API list: %+v", edge)
			}
		}
		foundNext = foundNext || source == "profile" && target == "identity"
		foundDirect = foundDirect || source == "orders" && target == "identity"
		if types, ok := edge["data_types"].([]interface{}); ok {
			for _, typ := range types {
				foundPhone = foundPhone || typ == "PHONE"
				foundID = foundID || typ == "CN_ID"
			}
		}
	}
	if !foundCall || !foundNext || !foundDirect || !foundPhone || !foundID {
		t.Fatalf("incomplete system API dataflow: call=%v next=%v direct=%v phone=%v id=%v graph=%+v", foundCall, foundNext, foundDirect, foundPhone, foundID, graph)
	}
	var hitCount int
	assetDeadline := time.Now().Add(15 * time.Second)
	for {
		err := env.db.QueryRow(context.Background(), `SELECT hit_count FROM api_endpoints WHERE http_method='POST' AND normalized_path='/profiles/{id}'`).Scan(&hitCount)
		if errors.Is(err, sql.ErrNoRows) && time.Now().Before(assetDeadline) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if hitCount != 1 {
		t.Fatalf("API hit_count=%d want 1 after duplicate projection", hitCount)
	}
	if callEdgeID == "" {
		t.Fatal("missing call edge id")
	}
	resp = env.get(t, "/api/v1/api-security/data-flow/evidence?edge_id="+callEdgeID, cookies)
	defer resp.Body.Close()
	evidenceBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Contains(evidenceBody, []byte("CORRELATED_FIELD")) || !bytes.Contains(evidenceBody, []byte("$.mobile")) || !bytes.Contains(evidenceBody, []byte("$.identity_no")) || !bytes.Contains(evidenceBody, []byte(`"side":"RESPONSE"`)) {
		t.Fatalf("unexpected evidence: status=%d body=%s", resp.StatusCode, evidenceBody)
	}

	baselineGraph, _ := readCloudAPIDataFlowGraph(t, env, cookies, "max_edges=50&application_id="+applicationID.String())
	baselineCall := requireCloudAPIDataFlowEdge(t, baselineGraph, "orders", "profile")
	beforeCredentialGraph, _ := readCloudAPIDataFlowGraph(t, env, cookies, "max_edges=1&data_type=CREDENTIAL&application_id="+applicationID.String())
	if len(beforeCredentialGraph.Edges) != 0 {
		t.Fatalf("runtime event has not arrived; CREDENTIAL edges must be empty: %+v", beforeCredentialGraph.Edges)
	}

	gatewayTraceID := strings.Repeat("a", 32)
	runtimeRequestID := "req-cdf-" + uuid.NewString()
	unmatchedRequestID := "req-cdf-unmatched-" + uuid.NewString()
	persistCloudAPIDataFlowRuntimeEvents(t, env, []map[string]interface{}{
		cloudAPIDataFlowRuntimeEvent(runtimeRequestID, gatewayTraceID, applicationID, "POST /profiles/{id}", "/profiles/{id}"),
		cloudAPIDataFlowRuntimeEvent(unmatchedRequestID, strings.Repeat("f", 32), applicationID, "POST /runtime/unpaired", "/runtime/unpaired"),
	})
	var storedTraceID, storedEndpointKey, storedMethod, storedPath string
	var storedApplicationID uuid.UUID
	var storedDetails []byte
	if err := env.db.QueryRow(context.Background(), `
SELECT trace_id, application_id, endpoint_key, method, raw_path, details_json
FROM api_runtime_events WHERE request_id=$1`, runtimeRequestID).
		Scan(&storedTraceID, &storedApplicationID, &storedEndpointKey, &storedMethod, &storedPath, &storedDetails); err != nil {
		t.Fatalf("read persisted gateway runtime event with trace: %v", err)
	}
	if storedTraceID != gatewayTraceID || storedApplicationID != applicationID || storedEndpointKey != "POST /profiles/{id}" || storedMethod != "POST" || storedPath != "/profiles/{id}" {
		t.Fatalf("runtime correlation fields were not persisted: trace=%q application=%s endpoint=%q method=%q path=%q", storedTraceID, storedApplicationID, storedEndpointKey, storedMethod, storedPath)
	}
	var persistedDetails []struct {
		Detector string            `json:"detector"`
		Evidence map[string]string `json:"evidence"`
	}
	if err := json.Unmarshal(storedDetails, &persistedDetails); err != nil {
		t.Fatalf("decode persisted runtime details: %v", err)
	}
	if len(persistedDetails) != 1 || persistedDetails[0].Detector != "sensitive_data" ||
		len(persistedDetails[0].Evidence) != 4 || persistedDetails[0].Evidence["field"] != "pwd" ||
		persistedDetails[0].Evidence["location"] != "form" || persistedDetails[0].Evidence["direction"] != "REQUEST" ||
		persistedDetails[0].Evidence["data_type"] != "credential" {
		t.Fatalf("runtime sensitive evidence was not persisted intact: %s", storedDetails)
	}
	if bytes.Contains(storedDetails, []byte("value_hmac")) || bytes.Contains(storedDetails, []byte("hmac-sha256")) || bytes.Contains(storedDetails, []byte("body_base64")) {
		t.Fatalf("runtime fixture must not invent HMAC or carry a body: %s", storedDetails)
	}

	credentialGraph, credentialGraphBody := readCloudAPIDataFlowGraph(t, env, cookies, "max_edges=1&data_type=CREDENTIAL&application_id="+applicationID.String())
	if len(credentialGraph.Edges) != 1 || credentialGraph.Truncated {
		t.Fatalf("gateway-only CREDENTIAL field must be filtered before LIMIT: %+v", credentialGraph)
	}
	credentialCall := credentialGraph.Edges[0]
	if credentialCall.ID != callEdgeID || credentialCall.SourceName != "orders" || credentialCall.TargetName != "profile" {
		t.Fatalf("CREDENTIAL filter selected the wrong real contribution: %+v", credentialCall)
	}
	wantGatewayField := cloudAPIDataFlowField{Side: "REQUEST", Path: "form.pwd", DataType: "CREDENTIAL", Match: "OBSERVED"}
	if got := requireCloudAPIDataFlowField(t, credentialCall.Fields, "form.pwd"); got != wantGatewayField {
		t.Fatalf("gateway field enrichment mismatch: got=%+v want=%+v", got, wantGatewayField)
	}
	if !cloudAPIDataFlowHasType(credentialCall.DataTypes, "CREDENTIAL") || cloudAPIDataFlowHasType(credentialCall.DataTypes, "PASSWORD") {
		t.Fatalf("credential must remain CREDENTIAL, not be guessed as PASSWORD: %+v", credentialCall.DataTypes)
	}

	enrichedGraph, enrichedGraphBody := readCloudAPIDataFlowGraph(t, env, cookies, "max_edges=50&application_id="+applicationID.String())
	if len(enrichedGraph.Edges) != 3 {
		t.Fatalf("runtime enrichment must not create edges, including for unmatched events: %+v", enrichedGraph.Edges)
	}
	enrichedCall := requireCloudAPIDataFlowEdge(t, enrichedGraph, "orders", "profile")
	if got := requireCloudAPIDataFlowField(t, enrichedCall.Fields, "form.pwd"); got != wantGatewayField {
		t.Fatalf("late runtime event must be visible on a subsequent full graph query: got=%+v want=%+v", got, wantGatewayField)
	}
	if enrichedCall.Calls != baselineCall.Calls || enrichedCall.Calls != 1 || enrichedCall.Errors != baselineCall.Errors ||
		enrichedCall.AvgLatencyMS != baselineCall.AvgLatencyMS || enrichedCall.MaxLatencyMS != baselineCall.MaxLatencyMS ||
		enrichedCall.EvidenceType != baselineCall.EvidenceType || enrichedCall.Confidence != baselineCall.Confidence {
		t.Fatalf("runtime enrichment changed real call metrics or evidence: before=%+v after=%+v", baselineCall, enrichedCall)
	}
	for _, edge := range enrichedGraph.Edges {
		if edge.ID == callEdgeID {
			continue
		}
		for _, field := range edge.Fields {
			if field.Path == "form.pwd" || field.DataType == "CREDENTIAL" {
				t.Fatalf("same-trace different endpoint or unmatched runtime event was incorrectly enriched: %+v", edge)
			}
		}
	}
	for _, body := range [][]byte{credentialGraphBody, enrichedGraphBody} {
		if bytes.Contains(body, []byte("13800138000")) || bytes.Contains(body, []byte("body_base64")) {
			t.Fatalf("runtime graph leaked a raw value or body: %s", body)
		}
	}

	resp = env.get(t, "/api/v1/api-security/data-flow/evidence?edge_id="+callEdgeID+"&application_id="+applicationID.String()+"&data_type=CREDENTIAL", cookies)
	runtimeEvidenceBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("runtime evidence status=%d body=%s", resp.StatusCode, runtimeEvidenceBody)
	}
	var runtimeEvidenceEnvelope struct {
		Data struct {
			Items []struct {
				EventID      string                  `json:"event_id"`
				TraceID      string                  `json:"trace_id"`
				Fields       []cloudAPIDataFlowField `json:"fields"`
				EvidenceType string                  `json:"evidence_type"`
				Confidence   float64                 `json:"confidence"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(runtimeEvidenceBody, &runtimeEvidenceEnvelope); err != nil {
		t.Fatal(err)
	}
	if len(runtimeEvidenceEnvelope.Data.Items) != 1 {
		t.Fatalf("CREDENTIAL evidence must select the existing paired contribution: %s", runtimeEvidenceBody)
	}
	runtimeEvidence := runtimeEvidenceEnvelope.Data.Items[0]
	if runtimeEvidence.EventID != "ev-cloud-0-client" || runtimeEvidence.TraceID != gatewayTraceID || runtimeEvidence.EvidenceType != baselineCall.EvidenceType || runtimeEvidence.Confidence != baselineCall.Confidence {
		t.Fatalf("runtime evidence changed or lost the real Observation association: %+v", runtimeEvidence)
	}
	if got := requireCloudAPIDataFlowField(t, runtimeEvidence.Fields, "form.pwd"); got != wantGatewayField {
		t.Fatalf("graph/evidence gateway field mismatch: evidence=%+v graph=%+v", got, wantGatewayField)
	}
	if bytes.Contains(runtimeEvidenceBody, []byte("13800138000")) || bytes.Contains(runtimeEvidenceBody, []byte("body_base64")) {
		t.Fatalf("runtime evidence leaked a raw value or body: %s", runtimeEvidenceBody)
	}

	type boundaryEdge struct {
		ID               string `json:"id"`
		SourceID         string `json:"source_id"`
		TargetID         string `json:"target_id"`
		SourceName       string `json:"source_name"`
		TargetName       string `json:"target_name"`
		SourceZone       string `json:"source_zone"`
		TargetZone       string `json:"target_zone"`
		BoundaryType     string `json:"boundary_type"`
		BoundaryEvidence string `json:"boundary_evidence"`
		Protocol         string `json:"protocol"`
		Calls            uint64 `json:"calls"`
	}
	var boundaryView string
	var boundaryEdges []boundaryEdge
	boundaryDeadline := time.Now().Add(15 * time.Second)
	for {
		resp := env.get(t, "/api/v1/api-security/data-flow/graph?max_edges=50&view=boundary&application_id="+applicationID.String(), cookies)
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("boundary graph status=%d body=%s", resp.StatusCode, data)
		}
		var envelope struct {
			Data struct {
				View  string         `json:"view"`
				Edges []boundaryEdge `json:"edges"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		boundaryView = envelope.Data.View
		boundaryEdges = envelope.Data.Edges
		if len(boundaryEdges) >= 2 || time.Now().After(boundaryDeadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if boundaryView != "boundary" || len(boundaryEdges) != 2 {
		t.Fatalf("expected exactly 2 boundary relations, view=%q graph=%+v", boundaryView, boundaryEdges)
	}
	var publicEdge, unknownEdge *boundaryEdge
	for i := range boundaryEdges {
		edge := &boundaryEdges[i]
		if edge.TargetID != "service:profile" || edge.TargetName != "profile" || edge.Protocol != "HTTP" || edge.Calls != 1 {
			t.Fatalf("unexpected boundary target or duplicate count: %+v", edge)
		}
		switch edge.SourceName {
		case "8.8.8.8":
			publicEdge = edge
		case "1.1.1.1":
			unknownEdge = edge
		default:
			t.Fatalf("unexpected boundary source: %+v", edge)
		}
	}
	if publicEdge == nil || publicEdge.SourceID != "client:8.8.8.8" || publicEdge.SourceZone != "PUBLIC" || publicEdge.TargetZone != "INTERNAL" || publicEdge.BoundaryType != "PUBLIC_TO_INTERNAL" || publicEdge.BoundaryEvidence != "DIRECT_PEER" {
		t.Fatalf("direct public peer did not form PUBLIC_TO_INTERNAL: %+v", publicEdge)
	}
	if unknownEdge == nil || unknownEdge.SourceID != "client:1.1.1.1" || unknownEdge.SourceZone != "UNKNOWN" || unknownEdge.TargetZone != "INTERNAL" || unknownEdge.BoundaryType != "UNKNOWN" || unknownEdge.BoundaryEvidence != "UNTRUSTED_CLIENT_SOURCE" {
		t.Fatalf("unknown client source was promoted to a certain boundary: %+v", unknownEdge)
	}

	type boundaryEvidenceRecord struct {
		EventID             string `json:"event_id"`
		ServiceName         string `json:"service_name"`
		TraceID             string `json:"trace_id"`
		PeerAddress         string `json:"peer_address"`
		ClientAddress       string `json:"client_address"`
		ClientAddressSource string `json:"client_address_source"`
		ServerAddress       string `json:"server_address"`
		SourceZone          string `json:"source_zone"`
		TargetZone          string `json:"target_zone"`
		BoundaryType        string `json:"boundary_type"`
		BoundaryEvidence    string `json:"boundary_evidence"`
		EvidenceType        string `json:"evidence_type"`
		Fields              []struct {
			Side      string `json:"side"`
			Path      string `json:"path"`
			DataType  string `json:"data_type"`
			ValueHMAC string `json:"value_hmac"`
		} `json:"fields"`
	}
	readBoundaryEvidence := func(edgeID string) (boundaryEvidenceRecord, []byte) {
		resp := env.get(t, "/api/v1/api-security/data-flow/evidence?view=boundary&application_id="+applicationID.String()+"&edge_id="+edgeID, cookies)
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("boundary evidence status=%d body=%s", resp.StatusCode, data)
		}
		var envelope struct {
			Data struct {
				Items []boundaryEvidenceRecord `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		if len(envelope.Data.Items) != 1 {
			t.Fatalf("expected one boundary evidence record for %s: %s", edgeID, data)
		}
		return envelope.Data.Items[0], data
	}
	for _, expected := range []struct {
		edge          *boundaryEdge
		eventID       string
		traceID       string
		address       string
		addressSource string
	}{
		{publicEdge, "ev-cloud-boundary-public", "dddddddddddddddddddddddddddddddd", "8.8.8.8", "DIRECT_PEER"},
		{unknownEdge, "ev-cloud-boundary-unknown", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "1.1.1.1", "UNKNOWN"},
	} {
		record, body := readBoundaryEvidence(expected.edge.ID)
		if record.EventID != expected.eventID || record.ServiceName != "profile" || record.TraceID != expected.traceID ||
			record.PeerAddress != expected.address || record.ClientAddress != expected.address || record.ClientAddressSource != expected.addressSource ||
			record.ServerAddress != "10.20.0.30" || record.SourceZone != expected.edge.SourceZone || record.TargetZone != "INTERNAL" ||
			record.BoundaryType != expected.edge.BoundaryType || record.BoundaryEvidence != expected.edge.BoundaryEvidence || record.EvidenceType != "OBSERVED_SERVER" {
			t.Fatalf("unexpected boundary evidence for %s: %+v", expected.address, record)
		}
		wantHMAC := "hmac-sha256:" + strings.Repeat(expected.traceID[:1], 64)
		if len(record.Fields) != 1 || record.Fields[0].Side != "REQUEST" || record.Fields[0].Path != "$.mobile" || record.Fields[0].DataType != "PHONE" || record.Fields[0].ValueHMAC != wantHMAC {
			t.Fatalf("boundary request field was not preserved as redacted evidence: %+v", record.Fields)
		}
		if bytes.Contains(body, []byte("13800138000")) || bytes.Contains(body, []byte("body_base64")) {
			t.Fatalf("boundary evidence leaked a raw value or body: %s", body)
		}
	}

	if os.Getenv("WDSP_DATA_FLOW_BROWSER_E2E") == "1" {
		runCloudAPIDataFlowBrowser(t, env, applicationID, username, password)
	}
}

type cloudAPIDataFlowField struct {
	Side      string `json:"side"`
	Path      string `json:"path"`
	DataType  string `json:"data_type"`
	ValueHMAC string `json:"value_hmac"`
	HMACKeyID string `json:"hmac_key_id"`
	Match     string `json:"match"`
}

type cloudAPIDataFlowEdge struct {
	ID           string                  `json:"id"`
	SourceName   string                  `json:"source_name"`
	TargetName   string                  `json:"target_name"`
	Calls        uint64                  `json:"calls"`
	Errors       uint64                  `json:"errors"`
	AvgLatencyMS float64                 `json:"avg_latency_ms"`
	MaxLatencyMS int64                   `json:"max_latency_ms"`
	DataTypes    []string                `json:"data_types"`
	Fields       []cloudAPIDataFlowField `json:"fields"`
	EvidenceType string                  `json:"evidence_type"`
	Confidence   float64                 `json:"confidence"`
}

type cloudAPIDataFlowGraph struct {
	Edges     []cloudAPIDataFlowEdge `json:"edges"`
	Truncated bool                   `json:"truncated"`
}

func readCloudAPIDataFlowGraph(t *testing.T, env *testEnv, cookies []*http.Cookie, query string) (cloudAPIDataFlowGraph, []byte) {
	t.Helper()
	resp := env.get(t, "/api/v1/api-security/data-flow/graph?"+query, cookies)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("graph status=%d body=%s", resp.StatusCode, body)
	}
	var envelope struct {
		Data cloudAPIDataFlowGraph `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode graph: %v body=%s", err, body)
	}
	return envelope.Data, body
}

func requireCloudAPIDataFlowEdge(t *testing.T, graph cloudAPIDataFlowGraph, source, target string) cloudAPIDataFlowEdge {
	t.Helper()
	for _, edge := range graph.Edges {
		if edge.SourceName == source && edge.TargetName == target {
			return edge
		}
	}
	t.Fatalf("missing real data-flow edge %s -> %s: %+v", source, target, graph.Edges)
	return cloudAPIDataFlowEdge{}
}

func requireCloudAPIDataFlowField(t *testing.T, fields []cloudAPIDataFlowField, path string) cloudAPIDataFlowField {
	t.Helper()
	found := -1
	for i, field := range fields {
		if field.Path != path {
			continue
		}
		if found >= 0 {
			t.Fatalf("duplicate enriched field %q: %+v", path, fields)
		}
		found = i
	}
	if found < 0 {
		t.Fatalf("missing enriched field %q: %+v", path, fields)
	}
	return fields[found]
}

func cloudAPIDataFlowHasType(types []string, want string) bool {
	for _, typ := range types {
		if typ == want {
			return true
		}
	}
	return false
}

func cloudAPIDataFlowRuntimeEvent(requestID, traceID string, applicationID uuid.UUID, endpointKey, normalizedPath string) map[string]interface{} {
	return map[string]interface{}{
		"request_id":      requestID,
		"occurred_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"application_id":  applicationID.String(),
		"trace_id":        traceID,
		"endpoint_key":    endpointKey,
		"method":          "POST",
		"path_template":   normalizedPath,
		"raw_path":        normalizedPath,
		"is_api":          true,
		"api_confidence":  1,
		"risk_score":      10,
		"risk_level":      "LOW",
		"final_action":    "OBSERVE",
		"response_status": http.StatusOK,
		"details": []map[string]interface{}{{
			"detector":    "sensitive_data",
			"rule_id":     "sensitive.field",
			"category":    "OBSERVE",
			"severity":    "MEDIUM",
			"score_delta": 10,
			"evidence": map[string]string{
				"field":     "pwd",
				"location":  "form",
				"direction": "REQUEST",
				"data_type": "credential",
			},
		}},
	}
}

func persistCloudAPIDataFlowRuntimeEvents(t *testing.T, env *testEnv, records []map[string]interface{}) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.jsonl")
	var lines bytes.Buffer
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		lines.Write(line)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, lines.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := apiruntime.NewCollector(apiruntime.NewStore(env.db), "cloud-dataflow-runtime-test", logPath, filepath.Join(dir, "checkpoint"), "gw-cloud-dataflow-test")
	processed, err := collector.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("collect real gateway runtime events: %v", err)
	}
	if processed != len(records) {
		t.Fatalf("runtime events processed=%d want=%d", processed, len(records))
	}
}

func cloudObservationBatch(bindings map[string]uuid.UUID) map[string]interface{} {
	bindingVersion := int64(1)
	base := func(eventID, traceID, service, direction, target, path string) map[string]interface{} {
		requestHMAC := "hmac-sha256:" + strings.Repeat(string(traceID[0]), 64)
		return map[string]interface{}{
			"event_id": eventID, "occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
			"application_binding_id": bindings[service].String(), "binding_version": bindingVersion,
			"source":  map[string]interface{}{"type": "IN_PROCESS", "language": "java", "framework": "spring-webmvc", "agent_version": "1.0.0", "source_epoch": 1},
			"service": map[string]interface{}{"name": service, "instance_id": service + "-1", "version": "1.0.0", "environment": "prod", "namespace": "shop", "cluster": "cloud-a"},
			"trace":   map[string]interface{}{"trace_id": traceID, "span_id": strings.Repeat(string(traceID[0]), 16), "parent_span_id": ""},
			"http":    map[string]interface{}{"direction": direction, "method": "POST", "scheme": "https", "host": target, "route": path, "path_template": path, "status": 200, "latency_ms": 12, "request_content_type": "application/json", "response_content_type": "application/json", "peer_service": target},
			"fields":  []map[string]interface{}{{"side": "REQUEST", "location": "JSON_BODY", "path": "$.mobile", "data_type": "PHONE", "level": "L3", "value_hmac": requestHMAC, "hmac_key_id": "key-1", "value_present": true, "truncated": false}},
			"quality": map[string]interface{}{"route_source": "FRAMEWORK", "request_body_state": "ANALYZED", "response_body_state": "ANALYZED", "capture_sampled": true, "truncated": false},
		}
	}
	pairs := []struct {
		source, target, path, traceID, spanID string
	}{
		{"orders", "profile", "/profiles/{id}", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa"},
		{"profile", "identity", "/identity/verify", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"},
		{"orders", "identity", "/identity/profile", "cccccccccccccccccccccccccccccccc", "cccccccccccccccc"},
	}
	records := []map[string]interface{}{}
	for i, pair := range pairs {
		client := base(fmt.Sprintf("ev-cloud-%d-client", i), pair.traceID, pair.source, "CLIENT", pair.target, pair.path)
		server := base(fmt.Sprintf("ev-cloud-%d-server", i), pair.traceID, pair.target, "SERVER", pair.target, pair.path)
		client["trace"].(map[string]interface{})["span_id"] = pair.spanID
		serverTrace := server["trace"].(map[string]interface{})
		serverTrace["span_id"] = fmt.Sprintf("%016x", i+16)
		serverTrace["parent_span_id"] = pair.spanID
		server["http"].(map[string]interface{})["host"] = "10.20.0.30"
		server["fields"] = []map[string]interface{}{
			{"side": "REQUEST", "location": "JSON_BODY", "path": "$.mobile", "data_type": "PHONE", "level": "L3", "value_hmac": "hmac-sha256:" + strings.Repeat(string(pair.traceID[0]), 64), "hmac_key_id": "key-1", "value_present": true, "truncated": false},
			{"side": "RESPONSE", "location": "JSON_BODY", "path": "$.identity_no", "data_type": "CN_ID", "level": "L4", "value_hmac": "hmac-sha256:" + strings.Repeat(string(pair.traceID[0]+1), 64), "hmac_key_id": "key-1", "value_present": true, "truncated": false},
		}
		records = append(records, client, server)
	}
	for _, source := range []struct {
		eventID       string
		traceID       string
		address       string
		addressSource string
	}{
		{"ev-cloud-boundary-public", "dddddddddddddddddddddddddddddddd", "8.8.8.8", "DIRECT_PEER"},
		{"ev-cloud-boundary-unknown", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "1.1.1.1", "UNKNOWN"},
	} {
		record := base(source.eventID, source.traceID, "profile", "SERVER", "profile", "/profiles/external")
		http := record["http"].(map[string]interface{})
		http["host"] = "10.20.0.30"
		http["peer_service"] = ""
		http["peer_address"] = source.address
		http["client_address"] = source.address
		http["client_address_source"] = source.addressSource
		http["server_address"] = "10.20.0.30"
		records = append(records, record)
	}
	return map[string]interface{}{"schema_version": 1, "records": records}
}
