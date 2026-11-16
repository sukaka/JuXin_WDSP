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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	agentmodel "github.com/jiuzhang-waf/server/internal/agents"
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
		source, target, path, traceID string
	}{
		{"orders", "profile", "/profiles/{id}", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"profile", "identity", "/identity/verify", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"orders", "identity", "/identity/profile", "cccccccccccccccccccccccccccccccc"},
	}
	records := []map[string]interface{}{}
	for i, pair := range pairs {
		client := base(fmt.Sprintf("ev-cloud-%d-client", i), pair.traceID, pair.source, "CLIENT", pair.target, pair.path)
		server := base(fmt.Sprintf("ev-cloud-%d-server", i), pair.traceID, pair.target, "SERVER", pair.target, pair.path)
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
