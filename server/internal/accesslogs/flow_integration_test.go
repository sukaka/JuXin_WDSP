package accesslogs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestFlowRealRequestFieldAggregationAndDrill(t *testing.T) {
	dsn := os.Getenv("ACCESSLOGS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ACCESSLOGS_TEST_PG_DSN not set, skipping real audit flow test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatal(err)
	}
	appID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO applications(id,code,name) VALUES($1,'flow-shop','订单系统')`, appID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store := NewStore(pool)
	entries := []LogEntry{
		{OccurredAt: now.Add(-3 * time.Minute), RequestID: "flow-req-1", ApplicationID: appID.String(), Domain: "shop.internal", ClientIP: "192.0.2.10", RequestMethod: "POST", RequestURI: "/v1/login", RequestPath: "/v1/login", EndpointKey: "POST /v1/login", PathTemplate: "/v1/login", RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}},
		{OccurredAt: now.Add(-2 * time.Minute), RequestID: "flow-req-2", ApplicationID: appID.String(), Domain: "shop.internal", ClientIP: "192.0.2.10", RequestMethod: "POST", RequestURI: "/v1/login", RequestPath: "/v1/login", EndpointKey: "POST /v1/login", PathTemplate: "/v1/login", RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}},
		{OccurredAt: now.Add(-time.Minute), RequestID: "flow-req-3", Domain: "health.internal", ClientIP: "192.0.2.11", RequestMethod: "GET", RequestURI: "/health", RequestPath: "/health", EndpointKey: "GET /health", PathTemplate: "/health", RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}},
	}
	for i := range entries {
		if _, err := store.Insert(ctx, &entries[i]); err != nil {
			t.Fatal(err)
		}
	}
	details := []map[string]interface{}{
		{"detector": "sensitive_data", "rule_id": "sensitive.field", "evidence": map[string]string{"field": "pwd", "location": "form", "direction": "REQUEST", "data_type": "credential", "value": "never-render-this-value"}},
		{"detector": "sensitive_data", "rule_id": "sensitive.response_value", "evidence": map[string]string{"field": "id_card", "location": "json", "direction": "RESPONSE", "data_type": "id_card"}},
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	for _, requestID := range []string{"flow-req-1", "flow-req-2"} {
		eventDetails := encoded
		if requestID == "flow-req-2" {
			eventDetails, _ = json.Marshal(details[:1])
		}
		if _, err := pool.Exec(ctx, `INSERT INTO api_runtime_events(request_id,endpoint_key,identity_fingerprint,jwt_verification,details_json,occurred_at)
			VALUES($1,'POST /v1/login','identity-hmac-flow','{"status":"VERIFIED"}',$2,$3)`, requestID, eventDetails, now); err != nil {
			t.Fatal(err)
		}
	}
	filter := ListFilter{StartTime: timePointer(now.Add(-time.Hour)), EndTime: timePointer(now.Add(time.Hour))}
	flow, err := store.Flow(ctx, filter, 8)
	if err != nil {
		t.Fatal(err)
	}
	if flow.RequestCount != 3 || flow.SensitiveRequestCount != 2 || flow.Truncated {
		t.Fatalf("unexpected real flow totals: %+v", flow)
	}
	var requestField, responseField, account FlowNode
	for _, node := range flow.Nodes {
		switch {
		case node.Kind == "REQUEST_FIELD" && strings.HasPrefix(node.Name, "form.pwd"):
			requestField = node
		case node.Kind == "RESPONSE_FIELD" && strings.HasPrefix(node.Name, "json.id_card"):
			responseField = node
		case node.Kind == "ACCOUNT":
			account = node
		}
		if strings.Contains(node.Name, "never-render-this-value") {
			t.Fatal("sensitive field value leaked into node")
		}
	}
	if requestField.RequestCount != 2 || requestField.FieldHits != 2 || responseField.RequestCount != 1 || responseField.FieldHits != 1 || !account.Verified || account.RequestCount != 2 {
		t.Fatalf("field or account aggregation incorrect: request=%+v response=%+v account=%+v", requestField, responseField, account)
	}
	for _, edge := range flow.Edges {
		if strings.HasPrefix(edge.SourceID, "RESPONSE_FIELD:") {
			t.Fatal("response field was incorrectly treated as a reverse API call")
		}
	}
	list, total, err := store.List(ctx, ListFilter{FieldPath: "form.pwd", Direction: "REQUEST", DataType: "credential", RequestIDs: requestField.RequestIDs, Page: 1, PageSize: 20})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("field drill did not restore the same request set: total=%d len=%d err=%v", total, len(list), err)
	}
	encodedFlow, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedFlow), "never-render-this-value") {
		t.Fatal("raw field value leaked into flow JSON")
	}

	handler := NewHandler(store, nil)
	query := httptest.NewRequest(http.MethodGet, "/api/v1/access-logs/flow?start_time="+filter.StartTime.Format(time.RFC3339)+"&end_time="+filter.EndTime.Format(time.RFC3339)+"&field_path=form.pwd&direction=REQUEST", nil)
	response := httptest.NewRecorder()
	handler.Flow(response, query)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"request_count":2`) {
		t.Fatalf("real flow HTTP query failed: %d %s", response.Code, response.Body.String())
	}
	flow, err = store.Flow(ctx, filter, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range flow.Nodes {
		if node.Kind == "SOURCE" && node.Other && (node.RequestCount != 1 || node.AggregatedNodes != 1) {
			t.Fatalf("other bucket did not retain distinct requests: %+v", node)
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestAuditFlowFiltersRejectInvalidDimensions(t *testing.T) {
	for _, query := range []string{"direction=BACKWARD", "field_path=" + strings.Repeat("f", 513), "request_ids=a,a", "request_ids=a&request_id=b"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?"+query, nil)
		filter := ListFilter{}
		if err := validateAuditFilter(&filter, request.URL.Query()); err == nil {
			t.Fatalf("invalid audit flow filter accepted: %s", query)
		}
	}
	filter := ListFilter{FieldPath: "'; DROP TABLE access_logs;--", Direction: "REQUEST", DataType: "credential", RequestIDs: []string{"req-1"}}
	where, args := buildListWhere(filter)
	if strings.Contains(where, "DROP TABLE") || len(args) != 4 {
		t.Fatalf("field filters are not parameterized: %s args=%v", where, args)
	}
}
