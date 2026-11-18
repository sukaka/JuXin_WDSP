package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
)

func TestRequestAuditAccessLogsEndToEnd(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	env.importBaseLicense(t)
	username := "audit_" + s5Rand()
	password := "S5@Test2026!"
	env.createUserDirect(t, username, password, "SECURITY_ADMIN")
	cookies, _ := env.login(t, username, password)

	applicationID := uuid.New()
	traceID := "0123456789abcdef0123456789abcdef"
	ttfb := int64(42)
	now := time.Now().UTC()
	store := accesslogs.NewStore(env.db)
	for _, entry := range []accesslogs.LogEntry{
		{
			OccurredAt: now.Add(-10 * time.Minute), RequestID: "req-audit-1", ApplicationID: applicationID.String(),
			Domain: "shop.internal", GatewayNodeID: "gw-audit", ClientIP: "192.0.2.10",
			RequestMethod: "POST", RequestURI: "/v1/login", RequestPath: "/v1/login", ResponseStatus: 200,
			DurationMS: 58, WAFAction: "ALLOW", TraceID: traceID, SpanID: "0123456789abcdef",
			EndpointKey: "POST /v1/login", PathTemplate: "/v1/login", TTFBMs: &ttfb,
			RequestHeaders: map[string][]string{"Authorization": {"masked"}}, RequestBody: "pwd=masked",
			ResponseHeaders: map[string][]string{},
		},
		{
			OccurredAt: now.Add(-5 * time.Minute), RequestID: "req-audit-2", ApplicationID: applicationID.String(),
			Domain: "shop.internal", GatewayNodeID: "gw-audit", ClientIP: "192.0.2.11",
			RequestMethod: "GET", RequestURI: "/health", RequestPath: "/health", ResponseStatus: 500,
			DurationMS: 12, WAFAction: "BLOCK", TraceID: "abcdef0123456789abcdef0123456789",
			RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{},
		},
	} {
		inserted, err := store.Insert(context.Background(), &entry)
		if err != nil || !inserted {
			t.Fatalf("insert real access log: inserted=%v err=%v", inserted, err)
		}
	}
	runtimeEvent := cloudAPIDataFlowRuntimeEvent("req-audit-1", traceID, applicationID, "POST /v1/login", "/v1/login")
	runtimeEvent["identity_fingerprint"] = "identity-hmac-audit-1"
	persistCloudAPIDataFlowRuntimeEvents(t, env, []map[string]interface{}{runtimeEvent})

	start := now.Add(-time.Hour).Format(time.RFC3339)
	end := now.Add(time.Hour).Format(time.RFC3339)
	filter := "application_id=" + applicationID.String() + "&trace_id=" + traceID +
		"&identity_fingerprint=identity-hmac-audit-1&rule_id=sensitive.field&start_time=" + start + "&end_time=" + end
	resp := env.get(t, "/api/v1/access-logs?"+filter, cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	var list struct {
		Data struct {
			Items []struct {
				ID        string `json:"id"`
				RequestID string `json:"request_id"`
			} `json:"items"`
			Total int `json:"total"`
		} `json:"data"`
	}
	decodeRequestAuditResponse(t, resp, &list)
	if list.Data.Total != 1 || len(list.Data.Items) != 1 || list.Data.Items[0].RequestID != "req-audit-1" {
		t.Fatalf("unexpected combined audit filter result: %+v", list.Data)
	}
	logID := uuid.MustParse(list.Data.Items[0].ID)
	stored, err := store.GetByID(context.Background(), logID)
	if err != nil {
		t.Fatalf("read real access log detail from store: %v", err)
	}
	if stored.TraceID != traceID || stored.TTFBMs == nil || *stored.TTFBMs != ttfb {
		t.Fatalf("store lost detail fields: %+v", stored)
	}

	resp = env.get(t, "/api/v1/access-logs/"+list.Data.Items[0].ID, cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	var detail struct {
		Data accesslogs.AccessLog `json:"data"`
	}
	decodeRequestAuditResponse(t, resp, &detail)
	if detail.Data.TraceID != traceID || detail.Data.SpanID != "0123456789abcdef" ||
		detail.Data.EndpointKey != "POST /v1/login" || detail.Data.TTFBMs == nil || *detail.Data.TTFBMs != ttfb {
		t.Fatalf("detail lost real Trace/endpoint/TTFB: %+v", detail.Data)
	}
	if detail.Data.RequestBody != "pwd=masked" || detail.Data.RequestHeaders["Authorization"][0] != "masked" {
		t.Fatalf("detail did not retain the already-masked HTTP evidence: %+v", detail.Data)
	}

	resp = env.get(t, "/api/v1/access-logs/trend?start_time="+start+"&end_time="+end+"&bucket_seconds=900&application_id="+applicationID.String(), cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	var trend struct {
		Data struct {
			Items []accesslogs.TrendPoint `json:"items"`
		} `json:"data"`
	}
	decodeRequestAuditResponse(t, resp, &trend)
	var total, blocked, errors int64
	for _, point := range trend.Data.Items {
		total += point.Total
		blocked += point.Blocked
		errors += point.Errors
	}
	if total != 2 || blocked != 1 || errors != 1 {
		t.Fatalf("trend must aggregate real logs: total=%d blocked=%d errors=%d items=%+v", total, blocked, errors, trend.Data.Items)
	}

	resp = env.get(t, "/api/v1/access-logs/trend?start_time="+start+"&end_time="+end+"&bucket_seconds=900&rule_id=sensitive.field", cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	decodeRequestAuditResponse(t, resp, &trend)
	if len(trend.Data.Items) != 1 || trend.Data.Items[0].Total != 1 || trend.Data.Items[0].Blocked != 0 || trend.Data.Items[0].Errors != 0 {
		t.Fatalf("trend did not reuse the rule filter: %+v", trend.Data.Items)
	}

	resp = env.get(t, "/api/v1/access-logs/export?"+filter, cookies)
	assertRequestAuditStatus(t, resp, http.StatusOK)
	csvBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csvBody), "req-audit-1") || strings.Contains(string(csvBody), "req-audit-2") {
		t.Fatalf("export did not preserve combined filters: %s", csvBody)
	}

	for _, invalid := range []string{"application_id=bad", "trace_id=00000000000000000000000000000000", "status=99"} {
		resp = env.get(t, "/api/v1/access-logs?"+invalid, cookies)
		assertRequestAuditStatus(t, resp, http.StatusBadRequest)
		resp.Body.Close()
	}

	auditUsername := "audit_read_" + s5Rand()
	env.createUserDirect(t, auditUsername, password, "AUDIT_ADMIN")
	auditCookies, _ := env.login(t, auditUsername, password)
	for _, path := range []string{"/api/v1/access-logs", "/api/v1/access-logs/trend"} {
		resp = env.get(t, path, auditCookies)
		assertRequestAuditStatus(t, resp, http.StatusForbidden)
		resp.Body.Close()
	}
	runRequestAuditBrowser(t, env, username, password)
}

func decodeRequestAuditResponse(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatalf("decode request audit response: %v", err)
	}
}

func assertRequestAuditStatus(t *testing.T, resp *http.Response, wanted int) {
	t.Helper()
	if resp.StatusCode == wanted {
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, wanted, body)
}
