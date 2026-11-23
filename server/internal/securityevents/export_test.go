package securityevents

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestParseListFilterAllFields(t *testing.T) {
	appID := uuid.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security-events/export?start_time=2026-11-01T00:00:00Z&end_time=2026-11-20T00:00:00Z"+
			"&application_id="+appID.String()+"&domain=api.example.com&client_ip=198.51.100.10"+
			"&uri=/v1/orders&method=POST&attack_type=SQLI&severity=HIGH&action=BLOCK"+
			"&disposition_status=CONFIRMED_ATTACK&request_id=req-123&gateway_node=gw-1&rule_id=942100", nil)
	f := parseListFilter(req)
	if f.StartTime == nil || f.EndTime == nil {
		t.Fatalf("start_time/end_time not parsed")
	}
	if f.ApplicationID == nil || *f.ApplicationID != appID {
		t.Fatalf("application_id = %v, want %s", f.ApplicationID, appID)
	}
	if f.Domain != "api.example.com" || f.ClientIP != "198.51.100.10" || f.URI != "/v1/orders" ||
		f.Method != "POST" || f.AttackType != "SQLI" || f.Severity != "HIGH" || f.Action != "BLOCK" ||
		f.DispositionStatus != "CONFIRMED_ATTACK" || f.RequestID != "req-123" || f.GatewayNode != "gw-1" {
		t.Fatalf("unexpected filter: %+v", f)
	}
	if f.RuleID == nil || *f.RuleID != 942100 {
		t.Fatalf("rule_id = %v, want 942100", f.RuleID)
	}
}

func TestBuildListWhereWithIDsAndAllFilters(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	ruleID := 942100
	where, args := buildListWhere(ListFilter{
		Domain:            "shop.example.com",
		ClientIP:          "198.51.100.8",
		URI:               "/login",
		Method:            "POST",
		AttackType:        "SQLI",
		Severity:          "CRITICAL",
		Action:            "BLOCK",
		DispositionStatus: "UNPROCESSED",
		RequestID:         "req-9",
		RuleID:            &ruleID,
		IDs:               []uuid.UUID{id1, id2},
	})
	for _, frag := range []string{
		"domain ILIKE", "client_ip =", "request_uri ILIKE", "request_method =",
		"attack_type =", "severity =", "action =", "disposition_status =",
		"request_id =", "security_event_matches", "id = ANY($11::uuid[])",
	} {
		if !strings.Contains(where, frag) {
			t.Fatalf("where missing %q: %s", frag, where)
		}
	}
	if len(args) != 11 {
		t.Fatalf("len(args) = %d, want 11", len(args))
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "secops"}
	for _, rawQuery := range []string{"ids=", "ids=bad-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/security-events/export?"+rawQuery, nil)
		req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400, body = %s", rawQuery, rr.Code, rr.Body.String())
		}
	}
}
