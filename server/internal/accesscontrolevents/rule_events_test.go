package accesscontrolevents

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBuildWhereAccessRuleID 规则过滤条件进入 WHERE 与参数列表。
func TestBuildWhereAccessRuleID(t *testing.T) {
	ruleID := "770e8400-e29b-41d4-a716-446655440000"
	where, args := buildWhere(ListFilter{AccessRuleID: ruleID})
	if !strings.Contains(where, "access_rule_id = $1") {
		t.Errorf("where = %q，期望含 access_rule_id = $1", where)
	}
	if len(args) != 1 || args[0] != ruleID {
		t.Errorf("args = %v，期望 [%s]", args, ruleID)
	}

	// 空 AccessRuleID 不产生条件（不破坏现有查询）
	where, args = buildWhere(ListFilter{ClientIP: "203.0.113.66"})
	if strings.Contains(where, "access_rule_id") {
		t.Errorf("空 AccessRuleID 不应产生条件，where = %q", where)
	}
	if len(args) != 1 {
		t.Errorf("args = %v，期望仅 client_ip 一个参数", args)
	}
}

// TestListByRuleInvalidID 非法规则 ID → 400（不触库）。
func TestListByRuleInvalidID(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/access-rules/not-a-uuid/events", nil)
	req.SetPathValue("id", "not-a-uuid")
	rec := httptest.NewRecorder()
	h.ListByRule(rec, req)
	if rec.Code != 400 {
		t.Fatalf("status = %d，期望 400，body: %s", rec.Code, rec.Body.String())
	}
}

// TestListByRuleInvalidFilter 规则 ID 合法但筛选参数非法 → 400（不触库）。
func TestListByRuleInvalidFilter(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("GET",
		"/api/v1/access-rules/770e8400-e29b-41d4-a716-446655440000/events?start_time=bad", nil)
	req.SetPathValue("id", "770e8400-e29b-41d4-a716-446655440000")
	rec := httptest.NewRecorder()
	h.ListByRule(rec, req)
	if rec.Code != 400 {
		t.Fatalf("status = %d，期望 400，body: %s", rec.Code, rec.Body.String())
	}
}
