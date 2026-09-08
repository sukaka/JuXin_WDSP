package audits

import (
	"strings"
	"testing"
	"time"
)

// TestSyslogSeverityHint 删除/禁用类操作 → warning，其余 → info（空提示）。
func TestSyslogSeverityHint(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"delete", "warning"},
		{"delete_template", "warning"},
		{"disable", "warning"},
		{"DISABLE", "warning"},
		{"create", ""},
		{"update", ""},
		{"enable", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := syslogSeverityHint(c.action); got != c.want {
			t.Errorf("syslogSeverityHint(%q) = %q, want %q", c.action, got, c.want)
		}
	}
}

// TestSyslogPayloadMasked 外发 payload 复用脱敏后摘要，且不遗漏关键字段。
func TestSyslogPayloadMasked(t *testing.T) {
	in := RecordInput{
		Username:   "admin",
		Module:     "users",
		Action:     "update",
		ObjectType: "user",
		ObjectID:   "u1",
		Result:     ResultSuccess,
		RiskLevel:  RiskMedium,
		RequestID:  "req-1",
	}
	before := MaskSensitiveJSON(`{"username":"admin","password":"secret123"}`)
	after := MaskSensitiveJSON(`{"display_name":"管理员"}`)
	ts := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)

	p := syslogPayload(in, ts, before, after, "hash1")
	if got := p["before_summary"].(string); strings.Contains(got, "secret123") {
		t.Errorf("payload 泄露敏感字段: %s", got)
	}
	if p["username"] != "admin" || p["module"] != "users" || p["action"] != "update" ||
		p["record_hash"] != "hash1" || p["request_id"] != "req-1" {
		t.Errorf("payload 字段缺失: %v", p)
	}
	if p["occurred_at"] != "2026-08-17T10:00:00Z" {
		t.Errorf("occurred_at 格式错误: %v", p["occurred_at"])
	}
}

// TestEnqueueSyslogNilSafe 未注入投递函数时安全跳过。
func TestEnqueueSyslogNilSafe(t *testing.T) {
	s := &Service{}
	s.enqueueSyslog("warning", map[string]interface{}{"k": "v"}) // 不应 panic
}

// TestEnqueueSyslogDelivers 注入投递函数时按提示与 payload 投递。
func TestEnqueueSyslogDelivers(t *testing.T) {
	var gotHint string
	var gotPayload interface{}
	calls := 0
	s := &Service{}
	s.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		calls++
		gotHint = severityHint
		gotPayload = payload
	})
	s.enqueueSyslog("warning", map[string]interface{}{"action": "delete"})
	if calls != 1 || gotHint != "warning" {
		t.Fatalf("投递次数/提示错误: calls=%d hint=%q", calls, gotHint)
	}
	if gotPayload.(map[string]interface{})["action"] != "delete" {
		t.Errorf("payload 错误: %v", gotPayload)
	}
}

// TestEnqueueSyslogPanicTolerated 投递函数 panic 不扩散到主流程。
func TestEnqueueSyslogPanicTolerated(t *testing.T) {
	s := &Service{}
	s.SetSyslogForwarder(func(string, interface{}) { panic("boom") })
	s.enqueueSyslog("", map[string]interface{}{}) // 不应 panic
}
