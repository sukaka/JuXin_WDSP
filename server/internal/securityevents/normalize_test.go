package securityevents

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleAudit = `{"transaction":{"timestamp":"2026/07/21 10:00:00","unix_timestamp":1784568800000000000,"id":"tx999","client_ip":"192.0.2.10","client_port":51234,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/search?q=1'%20OR%20'1'='1&password=hunter2&token=abc123","headers":{"host":["waf.test"],"user-agent":["sqlmap/1.5"],"x-request-id":["req-abc-123"],"cookie":["session=xyz"],"authorization":["Bearer secret"]}},"response":{"status":0},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.28.0"]},"is_interrupted":true},"messages":[{"error_message":"[client \"192.0.2.10\"] Coraza: Warning. SQL Injection [id \"942100\"] [msg \"SQL Injection Attack\"] [data \"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1\"] [severity \"critical\"] [tag \"attack-sqli\"]"},{"error_message":"[id \"949110\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 8)\"]"}]}`

func TestParseAuditLineValid(t *testing.T) {
	evt, err := ParseAuditLine([]byte(sampleAudit), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt.RequestID != "req-abc-123" {
		t.Errorf("request_id = %q", evt.RequestID)
	}
	if evt.ClientIP != "192.0.2.10" {
		t.Errorf("client_ip = %q", evt.ClientIP)
	}
	if evt.AttackType != "SQL_INJECTION" {
		t.Errorf("attack_type = %q", evt.AttackType)
	}
	if evt.Severity != "HIGH" {
		t.Errorf("severity = %q", evt.Severity)
	}
	if evt.AnomalyScore != 8 {
		t.Errorf("anomaly_score = %d, want 8", evt.AnomalyScore)
	}
	if evt.Action != "BLOCK" {
		t.Errorf("action = %q, want BLOCK", evt.Action)
	}
	if evt.ResponseStatus != 403 {
		t.Errorf("response_status = %d, want 403", evt.ResponseStatus)
	}
	if len(evt.Matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(evt.Matches))
	}
	if evt.Matches[0].RuleID != 942100 {
		t.Errorf("match rule_id = %d", evt.Matches[0].RuleID)
	}
}

func TestParseAuditLineMasking(t *testing.T) {
	evt, err := ParseAuditLine([]byte(sampleAudit), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	// 敏感参数必须脱敏
	if strings.Contains(evt.URI, "hunter2") || strings.Contains(evt.URI, "abc123") {
		t.Errorf("URI leaks sensitive params: %s", evt.URI)
	}
	if strings.Contains(evt.QuerySummary, "hunter2") || strings.Contains(evt.QuerySummary, "abc123") {
		t.Errorf("QuerySummary leaks sensitive params: %s", evt.QuerySummary)
	}
	// 不含 Authorization/Cookie 值
	evtJSON := toJSON(evt)
	if strings.Contains(evtJSON, "secret") || strings.Contains(evtJSON, "session=xyz") {
		t.Errorf("event leaks sensitive headers: %s", evtJSON)
	}
}

func TestParseAuditLineObserve(t *testing.T) {
	line := strings.Replace(sampleAudit, `"is_interrupted":true`, `"is_interrupted":false`, 1)
	evt, err := ParseAuditLine([]byte(line), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt.Action != "OBSERVE" {
		t.Errorf("action = %q, want OBSERVE", evt.Action)
	}
}

func TestParseAuditLineInvalid(t *testing.T) {
	if _, err := ParseAuditLine([]byte("{not json"), "node"); err == nil {
		t.Error("invalid json should fail")
	}
	if _, err := ParseAuditLine([]byte(""), "node"); err == nil {
		t.Error("empty line should fail")
	}
	if _, err := ParseAuditLine([]byte(`{"transaction":{},"messages":[]}`), "node"); err == nil {
		t.Error("missing tx id should fail")
	}
}

func TestMaskURI(t *testing.T) {
	cases := []struct{ in, wantNotContain string }{
		{"/p?password=x&a=1", "password=x"},
		{"/p?token=t123&b=2", "token=t123"},
	}
	for _, c := range cases {
		got := maskURI(c.in)
		if strings.Contains(got, c.wantNotContain) {
			t.Errorf("maskURI(%q) = %q, still contains %q", c.in, got, c.wantNotContain)
		}
		if !strings.Contains(got, "masked") {
			t.Errorf("maskURI(%q) = %q, no mask applied", c.in, got)
		}
	}
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonString(v interface{}) string { return toJSON(v) }

var _ = jsonString
