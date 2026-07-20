package eventparser

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleAuditLine = `{"transaction":{"timestamp":"2026/07/20 13:40:14","unix_timestamp":1784554814948331880,"id":"tx123","client_ip":"192.0.2.10","client_port":51234,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/echo?q=1'%20OR%20'1'='1&password=hunter2","headers":{"host":["waf.test"],"user-agent":["sqlmap/1.5"],"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"],"cookie":["session=abc123"],"authorization":["Bearer secret-token"]}},"response":{"status":0},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.28.0"]},"is_interrupted":true},"messages":[{"actionset":"","message":"","error_message":"[client \"192.0.2.10\"] Coraza: Warning. SQL Injection Attack Detected via libinjection [file \"/etc/caddy/rules/REQUEST-942.conf\"] [line \"9129\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [data \"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1\"] [severity \"critical\"] [tag \"attack-sqli\"] [tag \"paranoia-level/1\"] [unique_id \"tx123\"]","data":null},{"actionset":"","message":"","error_message":"[client \"192.0.2.10\"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 8) [id \"949110\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 8)\"] [severity \"unknown\"]","data":null}]}`

func testApp() ApplicationRef {
	return ApplicationRef{ID: "poc-app", Name: "测试应用", Domain: "waf.test"}
}

func TestParseLineValid(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLine), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}

	if evt.EventID == "" {
		t.Error("event_id empty")
	}
	if evt.RequestID != "612b408c-b8ad-4e78-acbe-10926c77ff22" {
		t.Errorf("request_id = %q, want injected x-request-id", evt.RequestID)
	}
	if evt.OccurredAt != "2026-07-20T13:40:14Z" {
		t.Errorf("occurred_at = %q", evt.OccurredAt)
	}
	if evt.Client.IP != "192.0.2.10" {
		t.Errorf("client.ip = %q", evt.Client.IP)
	}
	if evt.Security.AttackType != "SQL_INJECTION" {
		t.Errorf("attack_type = %q", evt.Security.AttackType)
	}
	if evt.Security.Severity != "HIGH" {
		t.Errorf("severity = %q", evt.Security.Severity)
	}
	if evt.Security.AnomalyScore != 8 {
		t.Errorf("anomaly_score = %d, want 8", evt.Security.AnomalyScore)
	}
	if evt.Security.Action != "BLOCK" {
		t.Errorf("action = %q, want BLOCK", evt.Security.Action)
	}
	if evt.Security.StatusCode != 403 {
		t.Errorf("status_code = %d, want 403", evt.Security.StatusCode)
	}
	if len(evt.Security.Matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(evt.Security.Matches))
	}
	m0 := evt.Security.Matches[0]
	if m0.RuleID != "942100" {
		t.Errorf("match rule_id = %q", m0.RuleID)
	}
	if m0.MatchedVariable != "ARGS:q" {
		t.Errorf("matched_variable = %q, want ARGS:q", m0.MatchedVariable)
	}
	if evt.RawRef != "coraza-audit:tx123" {
		t.Errorf("raw_log_reference = %q", evt.RawRef)
	}
}

func TestParseLineMasking(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLine), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	raw, _ := json.Marshal(evt)
	s := string(raw)

	// 敏感信息不得出现在事件中
	for _, forbidden := range []string{"hunter2", "abc123", "secret-token", "Bearer"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("event leaks sensitive data: %q found in %s", forbidden, s)
		}
	}
	// URI 中的 password 参数必须脱敏
	if !strings.Contains(evt.Request.URI, "password=masked") {
		t.Errorf("uri not masked: %q", evt.Request.URI)
	}
}

func TestParseLineDetectAction(t *testing.T) {
	detectLine := strings.Replace(sampleAuditLine, `"is_interrupted":true`, `"is_interrupted":false`, 1)
	detectLine = strings.Replace(detectLine, `"rule_engine":"On"`, `"rule_engine":"DetectionOnly"`, 1)
	evt, err := ParseLine([]byte(detectLine), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if evt.Security.Action != "DETECT" {
		t.Errorf("action = %q, want DETECT", evt.Security.Action)
	}
	if evt.Security.RuleEngine != "DetectionOnly" {
		t.Errorf("rule_engine = %q", evt.Security.RuleEngine)
	}
}

func TestParseLineInvalidJSON(t *testing.T) {
	if _, err := ParseLine([]byte(`{not json`), "node", testApp()); err == nil {
		t.Fatal("expected error for invalid json, got nil")
	}
}

func TestParseLineMissingTxID(t *testing.T) {
	if _, err := ParseLine([]byte(`{"transaction":{},"messages":[]}`), "node", testApp()); err == nil {
		t.Fatal("expected error for missing transaction id, got nil")
	}
}

func TestParseLineEmpty(t *testing.T) {
	if _, err := ParseLine([]byte("   "), "node", testApp()); err == nil {
		t.Fatal("expected error for empty line, got nil")
	}
}

func TestMaskURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/path?a=1&token=xyz&b=2", "/path?a=1&token=masked&b=2"},
		{"/path?password=p%40ss", "/path?password=masked"},
		{"/path?a=1", "/path?a=1"},
		{"/path", "/path"},
	}
	for _, c := range cases {
		if got := maskURI(c.in); got != c.want {
			t.Errorf("maskURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRequestIDFallbackToTxID(t *testing.T) {
	line := strings.Replace(sampleAuditLine, `"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"],`, ``, 1)
	evt, err := ParseLine([]byte(line), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if evt.RequestID != "tx123" {
		t.Errorf("request_id fallback = %q, want tx id tx123", evt.RequestID)
	}
}
