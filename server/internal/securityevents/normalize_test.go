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
	if evt.Matches[0].RuleSource != "OWASP_CRS" || evt.Matches[0].RuleVersion != "4.28.0" {
		t.Errorf("match rule metadata = %q/%q", evt.Matches[0].RuleSource, evt.Matches[0].RuleVersion)
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

// buildAuditLine 构造最小审计日志行，messages 为 ModSecurity 风格错误消息（JSON 转义后）。
func buildAuditLine(messages ...string) string {
	msgs := ""
	for i, m := range messages {
		if i > 0 {
			msgs += ","
		}
		msgs += `{"error_message":"` + m + `"}`
	}
	return `{"transaction":{"timestamp":"2026/07/21 10:00:00","id":"tx-atk","client_ip":"192.0.2.1","client_port":12345,` +
		`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/","headers":{"host":["waf.test"]}},` +
		`"response":{"status":0},"producer":{"rule_engine":"On"},"is_interrupted":true},"messages":[` + msgs + `]}`
}

// 攻击类型按严重度优先：notice 级扫描器规则不得抢在 critical 级攻击规则前面；
// 严重度并列时取先出现者；纯扫描器事件仍判 SCANNER_DETECTION。
func TestParseAuditLineAttackTypeSeverityPriority(t *testing.T) {
	// 自定义规则 1000712：扫描器检测，notice 级，phase 1（总先于 CRS phase-2 规则出现）
	scannerMsg := `[client \"192.0.2.1\"] Coraza: Warning. Scanner [id \"1000712\"] [msg \"Scanner Detected\"] [severity \"notice\"] [tag \"attack-scanner\"] [phase \"1\"]`
	xssMsg := `[client \"192.0.2.1\"] Coraza: Warning. XSS [id \"941100\"] [msg \"XSS Attack\"] [severity \"critical\"] [tag \"attack-xss\"]`
	sqliMsg := `[client \"192.0.2.1\"] Coraza: Warning. SQLi [id \"942100\"] [msg \"SQL Injection Attack\"] [severity \"critical\"] [tag \"attack-sqli\"]`

	cases := []struct {
		name string
		line string
		want string
	}{
		{"扫描器在前+critical XSS 在后", buildAuditLine(scannerMsg, xssMsg), "XSS"},
		{"仅扫描器", buildAuditLine(scannerMsg), "SCANNER_DETECTION"},
		{"sqli 与 xss 同为 critical 取先出现者", buildAuditLine(sqliMsg, xssMsg), "SQL_INJECTION"},
		{"同级并列 xss 在前", buildAuditLine(xssMsg, sqliMsg), "XSS"},
		{"既有样例仍判 SQL_INJECTION", sampleAudit, "SQL_INJECTION"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evt, err := ParseAuditLine([]byte(c.line), "node-01")
			if err != nil {
				t.Fatalf("ParseAuditLine: %v", err)
			}
			if evt.AttackType != c.want {
				t.Errorf("attack_type = %q, want %q", evt.AttackType, c.want)
			}
		})
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

func TestMaskBody(t *testing.T) {
	cases := []struct{ name, in, wantNotContain string }{
		{"form", "username=admin&password=topsecret&note=hello", "topsecret"},
		{"json compact", `{"username":"admin","password":"topsecret"}`, "topsecret"},
		{"json spaced", `{ "token": "abc123", "a": 1 }`, "abc123"},
	}
	for _, c := range cases {
		got := maskBody(c.in)
		if strings.Contains(got, c.wantNotContain) {
			t.Errorf("%s: maskBody(%q) = %q, still contains %q", c.name, c.in, got, c.wantNotContain)
		}
		if !strings.Contains(got, "masked") {
			t.Errorf("%s: maskBody(%q) = %q, no mask applied", c.name, c.in, got)
		}
	}
	// 非敏感字段不受影响
	if got := maskBody("username=admin&note=hello"); got != "username=admin&note=hello" {
		t.Errorf("non-sensitive body changed: %q", got)
	}
}

func TestMaskHeaders(t *testing.T) {
	in := map[string][]string{
		"Cookie":        {"session=abc"},
		"Authorization": {"Bearer xyz"},
		"X-Custom":      {"keep"},
	}
	out := maskHeaders(in)
	if out["Cookie"][0] != "masked" || out["Authorization"][0] != "masked" {
		t.Errorf("sensitive headers not masked: %v", out)
	}
	if out["X-Custom"][0] != "keep" {
		t.Errorf("non-sensitive header changed: %v", out)
	}
}

func TestTruncateBody(t *testing.T) {
	body, truncated := truncateBody(strings.Repeat("a", maxBodyLen+1))
	if !truncated || len(body) != maxBodyLen {
		t.Errorf("expected truncation at %d, got len=%d truncated=%v", maxBodyLen, len(body), truncated)
	}
	body, truncated = truncateBody("short")
	if truncated || body != "short" {
		t.Errorf("short body should not be truncated")
	}
}

// 自定义/内置规则 ID 段标注规则来源（不被规则集元数据误标 OWASP_CRS）；
// 原始攻击类型 tag（GenerateSecLang 写入）参与主类型聚合，critical 自定义规则
// 压过 notice 级 CRS 扫描器规则。
func TestParseAuditLineCustomRuleSourceAndAttackType(t *testing.T) {
	scannerMsg := `[client \"192.0.2.1\"] Coraza: Warning. Scanner [id \"1000712\"] [msg \"Scanner Detected\"] [severity \"notice\"] [tag \"attack-scanner\"] [phase \"1\"]`
	customRCE := `[client \"192.0.2.1\"] Coraza: Warning. JNDI [id \"7100101\"] [msg \"Log4j2 JNDI 注入探测拦截\"] [severity \"critical\"] [tag \"jiuzhang-custom\"] [tag \"REMOTE_CODE_EXECUTION\"]`
	builtinMsg := `[client \"192.0.2.1\"] Coraza: Warning. Builtin [id \"7050001\"] [msg \"九章内置规则\"] [severity \"error\"] [tag \"jiuzhang-builtin\"] [tag \"WEBSHELL\"]`

	evt, err := ParseAuditLine([]byte(buildAuditLine(scannerMsg, customRCE)), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt.AttackType != "REMOTE_CODE_EXECUTION" {
		t.Errorf("attack_type = %q, want REMOTE_CODE_EXECUTION（critical 自定义规则压过 notice 扫描器）", evt.AttackType)
	}
	if evt.Matches[1].RuleSource != "USER_CUSTOM" || evt.Matches[1].RuleVersion != "" {
		t.Errorf("custom rule source = %q/%q, want USER_CUSTOM/空", evt.Matches[1].RuleSource, evt.Matches[1].RuleVersion)
	}
	if evt.Matches[0].RuleSource != "" && evt.Matches[0].RuleSource != "OWASP_CRS" {
		// 无 rulesets 元数据时 CRS 规则来源为空（现状口径），不得误标 USER_CUSTOM
		t.Errorf("scanner rule source = %q", evt.Matches[0].RuleSource)
	}

	evt2, err := ParseAuditLine([]byte(buildAuditLine(builtinMsg)), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt2.Matches[0].RuleSource != "JIUZHANG_BUILTIN" {
		t.Errorf("builtin rule source = %q, want JIUZHANG_BUILTIN", evt2.Matches[0].RuleSource)
	}
	if evt2.AttackType != "WEBSHELL" {
		t.Errorf("attack_type = %q, want WEBSHELL（原始类型 tag 恒等映射）", evt2.AttackType)
	}
}

func TestParseAuditLineConnectionAddr(t *testing.T) {
	// guard 注入内部头：审计 client_ip 为改写后真实 IP，connection_ip/client_port 回填 TCP 对端
	line := strings.Replace(sampleAudit,
		`"x-request-id":["req-abc-123"]`,
		`"x-request-id":["req-abc-123"],"x-jiuzhang-connection-addr":["172.19.0.1:43210"]`, 1)
	evt, err := ParseAuditLine([]byte(line), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt.ClientIP != "192.0.2.10" {
		t.Errorf("client_ip = %q（真实 IP 不应被内部头影响）", evt.ClientIP)
	}
	if evt.ConnectionIP != "172.19.0.1" {
		t.Errorf("connection_ip = %q, want 172.19.0.1", evt.ConnectionIP)
	}
	if evt.ClientPort != 43210 {
		t.Errorf("client_port = %d, want 43210（内部头回填）", evt.ClientPort)
	}
	for k := range evt.RequestHeaders {
		if strings.EqualFold(k, connectionAddrHeader) {
			t.Error("内部头不得进入 request_headers 留痕")
		}
	}

	// 非法内部头忽略：ConnectionIP 留空、端口保持审计值
	bad := strings.Replace(sampleAudit,
		`"x-request-id":["req-abc-123"]`,
		`"x-request-id":["req-abc-123"],"x-jiuzhang-connection-addr":["garbage"]`, 1)
	evt2, err := ParseAuditLine([]byte(bad), "node-01")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	if evt2.ConnectionIP != "" || evt2.ClientPort != 51234 {
		t.Errorf("invalid header must be ignored: conn=%q port=%d", evt2.ConnectionIP, evt2.ClientPort)
	}
}
