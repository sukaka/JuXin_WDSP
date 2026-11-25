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

// maskMatchedData 循环遮蔽：同名敏感参数每次出现都必须脱敏（修复前只遮蔽首处）。
func TestMaskMatchedDataMasksAllOccurrences(t *testing.T) {
	in := "password=hunter2&x=1&password=hunter2 token: abc token: abc; pwd:pw1 pwd=pw1"
	got := maskMatchedData(in)
	for _, forbidden := range []string{"hunter2", "abc", "pw1"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("maskMatchedData(%q) = %q, 仍含敏感值 %q", in, got, forbidden)
		}
	}
	if !strings.Contains(got, "password=masked") || !strings.Contains(got, "token: masked") || !strings.Contains(got, "pwd:masked") {
		t.Errorf("遮蔽标记缺失: %q", got)
	}
	if !strings.Contains(got, "x=1") {
		t.Errorf("非敏感键值不应受影响: %q", got)
	}
}

// 命中变量为敏感头（REQUEST_HEADERS:Authorization/Cookie 等）时 Matched Data 整段遮蔽。
func TestParseLineMasksSensitiveHeaderMatchedData(t *testing.T) {
	line := strings.Replace(sampleAuditLine,
		`[data \"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1\"]`,
		`[data \"Matched Data: Bearer leaked-token found within REQUEST_HEADERS:Authorization: Bearer leaked-token\"]`, 1)
	evt, err := ParseLine([]byte(line), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	m0 := evt.Security.Matches[0]
	if m0.MatchedVariable != "REQUEST_HEADERS:Authorization" {
		t.Fatalf("matched_variable = %q", m0.MatchedVariable)
	}
	if m0.MatchedData != "masked" {
		t.Errorf("敏感头命中值应整段遮蔽, got %q", m0.MatchedData)
	}
	raw, _ := json.Marshal(evt)
	if strings.Contains(string(raw), "leaked-token") {
		t.Errorf("事件泄漏敏感头值: %s", raw)
	}
}

// 非敏感头命中不做整段遮蔽（保留调查所需内容，仅按键值模式脱敏）。
func TestParseLineNonSensitiveHeaderMatchedDataKept(t *testing.T) {
	line := strings.Replace(sampleAuditLine,
		`[data \"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1\"]`,
		`[data \"Matched Data: sqlmap found within REQUEST_HEADERS:User-Agent: sqlmap/1.5\"]`, 1)
	evt, err := ParseLine([]byte(line), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if got := evt.Security.Matches[0].MatchedData; got != "sqlmap/1.5" {
		t.Errorf("matched_data = %q, want sqlmap/1.5（非敏感头不整段遮蔽）", got)
	}
}

// buildAuditLineWithTags 构造带指定标签的最小审计日志行。
func buildAuditLineWithTags(tags string) string {
	return `{"transaction":{"timestamp":"2026/07/20 13:40:14","id":"txA","client_ip":"192.0.2.1","client_port":1,` +
		`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/","headers":{}},"response":{"status":0},` +
		`"producer":{"rule_engine":"On"},"is_interrupted":false},"messages":[{"error_message":"[id \"1001\"] [msg \"m\"] ` +
		tags + ` [severity \"warning\"]"}]}`
}

// 扩展攻击类型映射（与规则库同步侧一致）：attack-ssrf 等新标签与 webshell/ 前缀。
func TestParseLineExtendedAttackTypes(t *testing.T) {
	cases := []struct{ tags, want string }{
		{`[tag \"attack-ssrf\"]`, "SSRF"},
		{`[tag \"attack-xxe\"]`, "XXE_INJECTION"},
		{`[tag \"attack-dos\"]`, "DOS"},
		{`[tag \"attack-mass-assignment\"]`, "MASS_ASSIGNMENT"},
		{`[tag \"attack-deserialization\"]`, "DESERIALIZATION"},
		{`[tag \"attack-ssti\"]`, "SSTI"},
		{`[tag \"attack-upload\"]`, "FILE_UPLOAD"},
		{`[tag \"attack-reputation-scanner\"]`, "SCANNER"},
		{`[tag \"attack-injection-php\"]`, "PHP_CODE_INJECTION"},
		{`[tag \"attack-injection-java\"]`, "JAVA_CODE_INJECTION"},
		{`[tag \"attack-multipart-header\"]`, "PROTOCOL_VIOLATION"},
		{`[tag \"OWASP_CRS/METHOD-ENFORCEMENT\"]`, "PROTOCOL_VIOLATION"},
		{`[tag \"webshell/upload\"]`, "WEBSHELL"},
		{`[tag \"webshell/chopper\"]`, "WEBSHELL"},
		{`[tag \"app/struts\"]`, "UNKNOWN"},
		// 首个命中优先：webshell/upload 在前时不受后续 attack-xss 影响
		{`[tag \"webshell/upload\"] [tag \"attack-xss\"]`, "WEBSHELL"},
	}
	for _, c := range cases {
		evt, err := ParseLine([]byte(buildAuditLineWithTags(c.tags)), "node", testApp())
		if err != nil {
			t.Fatalf("ParseLine(%s) error = %v", c.tags, err)
		}
		if evt.Security.AttackType != c.want {
			t.Errorf("tags %s: attack_type = %q, want %q", c.tags, evt.Security.AttackType, c.want)
		}
	}

	// 中文二次阻断评估总分提取（9000102/9000104）
	cnScoreLine := `{"transaction":{"timestamp":"2026/11/25 19:03:26","id":"txCN","client_ip":"45.148.10.119","client_port":51234,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/backend/.env","headers":{"host":["www.jxdr.cn"]}},"response":{"status":0},"producer":{"rule_engine":"On"},"is_interrupted":true},"messages":[{"error_message":"[id \"930130\"] [msg \"Restricted File Access Attempt\"] [severity \"critical\"] [tag \"attack-lfi\"]"},{"error_message":"[id \"9000102\"] [msg \"九章二次阻断评估：阶段 1 入站异常评分超过阈值（总分：10）\"] [severity \"critical\"] [tag \"jiuzhang-custom\"] [tag \"anomaly-evaluation\"]"}]}`
	evtCN, err := ParseLine([]byte(cnScoreLine), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine(cnScoreLine) error = %v", err)
	}
	if evtCN.Security.AnomalyScore != 10 {
		t.Errorf("anomaly_score = %d, want 10", evtCN.Security.AnomalyScore)
	}
	if evtCN.Security.AttackType != "LOCAL_FILE_INCLUSION" {
		t.Errorf("attack_type = %q, want LOCAL_FILE_INCLUSION", evtCN.Security.AttackType)
	}
}

// ---------- WDSP P0-04：final_decision 重建与受限例外命中分流 ----------

// 例外效果规则命中（ID 8000002 = effect 规则，携带 exc:/excv: tag）+ 真实攻击命中混合。
const sampleAuditLineWithException = `{"transaction":{"timestamp":"2026/09/07 10:00:00","unix_timestamp":1788775200,"id":"txexc1","client_ip":"192.0.2.20","client_port":40000,"request":{"method":"POST","protocol":"HTTP/1.1","uri":"/api/orders","headers":{"host":["api.test"],"x-request-id":["req-exc-1"]}},"response":{"status":0},"producer":{"rule_engine":"On"},"is_interrupted":true},"messages":[{"error_message":"[client \"192.0.2.20\"] Coraza: Warning. SQL Injection Attack [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"critical\"] [tag \"attack-sqli\"]"},{"error_message":"[client \"192.0.2.20\"] Coraza: Warning. exception applied [id \"8000002\"] [msg \"jiuzhang exception effect\"] [tag \"jiuzhang-exception\"] [tag \"exc:11111111-2222-3333-4444-555555555555\"] [tag \"excv:3\"]"}]}`

func TestParseLineFinalDecisionBlocked(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLine), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	fd := evt.FinalDecision
	if fd == nil {
		t.Fatal("final_decision 缺失")
	}
	if fd.SchemaVersion != 1 || fd.RequestID != evt.RequestID || fd.GatewayNode != "gateway-poc-01" {
		t.Errorf("标识字段不符: %+v", fd)
	}
	if fd.CompletionStatus != "ABORTED" || fd.SecurityAction != "BLOCK" ||
		fd.ExecutorModule != "WAF" || fd.ResponseSource != "GATEWAY" {
		t.Errorf("终止事实不符: %+v", fd)
	}
	if fd.HTTPStatus != 403 || !fd.ResponseCommitted {
		t.Errorf("status/committed = %d/%v", fd.HTTPStatus, fd.ResponseCommitted)
	}
	if fd.ApplicationID != "poc-app" {
		t.Errorf("application_id = %q", fd.ApplicationID)
	}
	// rule_refs 取真实攻击命中（942100 + 949110）
	if len(fd.RuleRefs) != 2 || fd.RuleRefs[0].Module != "WAF" || fd.RuleRefs[0].RuleID != "942100" {
		t.Errorf("rule_refs = %+v", fd.RuleRefs)
	}
	if len(fd.MatchedExceptions) != 0 {
		t.Errorf("无例外命中应为空: %+v", fd.MatchedExceptions)
	}
	if fd.FinalizedAt != evt.OccurredAt {
		t.Errorf("finalized_at = %q", fd.FinalizedAt)
	}
}

func TestParseLineExceptionHitNotAttack(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLineWithException), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	// 例外效果规则命中分流：matches 只含真实攻击规则
	if len(evt.Security.Matches) != 1 || evt.Security.Matches[0].RuleID != "942100" {
		t.Errorf("matches = %+v（例外命中不得进入）", evt.Security.Matches)
	}
	if evt.Security.AttackType != "SQL_INJECTION" {
		t.Errorf("attack_type = %q（例外命中不得影响攻击分类）", evt.Security.AttackType)
	}
	fd := evt.FinalDecision
	if fd == nil {
		t.Fatal("final_decision 缺失")
	}
	if len(fd.MatchedExceptions) != 1 {
		t.Fatalf("matched_exceptions = %+v", fd.MatchedExceptions)
	}
	me := fd.MatchedExceptions[0]
	if me.ExceptionID != "11111111-2222-3333-4444-555555555555" || me.Version != 3 || me.Target != "WAF" {
		t.Errorf("matched_exception = %+v", me)
	}
	if len(me.RuleRefs) != 1 || me.RuleRefs[0] != "8000002" {
		t.Errorf("matched_exception.rule_refs = %v", me.RuleRefs)
	}
	// rule_refs 不含例外规则 ID
	for _, rr := range fd.RuleRefs {
		if rr.RuleID == "8000002" {
			t.Errorf("例外规则不得进 rule_refs: %+v", fd.RuleRefs)
		}
	}
}

// 仅例外命中、无攻击命中：matches 为空（采集端按无攻击命中过滤——例外命中不是攻击）。
const sampleAuditLineExceptionOnly = `{"transaction":{"timestamp":"2026/09/07 10:01:00","unix_timestamp":1788775260,"id":"txexc2","client_ip":"192.0.2.21","client_port":40001,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/health","headers":{"host":["api.test"],"x-request-id":["req-exc-2"]}},"response":{"status":200},"producer":{"rule_engine":"On"},"is_interrupted":false},"messages":[{"error_message":"[client \"192.0.2.21\"] Coraza: Warning. exception applied [id \"8000004\"] [msg \"jiuzhang exception effect\"] [tag \"jiuzhang-exception\"] [tag \"exc:aaaa1111-2222-3333-4444-555555555555\"] [tag \"excv:1\"]"}]}`

func TestParseLineExceptionOnlyNoAttack(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLineExceptionOnly), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if len(evt.Security.Matches) != 0 {
		t.Errorf("matches 应为空: %+v", evt.Security.Matches)
	}
	if evt.Security.AttackType != "UNKNOWN" || evt.Security.Severity != "INFO" {
		t.Errorf("attack_type/severity = %q/%q", evt.Security.AttackType, evt.Security.Severity)
	}
	fd := evt.FinalDecision
	if fd == nil {
		t.Fatal("final_decision 缺失")
	}
	// 未中断：COMPLETED/NONE/ORIGIN，http_status 取响应码 200
	if fd.CompletionStatus != "COMPLETED" || fd.SecurityAction != "NONE" ||
		fd.ExecutorModule != "NONE" || fd.ResponseSource != "ORIGIN" {
		t.Errorf("放行事实不符: %+v", fd)
	}
	if fd.HTTPStatus != 200 {
		t.Errorf("http_status = %d, 期望 200", fd.HTTPStatus)
	}
	if len(fd.MatchedExceptions) != 1 || fd.MatchedExceptions[0].Version != 1 {
		t.Errorf("matched_exceptions = %+v", fd.MatchedExceptions)
	}
	if len(fd.RuleRefs) != 0 {
		t.Errorf("rule_refs 应为空: %+v", fd.RuleRefs)
	}
}

// 例外段内规则 ID 但无 exc: tag（防御：非例外锚点不分流）；例外段外规则带 exc: tag
// （防御：段外不识别）均按普通命中处理。
const sampleAuditLineExceptionGuard = `{"transaction":{"timestamp":"2026/09/07 10:02:00","unix_timestamp":1788775320,"id":"txexc3","client_ip":"192.0.2.22","client_port":40002,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/x","headers":{"host":["api.test"],"x-request-id":["req-exc-3"]}},"response":{"status":200},"producer":{"rule_engine":"On"},"is_interrupted":false},"messages":[{"error_message":"[client \"192.0.2.22\"] Coraza: Warning. in-segment no tag [id \"8000010\"] [msg \"in segment without exc tag\"] [severity \"warning\"]"},{"error_message":"[client \"192.0.2.22\"] Coraza: Warning. out-segment with tag [id \"942100\"] [msg \"out of segment with exc tag\"] [severity \"critical\"] [tag \"attack-sqli\"] [tag \"exc:bbbb2222-2222-3333-4444-555555555555\"]"}]}`

func TestParseLineExceptionSegmentGuard(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLineExceptionGuard), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	// 段内无 tag + 段外有 tag：均不分流（双条件缺一不可）
	if len(evt.Security.Matches) != 2 {
		t.Errorf("matches = %+v，期望 2 条均不分流", evt.Security.Matches)
	}
	if evt.FinalDecision != nil && len(evt.FinalDecision.MatchedExceptions) != 0 {
		t.Errorf("matched_exceptions 应为空: %+v", evt.FinalDecision.MatchedExceptions)
	}
}

// 响应相位中断：response.status 有效 4xx/5xx 时 final_decision 取之（phase 4 中断码先行写出）。
const sampleAuditLinePhase4 = `{"transaction":{"timestamp":"2026/09/07 10:03:00","unix_timestamp":1788775380,"id":"txp4","client_ip":"192.0.2.23","client_port":40003,"request":{"method":"GET","protocol":"HTTP/1.1","uri":"/dl","headers":{"host":["api.test"],"x-request-id":["req-p4"]}},"response":{"status":451},"producer":{"rule_engine":"On"},"is_interrupted":true},"messages":[{"error_message":"[client \"192.0.2.23\"] Coraza: Warning. outbound block [id \"950100\"] [msg \"outbound anomaly\"] [severity \"error\"] [tag \"attack-disclosure\"]"}]}`

func TestParseLinePhase4InterruptedStatus(t *testing.T) {
	evt, err := ParseLine([]byte(sampleAuditLinePhase4), "gateway-poc-01", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if evt.Security.StatusCode != 451 {
		t.Errorf("status_code = %d, 期望响应相位真实中断码 451", evt.Security.StatusCode)
	}
	if evt.FinalDecision.HTTPStatus != 451 {
		t.Errorf("final_decision.http_status = %d, 期望 451", evt.FinalDecision.HTTPStatus)
	}
	if evt.FinalDecision.CompletionStatus != "ABORTED" || evt.FinalDecision.ExecutorModule != "WAF" {
		t.Errorf("final_decision = %+v", evt.FinalDecision)
	}
}

func TestParseLineConnectionAddr(t *testing.T) {
	// guard 注入内部头：审计 client_ip 为改写后真实 IP，connection_ip 回填 TCP 对端
	line := strings.Replace(sampleAuditLine,
		`"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"]`,
		`"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"],"x-jiuzhang-connection-addr":["172.19.0.1:43210"]`, 1)
	evt, err := ParseLine([]byte(line), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if evt.Client.ConnectionIP != "172.19.0.1" {
		t.Errorf("connection_ip = %q, want 172.19.0.1", evt.Client.ConnectionIP)
	}
	if evt.Client.Port != 43210 {
		t.Errorf("client.port = %d, want 43210（内部头回填）", evt.Client.Port)
	}
	filtered := FilterHeaders(map[string][]string{"X-Jiuzhang-Connection-Addr": {"1.1.1.1:1"}, "A": {"b"}})
	if _, ok := filtered["X-Jiuzhang-Connection-Addr"]; ok {
		t.Error("internal header must be dropped from FilterHeaders output")
	}

	// 非法内部头忽略：ConnectionIP 留空、端口保持审计值
	bad := strings.Replace(sampleAuditLine,
		`"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"]`,
		`"x-request-id":["612b408c-b8ad-4e78-acbe-10926c77ff22"],"x-jiuzhang-connection-addr":["not-an-addr"]`, 1)
	evt2, err := ParseLine([]byte(bad), "node", testApp())
	if err != nil {
		t.Fatalf("ParseLine() error = %v", err)
	}
	if evt2.Client.ConnectionIP != "" || evt2.Client.Port != 51234 {
		t.Errorf("invalid header must be ignored: conn=%q port=%d", evt2.Client.ConnectionIP, evt2.Client.Port)
	}
}
