package wafrules

import (
	"strings"
	"testing"
)

const sampleCRS = `
# 注释行
SecRule ARGS "@rx (?i)union\s+select" \
    "id:942100,phase:2,block,capture,t:none,t:urlDecodeUni,t:replaceComments,msg:'SQL Injection Attack Detected via libinjection',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',tag:'paranoia-level/1',tag:'OWASP_CRS',tag:'OWASP_CRS/ATTACK-SQLI',tag:'capec/1000/152/248/66',severity:'CRITICAL',ver:'OWASP_CRS/4.28.0',multiMatch"

SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:sqlmap|nikto)" \
    "id:913100,phase:1,deny,status:403,msg:'Found User-Agent associated with security scanner',tag:'attack-scanner',severity:'WARNING',ver:'OWASP_CRS/4.28.0'"

SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"

SecRule ARGS "@rx <script" "id:941100,phase:2,block,msg:'XSS Attack',tag:'attack-xss',severity:'ERROR'"
`

func TestParseCRSRules(t *testing.T) {
	rules, failed, err := ParseCRSRules(sampleCRS, "TEST.conf", SourceCRS)
	if err != nil {
		t.Fatalf("ParseCRSRules: %v", err)
	}
	if len(failed) > 0 {
		t.Errorf("unexpected parse failures: %v", failed)
	}
	if len(rules) != 3 {
		t.Fatalf("parsed %d rules, want 3 (SecAction excluded)", len(rules))
	}

	// 942100 SQLi
	r0 := rules[0]
	if r0.RuleID != 942100 {
		t.Errorf("rule0 id = %d", r0.RuleID)
	}
	if r0.AttackType != "SQL_INJECTION" {
		t.Errorf("rule0 attack_type = %q", r0.AttackType)
	}
	if r0.Severity != "CRITICAL" {
		t.Errorf("rule0 severity = %q", r0.Severity)
	}
	if r0.Phase != 2 {
		t.Errorf("rule0 phase = %d", r0.Phase)
	}
	if r0.RuleSource != SourceCRS {
		t.Errorf("rule0 source = %q", r0.RuleSource)
	}

	// 913100 scanner
	r1 := rules[1]
	if r1.RuleID != 913100 {
		t.Errorf("rule1 id = %d", r1.RuleID)
	}
	if r1.AttackType != "SCANNER_DETECTION" {
		t.Errorf("rule1 attack_type = %q", r1.AttackType)
	}
	if r1.Phase != 1 {
		t.Errorf("rule1 phase = %d", r1.Phase)
	}

	// 941100 XSS
	r2 := rules[2]
	if r2.RuleID != 941100 {
		t.Errorf("rule2 id = %d", r2.RuleID)
	}
	if r2.AttackType != "XSS" {
		t.Errorf("rule2 attack_type = %q", r2.AttackType)
	}
}

func TestParseSkipsSecAction(t *testing.T) {
	rules, _, _ := ParseCRSRules(sampleCRS, "TEST.conf", SourceCRS)
	for _, r := range rules {
		if r.RuleID == 900000 {
			t.Error("SecAction should not be parsed as rule")
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if normalizeSeverity("critical") != "CRITICAL" {
		t.Error("severity normalization failed")
	}
	if normalizeSeverity("invalid") != "NOTICE" {
		t.Error("invalid severity should default to NOTICE")
	}
}

func TestContentHashDiffers(t *testing.T) {
	r1, _, _ := ParseCRSRules(`SecRule ARGS "@rx a" "id:1,phase:2,msg:'a'"`, "a.conf", SourceCRS)
	r2, _, _ := ParseCRSRules(`SecRule ARGS "@rx b" "id:1,phase:2,msg:'b'"`, "a.conf", SourceCRS)
	if r1[0].ContentHash == r2[0].ContentHash {
		t.Error("different rules should have different hashes")
	}
	if !strings.HasPrefix(r1[0].ContentHash, r1[0].ContentHash[:8]) {
		t.Error("hash format invalid")
	}
}

// 无 msg 的 THIRD_PARTY 排除规则：内置规则 ID 转为中文名，未知规则按文件族名兜底，
// 攻击类型按文件名兜底为 EXCLUSION。
func TestParseThirdPartyExclusionRule(t *testing.T) {
	content := `
# ------------------------------------------------------------------------
# OWASP CRS Plugin
# Copyright (c) 2022-2026 CRS project. All rights reserved.
# ------------------------------------------------------------------------

# Fix FP with requesttoken used for various requests in Nextcloud.
# Fix FP with timezone
SecRule REQUEST_FILENAME "@unconditionalMatch" \
    "id:9508510,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=942130"
`
	rules, failed, err := ParseCRSRules(content, "nextcloud-rule-exclusions-before.conf", SourceThirdParty)
	if err != nil {
		t.Fatalf("ParseCRSRules: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("unexpected parse failures: %v", failed)
	}
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}
	r := rules[0]
	wantName := "Nextcloud 排除规则：Cookie、requesttoken 与时区参数误报放行"
	if r.Name != wantName {
		t.Errorf("name = %q, want %q", r.Name, wantName)
	}
	if r.Message != wantName {
		t.Errorf("message = %q, want %q", r.Message, wantName)
	}
	if r.AttackType != "EXCLUSION" {
		t.Errorf("attack_type = %q, want EXCLUSION", r.AttackType)
	}
}

// 无 msg 且无注释且非内置文件时：名称兜底为「文件名去扩展名 规则 <id>」；
// 未知 ID 落在已知排除插件文件时按中文族名兜底。
func TestParseFallbackNameWithoutComment(t *testing.T) {
	rules, _, _ := ParseCRSRules(`
SecRule REQUEST_FILENAME "@unconditionalMatch" "id:9998511,phase:1,pass,nolog,ctl:ruleRemoveById=942130"
`, "custom-rule-exclusions-before.conf", SourceThirdParty)
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}
	want := "custom-rule-exclusions-before 规则 9998511"
	if rules[0].Name != want {
		t.Errorf("name = %q, want %q", rules[0].Name, want)
	}
	if rules[0].AttackType != "EXCLUSION" {
		t.Errorf("attack_type = %q, want EXCLUSION", rules[0].AttackType)
	}
}

// 新增标签映射：attack-ssrf/attack-xxe 与 webshell/ 前缀。
func TestParseNewAttackTypeTags(t *testing.T) {
	rules, _, _ := ParseCRSRules(`
SecRule ARGS "@rx gopher://" "id:1002001,phase:2,block,msg:'SSRF attempt',tag:'attack-ssrf',severity:'CRITICAL'"

SecRule REQUEST_FILENAME "@rx \\.jsp$" "id:1002002,phase:2,block,msg:'webshell upload',tag:'webshell/upload',severity:'CRITICAL'"

SecRule ARGS "@rx <!ENTITY" "id:1002003,phase:2,block,msg:'XXE',tag:'attack-xxe',severity:'ERROR'"
`, "TEST.conf", SourceCustomPack)
	if len(rules) != 3 {
		t.Fatalf("parsed %d rules, want 3", len(rules))
	}
	wants := []string{"SSRF", "WEBSHELL", "XXE_INJECTION"}
	for i, want := range wants {
		if rules[i].AttackType != want {
			t.Errorf("rule %d attack_type = %q, want %q", rules[i].RuleID, rules[i].AttackType, want)
		}
	}
}

// 标签无法识别时按文件名兜底（自建包文件）。
func TestParseFileFallbackAttackType(t *testing.T) {
	rules, _, _ := ParseCRSRules(`
SecRule REQUEST_URI "@rx ^/internal" "id:1003001,phase:1,block,msg:'unauth access',severity:'ERROR'"
`, "unauth-access.conf", SourceCustomPack)
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}
	if rules[0].AttackType != "INFORMATION_DISCLOSURE" {
		t.Errorf("attack_type = %q, want INFORMATION_DISCLOSURE", rules[0].AttackType)
	}
}

// CRS 初始化类规则（无 attack 标签、非兜底文件）保持 OTHER，名称自动中文化。
func TestParseCRSInitRuleStaysOther(t *testing.T) {
	rules, _, _ := ParseCRSRules(`
# Initialize anomaly score variables.
SecRule TX:anomaly_score "@eq 0" "id:901001,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score=0"
`, "REQUEST-901-INITIALIZATION.conf", SourceCRS)
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}
	if rules[0].AttackType != "OTHER" {
		t.Errorf("attack_type = %q, want OTHER", rules[0].AttackType)
	}
	if rules[0].Name != "检测到未配置 CRS 的部署" {
		t.Errorf("name = %q", rules[0].Name)
	}
}

// msg 优先原则：有 msg 时名称不受上方注释影响。
func TestMsgPreferredOverComment(t *testing.T) {
	rules, _, _ := ParseCRSRules(`
# 注释描述不应作为名称
SecRule ARGS "@rx x" "id:1004001,phase:2,block,msg:'真实消息',tag:'attack-xss'"
`, "TEST.conf", SourceCustomPack)
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}
	if rules[0].Name != "真实消息" {
		t.Errorf("name = %q, want 真实消息", rules[0].Name)
	}
}
