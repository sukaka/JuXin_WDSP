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
	rules, failed, err := ParseCRSRules(sampleCRS, "TEST.conf")
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
	rules, _, _ := ParseCRSRules(sampleCRS, "TEST.conf")
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
	r1, _, _ := ParseCRSRules(`SecRule ARGS "@rx a" "id:1,phase:2,msg:'a'"`, "a.conf")
	r2, _, _ := ParseCRSRules(`SecRule ARGS "@rx b" "id:1,phase:2,msg:'b'"`, "a.conf")
	if r1[0].ContentHash == r2[0].ContentHash {
		t.Error("different rules should have different hashes")
	}
	if !strings.HasPrefix(r1[0].ContentHash, r1[0].ContentHash[:8]) {
		t.Error("hash format invalid")
	}
}
