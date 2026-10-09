package customrules

import (
	"strings"
	"testing"
)

func validRule() *CustomRule {
	return &CustomRule{
		RuleID:          7100001,
		Name:            "测试SQLi规则",
		AttackType:      "SQL_INJECTION",
		Severity:        "CRITICAL",
		Phase:           2,
		Operator:        "rx",
		OperatorValue:   `(?i)union\s+select`,
		TargetVariables: []string{"ARGS"},
		Action:          "BLOCK",
	}
}

func TestValidateInputValid(t *testing.T) {
	gen, err := ValidateInput(validRule())
	if err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if !strings.Contains(gen, "id:7100001") {
		t.Errorf("generated rule missing id: %s", gen)
	}
	if !strings.Contains(gen, "deny") {
		t.Errorf("BLOCK action should produce deny: %s", gen)
	}
	if !strings.Contains(gen, "phase:2") {
		t.Errorf("missing phase: %s", gen)
	}
}

func TestIDOutOfRange(t *testing.T) {
	r := validRule()
	r.RuleID = 942100 // CRS 段，非法
	if _, err := ValidateInput(r); err == nil {
		t.Error("CRS-range id should be rejected")
	}
	r.RuleID = 7100000
	if _, err := ValidateInput(r); err != nil {
		t.Errorf("boundary id 7100000 should pass: %v", err)
	}
	r.RuleID = 7199999
	if _, err := ValidateInput(r); err != nil {
		t.Errorf("boundary id 7199999 should pass: %v", err)
	}
}

func TestDangerousContent(t *testing.T) {
	dangerous := []string{
		"@exec(/bin/cat)",
		"`cat /etc/passwd`",
		"$(cat /etc/passwd)",
		"/etc/passwd",
		"@pmFromFile /etc/hosts",
	}
	for _, d := range dangerous {
		r := validRule()
		r.OperatorValue = d
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("dangerous content %q should be rejected", d)
		}
	}
}

func TestDisallowedOperator(t *testing.T) {
	r := validRule()
	r.Operator = "pmFromFile"
	if _, err := ValidateInput(r); err == nil {
		t.Error("pmFromFile should be rejected (arbitrary file read)")
	}
	r.Operator = "shell_exec"
	if _, err := ValidateInput(r); err == nil {
		t.Error("shell operator should be rejected")
	}
}

func TestDisallowedVariable(t *testing.T) {
	r := validRule()
	r.TargetVariables = []string{"REQUEST_BODY_RAW"}
	if _, err := ValidateInput(r); err == nil {
		t.Error("unsupported variable should be rejected")
	}
	r.TargetVariables = []string{}
	if _, err := ValidateInput(r); err == nil {
		t.Error("empty variables should be rejected")
	}
}

// TestTargetVariablesSecLangInjection 回归：TargetVariables 曾只看 : 前缀白名单，
// GenerateSecLang 以 | 原样拼接，含换行的变量可注入独立 SecLang 指令行关停 WAF。
func TestTargetVariablesSecLangInjection(t *testing.T) {
	malicious := []string{
		"ARGS:x\nSecAction \"ctl:ruleEngine=Off\"", // 换行注入新指令
		"ARGS:x\r\nSecRule REQUEST_URI \"@rx .*\" \"id:1,ctl:ruleRemoveById=949110\"",
		"ARGS\" \"@rx .*\" \"pass", // 引号闭合注入
		"ARGS|REQUEST_URI",         // 管道符拼接注入（绕过白名单扩面）
		"ARGS:",                    // 空选择器
		"ARGS:x y",                 // 空白
		"ARGS:\t",                  // 制表符
		"args",                     // 小写变量名（白名单外且不合形态）
		"ARGS:x\x7f",               // DEL 控制字符
		"ARGS:x`id`",               // 反引号
		"ARGS:${x}",                // 变量引用
	}
	for _, v := range malicious {
		r := validRule()
		r.TargetVariables = []string{v}
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("malicious variable %q should be rejected", v)
		}
	}
	// 合法形态不受影响
	for _, v := range []string{"ARGS", "REQUEST_HEADERS:User-Agent", "ARGS_GET:foo.bar-1_2", "QUERY_STRING"} {
		r := validRule()
		r.TargetVariables = []string{v}
		gen, err := ValidateInput(r)
		if err != nil {
			t.Errorf("variable %q should pass: %v", v, err)
			continue
		}
		if strings.ContainsAny(gen, "\n\r") {
			t.Errorf("generated rule for %q contains control character: %q", v, gen)
		}
	}
	// 生成的 SecLang 单行性兜底校验：任意通过校验的变量组合输出不得含换行
	r := validRule()
	r.TargetVariables = []string{"ARGS", "REQUEST_HEADERS:X-Token"}
	gen, err := ValidateInput(r)
	if err != nil {
		t.Fatalf("ValidateInput: %v", err)
	}
	if strings.ContainsAny(gen, "\n\r") {
		t.Errorf("generated rule must be single-line: %q", gen)
	}
}

// TestJSONRoundTrip 回归：手写 JSON 曾不转义反斜杠、按逗号裸切分，含 \ 或 , 的值损坏数据。
func TestJSONRoundTrip(t *testing.T) {
	values := []string{`ARGS:\path\to`, "a,b", `quote"inside`, "普通值", `tail\`}
	got := fromJSON([]byte(mustJSON(values)))
	if len(got) != len(values) {
		t.Fatalf("round trip length = %d, want %d (%v)", len(got), len(values), got)
	}
	for i := range values {
		if got[i] != values[i] {
			t.Errorf("round trip[%d] = %q, want %q", i, got[i], values[i])
		}
	}
	if got := fromJSON([]byte(mustJSON(nil))); got != nil {
		t.Errorf("empty slice should round trip to nil, got %v", got)
	}
	if got := fromJSON([]byte("null")); got != nil {
		t.Errorf("null should decode to nil, got %v", got)
	}
	if got := fromJSON(nil); got != nil {
		t.Errorf("empty data should decode to nil, got %v", got)
	}
}

func TestDisallowedAction(t *testing.T) {
	r := validRule()
	r.Action = "EXEC"
	if _, err := ValidateInput(r); err == nil {
		t.Error("non-whitelist action should be rejected")
	}
}

// TestVulnIDsValidation CNNVD 兼容性 P1：编号格式校验矩阵（合法/非法/大小写/重复）。
func TestVulnIDsValidation(t *testing.T) {
	r := validRule()
	r.CNNVDIDs = []string{"cnnvd-202401-2345", "CNNVD-202401-2345 ", "CNNVD-202402-0007"}
	r.CVEIDs = []string{"cve-2024-0001", "CVE-2024-0001"}
	if _, err := ValidateInput(r); err != nil {
		t.Fatalf("valid vuln ids rejected: %v", err)
	}
	// 就地规范化：大写归一 + 去重保序
	if got := strings.Join(r.CNNVDIDs, ","); got != "CNNVD-202401-2345,CNNVD-202402-0007" {
		t.Errorf("cnnvd_ids not normalized: %v", r.CNNVDIDs)
	}
	if got := strings.Join(r.CVEIDs, ","); got != "CVE-2024-0001" {
		t.Errorf("cve_ids not normalized: %v", r.CVEIDs)
	}

	badCNNVD := []string{"CNNVD-20241-2345", "CNNVD-202401-23", "CVE-2024-0001", "CNNVD_202401_2345", ""}
	for _, v := range badCNNVD {
		r := validRule()
		r.CNNVDIDs = []string{v}
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("invalid cnnvd id %q should be rejected", v)
		}
	}
	badCVE := []string{"CVE-24-0001", "CVE-2024-001", "CNNVD-202401-2345", "CVE20240001"}
	for _, v := range badCVE {
		r := validRule()
		r.CVEIDs = []string{v}
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("invalid cve id %q should be rejected", v)
		}
	}
	// 缺省空数组通过且不产生 null 语义
	r = validRule()
	if _, err := ValidateInput(r); err != nil {
		t.Fatalf("nil vuln ids should pass: %v", err)
	}
	if r.CNNVDIDs == nil || r.CVEIDs == nil {
		t.Error("normalized vuln ids must be empty slice, not nil")
	}
}

// TestScanRuleVulnIDsNonNull 契约：编号列读出空恒为 [] 非 nil（JSON 序列化为 []）。
func TestScanRuleVulnIDsNonNull(t *testing.T) {
	r := &CustomRule{}
	fillJSONFields(r, nil, nil, nil, nil, nil)
	if r.CNNVDIDs == nil || r.CVEIDs == nil {
		t.Error("cnnvd_ids/cve_ids must default to empty slice")
	}
	fillJSONFields(r, nil, nil, []byte(`["CNNVD-202401-2345"]`), []byte(`["CVE-2024-0001"]`), nil)
	if len(r.CNNVDIDs) != 1 || r.CNNVDIDs[0] != "CNNVD-202401-2345" {
		t.Errorf("cnnvd_ids decode wrong: %v", r.CNNVDIDs)
	}
	if len(r.CVEIDs) != 1 || r.CVEIDs[0] != "CVE-2024-0001" {
		t.Errorf("cve_ids decode wrong: %v", r.CVEIDs)
	}
}

func TestInvalidRegex(t *testing.T) {
	r := validRule()
	r.OperatorValue = "(?i)(unclosed"
	if _, err := ValidateInput(r); err == nil {
		t.Error("invalid regex should be rejected")
	}
}

func TestSecLangEscaping(t *testing.T) {
	r := validRule()
	r.Name = "test'quote\"and\nnewline"
	gen, err := ValidateInput(r)
	if err != nil {
		t.Fatalf("ValidateInput: %v", err)
	}
	if strings.Contains(gen, "\n") {
		t.Error("generated rule contains control character")
	}
}

func TestSecLangRegexEscapingPreservesBackslashesAndRejectsInjection(t *testing.T) {
	r := validRule()
	r.OperatorValue = `^hello\s+world$`
	gen, err := ValidateInput(r)
	if err != nil {
		t.Fatalf("ValidateInput: %v", err)
	}
	if !strings.Contains(gen, `@rx ^hello\s+world$`) {
		t.Fatalf("regex backslash semantics changed: %s", gen)
	}
	if strings.Contains(gen, `\\s`) {
		t.Fatalf("regex backslash was doubled: %s", gen)
	}

	r.OperatorValue = "safe\"\nSecAction id:999"
	if _, err := ValidateInput(r); err == nil {
		t.Fatal("operator value with quote/newline must be rejected")
	}
}

func TestGenerateActions(t *testing.T) {
	actions := map[string]string{
		"BLOCK":   "deny",
		"OBSERVE": "pass",
		"LOG":     "log",
	}
	for action, expect := range actions {
		r := validRule()
		r.Action = action
		gen, err := ValidateInput(r)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(gen, expect) {
			t.Errorf("action %s should contain %q: %s", action, expect, gen)
		}
		if action == "OBSERVE" && strings.Contains(gen, "ctl:ruleEngine=DetectionOnly") {
			t.Errorf("OBSERVE must not disable the whole transaction: %s", gen)
		}
	}
}
