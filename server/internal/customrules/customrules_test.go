package customrules

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	// C-05: Name 含双引号、反斜杠或控制字符必须在 ValidateInput 阶段被拒绝
	for _, badName := range []string{
		"test\"quote",
		"test\\backslash",
		"test\nnewline",
		"test\rcr",
		"test\x00nul",
		"test\x7fdel",
	} {
		r := validRule()
		r.Name = badName
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("Name %q should be rejected by ValidateInput", badName)
		}
	}
	// 单引号在合法 Name 中仍可安全转义
	r := validRule()
	r.Name = "user's sql rule"
	gen, err := ValidateInput(r)
	if err != nil {
		t.Fatalf("ValidateInput with single quote in Name: %v", err)
	}
	if !strings.Contains(gen, `msg:'user\'s sql rule'`) {
		t.Errorf("expected escaped single quote in msg: %s", gen)
	}
	// 纵深兜底：直接调用 GenerateSecLang 时也不得留下控制字符、双引号或尾部反斜杠
	direct := GenerateSecLang(7100001, "a\"b\\c\nd", []string{"ARGS"}, "contains", "foo\\", "BLOCK", "HIGH", 2, `SQLI\`, []string{",ctl:ruleEngine=Off"})
	if strings.ContainsAny(direct, "\n\r") {
		t.Errorf("direct GenerateSecLang contains control char: %q", direct)
	}
	if strings.Contains(direct, `foo\"`) {
		t.Errorf("direct GenerateSecLang allowed trailing backslash to escape closing quote: %q", direct)
	}
	if strings.Contains(direct, `tag:'SQLI\`) {
		t.Errorf("direct GenerateSecLang preserved backslash in tag: %q", direct)
	}
}

func TestC05SecLangActionInjectionAndTrailingBackslashRejected(t *testing.T) {
	// 场景1：trailing-backslash attack_type + `,ctl:ruleEngine=Off` tag 注入
	r := validRule()
	r.AttackType = `SQLI\`
	r.Tags = []string{",ctl:ruleEngine=Off"}
	if _, err := ValidateInput(r); err == nil {
		t.Fatal("trailing-backslash attack_type with ctl tag injection must be rejected")
	}

	// 单独测试 AttackType 严格白名单与危险内容
	for _, badType := range []string{
		`SQLI\`,
		`SQLI"`,
		"SQLI'",
		"SQLI,ctl:ruleEngine=Off",
		"SQLI\nSecAction",
		"/etc/passwd",
		strings.Repeat("A", 65),
	} {
		r := validRule()
		r.AttackType = badType
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("malicious AttackType %q should be rejected", badType)
		}
	}

	// 单独测试 Tags 严格白名单与危险内容
	for _, badTag := range []string{
		",ctl:ruleEngine=Off",
		`tag\`,
		`tag"`,
		"tag'",
		"tag\nnewline",
		"tag\x7f",
		"/etc/shadow",
		"",
		strings.Repeat("t", 65),
	} {
		r := validRule()
		r.Tags = []string{badTag}
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("malicious Tag %q should be rejected", badTag)
		}
	}

	// 合法 AttackType / Tags 通过
	rOK := validRule()
	rOK.AttackType = "OWASP_CRS/SQLI:v1.0"
	rOK.Tags = []string{"attack-sqli", "app:portal 1.0"}
	if _, err := ValidateInput(rOK); err != nil {
		t.Fatalf("valid AttackType/Tags rejected: %v", err)
	}

	// 场景2：非正则操作符尾部奇数个反斜杠会吞并闭合双引号导致 Coraza 编译失败/注入
	for _, op := range []string{"contains", "streq", "beginsWith", "endsWith", "pm"} {
		for _, badVal := range []string{`foo\`, `foo\\\`, `\`, "foo\x00bar", "foo\tbar"} {
			r := validRule()
			r.Operator = op
			r.OperatorValue = badVal
			if _, err := ValidateInput(r); err == nil {
				t.Errorf("operator %s with %q should be rejected", op, badVal)
			}
		}
		// 偶数个反斜杠结尾（不会转义闭合引号）允许通过
		rEven := validRule()
		rEven.Operator = op
		rEven.OperatorValue = `foo\\`
		if _, err := ValidateInput(rEven); err != nil {
			t.Errorf("operator %s with even trailing backslashes should pass: %v", op, err)
		}
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

func TestInferPhase(t *testing.T) {
	cases := []struct {
		name string
		vars []string
		want int
	}{
		{"empty defaults to phase 1", nil, 1},
		{"REQUEST_URI header only", []string{"REQUEST_URI"}, 1},
		{"ARGS_GET header only", []string{"ARGS_GET", "ARGS_GET:id"}, 1},
		{"headers and cookies only", []string{"REQUEST_HEADERS:User-Agent", "REQUEST_COOKIES:sid", "HTTP_USER_AGENT", "QUERY_STRING", "REMOTE_ADDR", "REQUEST_METHOD", "REQUEST_FILENAME", "REQUEST_BASENAME", "CONTENT_TYPE", "REQUEST_PROTOCOL", "REQUEST_LINE", "REQUEST_HEADERS_NAMES"}, 1},
		{"REQUEST_BODY", []string{"REQUEST_BODY"}, 2},
		{"ARGS_POST", []string{"ARGS_POST"}, 2},
		{"ARGS", []string{"ARGS"}, 2},
		{"ARGS_NAMES", []string{"ARGS_NAMES"}, 2},
		{"selector ARGS:id", []string{"ARGS:id"}, 2},
		{"selector ARGS_POST:comment", []string{"ARGS_POST:comment"}, 2},
		{"selector ARGS_NAMES:key", []string{"ARGS_NAMES:key"}, 2},
		{"mixed header and body", []string{"REQUEST_URI", "HTTP_USER_AGENT", "ARGS:id"}, 2},
		{"mixed header and REQUEST_BODY", []string{"REQUEST_HEADERS:Host", "REQUEST_BODY"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InferPhase(tc.vars); got != tc.want {
				t.Errorf("InferPhase(%v) = %d, want %d", tc.vars, got, tc.want)
			}
		})
	}
}

func TestValidateInputAutoInferPhase(t *testing.T) {
	t.Run("header-only vars derive phase 1", func(t *testing.T) {
		r := validRule()
		r.Phase = 0
		r.TargetVariables = []string{"REQUEST_URI", "REQUEST_HEADERS:User-Agent"}
		gen, err := ValidateInput(r)
		if err != nil {
			t.Fatalf("ValidateInput failed: %v", err)
		}
		if r.Phase != 1 {
			t.Errorf("r.Phase = %d, want 1", r.Phase)
		}
		if !strings.Contains(gen, "phase:1") {
			t.Errorf("generated rule should contain phase:1, got: %s", gen)
		}
	})

	t.Run("body vars derive phase 2", func(t *testing.T) {
		for _, vars := range [][]string{
			{"REQUEST_BODY"},
			{"ARGS_POST"},
			{"ARGS:id"},
			{"REQUEST_URI", "ARGS_NAMES"},
		} {
			r := validRule()
			r.Phase = 0
			r.TargetVariables = vars
			gen, err := ValidateInput(r)
			if err != nil {
				t.Fatalf("ValidateInput(%v) failed: %v", vars, err)
			}
			if r.Phase != 2 {
				t.Errorf("vars=%v: r.Phase = %d, want 2", vars, r.Phase)
			}
			if !strings.Contains(gen, "phase:2") {
				t.Errorf("vars=%v: generated rule should contain phase:2, got: %s", vars, gen)
			}
		}
	})

	t.Run("invalid target variable rejected before phase inference", func(t *testing.T) {
		r := validRule()
		r.Phase = 0
		r.TargetVariables = []string{"INVALID_VAR"}
		if _, err := ValidateInput(r); err == nil {
			t.Fatal("invalid target variable should be rejected")
		}
		if r.Phase != 0 {
			t.Errorf("phase should not be mutated on target variable validation failure, got %d", r.Phase)
		}
	})
}

func TestValidateInputExplicitPhaseCompatibility(t *testing.T) {
	for phase := 1; phase <= 5; phase++ {
		r := validRule()
		r.Phase = phase
		r.TargetVariables = []string{"REQUEST_URI"}
		gen, err := ValidateInput(r)
		if err != nil {
			t.Fatalf("explicit phase %d should be allowed: %v", phase, err)
		}
		if r.Phase != phase {
			t.Errorf("explicit phase %d was mutated to %d", phase, r.Phase)
		}
		want := "phase:" + string(rune('0'+phase))
		if !strings.Contains(gen, want) {
			t.Errorf("generated rule missing %s: %s", want, gen)
		}
	}

	for _, badPhase := range []int{-1, 6, 99} {
		r := validRule()
		r.Phase = badPhase
		if _, err := ValidateInput(r); err == nil {
			t.Errorf("phase %d should be rejected", badPhase)
		}
	}
}

func TestHandlerValidateAutoPhase(t *testing.T) {
	h := NewHandler(nil, nil)

	callValidate := func(body string) (bool, string, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/custom-rules/new/validate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.Validate(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Valid         bool   `json:"valid"`
				Error         string `json:"error"`
				GeneratedRule string `json:"generated_rule"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal response: %v (%s)", err, rec.Body.String())
		}
		return env.Data.Valid, env.Data.GeneratedRule, env.Data.Error
	}

	// 1. 缺省 phase + 请求头变量 -> 自动推导 phase:1
	valid, gen, errMsg := callValidate(`{"rule_id":7100001,"name":"header rule","operator":"rx","operator_value":"admin","target_variables":["REQUEST_URI"],"action":"BLOCK"}`)
	if !valid || !strings.Contains(gen, "phase:1") {
		t.Errorf("omitted phase + REQUEST_URI: valid=%v gen=%q err=%q", valid, gen, errMsg)
	}

	// 2. 缺省 phase + 请求体变量 -> 自动推导 phase:2
	valid, gen, errMsg = callValidate(`{"rule_id":7100002,"name":"body rule","operator":"rx","operator_value":"(?i)union","target_variables":["REQUEST_BODY"],"action":"BLOCK"}`)
	if !valid || !strings.Contains(gen, "phase:2") {
		t.Errorf("omitted phase + REQUEST_BODY: valid=%v gen=%q err=%q", valid, gen, errMsg)
	}

	// 3. phase=0 + ARGS:id -> 自动推导 phase:2
	valid, gen, errMsg = callValidate(`{"rule_id":7100003,"name":"args rule","phase":0,"operator":"contains","operator_value":"test","target_variables":["ARGS:id"],"action":"BLOCK"}`)
	if !valid || !strings.Contains(gen, "phase:2") {
		t.Errorf("phase=0 + ARGS:id: valid=%v gen=%q err=%q", valid, gen, errMsg)
	}

	// 4. 显式 phase=3 保持向后兼容
	valid, gen, errMsg = callValidate(`{"rule_id":7100004,"name":"explicit phase","phase":3,"operator":"contains","operator_value":"test","target_variables":["REQUEST_URI"],"action":"OBSERVE"}`)
	if !valid || !strings.Contains(gen, "phase:3") {
		t.Errorf("explicit phase=3: valid=%v gen=%q err=%q", valid, gen, errMsg)
	}

	// 5. 非法 phase=-1 / 6 拒绝
	valid, _, _ = callValidate(`{"rule_id":7100005,"name":"bad phase","phase":-1,"operator":"contains","operator_value":"test","target_variables":["REQUEST_URI"],"action":"BLOCK"}`)
	if valid {
		t.Error("phase=-1 should fail validation")
	}
	valid, _, _ = callValidate(`{"rule_id":7100006,"name":"bad phase 6","phase":6,"operator":"contains","operator_value":"test","target_variables":["REQUEST_URI"],"action":"BLOCK"}`)
	if valid {
		t.Error("phase=6 should fail validation")
	}
}
