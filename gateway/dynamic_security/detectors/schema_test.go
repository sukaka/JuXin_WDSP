package detectors

import (
	"encoding/json"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// parsedForConstraints 构造带观测值的解析产物（QUERY/HEADER/JSONFields/JSONValues）。
func parsedForConstraints() *parser.Parsed {
	return &parser.Parsed{
		Query:   map[string]string{"page": "0", "status": "ARCHIVED", "tok": "abcdef"},
		Headers: map[string]string{"x-tenant": "t-1234567890"},
		JSONFields: map[string]string{
			"name": "string", "price": "number", "tags": "array", "note": "null",
		},
		JSONValues: map[string]string{
			"name": "这是一个超长的名字", "price": "-5",
		},
	}
}

func matchRules(ctx *dsctx.RequestContext) []string {
	var out []string
	for _, m := range ctx.CopyMatches() {
		out = append(out, m.RuleID)
	}
	return out
}

func hasMatch(ctx *dsctx.RequestContext, ruleID string) bool {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// 规则矩阵：QUERY/HEADER/BODY × required/length/range/enum。
func TestCheckParamConstraintsMatrix(t *testing.T) {
	params := []ParamConstraint{
		// QUERY required 缺失 → OBSERVE/LOW
		{Location: "QUERY", Name: "missing_q", Required: true},
		// QUERY 数值区间：page=0 低于 minimum=1 → param_range
		{Location: "QUERY", Name: "page", Constraints: map[string]any{"minimum": float64(1), "maximum": float64(1000)}},
		// QUERY 枚举：status=ARCHIVED 不在枚举内 → param_enum
		{Location: "QUERY", Name: "status", Constraints: map[string]any{"enum": []any{"PAID", "CLOSED"}}},
		// QUERY 长度：tok 长 6，max_length=3 → param_length
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"max_length": float64(3)}},
		// HEADER（大小写不敏感）：x-tenant 长 11，max_length=20 → 通过
		{Location: "HEADER", Name: "X-Tenant", Constraints: map[string]any{"max_length": float64(20)}},
		// HEADER required 存在 → 无明细
		{Location: "HEADER", Name: "x-tenant", Required: true},
		// BODY 长度：name 8 字符，max_length=4 → param_length
		{Location: "BODY", Name: "name", Path: "name", BaseType: "string",
			Constraints: map[string]any{"max_length": float64(4)}},
		// BODY 数值区间：price=-5 低于 minimum=0 → param_range
		{Location: "BODY", Name: "price", Path: "price", BaseType: "number",
			Constraints: map[string]any{"minimum": float64(0)}},
		// BODY required 存在 → 无明细
		{Location: "BODY", Name: "name", Path: "name", Required: true},
		// BODY required 缺失 → param_required
		{Location: "BODY", Name: "email", Path: "email", Required: true},
		// BODY 非标量（array/null）存在但无留存值 → 跳过取值约束，不误报缺失
		{Location: "BODY", Name: "tags", Path: "tags", Required: true,
			Constraints: map[string]any{"max_length": float64(1)}},
		{Location: "BODY", Name: "note", Path: "note", Required: true},
	}
	ctx := dsctx.New("r-param-matrix", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)

	rules := matchRules(ctx)
	wantCounts := map[string]int{
		"schema.param_required": 2, // missing_q + email
		"schema.param_range":    2, // page + price
		"schema.param_enum":     1, // status
		"schema.param_length":   2, // tok + name
	}
	got := map[string]int{}
	for _, r := range rules {
		got[r]++
	}
	for rule, want := range wantCounts {
		if got[rule] != want {
			t.Errorf("%s count = %d, want %d (all matches: %+v)", rule, got[rule], want, ctx.CopyMatches())
		}
	}
	// 类别/严重度（PROTECT 模式）：required 升级为 BLOCK/HIGH，与取值违规同类
	for _, m := range ctx.CopyMatches() {
		if m.Category != "BLOCK" || m.Severity != "HIGH" {
			t.Errorf("%s category/severity = %s/%s, want BLOCK/HIGH (PROTECT)", m.RuleID, m.Category, m.Severity)
		}
	}
}

// 证据只含 field/constraint/location，永不出现参数原始值。
func TestCheckParamConstraintsEvidenceNoValues(t *testing.T) {
	params := []ParamConstraint{
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"max_length": float64(1)}},
		{Location: "QUERY", Name: "status", Constraints: map[string]any{"enum": []any{"PAID"}}},
		{Location: "BODY", Name: "name", Path: "name", Constraints: map[string]any{"max_length": float64(1)}},
	}
	ctx := dsctx.New("r-param-evidence", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)
	matches := ctx.CopyMatches()
	if len(matches) != 3 {
		t.Fatalf("want 3 matches, got %+v", matches)
	}
	secrets := []string{"abcdef", "ARCHIVED", "这是一个超长的名字"}
	for _, m := range matches {
		for k, v := range m.Evidence {
			switch k {
			case "field", "constraint", "location":
			default:
				t.Errorf("unexpected evidence key %q in %+v", k, m.Evidence)
			}
			for _, s := range secrets {
				if v == s {
					t.Errorf("raw value leaked into evidence: %+v", m.Evidence)
				}
			}
		}
	}
}

// 宽容读取：未知约束键忽略；约束解析失败跳过该条；空枚举跳过（防配置笔误放大）。
// 非数值观测对数值约束报 param_type（见独立用例）。
func TestCheckParamConstraintsLenient(t *testing.T) {
	params := []ParamConstraint{
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"pattern": "^[a-z]+$"}}, // 未知键
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"max_length": "abc"}},   // 解析失败
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"enum": []any{}}},       // 空枚举
		{Location: "HEADER", Name: "x-missing", Required: false},                             // 非必填缺失不报
	}
	ctx := dsctx.New("r-param-lenient", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)
	if n := ctx.MatchCount(); n != 0 {
		t.Fatalf("lenient cases must produce no match, got %+v", ctx.CopyMatches())
	}
}

// QUERY 非数值对 minimum/maximum 报 schema.param_type（且 min+max 只报一条）。
func TestCheckParamConstraintsNonNumericRange(t *testing.T) {
	params := []ParamConstraint{
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{
			"minimum": float64(1), "maximum": float64(10),
		}},
	}
	ctx := dsctx.New("r-param-type", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)
	if !hasMatch(ctx, "schema.param_type") {
		t.Fatalf("want param_type, got %+v", ctx.CopyMatches())
	}
	if n := ctx.MatchCount(); n != 1 {
		t.Fatalf("min+max non-numeric should emit one match, got %d: %+v", n, ctx.CopyMatches())
	}
}

// 脱敏头仅校验 required，取值约束不落在 "[redacted]" 占位上。
func TestCheckParamConstraintsRedactedHeader(t *testing.T) {
	p := &parser.Parsed{
		Headers: map[string]string{"authorization": "[redacted]", "x-api-key": "[redacted]"},
	}
	params := []ParamConstraint{
		{Location: "HEADER", Name: "Authorization", Required: true,
			Constraints: map[string]any{"max_length": float64(3), "enum": []any{"Bearer x"}}},
		{Location: "HEADER", Name: "X-API-Key", Required: true,
			Constraints: map[string]any{"min_length": float64(100)}},
		{Location: "HEADER", Name: "X-Missing", Required: true},
	}
	ctx := dsctx.New("r-param-redact", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, p, params, decision.ModeProtect)
	// 仅缺失头 required；脱敏头不得因占位值触发 length/enum
	if ctx.MatchCount() != 1 || !hasMatch(ctx, "schema.param_required") {
		t.Fatalf("redacted headers must only contribute missing required: %+v", ctx.CopyMatches())
	}
}

// nil/空输入安全。
func TestCheckParamConstraintsNilSafety(t *testing.T) {
	p := parsedForConstraints()
	CheckParamConstraints(nil, p, []ParamConstraint{{Location: "QUERY", Name: "tok"}}, decision.ModeProtect)
	ctx := dsctx.New("r-param-nil", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, nil, []ParamConstraint{{Location: "QUERY", Name: "tok"}}, decision.ModeProtect)
	CheckParamConstraints(ctx, p, nil, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatal("nil inputs must produce no match")
	}
}

// HEADER 约束命中（x-tenant 超界）与 required 缺失各产生一条明细。
func TestCheckParamConstraintsHeader(t *testing.T) {
	params := []ParamConstraint{
		{Location: "HEADER", Name: "X-Tenant", Constraints: map[string]any{"max_length": float64(4)}},
		{Location: "HEADER", Name: "x-missing", Required: true},
	}
	ctx := dsctx.New("r-param-header", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)
	if !hasMatch(ctx, "schema.param_length") || !hasMatch(ctx, "schema.param_required") {
		t.Fatalf("header rules missing: %+v", ctx.CopyMatches())
	}
}

// constraintNumber：兼容 float64/整型/json.Number/字符串；未知类型失败。
func TestConstraintNumber(t *testing.T) {
	cases := []struct {
		raw  any
		want float64
		ok   bool
	}{
		{float64(3.5), 3.5, true},
		{float32(2), 2, true},
		{int(7), 7, true},
		{int64(9), 9, true},
		{int32(4), 4, true},
		{json.Number("12.5"), 12.5, true},
		{" 8 ", 8, true},
		{"abc", 0, false},
		{true, 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := constraintNumber(c.raw)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("constraintNumber(%T %v)=(%v,%v) want (%v,%v)", c.raw, c.raw, got, ok, c.want, c.ok)
		}
	}
}

// constraintStringSet：兼容 []any 与 []string；空/含非字符串失败。
func TestConstraintStringSet(t *testing.T) {
	if set, ok := constraintStringSet([]any{"A", "B"}); !ok || !set["A"] || !set["B"] {
		t.Fatalf("[]any enum failed: %v %v", set, ok)
	}
	if set, ok := constraintStringSet([]string{"X", "Y"}); !ok || !set["X"] || !set["Y"] {
		t.Fatalf("[]string enum failed: %v %v", set, ok)
	}
	if _, ok := constraintStringSet([]any{}); ok {
		t.Fatal("empty []any must fail")
	}
	if _, ok := constraintStringSet([]string{}); ok {
		t.Fatal("empty []string must fail")
	}
	if _, ok := constraintStringSet([]any{"A", 1}); ok {
		t.Fatal("mixed []any must fail")
	}
	if _, ok := constraintStringSet("A"); ok {
		t.Fatal("non-array must fail")
	}
}

// []string 枚举约束可命中（手工构造/部分序列化路径）。
func TestCheckParamConstraintsStringSliceEnum(t *testing.T) {
	params := []ParamConstraint{
		{Location: "QUERY", Name: "status", Constraints: map[string]any{"enum": []string{"PAID", "CLOSED"}}},
	}
	ctx := dsctx.New("r-param-enum-slice", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, parsedForConstraints(), params, decision.ModeProtect)
	if !hasMatch(ctx, "schema.param_enum") {
		t.Fatalf("[]string enum should fire: %+v", ctx.CopyMatches())
	}
}

// cookie 存在性信号：INFO 级 match + SessionFingerprint 标记；
// AuthenticationType=cookie_session 仅在无 token/api_key 时设置（优先级最低）。
func TestCheckIdentitySignalsCookie(t *testing.T) {
	// 仅 cookie：cookie_session
	ctx := dsctx.New("r-cookie", dsctx.DefaultParseLimits())
	CheckIdentitySignals(ctx, &parser.Parsed{Headers: map[string]string{"cookie": "[redacted]"}})
	if !hasMatch(ctx, "identity.cookie_present") {
		t.Fatalf("expected identity.cookie_present, got %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "identity.cookie_present" && (m.Category != "INFO" || m.Severity != "INFO") {
			t.Fatalf("cookie signal must be INFO level, got %+v", m)
		}
	}
	if ctx.AuthenticationType != "cookie_session" {
		t.Fatalf("auth type = %q, want cookie_session", ctx.AuthenticationType)
	}
	if ctx.SessionFingerprint != "present" {
		t.Fatalf("session fingerprint = %q, want present", ctx.SessionFingerprint)
	}

	// cookie + authorization：auth_type 保持 bearer_or_basic（cookie 不覆盖）
	ctx2 := dsctx.New("r-cookie-auth", dsctx.DefaultParseLimits())
	CheckIdentitySignals(ctx2, &parser.Parsed{Headers: map[string]string{
		"cookie": "[redacted]", "authorization": "[redacted]",
	}})
	if ctx2.AuthenticationType != "bearer_or_basic" {
		t.Fatalf("auth type = %q, want bearer_or_basic", ctx2.AuthenticationType)
	}

	// cookie + x-api-key：auth_type 保持 api_key
	ctx3 := dsctx.New("r-cookie-key", dsctx.DefaultParseLimits())
	CheckIdentitySignals(ctx3, &parser.Parsed{Headers: map[string]string{
		"cookie": "[redacted]", "x-api-key": "[redacted]",
	}})
	if ctx3.AuthenticationType != "api_key" {
		t.Fatalf("auth type = %q, want api_key", ctx3.AuthenticationType)
	}

	// 负例：无 cookie 头不产生 cookie 信号，auth_type 为空
	ctx4 := dsctx.New("r-no-cookie", dsctx.DefaultParseLimits())
	CheckIdentitySignals(ctx4, &parser.Parsed{Headers: map[string]string{}})
	if hasMatch(ctx4, "identity.cookie_present") {
		t.Fatalf("no cookie header must not produce cookie signal, got %+v", ctx4.CopyMatches())
	}
	if ctx4.AuthenticationType != "" {
		t.Fatalf("auth type = %q, want empty", ctx4.AuthenticationType)
	}
}

// ---------- G2 约束词汇：required 模式升级 / regex / nullable / empty_allowed ----------

// required 违例按模式定类别：PROTECT 升级 BLOCK/HIGH（可定案阻断）；OBSERVE/OFF 维持 OBSERVE/LOW。
func TestCheckParamConstraintsRequiredModeUpgrade(t *testing.T) {
	params := []ParamConstraint{{Location: "QUERY", Name: "missing_q", Required: true}}

	ctxP := dsctx.New("r-req-protect", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctxP, parsedForConstraints(), params, decision.ModeProtect)
	m := ctxP.CopyMatches()
	if len(m) != 1 || m[0].RuleID != "schema.param_required" {
		t.Fatalf("want 1 param_required, got %+v", m)
	}
	if m[0].Category != "BLOCK" || m[0].Severity != "HIGH" {
		t.Fatalf("PROTECT required = %s/%s, want BLOCK/HIGH", m[0].Category, m[0].Severity)
	}

	for _, mode := range []decision.Mode{decision.ModeObserve, decision.ModeOff, ""} {
		ctxO := dsctx.New("r-req-observe", dsctx.DefaultParseLimits())
		CheckParamConstraints(ctxO, parsedForConstraints(), params, mode)
		mo := ctxO.CopyMatches()
		if len(mo) != 1 || mo[0].Category != "OBSERVE" || mo[0].Severity != "LOW" {
			t.Fatalf("mode %q required = %+v, want OBSERVE/LOW", mode, mo)
		}
	}
}

// regex：命中/偏离产生 BLOCK 类 param_regex；编译失败/超长保守 OBSERVE（constraint_invalid，不计分不阻断）；
// 非字符串/空 pattern 宽容跳过（与未知键同语义）。
func TestCheckParamConstraintsRegex(t *testing.T) {
	p := parsedForConstraints() // tok=abcdef
	params := []ParamConstraint{
		// 命中：tok 全小写字母 → 无明细
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"regex": "^[a-z]+$"}},
		// 偏离：status 非枚举词表 → param_regex
		{Location: "QUERY", Name: "status", Constraints: map[string]any{"regex": "^(PAID|CLOSED)$"}},
		// 语法错误：保守 OBSERVE
		{Location: "QUERY", Name: "page", Constraints: map[string]any{"regex": "([0-9"}},
		// 超长（>512 字符）：保守 OBSERVE
		{Location: "HEADER", Name: "x-tenant", Constraints: map[string]any{"regex": strings.Repeat("a", 513)}},
		// 非字符串/空 pattern：宽容跳过
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"regex": float64(1)}},
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"regex": ""}},
	}
	ctx := dsctx.New("r-regex", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, p, params, decision.ModeProtect)

	var regexHit, invalid int
	for _, m := range ctx.CopyMatches() {
		switch m.RuleID {
		case "schema.param_regex":
			regexHit++
			if m.Category != "BLOCK" || m.Severity != "HIGH" {
				t.Fatalf("param_regex = %s/%s, want BLOCK/HIGH", m.Category, m.Severity)
			}
			if m.Evidence["field"] != "status" {
				t.Fatalf("param_regex field = %q, want status", m.Evidence["field"])
			}
		case "schema.param_constraint_invalid":
			invalid++
			if m.Category != "OBSERVE" || m.ScoreDelta != 0 {
				t.Fatalf("constraint_invalid must be OBSERVE without score: %+v", m)
			}
		default:
			t.Fatalf("unexpected rule %q: %+v", m.RuleID, m)
		}
	}
	if regexHit != 1 || invalid != 2 {
		t.Fatalf("regexHit=%d invalid=%d, want 1/2: %+v", regexHit, invalid, ctx.CopyMatches())
	}
	// 证据不含原始值
	for _, m := range ctx.CopyMatches() {
		for _, v := range m.Evidence {
			if v == "abcdef" || v == "ARCHIVED" {
				t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
			}
		}
	}
}

// CompileConstraintRegex：合法 RE2 可编译；超长与语法错误返回 error。
func TestCompileConstraintRegex(t *testing.T) {
	if _, err := CompileConstraintRegex("^[a-z]{1,3}$"); err != nil {
		t.Fatalf("valid regex: %v", err)
	}
	if _, err := CompileConstraintRegex(strings.Repeat("a", 513)); err == nil {
		t.Fatal("over-length regex must fail")
	}
	if _, err := CompileConstraintRegex("([0-9"); err == nil {
		t.Fatal("bad syntax must fail")
	}
}

// nullable：BODY JSON null 仅在显式 nullable=false 时违例；true/缺省不判定；非 BODY 位置不适用（宽容）。
func TestCheckParamConstraintsNullable(t *testing.T) {
	p := parsedForConstraints() // note: null
	mk := func(c map[string]any) []ParamConstraint {
		return []ParamConstraint{{Location: "BODY", Name: "note", Path: "note", Constraints: c}}
	}

	// nullable=false + null 观测 → BLOCK 类 param_nullable
	ctx := dsctx.New("r-null-false", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, p, mk(map[string]any{"nullable": false}), decision.ModeProtect)
	if !hasMatch(ctx, "schema.param_nullable") {
		t.Fatalf("nullable=false on null must fire: %+v", ctx.CopyMatches())
	}

	// nullable=true / 缺省 → 无明细
	for name, c := range map[string]map[string]any{
		"true":   {"nullable": true},
		"absent": {},
	} {
		ctxOK := dsctx.New("r-null-ok", dsctx.DefaultParseLimits())
		CheckParamConstraints(ctxOK, p, mk(c), decision.ModeProtect)
		if ctxOK.MatchCount() != 0 {
			t.Fatalf("nullable %s must not fire: %+v", name, ctxOK.CopyMatches())
		}
	}

	// 非 BODY 位置无 null 语义：nullable=false 宽容忽略（QUERY 有值不判 null）
	ctxQ := dsctx.New("r-null-query", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctxQ, p, []ParamConstraint{
		{Location: "QUERY", Name: "tok", Constraints: map[string]any{"nullable": false}},
	}, decision.ModeProtect)
	if ctxQ.MatchCount() != 0 {
		t.Fatalf("nullable on non-BODY must be ignored: %+v", ctxQ.CopyMatches())
	}
}

// empty_allowed：空串（QUERY/HEADER/BODY 字符串）与空数组（BODY）在显式 false 时违例；true/缺省不判定；
// 非空数组不误报；空值违例与其他取值约束独立（互不抑制）。
func TestCheckParamConstraintsEmptyAllowed(t *testing.T) {
	p := &parser.Parsed{
		Query:      map[string]string{"q_empty": "", "q_full": "x"},
		JSONFields: map[string]string{"s_empty": "string", "arr_empty": "array", "arr_full": "array", "arr_full[]": "string"},
		JSONValues: map[string]string{"s_empty": "", "arr_full[]": "a"},
	}
	params := []ParamConstraint{
		// 空串违例：QUERY / BODY 字符串
		{Location: "QUERY", Name: "q_empty", Constraints: map[string]any{"empty_allowed": false}},
		{Location: "BODY", Name: "s_empty", Path: "s_empty", Constraints: map[string]any{"empty_allowed": false}},
		// 空数组违例
		{Location: "BODY", Name: "arr_empty", Path: "arr_empty", Constraints: map[string]any{"empty_allowed": false}},
		// 反向：非空 QUERY / 非空数组 / 显式 true / 缺省 → 均不报
		{Location: "QUERY", Name: "q_full", Constraints: map[string]any{"empty_allowed": false}},
		{Location: "BODY", Name: "arr_full", Path: "arr_full", Constraints: map[string]any{"empty_allowed": false}},
		{Location: "QUERY", Name: "q_empty", Constraints: map[string]any{"empty_allowed": true}},
		{Location: "QUERY", Name: "q_empty"},
	}
	ctx := dsctx.New("r-empty", dsctx.DefaultParseLimits())
	CheckParamConstraints(ctx, p, params, decision.ModeProtect)

	fields := map[string]int{}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "schema.param_empty" {
			t.Fatalf("unexpected rule %q: %+v", m.RuleID, m)
		}
		if m.Category != "BLOCK" || m.Severity != "HIGH" {
			t.Fatalf("param_empty = %s/%s, want BLOCK/HIGH", m.Category, m.Severity)
		}
		fields[m.Evidence["field"]]++
	}
	want := map[string]int{"q_empty": 1, "s_empty": 1, "arr_empty": 1}
	if len(fields) != len(want) {
		t.Fatalf("param_empty fields = %v, want %v", fields, want)
	}
	for f, n := range want {
		if fields[f] != n {
			t.Fatalf("param_empty[%q] = %d, want %d (all: %+v)", f, fields[f], n, ctx.CopyMatches())
		}
	}
}

// missing_field 事件确定性：formal 键序排序遍历，多次执行事件顺序一致（map 遍历序抖动修复）。
func TestCheckSchemaDeviationMissingFieldDeterministicOrder(t *testing.T) {
	formal := map[string]string{"zeta": "string", "alpha": "string", "mid": "number"}
	want := []string{"alpha", "mid", "zeta"}
	for i := 0; i < 8; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckSchemaDeviation(ctx, map[string]string{}, formal)
		ms := ctx.CopyMatches()
		if len(ms) != 3 {
			t.Fatalf("run %d: want 3 missing_field matches, got %+v", i, ms)
		}
		for j, m := range ms {
			if m.RuleID != "schema.missing_field" {
				t.Fatalf("run %d: unexpected rule: %+v", i, m)
			}
			if m.Evidence["field"] != want[j] {
				t.Fatalf("run %d: missing_field[%d] = %q, want %q (all: %+v)", i, j, m.Evidence["field"], want[j], ms)
			}
		}
	}
}
