package exceptions

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func preciseException() *Exception {
	return &Exception{
		Name:            "富文本误报例外",
		ScopeType:       "APPLICATION",
		URIPrefix:       "/api/richtext",
		ParamNames:      []string{"content"},
		RuleIDs:         []int{942100},
		ExceptionAction: ActionRemoveRule,
		Status:          "ENABLED",
	}
}

func TestPreciseExceptionValid(t *testing.T) {
	e := preciseException()
	if err := ValidateInput(e); err != nil {
		t.Fatalf("precise exception rejected: %v", err)
	}
	if e.IsBroad() {
		t.Error("precise exception should not be broad")
	}
}

func TestBroadExceptionNeedsAck(t *testing.T) {
	// 对全部 SQLi 攻击类型的例外 = 宽泛
	e := &Exception{
		Name:            "全部SQLi例外",
		ScopeType:       "GLOBAL",
		AttackTypes:     []string{"SQL_INJECTION"},
		ExceptionAction: ActionRemoveRuleTag,
		RuleTags:        []string{"attack-sqli"},
		Status:          "ENABLED",
	}
	if !e.IsBroad() {
		t.Error("attack-type exception should be broad")
	}
	if err := ValidateInput(e); err == nil {
		t.Error("broad exception without ack should be rejected")
	}
	// 确认风险后允许
	e.RiskAcknowledged = true
	if err := ValidateInput(e); err != nil {
		t.Errorf("broad exception with ack should pass: %v", err)
	}
}

func TestGlobalBroadRejected(t *testing.T) {
	e := &Exception{
		Name:            "全局无条件例外",
		ScopeType:       "GLOBAL",
		ExceptionAction: ActionRemoveRule,
		Status:          "ENABLED",
	}
	if !e.IsBroad() {
		t.Error("global unconditional should be broad")
	}
	if err := ValidateInput(e); err == nil {
		t.Error("global broad should be rejected")
	}
}

func TestTemporaryRequiresExpiry(t *testing.T) {
	e := preciseException()
	e.IsTemporary = true
	e.EffectiveUntil = nil
	if err := ValidateInput(e); err == nil {
		t.Error("temporary without expiry should be rejected")
	}
	now := time.Now()
	later := now.Add(24 * time.Hour)
	e.EffectiveFrom = &now
	e.EffectiveUntil = &later
	if err := ValidateInput(e); err != nil {
		t.Errorf("temporary with expiry should pass: %v", err)
	}
}

func TestInvalidTimeRange(t *testing.T) {
	e := preciseException()
	now := time.Now()
	earlier := now.Add(-time.Hour)
	e.EffectiveFrom = &now
	e.EffectiveUntil = &earlier
	if err := ValidateInput(e); err == nil {
		t.Error("invalid time range should be rejected")
	}
}

func TestInvalidSourceIP(t *testing.T) {
	e := preciseException()
	e.SourceIPs = []string{"not-an-ip"}
	if err := ValidateInput(e); err == nil {
		t.Error("invalid source ip should be rejected")
	}
	e.SourceIPs = []string{"192.0.2.0/24"}
	if err := ValidateInput(e); err != nil {
		t.Errorf("valid CIDR should pass: %v", err)
	}
}

func TestGenerateSecLangPrecise(t *testing.T) {
	e := preciseException()
	e.ID = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	e.Version = 1
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(gen, "id:8000001") {
		t.Errorf("generated missing marker rule id: %s", gen)
	}
	if !strings.Contains(gen, "942100") {
		t.Errorf("generated missing target rule id: %s", gen)
	}
	if !strings.Contains(gen, "ARGS:content") {
		t.Errorf("generated missing param: %s", gen)
	}
	// 前缀按路径段边界匹配（旧 beginsWith 会把 /api/richtext2 一并放行）
	if !strings.Contains(gen, `@rx ^/api/richtext(?:/|$)`) {
		t.Errorf("prefix exception should use segment-boundary regex: %s", gen)
	}
}

func TestGenerateSecLangEscapes(t *testing.T) {
	e := preciseException()
	e.URIExact = "/api/x\"injection"
	e.URIPrefix = ""
	gen, err := GenerateSecLang(e, 8000001)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(gen, `x"injection"`) && !strings.Contains(gen, `\"`) {
		t.Error("quote should be escaped")
	}
}

// TestURIFieldsRejectControlChars 回归：URIExact/URIPrefix/URIRegex 曾无控制字符校验，
// escapeArg 只转义 \ 与 "，换行即可在 before-crs 段注入独立 SecLang 指令行。
func TestURIFieldsRejectControlChars(t *testing.T) {
	inject := "/api/ok\nSecAction \"ctl:ruleEngine=Off\""
	for _, set := range []func(e *Exception){
		func(e *Exception) { e.URIExact = inject },
		func(e *Exception) { e.URIPrefix = inject },
		func(e *Exception) { e.URIRegex = inject },
	} {
		e := preciseException()
		e.URIPrefix = ""
		set(e)
		if err := ValidateInput(e); err == nil {
			t.Error("URI field with newline should be rejected")
		}
	}
	// DEL 与其他控制字符同样拒绝
	e := preciseException()
	e.URIExact = "/api/\x01x"
	if err := ValidateInput(e); err == nil {
		t.Error("URI field with control char should be rejected")
	}
	e = preciseException()
	e.URIExact = "/api/x\x7f"
	if err := ValidateInput(e); err == nil {
		t.Error("URI field with DEL should be rejected")
	}
}

// TestURIFieldsLengthLimit URI 字段长度上限（2048）。
func TestURIFieldsLengthLimit(t *testing.T) {
	e := preciseException()
	e.URIPrefix = ""
	e.URIExact = "/" + strings.Repeat("a", MaxURILen)
	if err := ValidateInput(e); err == nil {
		t.Error("overlong URIExact should be rejected")
	}
	e.URIExact = "/" + strings.Repeat("a", MaxURILen-10)
	if err := ValidateInput(e); err != nil {
		t.Errorf("URI within limit should pass: %v", err)
	}
}

// TestEscapeArgStripsControlChars 兜底：修复前已入库的数据在发布生成时剥离控制字符。
func TestEscapeArgStripsControlChars(t *testing.T) {
	if got := escapeArg("/a\nb\r\tc"); got != "/abc" {
		t.Errorf("escapeArg should strip control chars, got %q", got)
	}
	if got := escapeArg(`/a\b"c`); got != `/a\\b\"c` {
		t.Errorf("escapeArg should escape backslash and quote, got %q", got)
	}
}

// TestJSONHelpersRoundTrip 回归：jsonArray/parseStrArray 曾不转义反斜杠、按逗号裸切分。
func TestJSONHelpersRoundTrip(t *testing.T) {
	values := []string{`p\ath`, "a,b", `q"q`, "普通值"}
	got := parseStrArray([]byte(jsonArray(values)))
	if len(got) != len(values) {
		t.Fatalf("round trip length = %d, want %d (%v)", len(got), len(values), got)
	}
	for i := range values {
		if got[i] != values[i] {
			t.Errorf("round trip[%d] = %q, want %q", i, got[i], values[i])
		}
	}
	ints := []int{942100, 941160}
	gotInts := parseIntArray([]byte(jsonIntArray(ints)))
	if len(gotInts) != len(ints) || gotInts[0] != ints[0] || gotInts[1] != ints[1] {
		t.Errorf("int round trip = %v, want %v", gotInts, ints)
	}
	if got := parseStrArray([]byte(jsonArray(nil))); got != nil {
		t.Errorf("empty should round trip to nil, got %v", got)
	}
	if got := parseIntArray([]byte(jsonIntArray(nil))); got != nil {
		t.Errorf("empty ints should round trip to nil, got %v", got)
	}
}

func TestCompilePreviewContent(t *testing.T) {
	e := preciseException()
	e.ID = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	e.Version = 3
	secLang, apiPayload, compileErr := CompilePreviewContent(e, nil)
	if compileErr != "" || apiPayload != nil {
		t.Fatalf("unexpected apiPayload=%v compileErr=%q", apiPayload, compileErr)
	}
	if !strings.Contains(secLang, "id:8000001") || !strings.Contains(secLang, "ctl:ruleRemoveTargetById=942100;ARGS:content") {
		t.Errorf("unexpected SecLang: %s", secLang)
	}

	// REMOVE_RULE_TAG 草稿通过 resolvedOverride 展开预览 SecLang
	tagExc := &Exception{
		ID:              e.ID,
		Version:         1,
		URIExact:        "/api/search",
		RuleTags:        []string{"attack-sqli"},
		ExceptionAction: ActionRemoveRuleTag,
	}
	secLang, _, compileErr = CompilePreviewContent(tagExc, []int{942100, 942110})
	if compileErr != "" {
		t.Fatalf("tag exception preview compileErr=%q", compileErr)
	}
	if !strings.Contains(secLang, "ctl:ruleRemoveById=942100") || !strings.Contains(secLang, "ctl:ruleRemoveById=942110") {
		t.Errorf("expected resolved rule IDs in SecLang: %s", secLang)
	}

	// 不支持动作返回明确 compileErr
	badExc := preciseException()
	badExc.ExceptionAction = ActionLogOnly
	secLang, _, compileErr = CompilePreviewContent(badExc, nil)
	if secLang != "" || compileErr == "" {
		t.Errorf("expected compileErr for LOG_ONLY, got secLang=%q err=%q", secLang, compileErr)
	}

	// API 引擎返回编译后 JSON 契约对象
	apiExc := &Exception{
		ID:              e.ID,
		Version:         2,
		TargetEngine:    EngineAPI,
		Domain:          "API.Example.com",
		URIExact:        "/v1/orders",
		Methods:         []string{"post", "get"},
		ExceptionAction: ActionObserveRule,
		APIRuleRefs:     []APIRuleRef{{DetectorID: "schema", RuleID: "schema.type_mismatch"}},
	}
	secLang, apiPayload, compileErr = CompilePreviewContent(apiExc, nil)
	if secLang != "" || compileErr != "" || apiPayload == nil {
		t.Fatalf("expected apiPayload, got secLang=%q payload=%v err=%q", secLang, apiPayload, compileErr)
	}
	if apiPayload["domain"] != "api.example.com" {
		t.Errorf("normalized domain = %v", apiPayload["domain"])
	}
}
