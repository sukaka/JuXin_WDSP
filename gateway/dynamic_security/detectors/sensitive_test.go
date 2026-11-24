package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func defaultPatterns(t *testing.T) []CompiledSensitivePattern {
	t.Helper()
	p, err := CompileSensitivePatterns(nil)
	if err != nil {
		t.Fatalf("compile default patterns: %v", err)
	}
	return p
}

func TestSensitive_JSONFieldMatch(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{JSONFields: map[string]string{
		"user.phone":   "string",
		"user.address": "string",
		"amount":       "number",
	}}
	CheckSensitiveData(ctx, p, defaultPatterns(t), nil)
	m := findMatch(ctx, "sensitive.field")
	if m == nil {
		t.Fatalf("expected SENSITIVE_FIELD, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 10 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["data_type"] != "phone" || m.Evidence["location"] != "json" || m.Evidence["field"] != "user.phone" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 字段名词表命中：置信度取检测器默认 0.8（未显式设置）
	if m.Confidence != 0.8 {
		t.Fatalf("field-name match confidence must default to 0.8, got %v", m.Confidence)
	}
	if ctx.MatchCount() != 1 {
		t.Fatalf("benign fields must not match, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_QueryMatchIsBlockClass(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{Query: map[string]string{"id_card": "110101**********34", "page": "1"}}
	CheckSensitiveData(ctx, p, defaultPatterns(t), nil)
	m := findMatch(ctx, "sensitive.in_query")
	if m == nil {
		t.Fatalf("expected SENSITIVE_IN_QUERY, got %+v", ctx.CopyMatches())
	}
	if m.Category != "BLOCK" || m.Severity != "HIGH" || m.ScoreDelta != 40 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["location"] != "query" || m.Evidence["data_type"] != "id_card" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 值不得出现在证据中
	for _, v := range m.Evidence {
		if strings.Contains(v, "110101") {
			t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestSensitive_NoMatchOnBenignNames(t *testing.T) {
	// 负例：常见易误伤命名（含 tel/pan/mail/phone/mobile 子串但非敏感字段）不得命中
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		JSONFields: map[string]string{
			"hotel_name":   "string",
			"company":      "string",
			"panel_id":     "number",
			"mailer":       "string",
			"mailinglist":  "string",
			"emailer":      "string",
			"emailing":     "bool",
			"pipermail":    "string",
			"blackmail":    "string",
			"voicemail":    "string",
			"microphone":   "string",
			"smartphone":   "string",
			"automobile":   "string",
			"telemetry":    "string",
			"userEmailer":  "string",
			"MAILING_LIST": "string",
		},
		FormFields: map[string]string{"title": "string", "content": "string"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("benign fields must not match, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_TruePositiveNamingVariants(t *testing.T) {
	patterns := defaultPatterns(t)
	cases := []struct {
		field string
		want  string
	}{
		{"phone", "phone"},
		{"phones", "phone"},
		{"user_phone", "phone"},
		{"buyer.phone", "phone"},
		{"userPhone", "phone"},
		{"phoneNumber", "phone"},
		{"telephone", "phone"},
		{"cellphone", "phone"},
		{"mobile", "phone"},
		{"mobile_no", "phone"},
		{"userMobile", "phone"},
		{"mobileNumber", "phone"},
		{"x-user-mobile", "phone"},
		{"tel", "phone"},
		{"user.address.tel", "phone"},
		{"userTel", "phone"},
		{"telNo", "phone"},
		{"shouji", "phone"},
		{"email", "email"},
		{"emails", "email"},
		{"e_mail", "email"},
		{"e-mail", "email"},
		{"user_email", "email"},
		{"USER_EMAIL", "email"},
		{"userEmail", "email"},
		{"userEmailAddress", "email"},
		{"emailAddress", "email"},
		{"mail", "email"},
		{"user_mail", "email"},
		{"userMail", "email"},
		{"mailAddress", "email"},
		{"youxiang", "email"},
	}
	for _, tc := range cases {
		got, ok := MatchSensitiveDataType(tc.field, patterns)
		if !ok || got != tc.want {
			t.Errorf("MatchSensitiveDataType(%q) = (%q, %v), want (%q, true)", tc.field, got, ok, tc.want)
		}
	}
}

func TestSensitive_FormAndXMLAndChinese(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		FormFields: map[string]string{"password": "string"},
		XMLFields:  map[string]string{"root.shouji": "string"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), nil)
	var formHit, xmlHit bool
	for _, m := range ctx.CopyMatches() {
		if m.Evidence["location"] == "form" && m.Evidence["data_type"] == "credential" {
			formHit = true
		}
		if m.Evidence["location"] == "xml" && m.Evidence["data_type"] == "phone" {
			xmlHit = true
		}
	}
	if !formHit || !xmlHit {
		t.Fatalf("form/xml matches missing: %+v", ctx.CopyMatches())
	}
}

func TestSensitive_CustomPatternsOverride(t *testing.T) {
	patterns, err := CompileSensitivePatterns([]SensitivePattern{
		{DataType: "internal_id", Pattern: `(?i)^biz_secret_`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	// 自定义表覆盖默认：phone 不再命中，biz_secret_ 命中
	p := &parser.Parsed{JSONFields: map[string]string{"phone": "string", "biz_secret_no": "string"}}
	CheckSensitiveData(ctx, p, patterns, nil)
	m := findMatch(ctx, "sensitive.field")
	if m == nil || m.Evidence["data_type"] != "internal_id" {
		t.Fatalf("custom pattern should match, got %+v", ctx.CopyMatches())
	}
	if ctx.MatchCount() != 1 {
		t.Fatalf("default patterns must be replaced, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_BadPatternReturnsError(t *testing.T) {
	if _, err := CompileSensitivePatterns([]SensitivePattern{{DataType: "x", Pattern: "([unclosed"}}); err == nil {
		t.Fatal("bad regex must return error (no silent swallow)")
	}
	if _, err := CompileSensitivePatterns([]SensitivePattern{{DataType: "", Pattern: "x"}}); err == nil {
		t.Fatal("empty data_type must return error")
	}
}

func TestSensitive_NilParsedNoPanic(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckSensitiveData(ctx, nil, defaultPatterns(t), nil)
	if ctx.MatchCount() != 0 {
		t.Fatal("nil parsed must produce no match")
	}
}

// ---------- 值级敏感检测（发布通道 api_sensitive_value_rules） ----------

func phoneValueRules(t *testing.T) []CompiledSensitiveValueRule {
	t.Helper()
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "json", "form", "header", "path"}, Level: "SENSITIVE"},
	})
	if err != nil {
		t.Fatalf("compile value rules: %v", err)
	}
	return rules
}

func TestSensitiveValue_QueryHitIsBlockClass(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	// 字段名不命中词表（contact 不在默认表），仅值命中
	p := &parser.Parsed{Query: map[string]string{"contact": "13800138000", "page": "1"}}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	m := findMatch(ctx, "sensitive.value_in_query")
	if m == nil {
		t.Fatalf("expected sensitive.value_in_query, got %+v", ctx.CopyMatches())
	}
	if m.Category != "BLOCK" || m.Severity != "HIGH" || m.ScoreDelta != 40 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["data_type"] != "phone" || m.Evidence["location"] != "query" || m.Evidence["level"] != "SENSITIVE" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 值级正则验证命中：置信度显式 1.0（确定性判定）
	if m.Confidence != 1.0 {
		t.Fatalf("value-level match confidence must be 1.0, got %v", m.Confidence)
	}
	// 证据绝不含值
	for _, v := range m.Evidence {
		if strings.Contains(v, "13800138000") {
			t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestSensitiveValue_JSONAndFormHitObserve(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		JSONValues: map[string]string{"addr1": "13912345678"},
		FormValues: map[string]string{"addr2": "13711112222"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	var jsonHit, formHit bool
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "sensitive.value" {
			t.Fatalf("non-query value hit must use sensitive.value, got %+v", m)
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
			t.Fatalf("bad attrs: %+v", m)
		}
		if m.Confidence != 1.0 {
			t.Fatalf("value-level match confidence must be 1.0, got %+v", m)
		}
		switch m.Evidence["location"] {
		case "json":
			jsonHit = true
		case "form":
			formHit = true
		}
		for _, v := range m.Evidence {
			if strings.Contains(v, "13912345678") || strings.Contains(v, "13711112222") {
				t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
			}
		}
	}
	if !jsonHit || !formHit {
		t.Fatalf("json/form value hits missing: %+v", ctx.CopyMatches())
	}
}

func TestSensitiveValue_NoMatchOnBenignValue(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Query:      map[string]string{"contact": "10086"}, // 非手机号形态
		JSONValues: map[string]string{"note": "hello world"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	if ctx.MatchCount() != 0 {
		t.Fatalf("benign values must not match, got %+v", ctx.CopyMatches())
	}
}

func TestSensitiveValue_LocationScopeRespected(t *testing.T) {
	// 规则仅声明 json 位置：query 中的同形态值不得命中
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{Query: map[string]string{"contact": "13800138000"}}
	CheckSensitiveData(ctx, p, defaultPatterns(t), rules)
	if ctx.MatchCount() != 0 {
		t.Fatalf("rule without query location must not match query value, got %+v", ctx.CopyMatches())
	}
}

func TestSensitiveValue_HeaderNameAndValue(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{Headers: map[string]string{
		"x-phone":        "13800138000", // 名称 + 值双命中
		"x-batch":        "13912345678", // 仅值命中
		"authorization":  "[redacted]",  // 脱敏头：跳过
		"cookie":         "[redacted]",  // cookie 整头脱敏：跳过
		"content-length": "123",
	}}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	var nameHit, valueHit, batchHit bool
	for _, m := range ctx.CopyMatches() {
		if m.Evidence["location"] != "header" {
			t.Fatalf("unexpected location: %+v", m)
		}
		if m.RuleID == "sensitive.field" && m.Evidence["field"] == "x-phone" {
			nameHit = true
		}
		if m.RuleID == "sensitive.value" && m.Evidence["field"] == "x-phone" {
			valueHit = true
		}
		if m.RuleID == "sensitive.value" && m.Evidence["field"] == "x-batch" {
			batchHit = true
		}
		for _, v := range m.Evidence {
			if strings.Contains(v, "13800138000") || strings.Contains(v, "13912345678") {
				t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
			}
		}
	}
	if !nameHit || !valueHit || !batchHit {
		t.Fatalf("header hits missing: name=%v value=%v batch=%v, %+v", nameHit, valueHit, batchHit, ctx.CopyMatches())
	}
}

func TestSensitiveValue_PathSegmentHit(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		RawPath:        "/user/13800138000/detail",
		NormalizedPath: "/user/{id}/detail",
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	m := findMatch(ctx, "sensitive.value")
	if m == nil {
		t.Fatalf("expected path value hit, got %+v", ctx.CopyMatches())
	}
	if m.Evidence["location"] != "path" || m.Evidence["field"] != "{id}" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	for _, v := range m.Evidence {
		if strings.Contains(v, "13800138000") {
			t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestSensitiveValue_PathLiteralSegmentValueUsesIndex(t *testing.T) {
	// 字面段（归一化保留原文）值命中时证据用段序号，不落段文本
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		RawPath:        "/profile/13800138000a/home",
		NormalizedPath: "/profile/13800138000a/home", // 含字母非 numeric，归一化保留字面
	}
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}a$`, Locations: []string{"path"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), rules)
	m := findMatch(ctx, "sensitive.value")
	if m == nil {
		t.Fatalf("expected path value hit, got %+v", ctx.CopyMatches())
	}
	if m.Evidence["field"] != "segment[1]" {
		t.Fatalf("literal segment value hit must use segment index, got %+v", m.Evidence)
	}
	for _, v := range m.Evidence {
		if strings.Contains(v, "13800138000a") {
			t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestSensitiveValue_PathLiteralSegmentDoesNotEmitFieldNoise(t *testing.T) {
	// URL 路径字面段仅代表路由或文件名（含备份压缩包扫描探测与业务路由词根），
	// 不得产出 sensitive.field 误报；真实路径值级匹配由 TestSensitiveValue_PathSegmentHit 独立覆盖。
	for _, rawPath := range []string{
		"/mobile.zip",
		"/mailer.zip",
		"/remind_password.zip",
		"/mailinglist.zip",
		"/emailer.zip",
		"/emailing.zip",
		"/phones.zip",
		"/mails.zip",
		"/pipermail.zip",
		"/api/id_card/lookup",
		"/v1/auth/reset-password",
	} {
		ctx := dsctx.New("t-path-noise", dsctx.DefaultParseLimits())
		p := &parser.Parsed{
			RawPath:        rawPath,
			NormalizedPath: rawPath,
		}
		CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
		if ctx.MatchCount() != 0 {
			t.Fatalf("path %q must not emit field-name noise, got %+v", rawPath, ctx.CopyMatches())
		}
	}
}

func TestSensitiveValue_InputLengthCap(t *testing.T) {
	rules := phoneValueRules(t)
	scans := 0
	// 超过 4096 字符的值被截断后参与匹配：尾部手机号截掉不得命中
	long := strings.Repeat("a", maxSensitiveValueInputLen) + "13800138000"
	if _, ok := matchValueRules(long, "json", rules, &scans); ok {
		t.Fatal("value beyond 4096 chars must be truncated before match")
	}
	// 4096 以内正常命中
	if _, ok := matchValueRules("13800138000", "json", rules, &scans); !ok {
		t.Fatal("value within cap must match")
	}
}

func TestSensitiveValue_ScanCountCap(t *testing.T) {
	rules := phoneValueRules(t)
	scans := maxSensitiveValueScans // 预算耗尽
	if _, ok := matchValueRules("13800138000", "json", rules, &scans); ok {
		t.Fatal("scan budget exhausted must not evaluate")
	}
	// 扫描计数随求值递增
	scans = 0
	_, _ = matchValueRules("x", "json", rules, &scans)
	if scans != 1 {
		t.Fatalf("scan counter must increment per evaluation, got %d", scans)
	}
}

func TestSensitiveValue_MatchCountCap(t *testing.T) {
	// 30 个全命中 query 键：值级命中同样受 maxSensitiveMatches 总预算封顶
	query := map[string]string{}
	for i := 0; i < 30; i++ {
		query[strings.Repeat("q", 4)+string(rune('a'+i%26))+strings.Repeat("0", i%3)+string(rune('a'+i))] = "13800138000"
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckSensitiveData(ctx, &parser.Parsed{Query: query}, defaultPatterns(t), phoneValueRules(t))
	if ctx.MatchCount() > maxSensitiveMatches {
		t.Fatalf("matches must be capped at %d, got %d", maxSensitiveMatches, ctx.MatchCount())
	}
}

func TestSensitiveValue_BadRuleRejected(t *testing.T) {
	if _, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "x", Regex: "([bad", Locations: []string{"query"}}}); err == nil {
		t.Fatal("bad regex must return error (no silent swallow)")
	}
	if _, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "", Regex: "x", Locations: []string{"query"}}}); err == nil {
		t.Fatal("empty data_type must return error")
	}
	if _, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "x", Regex: "", Locations: []string{"query"}}}); err == nil {
		t.Fatal("empty regex must return error")
	}
	if _, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "x", Regex: strings.Repeat("a", maxSensitiveValueRegexLen+1), Locations: []string{"query"}}}); err == nil {
		t.Fatal("oversized regex must return error")
	}
}

func TestSensitiveValue_UnsupportedLocationsSkipped(t *testing.T) {
	// 仅 cookie/response_body/xml 位置的规则无请求侧可用位置，编译时跳过
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "token", Regex: `^eyJ`, Locations: []string{"cookie", "response_body"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules without request-side locations must be skipped, got %d", len(rules))
	}
	// 混合位置保留请求侧子集
	rules, err = CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "jwt", Regex: `^eyJ`, Locations: []string{"query", "cookie"}},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(rules) != 1 || !rules[0].locations["query"] || rules[0].locations["cookie"] {
		t.Fatalf("locations must be filtered to request-side subset, got %+v", rules)
	}
}

func TestSensitiveValue_NilRulesZeroChange(t *testing.T) {
	// 无值级规则：HEADER/PATH 不参与任何检测（与历史行为一致）
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Headers:        map[string]string{"x-phone": "13800138000"},
		RawPath:        "/user/13800138000",
		NormalizedPath: "/user/{id}",
		Query:          map[string]string{"contact": "13800138000"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("nil value rules must keep legacy behavior (no header/path/value scan), got %+v", ctx.CopyMatches())
	}
}

// scanValueLevel 事件确定性：map 键序排序遍历，命中明细按字段名序产出（map 遍历序抖动修复）。
func TestSensitiveValue_DeterministicOrder(t *testing.T) {
	want := []string{"a-contact", "m-contact", "z-contact"}
	for i := 0; i < 8; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		p := &parser.Parsed{Query: map[string]string{
			"z-contact": "13800138000",
			"a-contact": "13912345678",
			"m-contact": "13711112222",
		}}
		CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
		ms := ctx.CopyMatches()
		if len(ms) != 3 {
			t.Fatalf("run %d: want 3 matches, got %+v", i, ms)
		}
		for j, m := range ms {
			if m.RuleID != "sensitive.value_in_query" {
				t.Fatalf("run %d: unexpected rule: %+v", i, m)
			}
			if m.Evidence["field"] != want[j] {
				t.Fatalf("run %d: field[%d] = %q, want %q (all: %+v)", i, j, m.Evidence["field"], want[j], ms)
			}
		}
	}
}

func TestSensitive_StandardBrowserHeadersDoNotFalsePositive(t *testing.T) {
	ctx := dsctx.New("t-headers", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="124"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"sec-fetch-mode":            "navigate",
			"sec-websocket-key":         "dGhlIHNhbXBsZSBub25jZQ==",
			"user-agent":                "Mozilla/5.0 Mobile Safari/537.36",
			"accept-encoding":           "gzip, deflate, br",
			"x-forwarded-for":           "1.2.3.4",
			"upgrade-insecure-requests": "1",
		},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), phoneValueRules(t))
	if ctx.MatchCount() != 0 {
		t.Fatalf("standard browser/HTTP protocol headers must not trigger false-positive sensitive hits: %+v", ctx.CopyMatches())
	}
}

func TestSensitive_ExcludeFieldsRespectedForNameAndValue(t *testing.T) {
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{{
		DataType:      "phone",
		Regex:         `^1[3-9]\d{9}$`,
		Locations:     []string{"json", "query"},
		Level:         "SENSITIVE",
		ExcludeFields: []string{"phone_verified", "test_skip_phone"},
	}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := dsctx.New("t-exclude", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		JSONFields: map[string]string{
			"user.phone_verified": "bool",
			"user.has_phone":      "bool",
			"user.is_phone":       "bool",
			"user.email_verified": "bool",
			"token_type":          "string",
			"password_strength":   "number",
		},
		JSONValues: map[string]string{
			"user.test_skip_phone": "13800138000",
			"user.contact":         "13912345678",
		},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), rules)
	matches := ctx.CopyMatches()
	if len(matches) != 1 {
		t.Fatalf("only non-excluded value hit expected, got %+v", matches)
	}
	if matches[0].RuleID != "sensitive.value" || matches[0].Evidence["field"] != "user.contact" ||
		matches[0].Evidence["masked_sample"] != "139****5678" {
		t.Fatalf("unexpected match: %+v", matches[0])
	}
}

func TestSensitiveValue_MaskedSampleEmittedWithoutPlaintext(t *testing.T) {
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `1[3-9]\d{9}`, Locations: []string{"json", "query"}, Level: "SENSITIVE"},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := dsctx.New("t-masked", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Query:      map[string]string{"note": "请联系13800138000处理"},
		JSONValues: map[string]string{"desc": "电话: 13912345678"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t), rules)
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("want 2 value matches, got %+v", matches)
	}
	gotSamples := map[string]string{}
	for _, m := range matches {
		gotSamples[m.Evidence["location"]] = m.Evidence["masked_sample"]
		for _, v := range m.Evidence {
			if strings.Contains(v, "13800138000") || strings.Contains(v, "13912345678") {
				t.Fatalf("raw plaintext leaked into evidence: %+v", m.Evidence)
			}
		}
	}
	if gotSamples["query"] != "138****8000" || gotSamples["json"] != "139****5678" {
		t.Fatalf("masked samples = %+v", gotSamples)
	}
}
