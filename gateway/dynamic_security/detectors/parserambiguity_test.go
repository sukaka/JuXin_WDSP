package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// parsedWithAmbiguities 构造覆盖四种位置的歧义解析产物（只含名/位置/次数，无值）。
func parsedWithAmbiguities() *parser.Parsed {
	return &parser.Parsed{Ambiguities: []parser.ParamAmbiguity{
		{Location: parser.AmbLocationQuery, ParameterName: "id", ValueCount: 3},
		{Location: parser.AmbLocationHeader, ParameterName: "x-dup", ValueCount: 2},
		{Location: parser.AmbLocationForm, ParameterName: "name", ValueCount: 2},
		{Location: parser.AmbLocationJSON, ParameterName: "count", ValueCount: 2, Path: "count"},
	}}
}

// 规则矩阵：四种位置各产一条 finding，detector=api_parser（红线：不复用 api_schema），
// OBSERVE/MEDIUM/ScoreDelta<50，规则码与版本随 Message/Evidence 携带。
func TestCheckParserAmbiguityFindings(t *testing.T) {
	ctx := dsctx.New("r-pa", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx, parsedWithAmbiguities())

	wantRules := map[string]string{ // rule_id → 文档规则码
		"parser.duplicate_json_key":    "PARSER-DUP-JSON-001",
		"parser.duplicate_query_param": "PARSER-DUP-QUERY-001",
		"parser.duplicate_header":      "PARSER-DUP-HEADER-001",
		"parser.duplicate_form_param":  "PARSER-DUP-FORM-001",
	}
	matches := ctx.CopyMatches()
	if len(matches) != len(wantRules) {
		t.Fatalf("want %d findings, got %+v", len(wantRules), matches)
	}
	for _, m := range matches {
		code, ok := wantRules[m.RuleID]
		if !ok {
			t.Fatalf("unexpected rule %q: %+v", m.RuleID, m)
		}
		delete(wantRules, m.RuleID)
		if m.Detector != "api_parser" {
			t.Errorf("%s detector = %q, want api_parser (api_schema 会实断，红线)", m.RuleID, m.Detector)
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Errorf("%s category/severity = %s/%s, want OBSERVE/MEDIUM", m.RuleID, m.Category, m.Severity)
		}
		if m.ScoreDelta <= 0 || m.ScoreDelta >= 50 {
			t.Errorf("%s score_delta = %d, want 0<x<50（决策引擎 ≥50 分支不得触发）", m.RuleID, m.ScoreDelta)
		}
		if m.Confidence != 1.0 {
			t.Errorf("%s confidence = %v, want 1.0（解析事实默认置信度）", m.RuleID, m.Confidence)
		}
		if m.Evidence["rule_code"] != code {
			t.Errorf("%s evidence rule_code = %q, want %q", m.RuleID, m.Evidence["rule_code"], code)
		}
		if !strings.Contains(m.Message, code) || !strings.Contains(m.Message, "v1.0.0") {
			t.Errorf("%s message must carry rule code + version, got %q", m.RuleID, m.Message)
		}
		// 证据键白名单：只含元信息键，禁止 raw_value/normalized_value 等原始值键
		for k := range m.Evidence {
			switch k {
			case "parameter_name", "location", "value_count", "rule_code", "path":
			default:
				t.Errorf("%s unexpected evidence key %q: %+v", m.RuleID, k, m.Evidence)
			}
		}
	}
	if len(wantRules) != 0 {
		t.Fatalf("missing rules: %v (all: %+v)", wantRules, matches)
	}
	// JSON 歧义携带路径；query 携带总次数
	for _, m := range matches {
		switch m.RuleID {
		case "parser.duplicate_json_key":
			if m.Evidence["path"] != "count" || m.Evidence["parameter_name"] != "count" {
				t.Errorf("json evidence broken: %+v", m.Evidence)
			}
		case "parser.duplicate_query_param":
			if m.Evidence["value_count"] != "3" || m.Evidence["location"] != "query" {
				t.Errorf("query evidence broken: %+v", m.Evidence)
			}
		}
	}
}

// 红线断言：歧义 finding 在 PROTECT 模式下定案 OBSERVE，绝不实断 BLOCK
// （api_parser 非可信阻断源，OBSERVE 类 + ScoreDelta<50 双保险）。
func TestCheckParserAmbiguityNeverBlocks(t *testing.T) {
	ctx := dsctx.New("r-pa-decide", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx, parsedWithAmbiguities())
	act := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect})
	if act != dsctx.ActionObserve {
		t.Fatalf("PROTECT final = %s, want OBSERVE（歧义规则默认观测）", act)
	}
	if act == dsctx.ActionBlock {
		t.Fatal("parser ambiguity must never finalize BLOCK")
	}
}

// 事件确定性：乱序/重复执行产出相同 finding 序（query/header 采集自 map 迭代，检测器排序兜底）。
func TestCheckParserAmbiguityDeterministicOrder(t *testing.T) {
	base := parsedWithAmbiguities().Ambiguities
	reversed := make([]parser.ParamAmbiguity, len(base))
	for i, a := range base {
		reversed[len(base)-1-i] = a
	}
	var want []string
	for run, ambs := range [][]parser.ParamAmbiguity{base, reversed, base, reversed} {
		ctx := dsctx.New("r-pa-det", dsctx.DefaultParseLimits())
		CheckParserAmbiguity(ctx, &parser.Parsed{Ambiguities: ambs})
		var got []string
		for _, m := range ctx.CopyMatches() {
			got = append(got, m.RuleID+"|"+m.Evidence["parameter_name"])
		}
		if run == 0 {
			want = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("run %d order %v != %v", run, got, want)
		}
	}
}

// 未知位置词表宽容跳过（解析层只写 AmbLocation* 词表；防御未来词表膨胀）。
func TestCheckParserAmbiguityUnknownLocation(t *testing.T) {
	ctx := dsctx.New("r-pa-unknown", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx, &parser.Parsed{Ambiguities: []parser.ParamAmbiguity{
		{Location: "cookie", ParameterName: "sid", ValueCount: 2},
	}})
	if ctx.MatchCount() != 0 {
		t.Fatalf("unknown location must be skipped: %+v", ctx.CopyMatches())
	}
}

// nil/空输入安全。
func TestCheckParserAmbiguityNilSafety(t *testing.T) {
	p := parsedWithAmbiguities()
	CheckParserAmbiguity(nil, p)
	ctx := dsctx.New("r-pa-nil", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx, nil)
	CheckParserAmbiguity(ctx, &parser.Parsed{})
	if ctx.MatchCount() != 0 {
		t.Fatal("nil inputs must produce no match")
	}
}

// 字段数截断可见性（MED-4 回归）：Query/Body 配额截断（QueryCapped/FieldCapped）产一条
// parser.field_count_capped OBSERVE 明细——截断事实必须进事件流（原只落 ctx 字段无消费方，
// ≥MaxFieldCount 个 distinct query 键挤占配额的攻击在事件流不可见）。
func TestCheckParserAmbiguityFieldCountCapped(t *testing.T) {
	// 双向同时截断：一条明细，location 证据含 query,body
	ctx := dsctx.New("r-pa-cap", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx, &parser.Parsed{QueryCapped: true, FieldCapped: true})
	ms := ctx.CopyMatches()
	if len(ms) != 1 {
		t.Fatalf("want 1 capped finding, got %+v", ms)
	}
	m := ms[0]
	if m.Detector != "api_parser" || m.RuleID != "parser.field_count_capped" ||
		m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("bad capped finding meta: %+v", m)
	}
	if m.ScoreDelta <= 0 || m.ScoreDelta >= 50 {
		t.Fatalf("score_delta = %d, want 0<x<50（单条永不抬为阻断）", m.ScoreDelta)
	}
	if m.Evidence["location"] != "query,body" || m.Evidence["rule_code"] != "PARSER-FIELD-CAP-001" {
		t.Fatalf("bad capped evidence: %+v", m.Evidence)
	}
	if !strings.Contains(m.Message, "PARSER-FIELD-CAP-001") {
		t.Fatalf("message must carry rule code, got %q", m.Message)
	}

	// 仅 Body 截断；未截断零行为
	ctx2 := dsctx.New("r-pa-cap2", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx2, &parser.Parsed{FieldCapped: true})
	if ms := ctx2.CopyMatches(); len(ms) != 1 || ms[0].Evidence["location"] != "body" {
		t.Fatalf("body-only cap: %+v", ms)
	}
	ctx3 := dsctx.New("r-pa-cap3", dsctx.DefaultParseLimits())
	CheckParserAmbiguity(ctx3, &parser.Parsed{})
	if ctx3.MatchCount() != 0 {
		t.Fatalf("no cap must be zero behavior: %+v", ctx3.CopyMatches())
	}
}
