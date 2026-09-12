// relationagg_test.go 数组聚合关系单测（任务书 §23 数量一致 COUNT_MATCHES / 汇总关系
// SUM_MATCHES）：每类正/反/缺失/截断/类型不符用例；只产 OBSERVE 级信号（PROTECT 下也不
// 阻断）；证据不落明文值与求和结果；配置校验接受新词表。
package detectors

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// parseBodyForAgg 真实解析 JSON body + query 串（端到端用例用 parser 留存口径联动验证）。
func parseBodyForAgg(t *testing.T, body string, limits dsctx.ParseLimits, rawQuery string) *parser.Parsed {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, "http://x/v1/orders?"+rawQuery, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	p, err := parser.ParseRequest(r, dsctx.New("r-agg-e2e", limits))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// countRelation 构造 item_count(QUERY) == items(BODY 数组长度) 数量一致关系。
func countRelation() ParamRelation {
	return ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: RelationTypeCountMatches,
		ParamA:       ParamRelationRef{Location: "QUERY", Name: "item_count"},
		ParamB:       ParamRelationRef{Location: "BODY", Name: "items", Path: "items"},
	}
}

// sumRelation 构造 total(QUERY) == Σ items[].price(BODY) 汇总关系。
func sumRelation() ParamRelation {
	return ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: RelationTypeSumMatches,
		ParamA:       ParamRelationRef{Location: "QUERY", Name: "total"},
		ParamB:       ParamRelationRef{Location: "BODY", Name: "price", Path: "items[].price"},
	}
}

// parsedForAggRelations 构造聚合关系检测用解析产物（QUERY A 值 + BODY 数组留存）。
func parsedForAggRelations(aName, aVal string, arrLen int, agg *parser.NumArrayAgg) *parser.Parsed {
	p := &parser.Parsed{
		Query:        map[string]string{aName: aVal},
		Headers:      map[string]string{},
		JSONFields:   map[string]string{"items": "array"},
		JSONValues:   map[string]string{},
		JSONArrayLen: map[string]int{"items": arrLen},
		JSONNumAgg:   map[string]parser.NumArrayAgg{},
	}
	if agg != nil {
		p.JSONNumAgg["items[].price"] = *agg
	}
	return p
}

// assertAggSignal 断言产生指定规则 OBSERVE 级信号且证据不落明文值/求和结果。
func assertAggSignal(t *testing.T, ctx *dsctx.RequestContext, ruleID string, rawVals ...string) {
	t.Helper()
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != ruleID {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Fatalf("aggregate relation must stay OBSERVE-level: %+v", m)
		}
		if m.Evidence["param_a"] == "" || m.Evidence["param_b"] == "" ||
			m.Evidence["value_a_sha256"] == "" || m.Evidence["param_b_agg_count"] == "" {
			t.Fatalf("evidence incomplete: %+v", m.Evidence)
		}
		for k, v := range m.Evidence {
			if k == "value_a_len" || k == "param_b_agg_count" {
				continue // 长度/计数是任务允许的证据元数据
			}
			for _, raw := range rawVals {
				if raw != "" && (v == raw || (len(raw) >= 6 && strings.Contains(v, raw))) {
					t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
				}
			}
		}
		return
	}
	t.Fatalf("expected %s, got %+v", ruleID, ctx.CopyMatches())
}

// COUNT_MATCHES：一致通过；不一致违例；缺失/类型不符/非 BODY 数组不判定；截断语义由
// 数组长度登记的完整性保证（JSONArrayLen 为完整长度，无截断态）。
func TestCheckAggregateRelationCountMatches(t *testing.T) {
	rel := countRelation()

	// 反：item_count=2 而 items 长 3 → 违例（PROTECT 下也只产信号不阻断）
	ctx := dsctx.New("c1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("item_count", "2", 3, nil), []ParamRelation{rel}, decision.ModeProtect)
	assertAggSignal(t, ctx, "schema.relation_count_matches", "2")

	// 正：item_count=3 == len(items)=3
	ctx = dsctx.New("c2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("item_count", "3", 3, nil), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("matching count must pass, got %+v", ctx.CopyMatches())
	}

	// 边界：零长度数组
	ctx = dsctx.New("c3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("item_count", "0", 0, nil), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("zero count must pass, got %+v", ctx.CopyMatches())
	}

	// 类型不符：A 端非整数（"3.0"/"3.5"/"abc"）→ 不判定
	for _, bad := range []string{"3.0", "3.5", "abc"} {
		ctx = dsctx.New("c4", dsctx.DefaultParseLimits())
		CheckParamRelations(ctx, parsedForAggRelations("item_count", bad, 3, nil), []ParamRelation{rel}, decision.ModeProtect)
		if ctx.MatchCount() != 0 {
			t.Fatalf("non-integer %q must not be judged, got %+v", bad, ctx.CopyMatches())
		}
	}

	// 缺失：A 端缺失 → 不判定（缺失语义归 REQUIRES）
	ctx = dsctx.New("c5", dsctx.DefaultParseLimits())
	p := parsedForAggRelations("item_count", "3", 3, nil)
	delete(p.Query, "item_count")
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing A must not be judged, got %+v", ctx.CopyMatches())
	}

	// 缺失：B 端数组未登记（字段未出现）→ 不判定
	ctx = dsctx.New("c6", dsctx.DefaultParseLimits())
	p = parsedForAggRelations("item_count", "3", 3, nil)
	delete(p.JSONArrayLen, "items")
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing array must not be judged, got %+v", ctx.CopyMatches())
	}

	// 非 BODY 数组引用（QUERY 无数组语义）→ 不判定
	relQ := countRelation()
	relQ.ParamB = ParamRelationRef{Location: "QUERY", Name: "items"}
	ctx = dsctx.New("c7", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("item_count", "2", 3, nil), []ParamRelation{relQ}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-BODY array side must not be judged, got %+v", ctx.CopyMatches())
	}
}

// SUM_MATCHES：一致通过（含浮点容差边界）；不一致违例；截断/超预算/类型不符不判定。
func TestCheckAggregateRelationSumMatches(t *testing.T) {
	rel := sumRelation()
	agg := parser.NumArrayAgg{Sum: 60.75, Count: 3}

	// 反：total=60 ≠ Σ=60.75 → 违例
	ctx := dsctx.New("s1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "60", 3, &agg), []ParamRelation{rel}, decision.ModeProtect)
	assertAggSignal(t, ctx, "schema.relation_sum_matches", "60")

	// 正：total=60.75 == Σ
	ctx = dsctx.New("s2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "60.75", 3, &agg), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("matching sum must pass, got %+v", ctx.CopyMatches())
	}

	// 精度边界：二进制浮点累加误差（0.1+0.2 vs "0.3"）在容差内 → 通过
	fp := parser.NumArrayAgg{Sum: 0.1 + 0.2, Count: 2}
	ctx = dsctx.New("s3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "0.3", 2, &fp), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("float accumulation error within tolerance must pass, got %+v", ctx.CopyMatches())
	}

	// 精度边界：一分钱级真实偏差（100 vs 100.01）远超容差 → 违例
	cent := parser.NumArrayAgg{Sum: 100.01, Count: 2}
	ctx = dsctx.New("s4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "100", 2, &cent), []ParamRelation{rel}, decision.ModeProtect)
	assertAggSignal(t, ctx, "schema.relation_sum_matches")

	// 截断降级：来源数组超上限（Truncated）→ 不判定（半份求和不产信号）
	trunc := parser.NumArrayAgg{Sum: 60.75, Count: 3, Truncated: true}
	ctx = dsctx.New("s5", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "1", 100, &trunc), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("truncated array must not be judged, got %+v", ctx.CopyMatches())
	}

	// 超预算降级：聚合趟 NumAggCapped → 不判定
	ctx = dsctx.New("s6", dsctx.DefaultParseLimits())
	p := parsedForAggRelations("total", "1", 3, &agg)
	p.NumAggCapped = true
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("capped aggregation must not be judged, got %+v", ctx.CopyMatches())
	}

	// 类型不符：A 端非数值 → 不判定
	ctx = dsctx.New("s7", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "abc", 3, &agg), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-numeric A must not be judged, got %+v", ctx.CopyMatches())
	}

	// 缺失：B 端聚合未留存（RetainJSONScalarValues=off 形态 / 路径无数值元素）→ 不判定
	ctx = dsctx.New("s8", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "60.75", 3, nil), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing aggregation must not be judged, got %+v", ctx.CopyMatches())
	}

	// 边界：Count==0（数组无该数值字段）→ 不判定（空和与 0 的巧合比对无意义）
	zero := parser.NumArrayAgg{Sum: 0, Count: 0}
	ctx = dsctx.New("s9", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForAggRelations("total", "0", 3, &zero), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty aggregation must not be judged, got %+v", ctx.CopyMatches())
	}
}

// 聚合关系端到端：ParseRequest 真实解析 → CheckParamRelations 判定（parser 留存口径联动）。
func TestCheckAggregateRelationEndToEnd(t *testing.T) {
	body := `{"items":[{"price":10.5},{"price":20},{"price":30.25}]}`
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	p := parseBodyForAgg(t, body, limits, "total=60.75&item_count=3")
	ctx := dsctx.New("e2e1", limits)
	CheckParamRelations(ctx, p, []ParamRelation{sumRelation(), countRelation()}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("consistent doc must pass, got %+v", ctx.CopyMatches())
	}

	p = parseBodyForAgg(t, body, limits, "total=60&item_count=2")
	ctx = dsctx.New("e2e2", limits)
	CheckParamRelations(ctx, p, []ParamRelation{sumRelation(), countRelation()}, decision.ModeProtect)
	assertAggSignal(t, ctx, "schema.relation_sum_matches", "60")
	assertAggSignal(t, ctx, "schema.relation_count_matches", "2")
}

// ValidateParamRelations：聚合关系两类合法；未知词仍拒绝。
func TestValidateParamRelationsAggregateTypes(t *testing.T) {
	for _, rel := range []ParamRelation{countRelation(), sumRelation()} {
		if err := ValidateParamRelations([]ParamRelation{rel}); err != nil {
			t.Fatalf("%s must pass validation: %v", rel.RelationType, err)
		}
	}
	bad := countRelation()
	bad.RelationType = "ARRAY_MATCHES"
	if err := ValidateParamRelations([]ParamRelation{bad}); err == nil {
		t.Fatal("unknown type must still be rejected")
	}
}
