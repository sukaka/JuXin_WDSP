// relationvalue_test.go 字段间值比较关系单测（任务书 §23 扩展）：
// EQUALS/NOT_EQUALS/GREATER_THAN/LESS_THAN/TIME_BEFORE/TIME_AFTER 每类正/反/类型不符/边界用例；
// 只产 OBSERVE 级信号（PROTECT 下也不阻断）；证据不落明文值；配置校验接受新词表。
package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// valueRelation 构造 QUERY 双参数值比较关系（min_value vs max_value）。
func valueRelation(relType string) ParamRelation {
	return ParamRelation{
		EndpointKey:  "GET /v1/search",
		RelationType: relType,
		ParamA:       ParamRelationRef{Location: "QUERY", Name: "min_value"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "max_value"},
	}
}

// parsedForValueRelations 构造值比较检测用解析产物（QUERY min_value/max_value）。
func parsedForValueRelations(a, b string) *parser.Parsed {
	return &parser.Parsed{
		Query:      map[string]string{"min_value": a, "max_value": b},
		Headers:    map[string]string{},
		JSONFields: map[string]string{},
		JSONValues: map[string]string{},
	}
}

// assertValueSignal 断言产生指定规则 OBSERVE 级信号且证据不落明文值。
func assertValueSignal(t *testing.T, ctx *dsctx.RequestContext, ruleID string, rawVals ...string) {
	t.Helper()
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != ruleID {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Fatalf("value relation must stay OBSERVE-level: %+v", m)
		}
		if m.Evidence["param_a"] == "" || m.Evidence["param_b"] == "" ||
			m.Evidence["value_a_sha256"] == "" || m.Evidence["value_b_sha256"] == "" ||
			m.Evidence["value_a_len"] == "" || m.Evidence["value_b_len"] == "" {
			t.Fatalf("evidence incomplete: %+v", m.Evidence)
		}
		for k, v := range m.Evidence {
			// 长度字段是任务允许的证据元数据（哈希/长度），不参与明文泄漏判定
			if k == "value_a_len" || k == "value_b_len" {
				continue
			}
			for _, raw := range rawVals {
				// 精确相等恒为泄漏；子串判定只对较长值启用
				// （短数字可能与哈希十六进制子串偶然相撞，不构成明文泄漏）
				if raw != "" && (v == raw || (len(raw) >= 6 && strings.Contains(v, raw))) {
					t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
				}
			}
		}
		return
	}
	t.Fatalf("expected %s, got %+v", ruleID, ctx.CopyMatches())
}

// EQUALS：值不等 → 违例；相等 → 通过；单侧缺失 → 不判定；PROTECT 下仍仅 OBSERVE。
func TestCheckValueRelationEquals(t *testing.T) {
	rel := valueRelation(RelationTypeEquals)

	// 反：不等 → 违例（PROTECT 下也只产信号不阻断）
	ctx := dsctx.New("e1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("abc", "abd"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_equals", "abc", "abd")

	// 正：相等 → 无明细
	ctx = dsctx.New("e2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("abc", "abc"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("equal values must pass, got %+v", ctx.CopyMatches())
	}

	// 单侧缺失 → 不判定（缺失语义归 REQUIRES）
	ctx = dsctx.New("e3", dsctx.DefaultParseLimits())
	p := parsedForValueRelations("abc", "abc")
	delete(p.Query, "max_value")
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing side must not be judged, got %+v", ctx.CopyMatches())
	}
}

// GREATER_THAN：a>b 通过；a<b 违例；a==b 违例（严格序边界）；非数值不判定。
func TestCheckValueRelationGreaterThan(t *testing.T) {
	rel := valueRelation(RelationTypeGreaterThan)

	// 正：2 > 1
	ctx := dsctx.New("g1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2", "1"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("2 > 1 must pass, got %+v", ctx.CopyMatches())
	}

	// 反：1 > 2 不成立 → 违例
	ctx = dsctx.New("g2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("1", "2"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_greater_than", "1", "2")

	// 边界：相等 → 违例（严格大于）
	ctx = dsctx.New("g3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2", "2"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_greater_than", "2", "2")

	// 边界：浮点/负数可解析（0.5 > -1 通过）
	ctx = dsctx.New("g4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("0.5", "-1"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("0.5 > -1 must pass, got %+v", ctx.CopyMatches())
	}

	// 类型不符：任一端非数值 → 不判定
	ctx = dsctx.New("g5", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("abc", "2"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-numeric must not be judged, got %+v", ctx.CopyMatches())
	}
}

// LESS_THAN：a<b 通过；a>b 违例；a==b 违例（严格序边界）；非数值不判定。
func TestCheckValueRelationLessThan(t *testing.T) {
	rel := valueRelation(RelationTypeLessThan)

	// 正：1 < 2（任务书示例 min_value <= max_value 的严格形态）
	ctx := dsctx.New("l1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("1", "2"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("1 < 2 must pass, got %+v", ctx.CopyMatches())
	}

	// 反：2 < 1 不成立 → 违例
	ctx = dsctx.New("l2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2", "1"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_less_than", "2", "1")

	// 边界：相等 → 违例（严格小于）
	ctx = dsctx.New("l3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("1", "1"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_less_than", "1", "1")

	// 类型不符：不判定
	ctx = dsctx.New("l4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("1", "xyz"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-numeric must not be judged, got %+v", ctx.CopyMatches())
	}
}

// TIME_BEFORE：A 早于 B 通过；晚于/等于违例（严格序边界）；多种时间格式；非时间不判定。
func TestCheckValueRelationTimeBefore(t *testing.T) {
	rel := valueRelation(RelationTypeTimeBefore)

	// 正：start_time 早于 end_time（RFC3339，任务书示例 start_time <= end_time 的严格形态）
	ctx := dsctx.New("tb1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("earlier time must pass, got %+v", ctx.CopyMatches())
	}

	// 反：A 晚于 B → 违例
	ctx = dsctx.New("tb2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T12:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_time_before", "2026-09-01T12:00:00Z", "2026-09-01T11:00:00Z")

	// 边界：相等 → 违例（严格早于）
	ctx = dsctx.New("tb3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T11:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_time_before")

	// 格式：日期-only 与 "2006-01-02 15:04:05"（UTC）可解析
	ctx = dsctx.New("tb4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01", "2026-09-02 00:00:00"),
		[]ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("date-only/datetime layouts must parse, got %+v", ctx.CopyMatches())
	}

	// 格式：纯数字 Unix 秒（1700000000 < 1800000000 通过）
	ctx = dsctx.New("tb5", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("1700000000", "1800000000"),
		[]ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("unix seconds must parse, got %+v", ctx.CopyMatches())
	}

	// 类型不符：任一端不可解析为时间 → 不判定
	ctx = dsctx.New("tb6", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("not-a-time", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-time must not be judged, got %+v", ctx.CopyMatches())
	}
}

// TIME_AFTER：A 晚于 B 通过；早于/等于违例；非时间不判定。
func TestCheckValueRelationTimeAfter(t *testing.T) {
	rel := valueRelation(RelationTypeTimeAfter)

	// 正：A 晚于 B
	ctx := dsctx.New("ta1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T12:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeObserve)
	if ctx.MatchCount() != 0 {
		t.Fatalf("later time must pass, got %+v", ctx.CopyMatches())
	}

	// 反：A 早于 B → 违例
	ctx = dsctx.New("ta2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeObserve)
	assertValueSignal(t, ctx, "schema.relation_time_after", "2026-09-01T10:00:00Z", "2026-09-01T11:00:00Z")

	// 边界：相等 → 违例（严格晚于）
	ctx = dsctx.New("ta3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T11:00:00Z", "2026-09-01T11:00:00Z"),
		[]ParamRelation{rel}, decision.ModeObserve)
	assertValueSignal(t, ctx, "schema.relation_time_after")

	// 类型不符：不判定
	ctx = dsctx.New("ta4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2026-09-01T11:00:00Z", "soon"),
		[]ParamRelation{rel}, decision.ModeObserve)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-time must not be judged, got %+v", ctx.CopyMatches())
	}
}

// 取值位置语义：BODY 取 JSONValues（未留存标量值时不判定）；HEADER 脱敏值不判定；
// COOKIE 恒不可取；PATH 占位段可取值。
func TestCheckValueRelationValueSources(t *testing.T) {
	// BODY：JSONValues 留存标量值时可判定
	rel := ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: RelationTypeGreaterThan,
		ParamA:       ParamRelationRef{Location: "BODY", Name: "total", Path: "price.total"},
		ParamB:       ParamRelationRef{Location: "BODY", Name: "paid", Path: "price.paid"},
	}
	p := &parser.Parsed{
		Query:      map[string]string{},
		Headers:    map[string]string{},
		JSONFields: map[string]string{"price.total": "number", "price.paid": "number"},
		JSONValues: map[string]string{"price.total": "100", "price.paid": "200"},
	}
	ctx := dsctx.New("v1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_greater_than", "100", "200")

	// BODY：JSONValues 未留存（RetainJSONScalarValues=off 形态）→ 不判定
	p2 := &parser.Parsed{
		Query:      map[string]string{},
		Headers:    map[string]string{},
		JSONFields: map[string]string{"price.total": "number", "price.paid": "number"},
		JSONValues: map[string]string{},
	}
	ctx = dsctx.New("v2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p2, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("body without retained scalar values must not be judged, got %+v", ctx.CopyMatches())
	}

	// HEADER：脱敏头（[redacted]）值不可得 → 不判定
	relH := ParamRelation{
		EndpointKey:  "GET /v1/search",
		RelationType: RelationTypeEquals,
		ParamA:       ParamRelationRef{Location: "HEADER", Name: "Authorization"},
		ParamB:       ParamRelationRef{Location: "HEADER", Name: "X-Token"},
	}
	p3 := &parser.Parsed{
		Query:      map[string]string{},
		Headers:    map[string]string{"authorization": "[redacted]", "x-token": "tok"},
		JSONFields: map[string]string{},
		JSONValues: map[string]string{},
	}
	ctx = dsctx.New("v3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p3, []ParamRelation{relH}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("redacted header value must not be judged, got %+v", ctx.CopyMatches())
	}

	// COOKIE：整头脱敏恒不可取 → 不判定
	relC := ParamRelation{
		EndpointKey:  "GET /v1/search",
		RelationType: RelationTypeEquals,
		ParamA:       ParamRelationRef{Location: "COOKIE", Name: "sid"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "sid"},
	}
	ctx = dsctx.New("v4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p3, []ParamRelation{relC}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("cookie value must never be judged, got %+v", ctx.CopyMatches())
	}

	// PATH：占位段可取值（{id} 段与 QUERY id 等值比较）
	relP := ParamRelation{
		EndpointKey:  "GET /v1/orders/{id}",
		RelationType: RelationTypeEquals,
		ParamA:       ParamRelationRef{Location: "PATH", Name: "{id}"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "id"},
	}
	p5 := &parser.Parsed{
		RawPath:        "/v1/orders/123",
		NormalizedPath: "/v1/orders/{id}",
		Query:          map[string]string{"id": "456"},
		Headers:        map[string]string{},
		JSONFields:     map[string]string{},
		JSONValues:     map[string]string{},
	}
	ctx = dsctx.New("v5", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p5, []ParamRelation{relP}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_equals", "123", "456")
}

// NOT_EQUALS：值相等 → 违例；不等 → 通过；单侧缺失 → 不判定；PROTECT 下仍仅 OBSERVE。
// （EQUALS 的严格对偶：字符串比较，无类型要求——任意可取值均可判定。）
func TestCheckValueRelationNotEquals(t *testing.T) {
	rel := valueRelation(RelationTypeNotEquals)

	// 反：相等 → 违例（PROTECT 下也只产信号不阻断）
	ctx := dsctx.New("ne1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("abc", "abc"), []ParamRelation{rel}, decision.ModeProtect)
	assertValueSignal(t, ctx, "schema.relation_not_equals", "abc")

	// 正：不等 → 无明细
	ctx = dsctx.New("ne2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("abc", "abd"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("distinct values must pass, got %+v", ctx.CopyMatches())
	}

	// 边界：数值形态按字符串比较（"2" 与 "2.0" 不相等 → 通过，不做数值归一化）
	ctx = dsctx.New("ne3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForValueRelations("2", "2.0"), []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("string-distinct numeric forms must pass, got %+v", ctx.CopyMatches())
	}

	// 单侧缺失 → 不判定（缺失语义归 REQUIRES）
	ctx = dsctx.New("ne4", dsctx.DefaultParseLimits())
	p := parsedForValueRelations("abc", "abc")
	delete(p.Query, "max_value")
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing side must not be judged, got %+v", ctx.CopyMatches())
	}
}

// ValidateParamRelations：新词表六类合法；未知词仍拒绝。
func TestValidateParamRelationsValueTypes(t *testing.T) {
	for _, typ := range []string{RelationTypeEquals, RelationTypeNotEquals, RelationTypeGreaterThan, RelationTypeLessThan,
		RelationTypeTimeBefore, RelationTypeTimeAfter} {
		rel := valueRelation(typ)
		if err := ValidateParamRelations([]ParamRelation{rel}); err != nil {
			t.Fatalf("%s must pass validation: %v", typ, err)
		}
	}
	bad := valueRelation("IMPLIES")
	if err := ValidateParamRelations([]ParamRelation{bad}); err == nil {
		t.Fatal("unknown type must still be rejected")
	}
}
