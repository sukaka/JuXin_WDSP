// relationcheck_test.go 参数条件关系运行时检测单测（W11-REL）：
// REQUIRES/MUTEX/CO_OCCURS 三类正反用例、模式定类别、证据不落值、配置校验与归组。
package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// parsedForRelations 构造关系检测用解析产物：
// QUERY page=1（无 page_size）；BODY buyer.phone（无 buyer.email）；HEADER x-tenant。
func parsedForRelations() *parser.Parsed {
	return &parser.Parsed{
		Query:      map[string]string{"page": "1"},
		Headers:    map[string]string{"x-tenant": "t-1"},
		JSONFields: map[string]string{"buyer.phone": "string", "buyer": "object"},
		JSONValues: map[string]string{"buyer.phone": "13800001111"},
	}
}

func requiresRelation() ParamRelation {
	return ParamRelation{
		EndpointKey:  "GET /v1/orders",
		RelationType: "REQUIRES",
		ParamA:       ParamRelationRef{Location: "QUERY", Name: "page", Path: "page"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "page_size", Path: "page_size"},
	}
}

func mutexRelation() ParamRelation {
	return ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: "MUTEX",
		ParamA:       ParamRelationRef{Location: "BODY", Name: "phone", Path: "buyer.phone"},
		ParamB:       ParamRelationRef{Location: "BODY", Name: "email", Path: "buyer.email"},
	}
}

// REQUIRES：A 存在 B 缺失 → 违例；A 缺失 → 不判定；A/B 同在 → 通过。
func TestCheckParamRelationsRequires(t *testing.T) {
	// A 存在 B 缺失：OBSERVE 模式 → OBSERVE 级明细
	ctx := dsctx.New("r1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{requiresRelation()}, decision.ModeObserve)
	if !hasMatch(ctx, "schema.relation_requires") {
		t.Fatalf("expected relation_requires, got %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "schema.relation_requires" {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Fatalf("OBSERVE mode must stay observe-level: %+v", m)
		}
		if m.Evidence["param_a"] != "QUERY:page" || m.Evidence["param_b"] != "QUERY:page_size" {
			t.Fatalf("evidence = %+v", m.Evidence)
		}
		// 证据只含参数名/路径/位置/关系类型，不落值
		for _, v := range m.Evidence {
			if v == "1" || strings.Contains(v, "13800001111") {
				t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
			}
		}
	}

	// A 存在 B 缺失：PROTECT 模式 → BLOCK 类（可定案阻断）
	ctx = dsctx.New("r2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{requiresRelation()}, decision.ModeProtect)
	found := false
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "schema.relation_requires" {
			found = true
			if m.Category != "BLOCK" || m.Severity != "HIGH" {
				t.Fatalf("PROTECT mode must escalate to BLOCK class: %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("expected relation_requires in PROTECT")
	}

	// A 缺失：REQUIRES 不判定（无明细）
	p := parsedForRelations()
	delete(p.Query, "page")
	ctx = dsctx.New("r3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{requiresRelation()}, decision.ModeProtect)
	if hasMatch(ctx, "schema.relation_requires") {
		t.Fatal("A absent must not trigger REQUIRES")
	}

	// A/B 同在：通过
	p = parsedForRelations()
	p.Query["page_size"] = "20"
	ctx = dsctx.New("r4", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{requiresRelation()}, decision.ModeProtect)
	if hasMatch(ctx, "schema.relation_requires") {
		t.Fatal("both present must pass REQUIRES")
	}
}

// MUTEX：A/B 同现 → 违例（PROTECT 升级 BLOCK 类）；单侧出现 → 通过。
func TestCheckParamRelationsMutex(t *testing.T) {
	// 同现：buyer.phone + buyer.email
	p := parsedForRelations()
	p.JSONFields["buyer.email"] = "string"
	p.JSONValues["buyer.email"] = "a@b.c"
	ctx := dsctx.New("m1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{mutexRelation()}, decision.ModeProtect)
	found := false
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "schema.relation_mutex" {
			found = true
			if m.Category != "BLOCK" || m.Severity != "HIGH" {
				t.Fatalf("PROTECT mutex must escalate: %+v", m)
			}
			if m.Evidence["param_a"] != "BODY:buyer.phone" || m.Evidence["param_b"] != "BODY:buyer.email" {
				t.Fatalf("evidence = %+v", m.Evidence)
			}
			for _, v := range m.Evidence {
				if strings.Contains(v, "13800001111") || strings.Contains(v, "a@b.c") {
					t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected relation_mutex, got %+v", ctx.CopyMatches())
	}

	// 单侧出现（仅 phone）：通过
	ctx = dsctx.New("m2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{mutexRelation()}, decision.ModeProtect)
	if hasMatch(ctx, "schema.relation_mutex") {
		t.Fatal("single side present must pass MUTEX")
	}
}

// CO_OCCURS：单侧出现 → INFO 观察（永不升级阻断，任何模式）；同现/同缺 → 无明细。
func TestCheckParamRelationsCoOccurs(t *testing.T) {
	rel := ParamRelation{
		EndpointKey:  "GET /v1/orders",
		RelationType: "CO_OCCURS",
		ParamA:       ParamRelationRef{Location: "QUERY", Name: "page"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "page_size"},
	}
	// 单侧出现（page 在、page_size 缺）：PROTECT 下仍仅 INFO
	ctx := dsctx.New("c1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{rel}, decision.ModeProtect)
	found := false
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "schema.relation_cooccurs" {
			found = true
			if m.Category != "INFO" || m.Severity != "INFO" || m.ScoreDelta != 0 {
				t.Fatalf("CO_OCCURS must stay INFO observe-only: %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("expected relation_cooccurs INFO match")
	}

	// 同现：无明细
	p := parsedForRelations()
	p.Query["page_size"] = "20"
	ctx = dsctx.New("c2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("both present must yield no match, got %+v", ctx.CopyMatches())
	}

	// 同缺：无明细
	p = parsedForRelations()
	delete(p.Query, "page")
	ctx = dsctx.New("c3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{rel}, decision.ModeObserve)
	if ctx.MatchCount() != 0 {
		t.Fatalf("both absent must yield no match, got %+v", ctx.CopyMatches())
	}
}

// 位置语义：HEADER 大小写不敏感；PATH 占位名匹配；未知位置/未知类型宽容忽略。
func TestCheckParamRelationsLocations(t *testing.T) {
	// HEADER 存在性（配置大写名，解析产物小写键）
	rel := ParamRelation{
		EndpointKey:  "GET /v1/orders",
		RelationType: "REQUIRES",
		ParamA:       ParamRelationRef{Location: "HEADER", Name: "X-Tenant"},
		ParamB:       ParamRelationRef{Location: "HEADER", Name: "X-Trace"},
	}
	ctx := dsctx.New("l1", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{rel}, decision.ModeProtect)
	if !hasMatch(ctx, "schema.relation_requires") {
		t.Fatal("header REQUIRES: x-tenant present, x-trace missing must violate")
	}

	// PATH 占位名存在性（归一化段 {id}）
	p := parsedForRelations()
	p.NormalizedPath = "/v1/orders/{id}"
	p.RawPath = "/v1/orders/123"
	relPath := ParamRelation{
		EndpointKey:  "GET /v1/orders/{id}",
		RelationType: "REQUIRES",
		ParamA:       ParamRelationRef{Location: "PATH", Name: "{id}"},
		ParamB:       ParamRelationRef{Location: "QUERY", Name: "verbose"},
	}
	ctx = dsctx.New("l2", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, p, []ParamRelation{relPath}, decision.ModeProtect)
	if !hasMatch(ctx, "schema.relation_requires") {
		t.Fatal("path REQUIRES: {id} present, verbose missing must violate")
	}

	// 未知关系类型：忽略（读取侧宽容）
	bad := requiresRelation()
	bad.RelationType = "IMPLIES"
	ctx = dsctx.New("l3", dsctx.DefaultParseLimits())
	CheckParamRelations(ctx, parsedForRelations(), []ParamRelation{bad}, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("unknown relation type must be ignored, got %+v", ctx.CopyMatches())
	}
}

// ValidateParamRelations：端点键/类型/参数名非法如实报错；合法配置通过（含 EXCLUDES 历史词表）。
func TestValidateParamRelations(t *testing.T) {
	if err := ValidateParamRelations(nil); err != nil {
		t.Fatal(err)
	}
	good := []ParamRelation{requiresRelation(), mutexRelation()}
	ex := requiresRelation()
	ex.RelationType = "EXCLUDES"
	good = append(good, ex)
	if err := ValidateParamRelations(good); err != nil {
		t.Fatalf("valid relations must pass: %v", err)
	}

	cases := []ParamRelation{
		{RelationType: "REQUIRES", ParamA: ParamRelationRef{Name: "a"}, ParamB: ParamRelationRef{Name: "b"}}, // endpoint_key 空
		{EndpointKey: "GET /x", RelationType: "IMPLIES", ParamA: ParamRelationRef{Name: "a"}, ParamB: ParamRelationRef{Name: "b"}},
		{EndpointKey: "GET /x", RelationType: "REQUIRES", ParamA: ParamRelationRef{Name: ""}, ParamB: ParamRelationRef{Name: "b"}},
	}
	for i, c := range cases {
		if err := ValidateParamRelations([]ParamRelation{c}); err == nil {
			t.Fatalf("case %d must fail validation", i)
		}
	}
}

// GroupParamRelations：按端点归组；空输入归一为 nil（零行为变化）。
func TestGroupParamRelations(t *testing.T) {
	if got := GroupParamRelations(nil); got != nil {
		t.Fatalf("nil input must yield nil: %+v", got)
	}
	a := requiresRelation()
	b := mutexRelation()
	c := requiresRelation()
	c.EndpointKey = "GET /v1/users"
	got := GroupParamRelations([]ParamRelation{a, b, c})
	if len(got["GET /v1/orders"]) != 1 || len(got["POST /v1/orders"]) != 1 || len(got["GET /v1/users"]) != 1 {
		t.Fatalf("grouped = %+v", got)
	}
}
