// apigraphql_test.go GraphQL 成本预算 guard 接线测试（NG-GQL-03）：
// 段编译归一 / 按应用解析 / PROTECT 实断 GraphQL 协议错误 JSON / OBSERVE 放行记录 /
// 默认关闭零行为。
package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"go.uber.org/zap"
)

// newGraphQLTestGuard 构造启用 API 动态防护 + GraphQL 策略的 Guard（不经过 Provision，
// 运行时字段直接注入；compile 路径由 TestCompileAPIGraphQLPolicies 覆盖）。
func newGraphQLTestGuard(t *testing.T, globalMode string, pol *pipeline.GraphQLPolicy) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, globalMode, nil)
	if pol != nil {
		g.apiGraphQL = map[string]*pipeline.GraphQLPolicy{"app-1": pol}
	}
	return g, logPath
}

func gqlJSONBody(query string) string {
	return `{"query":` + strconv_Quote(query) + `}`
}

// strconv_Quote 测试内联转义（避免引入 strconv 仅为一行）。
func strconv_Quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(c)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------- 配置编译（fail-safe 归一） ----------

func TestCompileAPIGraphQLPolicies(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	if got := g.compileAPIGraphQLPolicies(); got != nil {
		t.Fatalf("nil section must compile to nil, got %+v", got)
	}
	g.APIGraphQLPolicies = &apiGraphQLSectionJSON{}
	if got := g.compileAPIGraphQLPolicies(); got != nil {
		t.Fatalf("empty policies must compile to nil, got %+v", got)
	}
	g.APIGraphQLPolicies = &apiGraphQLSectionJSON{Policies: map[string]apiGraphQLPolicyJSON{
		"app-1": {
			Enabled:           true,
			Limits:            apiGraphQLLimitsJSON{MaxDocBytes: 128 << 10, MaxDepth: 8},
			Weights:           gqlast.WeightsConfig{DefaultFieldWeight: 2},
			Budget:            gqlast.BudgetConfig{PerRequest: 100},
			TrustedDocDigests: []string{"abc123"},
		},
		"": {Enabled: true}, // 空 application_id 跳过
	}}
	got := g.compileAPIGraphQLPolicies()
	if len(got) != 1 {
		t.Fatalf("仅合法键存活（空键跳过）: %+v", got)
	}
	p := got["app-1"]
	if p == nil || !p.Enabled || p.Limits.MaxDocBytes != 128<<10 || p.Limits.MaxDepth != 8 ||
		p.Weights.DefaultFieldWeight != 2 || p.Budget.PerRequest != 100 ||
		len(p.TrustedDocDigests) != 1 || p.TrustedDocDigests[0] != "abc123" {
		t.Fatalf("策略映射不符: %+v", p)
	}
	// 超 64MiB 文档上限归零走引擎默认（防 OOM 配置）
	g.APIGraphQLPolicies = &apiGraphQLSectionJSON{Policies: map[string]apiGraphQLPolicyJSON{
		"app-1": {Enabled: true, Limits: apiGraphQLLimitsJSON{MaxDocBytes: 1 << 30}},
	}}
	if p := g.compileAPIGraphQLPolicies()["app-1"]; p.Limits.MaxDocBytes != 0 {
		t.Fatalf("超限 MaxDocBytes 应归零走默认: %+v", p.Limits)
	}
}

func TestAPIGraphQLPolicyForApp(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	if p := g.apiGraphQLPolicyForApp(); p != nil {
		t.Fatalf("no policies must resolve nil, got %+v", p)
	}
	g.AppID = "app-1"
	pol := &pipeline.GraphQLPolicy{Enabled: true}
	g.apiGraphQL = map[string]*pipeline.GraphQLPolicy{"app-1": pol}
	if p := g.apiGraphQLPolicyForApp(); p != pol {
		t.Fatalf("own app policy must resolve, got %+v", p)
	}
	g.AppID = "app-other"
	if p := g.apiGraphQLPolicyForApp(); p != nil {
		t.Fatalf("other app must resolve nil, got %+v", p)
	}
	g.AppID = ""
	if p := g.apiGraphQLPolicyForApp(); p != nil {
		t.Fatalf("empty AppID must resolve nil, got %+v", p)
	}
}

// ---------- 端到端：PROTECT 实断 GraphQL 协议错误 JSON ----------

func TestServeNext_GraphQLCostProtectDeniesProtocolJSON(t *testing.T) {
	g, logPath := newGraphQLTestGuard(t, "PROTECT", &pipeline.GraphQLPolicy{
		Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 3},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(gqlJSONBody(`{ users { id name email posts { title } } }`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-gql-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("graphql-denied response is written directly, err must be nil, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when graphql-denied")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	wantBody := `{"errors":[{"extensions":{"code":"GQL_COST_EXCEEDED","request_id":"req-gql-1"},"message":"GraphQL request rejected by protection policy"}]}`
	if got := rec.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q（GraphQL 协议错误 JSON，非 WAF HTML 阻断页）", ct)
	}
	// 事件照常落盘：BLOCK + 403 + gql.cost_v1 明细（reason/cost/budget 脱敏证据）
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" || recs[0].ResponseStatus != http.StatusForbidden {
		t.Fatalf("event = %+v", recs)
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.Detector == "graphql" && m.RuleID == "gql.cost_v1" && m.Category == "BLOCK" &&
			m.Evidence["reason"] == "GQL_COST_EXCEEDED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("event must carry gql.cost_v1 BLOCK detail: %+v", recs[0].Details)
	}
}

// 结构准入失败（多 operation 未命名）PROTECT 拒绝 reason=GQL_ADMISSION_REJECTED。
func TestServeNext_GraphQLAdmissionRejectReason(t *testing.T) {
	g, _ := newGraphQLTestGuard(t, "PROTECT", &pipeline.GraphQLPolicy{
		Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 1000},
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(gqlJSONBody(`query A { a } query B { b }`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-gql-2")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	wantBody := `{"errors":[{"extensions":{"code":"GQL_ADMISSION_REJECTED","request_id":"req-gql-2"},"message":"GraphQL request rejected by protection policy"}]}`
	if got := rec.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}

// OBSERVE 放行仅记录（成本超限不阻断，事件含拟动作 finding）。
func TestServeNext_GraphQLObservePasses(t *testing.T) {
	g, logPath := newGraphQLTestGuard(t, "OBSERVE", &pipeline.GraphQLPolicy{
		Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 3},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"a":1}}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(gqlJSONBody(`{ a b c d e f g h i j }`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-gql-3")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("OBSERVE 必须放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	var found bool
	for _, m := range recs[0].Details {
		if m.Detector == "graphql" && m.RuleID == "gql.cost_v1" && m.Evidence["reason"] == "GQL_COST_EXCEEDED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("OBSERVE 事件应含成本拟动作明细: %+v", recs[0].Details)
	}
}

// 默认关闭零行为：无策略段 GraphQL 请求照常放行、无 graphql 明细。
func TestServeNext_GraphQLDisabledZeroBehavior(t *testing.T) {
	g, logPath := newGraphQLTestGuard(t, "PROTECT", nil)
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"users":[]}}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(gqlJSONBody(`{ users { id name } }`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-gql-4")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("无策略段必须零行为放行: called=%v code=%d", called, rec.Code)
	}
	for _, m := range readAPIRecords(t, logPath)[0].Details {
		if m.Detector == "graphql" {
			t.Fatalf("无策略段不得产 graphql 明细: %+v", m)
		}
	}
}

// ---------- 阻断 reason 提取 ----------

func TestGraphQLBlockReason(t *testing.T) {
	mk := func(detector, category, reason string, excepted bool) dsctx.DetectorMatch {
		m := dsctx.DetectorMatch{Detector: detector, RuleID: "r", Category: category, Excepted: excepted}
		if reason != "" {
			m.Evidence = map[string]string{"reason": reason}
		}
		return m
	}
	if _, ok := graphqlBlockReason(nil); ok {
		t.Fatal("空明细不匹配")
	}
	if _, ok := graphqlBlockReason([]dsctx.DetectorMatch{mk("graphql", "OBSERVE", "GQL_COST_EXCEEDED", false)}); ok {
		t.Fatal("OBSERVE 类不匹配")
	}
	if _, ok := graphqlBlockReason([]dsctx.DetectorMatch{mk("graphql", "BLOCK", "GQL_WINDOW_EXCEEDED", true)}); ok {
		t.Fatal("豁免明细不驱动 reason")
	}
	r, ok := graphqlBlockReason([]dsctx.DetectorMatch{
		mk("waf", "BLOCK", "", false),
		mk("graphql", "BLOCK", "GQL_COST_EXCEEDED", false),
	})
	if !ok || r != "GQL_COST_EXCEEDED" {
		t.Fatalf("应取首条 graphql BLOCK reason: %q %v", r, ok)
	}
	// BLOCK 但 evidence 无 reason 时回退 GQL_ADMISSION_REJECTED
	r, ok = graphqlBlockReason([]dsctx.DetectorMatch{mk("graphql", "BLOCK", "", false)})
	if !ok || r != "GQL_ADMISSION_REJECTED" {
		t.Fatalf("无 reason 应回退 GQL_ADMISSION_REJECTED: %q %v", r, ok)
	}
}
