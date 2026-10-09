// pipeline_graphql_test.go GraphQL 成本预算链路测试（NG-GQL-03）：
// 默认关闭零行为 / 正常放行 / 超限 OBSERVE 不阻断 / 超限 PROTECT 阻断且证据脱敏 /
// 多 operation 只算选定者 / 结构失败两路 reason / trusted 直通 / 时间窗匿名独立桶 /
// 覆盖记录三态。
package pipeline

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
)

// obsByDetector 过滤覆盖记录（按 detector）。
func obsByDetector(sink *covMemSink, detector string) []coverage.Observation {
	var out []coverage.Observation
	for _, o := range sink.all() {
		if o.Detector == detector {
			out = append(out, o)
		}
	}
	return out
}

// resetSink 清空覆盖记录（同包测试辅助）。
func resetSink(sink *covMemSink) {
	sink.mu.Lock()
	sink.obs = nil
	sink.mu.Unlock()
}

// gqlJSONReq 构造 /graphql JSON 请求。
func gqlJSONReq(t *testing.T, query, operationName string) *http.Request {
	t.Helper()
	body := fmt.Sprintf(`{"query":%q`, query)
	if operationName != "" {
		body += fmt.Sprintf(`,"operationName":%q`, operationName)
	}
	body += "}"
	r, err := http.NewRequest(http.MethodPost, "http://h/graphql", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "gql-t")
	return r
}

// gqlRawReq 构造 application/graphql 请求（body 即文档）。
func gqlRawReq(t *testing.T, query string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://h/graphql", strings.NewReader(query))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/graphql")
	r.Header.Set("X-Request-Id", "gql-t")
	return r
}

func gqlFindings(res *Result) []dsctx.DetectorMatch {
	var out []dsctx.DetectorMatch
	for _, m := range res.Context.CopyMatches() {
		if m.Detector == graphqlDetector {
			out = append(out, m)
		}
	}
	return out
}

// 默认关闭零行为：nil 策略与 disabled 策略下 GraphQL 请求均不产生 graphql finding、不阻断。
func TestGraphQLDisabledZeroBehavior(t *testing.T) {
	q := `{ users { id name posts { title } } }`
	for _, pol := range []*GraphQLPolicy{nil, {Enabled: false}} {
		res, err := Process(gqlJSONReq(t, q, ""), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := gqlFindings(res); len(got) != 0 {
			t.Fatalf("策略关闭不得产 graphql finding: %+v", got)
		}
		if res.FinalAction == dsctx.ActionBlock {
			t.Fatal("策略关闭不得阻断")
		}
	}
}

// 正常放行：小查询成本在预算内，无 finding，覆盖 FULL。
func TestGraphQLSmallQueryAllows(t *testing.T) {
	sink := &covMemSink{}
	em := coverage.NewEmitter(16, 4, sink)
	em.Start()
	defer em.Stop()
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 1000}}
	res, err := Process(gqlJSONReq(t, `{ a b }`, ""), Config{
		Enabled: true, Mode: "PROTECT", GraphQL: pol, Coverage: em}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := gqlFindings(res); len(got) != 0 {
		t.Fatalf("预算内不得产 finding: %+v", got)
	}
	time.Sleep(300 * time.Millisecond)
	obs := obsByDetector(sink, graphqlCovDetector)
	if len(obs) != 1 || obs[0].Status != coverage.StatusFull {
		t.Fatalf("覆盖应为 FULL 一条: %+v", obs)
	}
	if obs[0].Scope.Bytes <= 0 || obs[0].BytesExamined != obs[0].Scope.Bytes {
		t.Fatalf("scope.bytes 应为文档字节: %+v", obs[0].Scope)
	}
}

// 超限 OBSERVE 不阻断：category=OBSERVE + reason=GQL_COST_EXCEEDED，定案非 BLOCK。
func TestGraphQLCostExceededObserveOnly(t *testing.T) {
	q := `{ a b c d e f g h i j }`
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 3}}
	res, err := Process(gqlJSONReq(t, q, ""), Config{Enabled: true, Mode: "OBSERVE", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := gqlFindings(res)
	if len(fs) != 1 || fs[0].RuleID != "gql.cost_v1" || fs[0].Category != "OBSERVE" {
		t.Fatalf("OBSERVE 应只记录: %+v", fs)
	}
	if fs[0].Evidence["reason"] != GQLReasonCostExceeded {
		t.Fatalf("reason 应为 GQL_COST_EXCEEDED: %+v", fs[0].Evidence)
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatal("OBSERVE 不得阻断")
	}
}

// 超限 PROTECT 阻断：category=BLOCK 取得阻断资格，定案 BLOCK；证据脱敏（无查询文本/变量）。
func TestGraphQLCostExceededProtectBlocks(t *testing.T) {
	q := `{ users { id name email posts { title body comments { text } } } }`
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 3}}
	res, err := Process(gqlRawReq(t, q), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("PROTECT 超预算应 BLOCK: %s", res.FinalAction)
	}
	fs := gqlFindings(res)
	if len(fs) != 1 || fs[0].Category != "BLOCK" {
		t.Fatalf("PROTECT 应 category=BLOCK: %+v", fs)
	}
	for k, v := range fs[0].Evidence {
		if strings.Contains(v, "users") || strings.Contains(v, "email") || strings.Contains(v, "{") {
			t.Fatalf("证据不得含查询内容: %s=%s", k, v)
		}
	}
	if fs[0].Evidence["reason"] != GQLReasonCostExceeded || fs[0].Evidence["cost"] == "" ||
		fs[0].Evidence["budget"] != "3" || fs[0].Evidence["operation_kind"] != "query" {
		t.Fatalf("证据键集不符: %+v", fs[0].Evidence)
	}
}

// 多 operation 只算选定者：选定小查询放行；不指定 operationName 结构失败；
// 指定不存在 operationName 同失败。两路 reason 均为 GQL_ADMISSION_REJECTED。
func TestGraphQLMultiOperationOnlySelectedCounted(t *testing.T) {
	big := `{ a1 b1 c1 d1 e1 f1 g1 h1 i1 j1 k1 }`
	doc := fmt.Sprintf("query Big %s query Small { x }", big)
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 3}}

	// 选定 Small（成本 1 ≤ 3）→ 放行（Big 不展开不计成本）
	res, err := Process(gqlJSONReq(t, doc, "Small"), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := gqlFindings(res); len(got) != 0 {
		t.Fatalf("选定小查询应放行（未选定 operation 不计成本）: %+v", got)
	}

	// 不指定 operationName → 结构准入失败（PROTECT 阻断）
	res, err = Process(gqlJSONReq(t, doc, ""), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := gqlFindings(res)
	if res.FinalAction != dsctx.ActionBlock || len(fs) != 1 ||
		fs[0].Evidence["reason"] != GQLReasonAdmissionRejected ||
		fs[0].Evidence["error_kind"] != string(gqlast.ErrMultipleOps) {
		t.Fatalf("多操作未命名应 GQL_ADMISSION_REJECTED: %s %+v", res.FinalAction, fs)
	}

	// 指定不存在的 operationName → 同路失败
	res, _ = Process(gqlJSONReq(t, doc, "Nope"), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	fs = gqlFindings(res)
	if len(fs) != 1 || fs[0].Evidence["error_kind"] != string(gqlast.ErrOpNotFound) {
		t.Fatalf("operationName 不存在应 OPERATION_NOT_FOUND: %+v", fs)
	}
}

// 结构失败两路 reason（NG-T-G06）：语法错误 → GQL_ADMISSION_REJECTED；
// 成本超限 → GQL_COST_EXCEEDED（与上条互补）；OBSERVE 下语法失败仅记录不阻断。
func TestGraphQLAdmissionFailureReasonSplit(t *testing.T) {
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 1000}}
	// 语法错误（未闭合选择集）
	res, err := Process(gqlRawReq(t, `{ users { id `), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := gqlFindings(res)
	if res.FinalAction != dsctx.ActionBlock || len(fs) != 1 ||
		fs[0].Evidence["reason"] != GQLReasonAdmissionRejected ||
		fs[0].Evidence["error_kind"] != string(gqlast.ErrSyntax) {
		t.Fatalf("语法失败应 GQL_ADMISSION_REJECTED/SYNTAX: %s %+v", res.FinalAction, fs)
	}
	// OBSERVE 下语法失败仅记录
	res, _ = Process(gqlRawReq(t, `{ users { id `), Config{Enabled: true, Mode: "OBSERVE", GraphQL: pol}, nil)
	fs = gqlFindings(res)
	if len(fs) != 1 || fs[0].Category != "OBSERVE" || res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("OBSERVE 语法失败仅记录: %s %+v", res.FinalAction, fs)
	}
	// 超硬边界（深度超限）→ PARTIAL 覆盖
	sink := &covMemSink{}
	em := coverage.NewEmitter(16, 4, sink)
	em.Start()
	defer em.Stop()
	deep := "{ a { a { a } } }"
	pol2 := &GraphQLPolicy{Enabled: true, Limits: gqlast.Limits{MaxDepth: 2}}
	_, err = Process(gqlRawReq(t, deep), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol2, Coverage: em}, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	obs := obsByDetector(sink, graphqlCovDetector)
	if len(obs) != 1 || obs[0].Status != coverage.StatusPartial ||
		obs[0].ReasonCode != coverage.ReasonInputTruncated || !obs[0].Truncated {
		t.Fatalf("超硬边界应 PARTIAL+COV_INPUT_TRUNCATED: %+v", obs)
	}
}

// trusted 直通：登记 digest 后同文档在 PROTECT 下也放行（记 GQL_TRUSTED_DOC OBSERVE）。
func TestGraphQLTrustedDocBypass(t *testing.T) {
	q := `{ a1 b1 c1 d1 e1 f1 }`
	digest := gqlast.DigestDocument(q)
	pol := &GraphQLPolicy{Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 1}, TrustedDocDigests: []string{digest}}
	res, err := Process(gqlJSONReq(t, q, ""), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := gqlFindings(res)
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatal("trusted 文档不得阻断")
	}
	if len(fs) != 1 || fs[0].RuleID != "gql.trusted_doc" || fs[0].Category != "OBSERVE" ||
		fs[0].Evidence["reason"] != GQLReasonTrustedDoc {
		t.Fatalf("trusted 直通应记 GQL_TRUSTED_DOC OBSERVE: %+v", fs)
	}
	// 白名单外文档不享受直通
	res2, _ := Process(gqlJSONReq(t, `{ z1 z2 }`, ""), Config{Enabled: true, Mode: "PROTECT", GraphQL: pol}, nil)
	if res2.FinalAction != dsctx.ActionBlock {
		t.Fatal("白名单外文档应照常成本判定")
	}
}

// 时间窗：匿名独立桶（AnonymousBudget）累计超限 → GQL_WINDOW_EXCEEDED；
// 注入独立内存存储隔离本用例（不污染默认单例）。
func TestGraphQLWindowBudgetAnonymousBucket(t *testing.T) {
	q := `{ a b }` // 成本 2
	store := NewMemoryWindowBudgetStore(100)
	pol := &GraphQLPolicy{Enabled: true, WindowStore: store,
		Budget: gqlast.BudgetConfig{PerRequest: 100, WindowSeconds: 60, WindowBudget: 1000, AnonymousBudget: 5}}
	cfg := Config{Enabled: true, Mode: "PROTECT", GraphQL: pol, ApplicationID: "app-gql-t"}
	// 第 1-2 次（累计 2/4 ≤ 5）放行
	for i := 0; i < 2; i++ {
		res, err := Process(gqlJSONReq(t, q, ""), cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if fs := gqlFindings(res); len(fs) != 0 {
			t.Fatalf("第 %d 次应在窗内: %+v", i+1, fs)
		}
	}
	// 第 3 次（累计 6 > 5）→ GQL_WINDOW_EXCEEDED 且 PROTECT 阻断
	res, err := Process(gqlJSONReq(t, q, ""), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := gqlFindings(res)
	if res.FinalAction != dsctx.ActionBlock || len(fs) != 1 ||
		fs[0].RuleID != "gql.window" || fs[0].Evidence["reason"] != GQLReasonWindowExceeded {
		t.Fatalf("窗超应 GQL_WINDOW_EXCEEDED: %s %+v", res.FinalAction, fs)
	}
	// 另一应用独立桶不受影响（键含 app）
	cfg2 := cfg
	cfg2.ApplicationID = "app-gql-other"
	res2, _ := Process(gqlJSONReq(t, q, ""), cfg2, nil)
	if fs := gqlFindings(res2); len(fs) != 0 {
		t.Fatalf("app 维度桶须隔离: %+v", fs)
	}
}

// 覆盖三态：SKIPPED（策略未启用 COV_DISABLED）。
func TestGraphQLCovSkippedWhenDisabled(t *testing.T) {
	sink := &covMemSink{}
	em := coverage.NewEmitter(16, 4, sink)
	em.Start()
	defer em.Stop()
	_, err := Process(gqlJSONReq(t, `{ a }`, ""), Config{
		Enabled: true, Mode: "PROTECT", GraphQL: nil, Coverage: em}, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	obs := obsByDetector(sink, graphqlCovDetector)
	if len(obs) != 1 || obs[0].Status != coverage.StatusSkipped || obs[0].ReasonCode != coverage.ReasonDisabled {
		t.Fatalf("策略未启用应 SKIPPED+COV_DISABLED: %+v", obs)
	}
	// 非 GraphQL 请求不产生该检测器记录
	resetSink(sink)
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	r.Header.Set("X-Request-Id", "non-gql")
	_, _ = Process(r, Config{Enabled: true, Mode: "PROTECT", Coverage: em}, nil)
	time.Sleep(300 * time.Millisecond)
	if obs := obsByDetector(sink, graphqlCovDetector); len(obs) != 0 {
		t.Fatalf("非 GraphQL 请求不得产 graphql.cost_v1 记录: %+v", obs)
	}
}
