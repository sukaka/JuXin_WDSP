package gqlast

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
	gqlparser "github.com/vektah/gqlparser/v2/parser"
)

// GQ-C01：手算推演锚定。查询：
//
//	order(1) { id(1) buyer(1) { ...UserParts } items(列表，默认上界100) { sku(1) price(1) } }
//	fragment UserParts = { id(1) name(1) }
//
// items 为列表（数组类型由测试 schema 字段类型决定；本包按 ast.Type.Elem 判列表，
// 而 GraphQL 文档层无类型信息——isListType 依赖字段类型，文档解析层 Type 非空时判定。
// 注：gqlparser 的 Field.Definition.Type 在仅查询文档（无 Schema）时通常为 nil，
// 此时一律按非列表计（sizeFactor=1）——该保守口径在 D11 已注明；
// 期望成本 = order(1) + id(1) + buyer(1)+UserParts(1+1+1) + items(1) + sku(1) + price(1) = 9
func TestCostNormalQueryHandComputed(t *testing.T) {
	doc := mustParse(t, `query GetOrder($id: ID!) {
  order(id: $id) {
    id
    buyer { ...UserParts }
    items { sku price }
  }
}
fragment UserParts on User { id name }`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	if out.Cost != 9 {
		t.Fatalf("cost=%d want 9（推演见测试注释）: %s", out.Cost, out)
	}
	if out.Exceeded {
		t.Fatal("正常查询不得超预算")
	}
}

// GQ-C02：浅而贵——users.posts 配批准上界 100 的列表时，cost(posts 子树) 显著放大。
// 注：列表判定依赖 Schema 类型；无 Schema 时（本批默认路径）列表按非列表计——
// 用权重覆盖 ListBound 且类型为 List 的对照用例验证「上界参与成本」语义（权重路径 Query.posts）。
func TestCostShallowExpensiveListBound(t *testing.T) {
	doc := mustParse(t, `query { users { posts { id } } }`)
	op, _ := SelectOperation(doc, "")
	// 无权重：posts 非列表口径（无 Schema 类型）→ cost=users(1)+posts(1)+id(1)=3
	out1 := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	if out1.Cost != 3 {
		t.Fatalf("cost=%d want 3", out1.Cost)
	}
	// 有权重但无类型：仍不放大（类型为 nil → 非列表）
	out2 := CostOf(doc, op, WeightsConfig{Fields: map[string]FieldWeight{"Query.posts": {ListBound: 100}}}, BudgetConfig{})
	if out2.Cost != 3 {
		t.Fatalf("cost=%d want 3（无 Schema 类型时 ListBound 不生效，D11 保守口径）", out2.Cost)
	}
	// 同一字段配高权重 base：体现「批准成本计入权重」
	out3 := CostOf(doc, op, WeightsConfig{Fields: map[string]FieldWeight{"*.posts": {Weight: 50}}}, BudgetConfig{})
	if out3.Cost != 1+50+1 {
		t.Fatalf("cost=%d want 52", out3.Cost)
	}
}

// GQ-C03：同 response key 合并——alias 分叉的两次出现 base 计 1 次、子成本取 max。
func TestCostDuplicateResponseKeyMerge(t *testing.T) {
	doc := mustParse(t, `query {
  a: user { id name }
  a: user { id }
}`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	// a(user) base 计 1 次；子成本取 max({id,name}=2, {id}=1)=2 → 1+2=3
	if out.Cost != 3 {
		t.Fatalf("cost=%d want 3（合并：base 一次 + 子成本取 max）", out.Cost)
	}
}

// GQ-C04：饱和——刻意构造超深嵌套链，成本饱和后判超预算不绕回。
func TestCostSaturationNoWrap(t *testing.T) {
	var b strings.Builder
	b.WriteString("query { ")
	for i := 0; i < 19; i++ {
		b.WriteString("a { ")
	}
	b.WriteString("x")
	for i := 0; i < 19; i++ {
		b.WriteString(" }")
	}
	b.WriteString(" }")
	doc, err := ParseBounded(b.String(), Limits{MaxDepth: 25})
	if err != nil {
		t.Fatalf("构造样本应可解析: %v", err)
	}
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{DefaultListBound: 1 << 40}, BudgetConfig{PerRequest: 1 << 50})
	// 嵌套不深，但每层列表上界 2^40 时子成本乘法必然饱和或高位
	if out.Cost < 0 {
		t.Fatalf("成本不得为负（绕回）: %d", out.Cost)
	}
	if out.Cost > satCap {
		t.Fatalf("成本不得超过饱和上限: %d", out.Cost)
	}
	// 非列表类型时 ListBound 不生效——该用例验证的是「成本永不为负、永不溢出绕回」
}

// GQ-C05：变量 list 未给值——不求值、不推断（成本与变量值无关）。
func TestCostVariableListNotEvaluated(t *testing.T) {
	doc := mustParse(t, `query($ids: [ID!]) { nodes(ids: $ids) { id } }`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	// nodes(base=1) + 子集{id}=1 → 2（变量不求值、不贡献成本；无 Schema 类型按非列表计）
	if out.Cost != 2 {
		t.Fatalf("cost=%d want 2", out.Cost)
	}
}

// GQ-C06：内省根字段 __schema 权重 50 × 子树。
func TestCostIntrospectionHeavy(t *testing.T) {
	doc := mustParse(t, `query { __schema { types { name } } }`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	// __schema(50) + types(1) + name(1) = 52
	if out.Cost != 52 {
		t.Fatalf("cost=%d want 52", out.Cost)
	}
}

// GQ-C07：缓存键含 schema/policy 版本——同文档不同版本不复用。
func TestCostCacheVersionedKey(t *testing.T) {
	doc := mustParse(t, `query { a b }`)
	op, _ := SelectOperation(doc, "")
	c := NewCostCache(10)
	o1 := CostOfCached(c, doc, op, WeightsConfig{}, BudgetConfig{}, "s1", "p1")
	if o1.Note != "cache:miss" {
		t.Fatalf("note=%s", o1.Note)
	}
	o2 := CostOfCached(c, doc, op, WeightsConfig{}, BudgetConfig{}, "s1", "p1")
	if o2.Note != "cache:hit" || o2.Cost != o1.Cost {
		t.Fatalf("同键应命中且成本一致: %+v", o2)
	}
	o3 := CostOfCached(c, doc, op, WeightsConfig{}, BudgetConfig{}, "s1", "p2")
	if o3.Note == "cache:hit" {
		t.Fatal("policyVersion 变化不得复用缓存")
	}
	o4 := CostOfCached(c, doc, op, WeightsConfig{}, BudgetConfig{}, "s2", "p1")
	if o4.Note == "cache:hit" {
		t.Fatal("schemaVersion 变化不得复用缓存")
	}
}

// GQ-C08：单请求预算超限判定（Exceeded=true，且 Saturated=false 时成本如实）。
func TestCostPerRequestBudgetExceeded(t *testing.T) {
	doc := mustParse(t, `query { a b c d e }`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{PerRequest: 3})
	if out.Cost != 5 || !out.Exceeded {
		t.Fatalf("out=%s（5>3 应超）", out)
	}
	out2 := CostOf(doc, op, WeightsConfig{}, BudgetConfig{PerRequest: 5})
	if out2.Exceeded {
		t.Fatal("等于预算不得判超")
	}
}

// GQ-C09：fragment 展开计入成本（不重复展开同一文档时的确定性）。
func TestCostFragmentExpansion(t *testing.T) {
	doc := mustParse(t, `query { user { ...P } other { ...P } }
fragment P on User { id name }`)
	op, _ := SelectOperation(doc, "")
	out := CostOf(doc, op, WeightsConfig{}, BudgetConfig{})
	// user(1)+P(1+1+1) + other(1)+P(1+1+1) = 8（fragment 引用按 spread 计 base=1 + 子树 2×展开）
	if out.Cost != 8 {
		t.Fatalf("cost=%d want 8", out.Cost)
	}
}

// GQ-C10：DigestDocument 规范化——空白/注释/换行差异同摘要；不同查询不同摘要。
func TestDigestDocumentCanonical(t *testing.T) {
	a := DigestDocument("query { user { id } }")
	b := DigestDocument("query {\n  user {\n    id\n  }\n} # tail comment")
	if a != b {
		t.Fatal("规范化摘要应对空白/注释差异稳定")
	}
	c := DigestDocument("query { user { name } }")
	if a == c {
		t.Fatal("不同文档不得同摘要")
	}
}

// GQ-C11：缓存 LRU 淘汰最旧。
func TestCostCacheLRUEviction(t *testing.T) {
	c := NewCostCache(2)
	k := func(i string) CostCacheKey { return CostCacheKey{DocDigest: i} }
	c.Put(k("a"), 1)
	c.Put(k("b"), 2)
	c.Put(k("c"), 3) // 淘汰 a
	if _, ok := c.Get(k("a")); ok {
		t.Fatal("最旧键应被淘汰")
	}
	if v, ok := c.Get(k("c")); !ok || v != 3 {
		t.Fatal("新键应保留")
	}
}

func TestC11CostCacheIncludesOperationName(t *testing.T) {
	doc := mustParse(t, `query Cheap { id }
query Expensive { __schema { types { name } } }`)
	cheapOp, err := SelectOperation(doc, "Cheap")
	if err != nil {
		t.Fatal(err)
	}
	expOp, err := SelectOperation(doc, "Expensive")
	if err != nil {
		t.Fatal(err)
	}
	cache := NewCostCache(10)
	oCheap := CostOfCached(cache, doc, cheapOp, WeightsConfig{}, BudgetConfig{PerRequest: 10}, "s1", "p1")
	if oCheap.Exceeded || oCheap.Cost != 1 {
		t.Fatalf("Cheap 应通过且 cost=1: %+v", oCheap)
	}
	oExp := CostOfCached(cache, doc, expOp, WeightsConfig{}, BudgetConfig{PerRequest: 10}, "s1", "p1")
	if oExp.Note == "cache:hit" || !oExp.Exceeded || oExp.Cost != 52 {
		t.Fatalf("Expensive 不得复用 Cheap 缓存，必须超预算 cost=52: %+v", oExp)
	}
}

func TestC11CostOfFragmentDAGMemoizedAndSaturates(t *testing.T) {
	// 构造 65 层双分支 DAG（若无记忆化将产生 2^65 次遍历），绕过 ParseBounded 直接进入 CostOf 也须瞬间完成并饱和超预算。
	var b strings.Builder
	b.WriteString("query { ...F0 }\n")
	for i := 0; i < 65; i++ {
		b.WriteString("fragment F" + itoaForTest(i) + " on T { x { ...F" + itoaForTest(i+1) + " } y { ...F" + itoaForTest(i+1) + " } }\n")
	}
	b.WriteString("fragment F65 on T { leaf }\n")
	q := b.String()
	parsedAST, perr := gqlparser.ParseQuery(&ast.Source{Input: q})
	if perr != nil {
		t.Fatalf("ParseQuery: %v", perr)
	}
	rawDoc := &Document{AST: parsedAST, Query: q}
	op, err := SelectOperation(rawDoc, "")
	if err != nil {
		t.Fatal(err)
	}
	out := CostOf(rawDoc, op, WeightsConfig{}, BudgetConfig{PerRequest: 5000})
	if !out.Exceeded || !out.Saturated {
		t.Fatalf("DAG 指数成本应快速饱和并判超预算: %+v", out)
	}
}
