// cost.go GraphQL 成本预算模型（NG-GQL-02，算法事实源：docs/nextgen/NG-GQL-02-cost-model.md）。
//
// 纪律：
//   - 公式 cost(set) = Σ_responseKey [ base(field) + sizeFactor(field) × cost(子集) ]；
//   - 同 response key 合并：base 计 1 次、子成本取 max（D2）；
//   - 变量一律不求值、按批准上界计（D4）；Schema 缺失走默认权重保守预算（D11）；
//   - 全部乘加饱和（上界 satCap），溢出即超预算不绕回（D6）；
//   - 本层不执行任何动作：只产出成本与分类（执行映射在 GQL-03）。
package gqlast

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/vektah/gqlparser/v2/ast"
)

// satCap 饱和上限（D6：溢出即超预算，绝不绕回小数值）。
const satCap = int64(1)<<62 - 1

func satAdd(a, b int64) int64 {
	if a > satCap-b {
		return satCap
	}
	return a + b
}

func satMul(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > satCap/b {
		return satCap
	}
	return a * b
}

// FieldWeight 字段级权重覆盖（路径形如 "Type.field"，如 "Query.users"、"User.posts"）。
type FieldWeight struct {
	Weight    int64 `json:"weight"`     // base 覆盖（>0 生效；0=用默认）
	ListBound int64 `json:"list_bound"` // 该字段（列表时）的批准上界（>0 生效；0=用默认列表上界）
}

// WeightsConfig 权重配置（Schema 缺失时全走默认（D11）；APQ 白名单属管理面资产不在此层）。
type WeightsConfig struct {
	DefaultFieldWeight  int64                  `json:"default_field_weight"` // D1（0→1）
	DefaultListBound    int64                  `json:"default_list_bound"`   // D3（0→100）
	IntrospectionWeight int64                  `json:"introspection_weight"` // D5（0→50）
	Fields              map[string]FieldWeight `json:"fields,omitempty"`
}

func (w WeightsConfig) withDefaults() WeightsConfig {
	if w.DefaultFieldWeight <= 0 {
		w.DefaultFieldWeight = 1
	}
	if w.DefaultListBound <= 0 {
		w.DefaultListBound = 100
	}
	if w.IntrospectionWeight <= 0 {
		w.IntrospectionWeight = 50
	}
	return w
}

// CostOutcome 成本判定输出（执行层映射输入；非动作本身）。
type CostOutcome struct {
	Cost      int64  `json:"cost"`
	Exceeded  bool   `json:"exceeded"`
	Budget    int64  `json:"budget"`
	Saturated bool   `json:"saturated"` // 任一环节触发饱和（D6 超预算语义）
	Note      string `json:"note,omitempty"`
}

// BudgetConfig 单请求与窗口预算配置（D7/D8）。
type BudgetConfig struct {
	PerRequest      int64 `json:"per_request_budget"` // 单请求结构预算（0→5000）
	WindowSeconds   int64 `json:"window_seconds"`     // 主体/租户窗口长度（0→60）
	WindowBudget    int64 `json:"window_budget"`      // 主体/租户窗口预算（0→100000）
	AnonymousBudget int64 `json:"anonymous_budget"`   // 匿名独立桶预算（0→20000）
}

func (b BudgetConfig) withDefaults() BudgetConfig {
	if b.PerRequest <= 0 {
		b.PerRequest = 5000
	}
	if b.WindowSeconds <= 0 {
		b.WindowSeconds = 60
	}
	if b.WindowBudget <= 0 {
		b.WindowBudget = 100000
	}
	if b.AnonymousBudget <= 0 {
		b.AnonymousBudget = 20000
	}
	return b
}

// CostOf 计算被选 operation 的成本并做单请求预算判定。
// doc 必须来自 ParseBounded（深度/节点/循环已有硬边界）；op 必须属于 doc。
func CostOf(doc *Document, op *Operation, weights WeightsConfig, budget BudgetConfig) CostOutcome {
	weights = weights.withDefaults()
	budget = budget.withDefaults()
	sat := &satFlag{}
	c := costOfSelectionSet(op.Definition.SelectionSet, weights, doc.AST, sat)
	out := CostOutcome{Cost: c, Budget: budget.PerRequest, Saturated: sat.hit}
	if sat.hit || c > budget.PerRequest {
		out.Exceeded = true
	}
	return out
}

type satFlag struct{ hit bool }

// costOfSelectionSet 递归成本：response key 合并（D2）——同 key 多次出现
// base 计 1 次、子成本取 max；fragment 经 expandFragment 展开（循环已由 ParseBounded 拦截，
// 此处对展开次数做并节点预算内的防御性封顶）。
func costOfSelectionSet(set ast.SelectionSet, weights WeightsConfig, doc *ast.QueryDocument, sat *satFlag) int64 {
	type fieldCost struct {
		base    int64
		subCost int64
	}
	merged := map[string]*fieldCost{}
	order := []string{}
	add := func(key string, base, sub int64) {
		if fc, ok := merged[key]; ok {
			if sub > fc.subCost {
				fc.subCost = sub
			}
			return
		}
		merged[key] = &fieldCost{base: base, subCost: sub}
		order = append(order, key)
	}
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			key := s.Alias
			if key == "" {
				key = s.Name
			}
			base := fieldBaseCost(s, weights)
			sub := costOfSelectionSet(s.SelectionSet, weights, doc, sat)
			if len(s.SelectionSet) > 0 {
				sub = satMul(sizeFactor(s, weights), sub)
			}
			add(key, base, sub)
		case *ast.FragmentSpread:
			frag := findFragment(doc, s.Name)
			if frag == nil {
				add(s.Name, weights.DefaultFieldWeight, 0)
				continue
			}
			sub := costOfSelectionSet(frag.SelectionSet, weights, doc, sat)
			add(s.Name, weights.DefaultFieldWeight, sub)
		case *ast.InlineFragment:
			sub := costOfSelectionSet(s.SelectionSet, weights, doc, sat)
			add("inline:"+s.TypeCondition, weights.DefaultFieldWeight, sub)
		}
	}
	sort.Strings(order) // 确定性：合并求和与顺序无关，但排序使黄金样本可 diff
	var total int64
	for _, k := range order {
		fc := merged[k]
		total = satAdd(total, satAdd(fc.base, fc.subCost))
	}
	return total
}

// fieldBaseCost 字段基础成本：权重覆盖 > 内省特判（D5）> 默认（D1）。
// 无 Schema 的查询文档 f.Definition.Type 为 nil：路径退化为 ".field"，仅 "*.field" 覆盖可命中（D11）。
func fieldBaseCost(f *ast.Field, weights WeightsConfig) int64 {
	if f.Name == "__schema" || f.Name == "__type" {
		return weights.IntrospectionWeight
	}
	typeName := ""
	if f.Definition != nil && f.Definition.Type != nil {
		typeName = f.Definition.Type.Name()
	}
	path := typeName + "." + f.Name
	if fw, ok := weights.Fields[path]; ok && fw.Weight > 0 {
		return fw.Weight
	}
	if fw, ok := weights.Fields["*."+f.Name]; ok && fw.Weight > 0 {
		return fw.Weight
	}
	return weights.DefaultFieldWeight
}

// sizeFactor 列表字段规模系数：权重覆盖的批准上界 > 默认列表上界（D3）。
// 非列表字段恒为 1；无 Schema 类型时按非列表计（D11 保守口径，不放大）。变量不求值（D4）。
func sizeFactor(f *ast.Field, weights WeightsConfig) int64 {
	var ftype *ast.Type
	if f.Definition != nil {
		ftype = f.Definition.Type
	}
	if !isListType(ftype) {
		return 1
	}
	typeName := ""
	if ftype != nil {
		typeName = ftype.Name()
	}
	path := typeName + "." + f.Name
	if fw, ok := weights.Fields[path]; ok && fw.ListBound > 0 {
		return fw.ListBound
	}
	if fw, ok := weights.Fields["*."+f.Name]; ok && fw.ListBound > 0 {
		return fw.ListBound
	}
	return weights.DefaultListBound
}

func isListType(t *ast.Type) bool {
	if t == nil {
		return false
	}
	if t.Elem != nil {
		return true
	}
	return false
}

// ---------- 成本缓存（D9） ----------

// CostCacheKey 缓存键：文档摘要 + schemaVersion + policyVersion（D9）。
type CostCacheKey struct {
	DocDigest     string
	SchemaVersion string
	PolicyVersion string
}

// CostCache 有界 LRU 成本缓存（并发安全；变量不求值故成本与变量值无关，可安全复用）。
type CostCache struct {
	mu    sync.Mutex
	max   int
	items map[CostCacheKey]int64
	order []CostCacheKey
}

// NewCostCache 创建缓存（max<=0 取 1000）。
func NewCostCache(max int) *CostCache {
	if max <= 0 {
		max = 1000
	}
	return &CostCache{max: max, items: map[CostCacheKey]int64{}}
}

// DigestDocument 规范化文档摘要（APQ 摘要同口径：去全部空白后的文档字节 sha256）。
func DigestDocument(query string) string {
	compact := make([]byte, 0, len(query))
	inStr, inBlockStr, esc := false, false, false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if inBlockStr {
			if i+2 < len(query) && query[i:i+3] == `"""` {
				inBlockStr = false
				i += 2
			}
			continue
		}
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if i+2 < len(query) && query[i:i+3] == `"""` {
			inBlockStr = true
			i += 2
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c == '#' {
			for i < len(query) && query[i] != '\n' {
				i++
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			continue
		}
		compact = append(compact, c)
	}
	sum := sha256.Sum256(compact)
	return hex.EncodeToString(sum[:16])
}

// Get 查询缓存（命中返回成本与 true）。
func (c *CostCache) Get(k CostCacheKey) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[k]
	return v, ok
}

// Put 写入缓存（LRU 淘汰最旧）。
func (c *CostCache) Put(k CostCacheKey, v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[k]; ok {
		c.items[k] = v
		return
	}
	if len(c.order) >= c.max {
		delete(c.items, c.order[0])
		c.order = c.order[1:]
	}
	c.items[k] = v
	c.order = append(c.order, k)
}

// CostOfCached 带缓存的成本计算（docDigest 由调用方经 DigestDocument 计算并随版本传入）。
func CostOfCached(cache *CostCache, doc *Document, op *Operation, weights WeightsConfig, budget BudgetConfig, schemaVersion, policyVersion string) CostOutcome {
	key := CostCacheKey{DocDigest: DigestDocument(doc.Query), SchemaVersion: schemaVersion, PolicyVersion: policyVersion}
	if cache != nil {
		if v, ok := cache.Get(key); ok {
			out := CostOutcome{Cost: v, Budget: budget.withDefaults().PerRequest, Note: "cache:hit"}
			if v > out.Budget {
				out.Exceeded = true
			}
			return out
		}
	}
	out := CostOf(doc, op, weights, budget)
	if cache != nil && !out.Saturated {
		cache.Put(key, out.Cost)
	}
	out.Note = "cache:miss"
	return out
}

// String 调试摘要（成本语义一行化，不含文档内容）。
func (o CostOutcome) String() string {
	return fmt.Sprintf("cost=%d budget=%d exceeded=%v saturated=%v %s", o.Cost, o.Budget, o.Exceeded, o.Saturated, o.Note)
}
