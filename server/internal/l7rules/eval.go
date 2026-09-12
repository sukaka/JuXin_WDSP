package l7rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Input 是一次请求的评估输入（规则测试器与网关评估语义一致）。
type Input struct {
	URI      string            // 请求 URI（可含 query，评估时仅取路径部分）
	Method   string            // 请求方法（大小写不敏感，评估时转大写）
	Headers  map[string]string // 请求头（名称大小写不敏感）
	Cookies  map[string]string // Cookie（名称大小写敏感）
	Query    map[string]string // Query 参数（名称大小写敏感）
	ClientIP string            // 来源 IP（为空或非法时 client_ip 条件不命中）
}

// Result 是评估结果。Matched=false 表示不命中任何规则，将继续后续检查。
type Result struct {
	Matched bool
	Rule    *Rule  // 命中规则（未命中为 nil）
	Reason  string // 中文原因说明（测试器回显）
}

// Evaluator 是编译后的规则集评估器（纯函数、无副作用；测试器复用，不产生真实流量、不写事件）。
type Evaluator struct {
	rules []compiledRule // 已按 (priority 升序, created_at 升序) 稳定排序
}

type compiledCondition struct {
	cond    Condition
	re      *regexp.Regexp  // op=regex 时非 nil
	addrs   []netip.Addr    // client_ip 单 IP 值
	cidrs   []netip.Prefix  // client_ip CIDR 值
	methods map[string]bool // method 值集合
}

type compiledRule struct {
	rule  Rule
	conds []compiledCondition
}

// NewEvaluator 编译规则集：正则预编译、CIDR/地址预解析、方法集合化。
// 编译失败返回错误（整条规则拒绝由写入侧校验保证，此处为防御性检查）。
func NewEvaluator(rules []Rule) (*Evaluator, error) {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	out := &Evaluator{rules: make([]compiledRule, 0, len(sorted))}
	for _, r := range sorted {
		cr := compiledRule{rule: r, conds: make([]compiledCondition, 0, len(r.Conditions))}
		for _, c := range r.Conditions {
			cc := compiledCondition{cond: c}
			switch {
			case c.Op == OpRegex:
				re, err := regexp.Compile(c.Value)
				if err != nil {
					return nil, fmt.Errorf("规则「%s」正则编译失败: %w", r.Name, err)
				}
				cc.re = re
			case c.Type == CondTypeClientIP:
				for _, v := range c.Values {
					if strings.Contains(v, "/") {
						p, err := netip.ParsePrefix(v)
						if err != nil {
							return nil, fmt.Errorf("规则「%s」CIDR 解析失败: %w", r.Name, err)
						}
						cc.cidrs = append(cc.cidrs, p.Masked())
					} else {
						a, err := netip.ParseAddr(v)
						if err != nil {
							return nil, fmt.Errorf("规则「%s」IP 解析失败: %w", r.Name, err)
						}
						cc.addrs = append(cc.addrs, a.Unmap())
					}
				}
			case c.Type == CondTypeMethod:
				cc.methods = make(map[string]bool, len(c.Values))
				for _, m := range c.Values {
					cc.methods[strings.ToUpper(m)] = true
				}
			}
			cr.conds = append(cr.conds, cc)
		}
		out.rules = append(out.rules, cr)
	}
	return out, nil
}

// evalView 是输入的预处理视图（评估时复用，避免每条件重复归一化）。
type evalView struct {
	uriPath    string
	method     string
	headers    map[string]string // 键已小写
	cookies    map[string]string
	query      map[string]string
	clientAddr netip.Addr
	hasClient  bool
}

func newEvalView(in Input) evalView {
	v := evalView{
		uriPath: in.URI,
		method:  strings.ToUpper(strings.TrimSpace(in.Method)),
		cookies: in.Cookies,
		query:   in.Query,
	}
	if i := strings.IndexByte(v.uriPath, '?'); i >= 0 {
		v.uriPath = v.uriPath[:i] // uri 条件只匹配路径部分
	}
	if len(in.Headers) > 0 {
		v.headers = make(map[string]string, len(in.Headers))
		for k, val := range in.Headers {
			v.headers[strings.ToLower(k)] = val
		}
	}
	if ip := strings.TrimSpace(in.ClientIP); ip != "" {
		if a, err := netip.ParseAddr(ip); err == nil {
			v.clientAddr = a.Unmap()
			v.hasClient = true
		}
	}
	return v
}

// Eval 评估输入：按序遍历启用规则，首个条件全中的规则生效（首中即停）；
// 全部未命中返回 Matched=false（继续后续检查，默认放行到 CC）。
func (e *Evaluator) Eval(in Input) Result {
	v := newEvalView(in)
	for i := range e.rules {
		cr := &e.rules[i]
		if !cr.rule.Enabled {
			continue
		}
		if matchAll(cr.conds, &v) {
			rule := cr.rule
			return Result{
				Matched: true,
				Rule:    &rule,
				Reason:  fmt.Sprintf("命中规则「%s」（优先级 %d，首中即停）", rule.Name, rule.Priority),
			}
		}
	}
	return Result{Matched: false, Reason: "不命中任何规则，将继续后续检查"}
}

// matchAll 多条件 AND：全部满足才命中。
func matchAll(conds []compiledCondition, v *evalView) bool {
	for _, c := range conds {
		if !c.match(v) {
			return false
		}
	}
	return true
}

// match 单条件匹配。值类运算符（eq/ne/prefix/contains/regex）在键不存在时一律不命中。
func (c compiledCondition) match(v *evalView) bool {
	switch c.cond.Type {
	case CondTypeURI:
		return matchValue(c.cond.Op, c.cond.Value, v.uriPath, c.re)
	case CondTypeMethod:
		return c.methods[v.method]
	case CondTypeHeader:
		return c.matchNamed(v.headers, strings.ToLower(c.cond.Name))
	case CondTypeCookie:
		return c.matchNamed(v.cookies, c.cond.Name)
	case CondTypeQuery:
		return c.matchNamed(v.query, c.cond.Name)
	case CondTypeClientIP:
		if !v.hasClient {
			return false
		}
		for _, a := range c.addrs {
			if a == v.clientAddr {
				return true
			}
		}
		for _, p := range c.cidrs {
			if p.Contains(v.clientAddr) {
				return true
			}
		}
		return false
	}
	return false
}

// matchNamed 命名条件匹配：先查表取存在性，再按运算符比较。
// name 为查找键（header 已小写化；cookie/query 精确大小写）。
func (c compiledCondition) matchNamed(m map[string]string, name string) bool {
	val, present := m[name]
	switch c.cond.Op {
	case OpExists:
		return present
	case OpNotExists:
		return !present
	}
	if !present {
		return false // 值类运算符：键不存在不命中（ne 也不例外）
	}
	return matchValue(c.cond.Op, c.cond.Value, val, c.re)
}

// matchValue 字符串值比较。
func matchValue(op, want, got string, re *regexp.Regexp) bool {
	switch op {
	case OpEq:
		return got == want
	case OpNe:
		return got != want
	case OpPrefix:
		return strings.HasPrefix(got, want)
	case OpContains:
		return strings.Contains(got, want)
	case OpRegex:
		return re != nil && re.MatchString(got)
	}
	return false
}
