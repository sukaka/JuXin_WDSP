// Package gqlast 有界 GraphQL AST 解析与操作选择（NG-GQL-01）。
//
// 边界纪律（RD_PLAN §7.1/§14.1，唯一事实源）：
//   - 库（vektah/gqlparser）不提供资源上限；全部硬边界在本层显式执行：
//     文档字节、词法深度、alias、展开选择集节点、fragment 循环；
//   - 解析资源硬上限与业务处置模式（OBSERVE/PROTECT）分离：超限即 LIMIT_EXCEEDED
//     类错误（非解析成功、非攻击判定），由调用方按协议/模式映射；
//   - 多 operation 文档只执行被选定 operation（NG-T-G01）：不执行不展开其他 operation；
//   - 变量不求值、不展开（成本模型阶段再处理；与现有 parse_graphql.go 顶层键名口径兼容）。
package gqlast

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Limits 解析硬上限（零值字段取默认；默认值为隔离实验候选，非生产承诺值）。
type Limits struct {
	MaxDocBytes    int // 文档字节硬上限（默认 64 KiB）
	MaxDepth       int // 选择集嵌套深度（默认 20）
	MaxNodes       int // 展开后选择集节点预算（默认 10000）
	MaxAliases     int // alias 数（默认 100）
	MaxFragmentExp int // 单 fragment 展开次数预算（默认 1000，并入 MaxNodes 计数）
}

// DefaultLimits 返回隔离实验候选默认值（RD_PLAN §14.1）。
func DefaultLimits() Limits {
	return Limits{MaxDocBytes: 64 * 1024, MaxDepth: 20, MaxNodes: 10000, MaxAliases: 100, MaxFragmentExp: 1000}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxDocBytes <= 0 {
		l.MaxDocBytes = d.MaxDocBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxAliases <= 0 {
		l.MaxAliases = d.MaxAliases
	}
	if l.MaxFragmentExp <= 0 {
		l.MaxFragmentExp = d.MaxFragmentExp
	}
	return l
}

// Stats 解析统计（覆盖观测/成本模型输入；不含任何文档内容）。
type Stats struct {
	DocBytes    int  `json:"doc_bytes"`
	Depth       int  `json:"depth"`
	Nodes       int  `json:"nodes"`   // 展开前选择集节点（操作选择层）
	Aliases     int  `json:"aliases"` // alias 出现数（按执行字段计费前的原始数）
	Operations  int  `json:"operations"`
	Fragments   int  `json:"fragments"`
	HasVariable bool `json:"has_variables"`
}

// Error 错误类型（协议化映射用；均非「解析成功」）。
type Error struct {
	Kind    ErrorKind `json:"kind"`
	Message string    `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Message) }

// ErrorKind 错误类别枚举（冻结：新增只准追加）。
type ErrorKind string

const (
	ErrDocTooLarge    ErrorKind = "DOC_TOO_LARGE"       // 超文档字节硬上限
	ErrTooDeep        ErrorKind = "TOO_DEEP"            // 选择集嵌套超限
	ErrTooManyNodes   ErrorKind = "TOO_MANY_NODES"      // 展开节点超预算
	ErrTooManyAliases ErrorKind = "TOO_MANY_ALIASES"    // alias 超限
	ErrFragmentCycle  ErrorKind = "FRAGMENT_CYCLE"      // fragment 循环引用
	ErrSyntax         ErrorKind = "SYNTAX"              // 语法错误（库解析失败）
	ErrNoOperation    ErrorKind = "NO_OPERATION"        // 文档无 operation
	ErrMultipleOps    ErrorKind = "MULTIPLE_OPERATIONS" // 多 operation 未指定 operationName
	ErrOpNotFound     ErrorKind = "OPERATION_NOT_FOUND" // 指定的 operationName 不存在
)

// Document 解析结果（文档内容以 ast 形式持有；Query 为原文（成本缓存摘要 D9 用，
// 规范化在 DigestDocument 内做，不另存副本）。
type Document struct {
	AST   *ast.QueryDocument
	Stats Stats
	Query string
}

// ParseBounded 有界解析：字节硬拒 → 词法预扫（深度/alias/粗节点数）→ 库 AST 解析
// → AST 复核（深度/alias 精确值、fragment 循环检测、节点预算）。
// 任何一步超限/失败返回 *Error（Kind 分类），绝不返回部分可用 AST（fail-closed）。
func ParseBounded(query string, limits Limits) (*Document, error) {
	limits = limits.withDefaults()
	if len(query) > limits.MaxDocBytes {
		return nil, &Error{ErrDocTooLarge, fmt.Sprintf("文档 %d 字节超过硬上限 %d", len(query), limits.MaxDocBytes)}
	}
	pre, err := prescan(query, limits)
	if err != nil {
		return nil, err
	}
	doc, perr := parser.ParseQuery(&ast.Source{Input: query})
	if perr != nil {
		return nil, &Error{ErrSyntax, perr.Error()}
	}
	stats := Stats{DocBytes: len(query), Depth: pre.depth, Aliases: pre.aliases, Operations: len(doc.Operations), Fragments: len(doc.Fragments)}
	if cycle := detectFragmentCycle(doc); cycle != "" {
		return nil, &Error{ErrFragmentCycle, "fragment 循环引用: " + cycle}
	}
	// AST 复核（以真实解析结果及 fragment 展开后的有效深度/alias/节点/展开预算为准，预扫仅作快速拒绝）
	depth, aliases, nodes, fragExp := measureAST(doc, limits)
	stats.Depth, stats.Aliases, stats.Nodes = depth, aliases, nodes
	if stats.Depth > limits.MaxDepth {
		return nil, &Error{ErrTooDeep, fmt.Sprintf("选择集深度 %d 超过硬上限 %d", stats.Depth, limits.MaxDepth)}
	}
	if stats.Aliases > limits.MaxAliases {
		return nil, &Error{ErrTooManyAliases, fmt.Sprintf("alias 数 %d 超过硬上限 %d", stats.Aliases, limits.MaxAliases)}
	}
	if fragExp > limits.MaxFragmentExp {
		return nil, &Error{ErrTooManyNodes, fmt.Sprintf("fragment 展开次数 %d 超过预算 %d", fragExp, limits.MaxFragmentExp)}
	}
	if stats.Nodes > limits.MaxNodes {
		return nil, &Error{ErrTooManyNodes, fmt.Sprintf("选择集节点 %d 超过预算 %d", stats.Nodes, limits.MaxNodes)}
	}
	if len(doc.Operations) == 0 {
		return nil, &Error{ErrNoOperation, "文档不包含 operation"}
	}
	stats.HasVariable = hasAnyVariable(doc)
	return &Document{AST: doc, Stats: stats, Query: query}, nil
}

// prescan 词法级快速预扫（O(n) 单趟、无正则）：仅用于快速拒绝明显超限输入，
// 精确度量以 measureAST 为准。返回深度上界与 alias 粗计数（在字符串/注释/参数括号外识别 "identifier:"）。
type prescanResult struct {
	depth   int
	aliases int
}

func prescan(query string, limits Limits) (prescanResult, error) {
	depth, maxDepth, parenDepth, aliases := 0, 0, 0, 0
	inStr, inBlockStr, esc := false, false, false
	lineComment := false
	inIdent, lastWasIdent := false, false
	i := 0
	for i < len(query) {
		c := query[i]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			i++
			continue
		}
		if inBlockStr {
			if strings.HasPrefix(query[i:], `"""`) {
				inBlockStr = false
				i += 3
				continue
			}
			i++
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
			i++
			continue
		}
		switch {
		case strings.HasPrefix(query[i:], `"""`):
			inIdent, lastWasIdent = false, false
			inBlockStr = true
			i += 3
			continue
		case c == '"':
			inIdent, lastWasIdent = false, false
			inStr = true
			i++
			continue
		case c == '#':
			if inIdent {
				inIdent, lastWasIdent = false, true
			}
			lineComment = true
			i++
			continue
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			if inIdent {
				inIdent, lastWasIdent = false, true
			}
		case c == ':':
			if (inIdent || lastWasIdent) && depth > 0 && parenDepth == 0 {
				aliases++
				if aliases > limits.MaxAliases {
					return prescanResult{}, &Error{ErrTooManyAliases, fmt.Sprintf("alias 数 %d 超过硬上限 %d", aliases, limits.MaxAliases)}
				}
			}
			inIdent, lastWasIdent = false, false
		case c == '(':
			inIdent, lastWasIdent = false, false
			parenDepth++
		case c == ')':
			inIdent, lastWasIdent = false, false
			if parenDepth > 0 {
				parenDepth--
			}
		case c == '{':
			inIdent, lastWasIdent = false, false
			depth++
			if depth > maxDepth {
				maxDepth = depth
				if maxDepth > limits.MaxDepth {
					return prescanResult{}, &Error{ErrTooDeep, fmt.Sprintf("词法嵌套深度 %d 超过硬上限 %d", maxDepth, limits.MaxDepth)}
				}
			}
		case c == '}':
			inIdent, lastWasIdent = false, false
			if depth > 0 {
				depth--
			}
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_':
			inIdent = true
			lastWasIdent = false
		default:
			inIdent, lastWasIdent = false, false
		}
		i++
	}
	return prescanResult{depth: maxDepth, aliases: aliases}, nil
}

func cappedAdd(a, b, capVal int) int {
	if a >= capVal || b >= capVal || a > capVal-b {
		return capVal
	}
	return a + b
}

// measureAST 以真实 AST 精确度量（含 FragmentSpread 记忆化 DAG 展开）：
// 最大有效选择集深度、展开后 alias 数、展开后选择集节点数与 fragment 展开总次数。
// 借助 DAG 记忆化保证 O(V+E) 线性时间，同时在预算超限时饱和封顶不发生指数遍历或整数溢出。
func measureAST(doc *ast.QueryDocument, limits Limits) (depth, aliases, nodes, fragExp int) {
	depthCap := limits.MaxDepth + 1
	aliasCap := limits.MaxAliases + 1
	nodeCap := limits.MaxNodes + 1
	fragCap := limits.MaxFragmentExp + 1

	fragMap := make(map[string]*ast.FragmentDefinition, len(doc.Fragments))
	for _, f := range doc.Fragments {
		fragMap[f.Name] = f
	}

	type setMetrics struct {
		maxRelDepth int // 本选择集内相对最大额外深度（单层标量字段为 0，含一层子选择集为 1）
		aliases     int
		nodes       int
		fragExp     int
	}

	memo := make(map[string]setMetrics, len(doc.Fragments))
	active := make(map[string]bool, len(doc.Fragments))

	var measureSet func(set ast.SelectionSet) setMetrics
	measureFrag := func(name string) (setMetrics, bool) {
		if m, ok := memo[name]; ok {
			return m, true
		}
		f, ok := fragMap[name]
		if !ok {
			return setMetrics{}, false
		}
		if active[name] {
			// 防御性环路兜底（ParseBounded 已先行 detectFragmentCycle）
			return setMetrics{maxRelDepth: depthCap, aliases: aliasCap, nodes: nodeCap, fragExp: fragCap}, true
		}
		active[name] = true
		m := measureSet(f.SelectionSet)
		delete(active, name)
		memo[name] = m
		return m, true
	}

	measureSet = func(set ast.SelectionSet) setMetrics {
		var out setMetrics
		for _, sel := range set {
			switch s := sel.(type) {
			case *ast.Field:
				out.nodes = cappedAdd(out.nodes, 1, nodeCap)
				if s.Alias != "" && s.Alias != s.Name {
					out.aliases = cappedAdd(out.aliases, 1, aliasCap)
				}
				if len(s.SelectionSet) > 0 {
					sub := measureSet(s.SelectionSet)
					if subDepth := cappedAdd(sub.maxRelDepth, 1, depthCap); subDepth > out.maxRelDepth {
						out.maxRelDepth = subDepth
					}
					out.aliases = cappedAdd(out.aliases, sub.aliases, aliasCap)
					out.nodes = cappedAdd(out.nodes, sub.nodes, nodeCap)
					out.fragExp = cappedAdd(out.fragExp, sub.fragExp, fragCap)
				}
			case *ast.FragmentSpread:
				out.nodes = cappedAdd(out.nodes, 1, nodeCap)
				out.fragExp = cappedAdd(out.fragExp, 1, fragCap)
				if fm, ok := measureFrag(s.Name); ok {
					if fm.maxRelDepth > out.maxRelDepth {
						out.maxRelDepth = fm.maxRelDepth
					}
					out.aliases = cappedAdd(out.aliases, fm.aliases, aliasCap)
					out.nodes = cappedAdd(out.nodes, fm.nodes, nodeCap)
					out.fragExp = cappedAdd(out.fragExp, fm.fragExp, fragCap)
				}
			case *ast.InlineFragment:
				out.nodes = cappedAdd(out.nodes, 1, nodeCap)
				sub := measureSet(s.SelectionSet)
				if subDepth := cappedAdd(sub.maxRelDepth, 1, depthCap); subDepth > out.maxRelDepth {
					out.maxRelDepth = subDepth
				}
				out.aliases = cappedAdd(out.aliases, sub.aliases, aliasCap)
				out.nodes = cappedAdd(out.nodes, sub.nodes, nodeCap)
				out.fragExp = cappedAdd(out.fragExp, sub.fragExp, fragCap)
			}
		}
		return out
	}

	for _, op := range doc.Operations {
		nodes = cappedAdd(nodes, 1, nodeCap) // 操作定义本身计 1
		m := measureSet(op.SelectionSet)
		opDepth := cappedAdd(1, m.maxRelDepth, depthCap)
		if opDepth > depth {
			depth = opDepth
		}
		aliases = cappedAdd(aliases, m.aliases, aliasCap)
		nodes = cappedAdd(nodes, m.nodes, nodeCap)
		fragExp = cappedAdd(fragExp, m.fragExp, fragCap)
	}
	// 同时检查未被引用的 fragment 定义自身（防巨型/超深未引用 fragment 隐藏在文档中）
	for _, f := range doc.Fragments {
		if _, visited := memo[f.Name]; visited {
			continue
		}
		fm, _ := measureFrag(f.Name)
		fDepth := cappedAdd(1, fm.maxRelDepth, depthCap)
		if fDepth > depth {
			depth = fDepth
		}
		aliases = cappedAdd(aliases, fm.aliases, aliasCap)
		nodes = cappedAdd(nodes, cappedAdd(1, fm.nodes, nodeCap), nodeCap)
		fragExp = cappedAdd(fragExp, fm.fragExp, fragCap)
	}
	return depth, aliases, nodes, fragExp
}

// detectFragmentCycle 检测 fragment 循环引用（DFS 访问栈；返回循环名或空串）。
func detectFragmentCycle(doc *ast.QueryDocument) string {
	visited := map[string]int{} // 0=未访问 1=栈中 2=完成
	var dfs func(name string) bool
	dfs = func(name string) bool {
		if visited[name] == 1 {
			return true
		}
		if visited[name] == 2 {
			return false
		}
		visited[name] = 1
		frag := findFragment(doc, name)
		if frag != nil {
			for _, sel := range frag.SelectionSet {
				for _, spread := range collectSpreads(sel) {
					if dfs(spread) {
						return true
					}
				}
			}
		}
		visited[name] = 2
		return false
	}
	for _, frag := range doc.Fragments {
		if dfs(frag.Name) {
			return frag.Name
		}
	}
	return ""
}

func findFragment(doc *ast.QueryDocument, name string) *ast.FragmentDefinition {
	for _, f := range doc.Fragments {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func collectSpreads(sel ast.Selection) []string {
	var out []string
	var walk func(s ast.Selection)
	walk = func(s ast.Selection) {
		switch n := s.(type) {
		case *ast.Field:
			for _, sub := range n.SelectionSet {
				walk(sub)
			}
		case *ast.FragmentSpread:
			out = append(out, n.Name)
		case *ast.InlineFragment:
			for _, sub := range n.SelectionSet {
				walk(sub)
			}
		}
	}
	walk(sel)
	return out
}

func hasAnyVariable(doc *ast.QueryDocument) bool {
	for _, op := range doc.Operations {
		if len(op.VariableDefinitions) > 0 {
			return true
		}
	}
	return false
}
