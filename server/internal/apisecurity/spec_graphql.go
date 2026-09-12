// spec_graphql.go 阶段8 §33：GraphQL Schema（SDL）规范导入解析。
// 解析 type Query / type Mutation（含 schema{} 自定义根类型名与 extend type 扩展），
// 每个字段生成一条合成操作：Method=QUERY/MUTATION，Path=/graphql/<字段名>，
// 字段参数展开为 ARG 参数（非空类型 …! 标记 required）。
// 不依赖第三方 GraphQL 库（go.mod 最小引入原则）：实现面向 SDL 结构提取的最小
// 词法/语法解析，注释、字符串/块字符串、指令（@…）与默认值均被正确跳过。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"fmt"
	"sort"
	"strings"
)

// gqlToken SDL 词法单元：kind 为 'n'（名称/数字字面量）、'p'（标点）、's'（字符串/块字符串，语法层跳过）。
type gqlToken struct {
	kind byte
	val  string
}

// gqlPunct SDL 中有语法意义的标点。
const gqlPunct = "{}()[]:=!|,@&"

// looksLikeGraphQLSDL SDL 形态粗判：含 type Query/Mutation/schema{ 结构
// （用于 YAML 解码失败后的回退判定，避免任意文本被当作 SDL 报误导性错误）。
func looksLikeGraphQLSDL(s string) bool {
	toks := gqlLex(s)
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind != 'n' {
			continue
		}
		switch toks[i].val {
		case "type", "interface":
			if toks[i+1].kind == 'n' && (toks[i+1].val == "Query" || toks[i+1].val == "Mutation") {
				return true
			}
		case "schema":
			if toks[i+1].kind == 'p' && toks[i+1].val == "{" {
				return true
			}
		}
	}
	return false
}

// gqlLex SDL 词法扫描：剥离 # 注释；字符串与 """ 块字符串归为 's'；名称 [_A-Za-z][_0-9A-Za-z]*。
// 数字字面量归入 'n'（仅在默认值中出现，语法层不关心其值）。
func gqlLex(s string) []gqlToken {
	toks := []gqlToken{}
	i, n := 0, len(s)
	s = strings.TrimPrefix(s, "\ufeff")
	for i < n {
		c := s[i]
		switch {
		case c == '#':
			for i < n && s[i] != '\n' {
				i++
			}
		case c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '"':
			if i+2 < n && s[i:i+3] == `"""` {
				// 块字符串（允许未转义的 " 与换行）
				j := i + 3
				for j < n {
					if s[j] == '\\' && j+3 < n && s[j+1:j+4] == `"""` {
						j += 4
						continue
					}
					if j+2 < n && s[j:j+3] == `"""` {
						break
					}
					j++
				}
				if j+2 < n {
					i = j + 3
				} else {
					i = n // 未闭合块字符串：吞到结尾（语法层后续报错）
				}
			} else {
				j := i + 1
				for j < n && s[j] != '"' {
					if s[j] == '\\' {
						j++
					}
					j++
				}
				if j < n {
					j++
				}
				i = j
			}
			toks = append(toks, gqlToken{kind: 's'})
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			j := i + 1
			for j < n {
				d := s[j]
				if d == '_' || (d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z') || (d >= '0' && d <= '9') {
					j++
				} else {
					break
				}
			}
			toks = append(toks, gqlToken{kind: 'n', val: s[i:j]})
			i = j
		case (c >= '0' && c <= '9') || c == '-':
			j := i + 1
			for j < n {
				d := s[j]
				if (d >= '0' && d <= '9') || d == '.' || d == 'e' || d == 'E' || d == '+' || d == '-' {
					j++
				} else {
					break
				}
			}
			toks = append(toks, gqlToken{kind: 'n', val: s[i:j]})
			i = j
		case strings.IndexByte(gqlPunct, c) >= 0:
			toks = append(toks, gqlToken{kind: 'p', val: string(c)})
			i++
		default:
			i++ // 其余字符（$ 等）忽略
		}
	}
	return toks
}

// gqlRootTypeNames schema{} 声明的根类型名映射（缺省 Query/Mutation/Subscription）。
type gqlRootTypeNames struct {
	query    string
	mutation string
}

// ParseGraphQLSDL 解析 GraphQL SDL 文档为操作清单。
// 找不到任何 Query/Mutation 字段时报 ErrSpecInvalidGraphQL（HTTP 层 400）。
func ParseGraphQLSDL(sdl string) ([]SpecOperation, error) {
	toks := gqlLex(sdl)
	if len(toks) == 0 {
		return nil, fmt.Errorf("%w: 空文档", ErrSpecInvalidGraphQL)
	}
	p := &sdlParser{toks: toks}
	roots := gqlRootTypeNames{query: "Query", mutation: "Mutation"}
	// 第一遍先收集 schema{} 根类型名（可能出现在 type 定义之后）
	p.collectRootTypeNames(&roots)
	p.pos = 0
	ops := []SpecOperation{}
	p.collectOperations(&roots, &ops)
	if p.unclosed {
		return nil, fmt.Errorf("%w: SDL 结构不完整（存在未闭合的定义块）", ErrSpecInvalidGraphQL)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: 未找到 type Query / type Mutation 字段定义", ErrSpecInvalidGraphQL)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key < ops[j].Key })
	return ops, nil
}

// sdlParser SDL 语法层游标（语法容错：无法识别的结构跳过而非报错，
// 但未闭合的定义块视为格式错误；最终无操作时返回 ErrSpecInvalidGraphQL）。
type sdlParser struct {
	toks     []gqlToken
	pos      int
	unclosed bool // 存在 token 耗尽前未闭合的 {} 块
}

func (p *sdlParser) peek() (gqlToken, bool) {
	if p.pos >= len(p.toks) {
		return gqlToken{}, false
	}
	return p.toks[p.pos], true
}

func (p *sdlParser) next() (gqlToken, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

// isKeyword 当前 token 是否为顶层定义关键字。
func (p *sdlParser) isKeyword() bool {
	t, ok := p.peek()
	if !ok || t.kind != 'n' {
		return false
	}
	switch t.val {
	case "type", "interface", "input", "enum", "union", "scalar", "directive", "schema", "extend":
		return true
	}
	return false
}

// skipBalanced 跳过已消费的 open 括号到匹配的 close（容忍嵌套与字符串）。
func (p *sdlParser) skipBalanced(open, close string) {
	depth := 1
	for depth > 0 {
		t, ok := p.next()
		if !ok {
			return
		}
		if t.kind != 'p' {
			continue
		}
		switch t.val {
		case open:
			depth++
		case close:
			depth--
		}
	}
}

// collectRootTypeNames 扫描 schema { query: Q mutation: M } 声明。
func (p *sdlParser) collectRootTypeNames(roots *gqlRootTypeNames) {
	for {
		t, ok := p.next()
		if !ok {
			return
		}
		if t.kind != 'n' || t.val != "schema" {
			continue
		}
		// 跳过指令后到 '{'
		for {
			t, ok = p.next()
			if !ok {
				return
			}
			if t.kind == 'p' && t.val == "{" {
				break
			}
		}
		depth := 1
		for depth > 0 {
			t, ok = p.next()
			if !ok {
				return
			}
			if t.kind == 'p' {
				switch t.val {
				case "{":
					depth++
				case "}":
					depth--
				}
				continue
			}
			if depth == 1 && t.kind == 'n' {
				if nt, ok := p.peek(); ok && nt.kind == 'p' && nt.val == ":" {
					p.pos++
					if nameTok, ok := p.next(); ok && nameTok.kind == 'n' {
						switch t.val {
						case "query":
							roots.query = nameTok.val
						case "mutation":
							roots.mutation = nameTok.val
						}
					}
				}
			}
		}
	}
}

// collectOperations 第二遍：解析 type/extend type <根类型> 的字段为操作。
func (p *sdlParser) collectOperations(roots *gqlRootTypeNames, ops *[]SpecOperation) {
	for {
		t, ok := p.next()
		if !ok {
			return
		}
		if t.kind != 'n' {
			continue
		}
		keyword := t.val
		if keyword == "extend" {
			nt, ok := p.next()
			if !ok || nt.kind != 'n' {
				continue
			}
			keyword = nt.val
		}
		switch keyword {
		case "type", "interface":
			nameTok, ok := p.next()
			if !ok || nameTok.kind != 'n' {
				continue
			}
			method := ""
			switch nameTok.val {
			case roots.query:
				method = "QUERY"
			case roots.mutation:
				method = "MUTATION"
			}
			p.skipToBrace()
			if !p.parseFieldBlock(method, ops) {
				p.unclosed = true
				return
			}
		case "input", "enum":
			if _, ok := p.next(); !ok { // 类型名
				return
			}
			p.skipToBrace()
			if !p.skipFieldBlock() {
				p.unclosed = true
				return
			}
		case "union", "scalar", "directive", "schema":
			p.skipDefinition()
		}
	}
}

// skipToBrace 跳过类型名后的 implements/指令，直到消费掉 '{'；未找到则标记未闭合。
func (p *sdlParser) skipToBrace() {
	for {
		t, ok := p.next()
		if !ok {
			p.unclosed = true
			return
		}
		if t.kind == 'p' && t.val == "{" {
			return
		}
		if t.kind == 'n' && p.isKeywordAt(t) {
			p.pos-- // 退回关键字，交由外层处理（畸形文档容错）
			p.unclosed = true
			return
		}
	}
}

func (p *sdlParser) isKeywordAt(t gqlToken) bool {
	if t.kind != 'n' {
		return false
	}
	switch t.val {
	case "type", "interface", "input", "enum", "union", "scalar", "directive", "schema", "extend":
		return true
	}
	return false
}

// parseFieldBlock 解析 '{...}' 内的字段定义；method 为空串时等价于跳过。
// 返回 false 表示 token 耗尽。
func (p *sdlParser) parseFieldBlock(method string, ops *[]SpecOperation) bool {
	for {
		t, ok := p.next()
		if !ok {
			return false
		}
		if t.kind == 'p' && t.val == "}" {
			return true
		}
		if t.kind != 'n' {
			continue
		}
		fieldName := t.val
		params := []SpecParam{}
		if nt, ok := p.peek(); ok && nt.kind == 'p' && nt.val == "(" {
			p.pos++
			params = p.parseArgs()
		}
		// 期望 ':' 返回值类型；类型引用本身跳过
		if nt, ok := p.peek(); ok && nt.kind == 'p' && nt.val == ":" {
			p.pos++
			p.skipTypeRef()
		}
		p.skipDirectives()
		if method != "" {
			path := "/graphql/" + fieldName
			sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
			*ops = append(*ops, SpecOperation{Method: method, Path: path, Key: method + " " + path, Params: params})
		}
	}
}

// skipFieldBlock 跳过非根类型的字段块（input/enum 等），返回 false 表示 token 耗尽。
func (p *sdlParser) skipFieldBlock() bool {
	return p.parseFieldBlock("", nil)
}

// parseArgs 解析字段参数列表（'(' 已消费），直到匹配的 ')'。
// 每个参数 name: Type = default @dir → SpecParam{In: ARG, Required: 非空类型}。
func (p *sdlParser) parseArgs() []SpecParam {
	out := []SpecParam{}
	for {
		t, ok := p.next()
		if !ok {
			return out
		}
		if t.kind == 'p' && t.val == ")" {
			return out
		}
		if t.kind != 'n' {
			continue
		}
		argName := t.val
		required := false
		typeName := ""
		if nt, ok := p.peek(); ok && nt.kind == 'p' && nt.val == ":" {
			p.pos++
			typeName, required = p.readTypeRef()
		}
		// 跳过默认值与参数级指令：平衡括号直到 ',' 语义不存在（',' 已被词法丢弃），
		// 故按深度 0 的下一个 name: 边界难以判定——统一跳过到当前参数消费完：
		// 默认值/指令中的 name 后若紧跟 ':' 会被误当新参数，因此此处仅在遇到
		// ')' 时结束，遇到 name 且前一个 token 非 '='/'@' 上下文时视为新参数由循环自然处理。
		p.skipArgTail()
		if argName != "" {
			out = append(out, SpecParam{Name: argName, In: "ARG", Type: typeName, Required: required})
		}
	}
}

// skipArgTail 跳过参数的默认值与指令部分：直到深度 0 处遇到 ')'（保留，
// 交由 parseArgs 消费）或明确的下一个参数起点。为保守起见仅在 ')' 停止；
// 默认值内部的括号/括号内名称因深度大于 0 不会干扰。
func (p *sdlParser) skipArgTail() {
	for {
		t, ok := p.peek()
		if !ok {
			return
		}
		if t.kind == 'p' {
			switch t.val {
			case ")":
				return // 留给 parseArgs 消费
			case "=", "@":
				p.pos++
				p.skipValue()
				continue
			case "(", "[":
				p.pos++
				p.skipBalanced(t.val, map[string]string{"(": ")", "[": "]"}[t.val])
				continue
			}
		}
		// 下一个 name token：新参数起点（',' 已在词法层丢弃）
		return
	}
}

// skipValue 跳过一个值字面量（名称/数字/字符串/列表/对象）。
func (p *sdlParser) skipValue() {
	t, ok := p.next()
	if !ok {
		return
	}
	if t.kind == 'p' {
		switch t.val {
		case "[":
			p.skipBalanced("[", "]")
		case "{":
			p.skipBalanced("{", "}")
		}
	}
}

// skipDirectives 跳过字段后的 @dir(...) 序列。
func (p *sdlParser) skipDirectives() {
	for {
		t, ok := p.peek()
		if !ok || t.kind != 'p' || t.val != "@" {
			return
		}
		p.pos++
		if _, ok := p.next(); !ok { // 指令名
			return
		}
		if nt, ok := p.peek(); ok && nt.kind == 'p' && nt.val == "(" {
			p.pos++
			p.skipBalanced("(", ")")
		}
	}
}

// readTypeRef 读取类型引用（Name / [Type] / 后缀 !），返回基础类型名与是否非空。
func (p *sdlParser) readTypeRef() (base string, nonNull bool) {
	depth := 0
	for {
		t, ok := p.next()
		if !ok {
			return base, nonNull
		}
		if t.kind == 'n' && base == "" {
			base = t.val
			continue
		}
		if t.kind == 'p' {
			switch t.val {
			case "[":
				depth++
			case "]":
				if depth > 0 {
					depth--
				}
			case "!":
				if depth == 0 {
					nonNull = true
				}
			default:
				p.pos-- // 类型引用结束（: = @ ) 等边界），退回
				return base, nonNull
			}
			continue
		}
		// 第二个 name 或字符串：类型引用已结束
		p.pos--
		return base, nonNull
	}
}

// skipTypeRef 跳过返回值类型引用。
func (p *sdlParser) skipTypeRef() {
	_, _ = p.readTypeRef()
}

// skipDefinition 跳过无花括号或带花括号的顶层定义（scalar/union/enum/directive/schema）。
func (p *sdlParser) skipDefinition() {
	for {
		t, ok := p.next()
		if !ok {
			return
		}
		if t.kind == 'p' {
			switch t.val {
			case "{":
				p.skipBalanced("{", "}")
				return
			case "(":
				p.skipBalanced("(", ")")
			}
			continue
		}
		if p.isKeywordAt(t) {
			p.pos--
			return
		}
	}
}
