// Package mcprpc MCP JSON-RPC 协议读取器（NG-MCP G1 批次 A，
// docs/nextgen/NG-MCP-g1-toolcall.md §5 批次 A 线契约逐字冻结——B2 直接消费，
// 签名不得改名改形）。
//
// 纪律（§1.10/D10 冻结）：
//   - 协议专属预算内全量解析（不经公共 1MiB 解析上限与 256 字符标量截留——
//     §11.2-4「不能只检查截断后的 256 字符」修复承载：300KiB 串尾部违规仍命中）；
//   - 重复 JSON 键全消息任意位置登记（点路径，上限 16；深层嵌套含数组内对象）——
//     重复键使 Schema 语义歧义（末值覆盖/首值保留实现相关），与白名单确定性互斥（§1.6）；
//   - 批处理形态（顶层 JSON 数组，冻结版协议已移除批处理）→ ErrShape
//     （合法旧生态形态不判攻击，§1.2）；解析失败/非 JSON-RPC 2.0 形态 → ErrMalformed；
//   - 解析全在调用方 goroutine（无后台任务，ctx 取消由数据源承担即释放——
//     grpcframe R06 纪律承接）；产物仅请求内存活。
//
// 字符串长度预算口径（保守）：按原文内容字节（引号间转义序列按原样计，
// 不展开解码后长度）——高估不高估内存但绝不低估，保守上界如实登记。
package mcprpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Budgets 协议专属预算（§1.10 冻结表；各字段 ≤0 时按 DefaultBudgets 对应值兜底）。
type Budgets struct {
	MaxMessageBytes  int // 单条 JSON-RPC 消息体（与体保全上限同源）
	MaxDepth         int // JSON 嵌套深度（容器层数，根容器=1）
	MaxObjectMembers int // 单对象成员数
	MaxArrayElements int // 单数组元素数
	MaxStringBytes   int // 单字符串原文内容字节
	MaxValues        int // 总 JSON 值数/消息
}

// DefaultBudgets §1.10 冻结常量。
func DefaultBudgets() Budgets {
	return Budgets{
		MaxMessageBytes:  4 << 20,
		MaxDepth:         32,
		MaxObjectMembers: 2048,
		MaxArrayElements: 4096,
		MaxStringBytes:   512 << 10,
		MaxValues:        65536,
	}
}

func (b Budgets) withDefaults() Budgets {
	d := DefaultBudgets()
	if b.MaxMessageBytes <= 0 {
		b.MaxMessageBytes = d.MaxMessageBytes
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = d.MaxDepth
	}
	if b.MaxObjectMembers <= 0 {
		b.MaxObjectMembers = d.MaxObjectMembers
	}
	if b.MaxArrayElements <= 0 {
		b.MaxArrayElements = d.MaxArrayElements
	}
	if b.MaxStringBytes <= 0 {
		b.MaxStringBytes = d.MaxStringBytes
	}
	if b.MaxValues <= 0 {
		b.MaxValues = d.MaxValues
	}
	return b
}

// Message 单条 JSON-RPC 2.0 消息（预算内全量解析产物）。
type Message struct {
	Method string          // method 成员值（必为字符串，否则 ErrMalformed）
	ID     json.RawMessage // id 成员原文（HasID=false 时 nil）
	HasID  bool            // id 成员存在性（null 值 id 视为存在——JSON-RPC 语义）
	Params json.RawMessage // params 成员原文（缺席时 nil）
	Raw    []byte          // 消息全体原文（输入子切片/原引用，不再拷贝）
	Stats  Stats           // 解析读数
}

// Stats 解析读数（覆盖/证据承载）。
type Stats struct {
	Bytes          int      // 消息体字节数
	Depth          int      // 实际最大嵌套深度
	Values         int      // 实际总 JSON 值数
	DuplicatePaths []string // 重复键点路径（上限 16；数组段形如 arr[0].x）
}

// 错误三分类（线契约冻结）：
//   - ErrMalformed：JSON 解析失败 / 非单条 JSON-RPC 2.0 消息形态
//     （jsonrpc!="2.0"、method 非字符串、顶层标量、尾缀垃圾）；
//   - ErrBudget：预算触顶（*BudgetError 携带 rule 词表）；
//   - ErrShape：批处理等非单消息形态（顶层 JSON 数组——合法旧生态，不判攻击）。
var (
	ErrMalformed = errors.New("mcprpc: malformed json-rpc message")
	ErrBudget    = errors.New("mcprpc: budget exceeded")
	ErrShape     = errors.New("mcprpc: not a single json-rpc message (batch shape)")
)

// BudgetError 预算触顶明细（rule 词表 §1.6 冻结 + SSE 事件预算）。
type BudgetError struct {
	Rule   string // message_bytes_exceeded/depth_exceeded/object_members_exceeded/array_exceeded/string_exceeded/value_count_exceeded/event_bytes_exceeded
	Limit  int
	Actual int
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("mcprpc: budget exceeded %s (limit %d, actual %d)", e.Rule, e.Limit, e.Actual)
}

func (e *BudgetError) Unwrap() error { return ErrBudget }

// maxDuplicatePaths 重复键登记上限（线契约冻结：点路径，上限 16）。
const maxDuplicatePaths = 16

// ParseMessage 预算内全量解析单条 JSON-RPC 2.0 消息（线契约冻结签名）。
// 错误：ErrShape（顶层数组批处理）/ErrMalformed（解析失败或形态不符）/
// ErrBudget（*BudgetError 带 rule）。b 零值字段按 DefaultBudgets 兜底。
func ParseMessage(body []byte, b Budgets) (*Message, error) {
	b = b.withDefaults()
	if len(body) > b.MaxMessageBytes {
		return nil, &BudgetError{Rule: "message_bytes_exceeded", Limit: b.MaxMessageBytes, Actual: len(body)}
	}
	p := &jsonParser{src: body, budgets: b}
	p.skipWS()
	if p.pos < len(body) && body[p.pos] == '[' {
		return nil, ErrShape // 批处理形态（冻结版协议已移除；合法旧生态不判攻击）
	}
	if err := p.parseValue(0, nil); err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(body) {
		return nil, fmt.Errorf("%w: trailing garbage at offset %d", ErrMalformed, p.pos)
	}
	if !p.topIsObject {
		return nil, fmt.Errorf("%w: top-level value is not an object", ErrMalformed)
	}
	if !p.jsonrpcOK {
		return nil, fmt.Errorf("%w: jsonrpc member missing or not \"2.0\"", ErrMalformed)
	}
	if !p.methodOK {
		return nil, fmt.Errorf("%w: method member missing or not a string", ErrMalformed)
	}
	msg := &Message{
		Method: p.method,
		Raw:    body,
		Stats: Stats{
			Bytes:          len(body),
			Depth:          p.maxDepth,
			Values:         p.values,
			DuplicatePaths: p.dups,
		},
	}
	if p.idSet {
		msg.HasID = true
		msg.ID = json.RawMessage(body[p.idSpan[0]:p.idSpan[1]])
	}
	if p.paramsSet {
		msg.Params = json.RawMessage(body[p.paramsSpan[0]:p.paramsSpan[1]])
	}
	return msg, nil
}

// jsonParser 手写递归下降 JSON 解析器（预算执行+重复键登记+顶层成员跨度捕获；
// stdlib 唯一依赖，无后台 goroutine）。
type jsonParser struct {
	src     []byte
	pos     int
	budgets Budgets

	values   int
	depth    int
	maxDepth int
	dups     []string
	segs     []string // 路径段栈（对象键/数组 [i]）

	topIsObject bool
	jsonrpcOK   bool
	methodOK    bool
	method      string
	idSet       bool
	idSpan      [2]int
	paramsSet   bool
	paramsSpan  [2]int
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) budget(rule string, limit, actual int) error {
	return &BudgetError{Rule: rule, Limit: limit, Actual: actual}
}

// parseValue 解析一个 JSON 值（depth 为当前容器深度——标量不占容器层）。
func (p *jsonParser) parseValue(depth int, segKey *string) error {
	p.values++
	if p.values > p.budgets.MaxValues {
		return p.budget("value_count_exceeded", p.budgets.MaxValues, p.values)
	}
	p.skipWS()
	if p.pos >= len(p.src) {
		return fmt.Errorf("%w: unexpected end of input", ErrMalformed)
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseObject(depth+1, segKey)
	case c == '[':
		return p.parseArray(depth+1, segKey)
	case c == '"':
		_, err := p.parseString()
		return err
	case c == 't':
		return p.parseLiteral("true")
	case c == 'f':
		return p.parseLiteral("false")
	case c == 'n':
		return p.parseLiteral("null")
	default:
		return p.parseNumber()
	}
}

func (p *jsonParser) parseLiteral(lit string) error {
	if len(p.src)-p.pos < len(lit) || string(p.src[p.pos:p.pos+len(lit)]) != lit {
		return fmt.Errorf("%w: invalid literal at offset %d", ErrMalformed, p.pos)
	}
	p.pos += len(lit)
	return nil
}

func (p *jsonParser) enterContainer(depth int) error {
	if depth > p.budgets.MaxDepth {
		return p.budget("depth_exceeded", p.budgets.MaxDepth, depth)
	}
	if depth > p.maxDepth {
		p.maxDepth = depth
	}
	return nil
}

// parseObject 解析对象（depth 为本对象容器深度；segKey 为本对象在父级的段名——
// 顶层为 nil）。
func (p *jsonParser) parseObject(depth int, segKey *string) error {
	if err := p.enterContainer(depth); err != nil {
		return err
	}
	if depth == 1 {
		p.topIsObject = true
	}
	p.pos++ // '{'
	seen := make(map[string]bool)
	members := 0
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		return nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != '"' {
			return fmt.Errorf("%w: object member name expected at offset %d", ErrMalformed, p.pos)
		}
		key, err := p.parseString()
		if err != nil {
			return err
		}
		members++
		if members > p.budgets.MaxObjectMembers {
			return p.budget("object_members_exceeded", p.budgets.MaxObjectMembers, members)
		}
		// 重复键登记（点路径；上限 16，超出仅停止登记不停止校验）
		if seen[key] && len(p.dups) < maxDuplicatePaths {
			p.dups = append(p.dups, p.memberPath(key))
		}
		seen[key] = true
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return fmt.Errorf("%w: ':' expected at offset %d", ErrMalformed, p.pos)
		}
		p.pos++
		p.skipWS()
		// 顶层成员跨度捕获（id/params 原文）与关键字段值（jsonrpc/method）
		valueStart := p.pos
		topLevel := depth == 1
		p.segs = append(p.segs, key)
		switch {
		case topLevel && key == "jsonrpc":
			var v string
			v, err = p.parseScalarAsString()
			switch {
			case errors.Is(err, errNotString):
				err = nil // 非字符串形态：OK 标志不置位，不致命（消费后继续）
			case err == nil && v == "2.0":
				p.jsonrpcOK = true
			}
		case topLevel && key == "method":
			var v string
			v, err = p.parseScalarAsString()
			switch {
			case errors.Is(err, errNotString):
				err = nil
			case err == nil:
				p.methodOK = true
				p.method = v
			}
		default:
			err = p.parseValue(depth, &key)
		}
		p.segs = p.segs[:len(p.segs)-1]
		if err != nil {
			return err
		}
		if topLevel {
			switch key {
			case "id":
				p.idSet = true
				p.idSpan = [2]int{valueStart, p.pos}
			case "params":
				p.paramsSet = true
				p.paramsSpan = [2]int{valueStart, p.pos}
			}
		}
		p.skipWS()
		if p.pos >= len(p.src) {
			return fmt.Errorf("%w: unexpected end of input in object", ErrMalformed)
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return nil
		default:
			return fmt.Errorf("%w: ',' or '}' expected at offset %d", ErrMalformed, p.pos)
		}
	}
}

// parseArray 解析数组（depth 为本数组容器深度）。
func (p *jsonParser) parseArray(depth int, segKey *string) error {
	if err := p.enterContainer(depth); err != nil {
		return err
	}
	p.pos++ // '['
	elements := 0
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		return nil
	}
	for {
		seg := "[" + itoa(elements) + "]"
		p.segs = append(p.segs, seg)
		err := p.parseValue(depth, &seg)
		p.segs = p.segs[:len(p.segs)-1]
		if err != nil {
			return err
		}
		elements++
		if elements > p.budgets.MaxArrayElements {
			return p.budget("array_exceeded", p.budgets.MaxArrayElements, elements)
		}
		p.skipWS()
		if p.pos >= len(p.src) {
			return fmt.Errorf("%w: unexpected end of input in array", ErrMalformed)
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return nil
		default:
			return fmt.Errorf("%w: ',' or ']' expected at offset %d", ErrMalformed, p.pos)
		}
	}
}

// memberPath 当前段栈 + 成员键的点路径（数组段已含 [i] 形态——
// 形如 params.arr[0].x）。
func (p *jsonParser) memberPath(key string) string {
	var sb strings.Builder
	for i, s := range p.segs {
		if i > 0 && !strings.HasPrefix(s, "[") {
			sb.WriteByte('.')
		}
		sb.WriteString(s)
	}
	if len(p.segs) > 0 {
		sb.WriteByte('.')
	}
	sb.WriteString(key)
	return sb.String()
}

// parseString 解析字符串并返回解码值（转义展开；长度预算按原文内容字节
// 保守口径——引号间转义序列按原样计）。
func (p *jsonParser) parseString() (string, error) {
	start := p.pos + 1 // 内容起点（跳过开引号）
	p.pos++            // '"'
	var sb strings.Builder
	for {
		if p.pos >= len(p.src) {
			return "", fmt.Errorf("%w: unterminated string", ErrMalformed)
		}
		c := p.src[p.pos]
		if c == '"' {
			contentLen := p.pos - start
			if contentLen > p.budgets.MaxStringBytes {
				return "", p.budget("string_exceeded", p.budgets.MaxStringBytes, contentLen)
			}
			p.pos++
			return sb.String(), nil
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.src) {
				return "", fmt.Errorf("%w: unterminated escape", ErrMalformed)
			}
			e := p.src[p.pos]
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				if p.pos+4 >= len(p.src) {
					return "", fmt.Errorf("%w: truncated \\u escape", ErrMalformed)
				}
				for i := 1; i <= 4; i++ {
					if !isHex(p.src[p.pos+i]) {
						return "", fmt.Errorf("%w: invalid \\u escape", ErrMalformed)
					}
				}
				// 长度预算按原文口径（不展开 UTF-8）；解码值仅需满足键比对与
				// method/jsonrpc 提取——\u 序列按原样保留（两端一致即等价）
				sb.WriteString(string(p.src[p.pos-1 : p.pos+5]))
				p.pos += 4
			default:
				return "", fmt.Errorf("%w: invalid escape \\%c", ErrMalformed, e)
			}
			p.pos++
			continue
		}
		if c < 0x20 {
			return "", fmt.Errorf("%w: unescaped control character in string", ErrMalformed)
		}
		sb.WriteByte(c)
		p.pos++
	}
}

// errNotString 内部哨兵：标量值非字符串（调用侧清除——OK 标志不置位即
// ErrMalformed 的最终承载在 ParseMessage 形态核对，不在解析中途）。
var errNotString = errors.New("mcprpc: scalar is not a string")

// parseScalarAsString 解析「须为字符串」的标量值（jsonrpc/method 成员专用——
// 非字符串消费合法 JSON 值后返回 errNotString）。
func (p *jsonParser) parseScalarAsString() (string, error) {
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == '"' {
		// 字符串值计入总值数预算（与 parseValue 同口径）
		p.values++
		if p.values > p.budgets.MaxValues {
			return "", p.budget("value_count_exceeded", p.budgets.MaxValues, p.values)
		}
		return p.parseString()
	}
	// 非字符串形态：按通用值解析（消费合法 JSON 值），OK 标志不置位
	if err := p.parseValue(1, nil); err != nil {
		return "", err
	}
	return "", errNotString
}

// parseNumber JSON 数值语法校验（-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?）。
func (p *jsonParser) parseNumber() error {
	start := p.pos
	if p.pos < len(p.src) && p.src[p.pos] == '-' {
		p.pos++
	}
	// 整数段
	if p.pos >= len(p.src) {
		return fmt.Errorf("%w: invalid number", ErrMalformed)
	}
	switch {
	case p.src[p.pos] == '0':
		p.pos++
	case p.src[p.pos] >= '1' && p.src[p.pos] <= '9':
		for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
			p.pos++
		}
	default:
		return fmt.Errorf("%w: invalid number at offset %d", ErrMalformed, start)
	}
	// 小数段
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		p.pos++
		if p.pos >= len(p.src) || !isDigit(p.src[p.pos]) {
			return fmt.Errorf("%w: invalid fraction", ErrMalformed)
		}
		for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
			p.pos++
		}
	}
	// 指数段
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		if p.pos >= len(p.src) || !isDigit(p.src[p.pos]) {
			return fmt.Errorf("%w: invalid exponent", ErrMalformed)
		}
		for p.pos < len(p.src) && isDigit(p.src[p.pos]) {
			p.pos++
		}
	}
	return nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// itoa 非负整数十进制（避免 strconv 仅为一处）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
