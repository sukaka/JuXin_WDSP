// sf.go RFC 8941 结构化字段解析最小子集（NG-ID G1 批次 A，设计 §4 纪律：
// 候选库 dunglas/httpsfv 许可证待核——自实现兜底优先，零新依赖）。
//
// 覆盖形态（G1 消费面冻结）：
//   - Dictionary（Signature-Input/Signature/Content-Digest 承载）；
//   - Inner List（覆盖成分列表带参数）；
//   - 参数（created/expires 整数、nonce/keyid/tag 字符串、alg 令牌、req 裸真值，
//     保序——签名基线重构须按 Signature-Input 原序逐字节重现，含未知参数）；
//   - bare item：string（"…"，转义仅 \" 与 \\，字符集 %x20-21/%x23-5B/%x5D-7E）/
//     token（标识符形）/integer（±，≤15 位）/byte sequence（:base64:）/boolean（?1/?0）；
//   - decimal/date/display-string 不在子集——解析拒绝（ErrMalformed，
//     unsupported_bare_item 明细，G1 消费面用不到）。
//
// 纪律：解析全在调用方 goroutine；输入预算由 httpsig 层（ParseHeaders）先验
// 后解析（头合计 ≤8KiB），本层不重复计体；保序参数是基线重构正确性的承载。
package httpsig

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// sfValueKind SF bare item 形态。
type sfValueKind byte

const (
	sfValueNone sfValueKind = iota
	sfValueString
	sfValueToken
	sfValueInteger
	sfValueBytes
	sfValueBool
)

// sfValue SF bare item 值。
type sfValue struct {
	Kind  sfValueKind
	Str   string // string/token
	Int   int64  // integer
	Bytes []byte // byte sequence
	Bool  bool   // boolean（Kind=sfValueBool 时有效；参数裸名 = 隐式 true（Kind None 承载））
}

// sfParam SF 参数（保序——基线重构按原序重现）。
type sfParam struct {
	Name  string
	Value sfValue // Kind=sfValueNone = 裸名（布尔 true 语义）
}

// sfItem SF item（值+保序参数）。
type sfItem struct {
	Value  sfValue
	Params []sfParam
}

// sfMember Dictionary 成员（IsList=true 时值在 Items+ListParams；否则 Item）。
type sfMember struct {
	Key        string
	IsList     bool
	Items      []sfItem
	ListParams []sfParam
	Item       sfItem
}

// sfParser 手写有界递归下降解析器（单输入单趟；无后台 goroutine）。
type sfParser struct {
	s   string
	pos int
}

// parseSFDictionary 解析 Dictionary（顶层入口；空字典合法返回空成员集）。
func parseSFDictionary(input string) ([]sfMember, error) {
	p := &sfParser{s: input}
	return p.parseDictionary()
}

func (p *sfParser) parseDictionary() ([]sfMember, error) {
	var members []sfMember
	p.skipOWS()
	if p.eof() {
		return members, nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		m := sfMember{Key: key}
		if p.eat('=') {
			if p.peek() == '(' {
				items, params, err := p.parseInnerList()
				if err != nil {
					return nil, err
				}
				m.IsList = true
				m.Items = items
				m.ListParams = params
			} else {
				item, err := p.parseItem()
				if err != nil {
					return nil, err
				}
				m.Item = item
			}
		} else {
			// 裸名成员（布尔 true 语义）+ 参数
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			m.Item = sfItem{Value: sfValue{Kind: sfValueBool, Bool: true}, Params: params}
		}
		members = append(members, m)
		p.skipOWS()
		if p.eof() {
			return members, nil
		}
		if !p.eat(',') {
			return nil, fmt.Errorf("sf: ',' expected at offset %d", p.pos)
		}
		p.skipOWS()
		if p.eof() {
			return nil, fmt.Errorf("sf: trailing ',' at offset %d", p.pos)
		}
	}
}

// parseInnerList 解析 "( item item ... );params"。
func (p *sfParser) parseInnerList() ([]sfItem, []sfParam, error) {
	if !p.eat('(') {
		return nil, nil, fmt.Errorf("sf: '(' expected at offset %d", p.pos)
	}
	var items []sfItem
	for {
		p.skipSP()
		if p.eat(')') {
			params, err := p.parseParams()
			if err != nil {
				return nil, nil, err
			}
			return items, params, nil
		}
		item, err := p.parseItem()
		if err != nil {
			return nil, nil, err
		}
		items = append(items, item)
		if p.eof() {
			return nil, nil, fmt.Errorf("sf: unterminated inner list")
		}
		// 项间至少一个 SP 或即到收尾 ')'（RFC 8941 §4.1.6 形态）
		if p.peek() != ' ' && p.peek() != ')' {
			return nil, nil, fmt.Errorf("sf: SP expected between inner list items at offset %d", p.pos)
		}
	}
}

// parseItem 解析 bare item + 参数。
func (p *sfParser) parseItem() (sfItem, error) {
	v, err := p.parseBareItem()
	if err != nil {
		return sfItem{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return sfItem{}, err
	}
	return sfItem{Value: v, Params: params}, nil
}

// parseParams 解析 ;key[=value] 参数序列（保序；';' 后容许零或多 SP——
// RFC 8941 §4.1.4 `*( ";" *SP parameter )` 形态）。
func (p *sfParser) parseParams() ([]sfParam, error) {
	var out []sfParam
	for p.eat(';') {
		p.skipSP()
		name, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		pr := sfParam{Name: name}
		if p.eat('=') {
			v, err := p.parseBareItem()
			if err != nil {
				return nil, err
			}
			pr.Value = v
		}
		out = append(out, pr)
	}
	return out, nil
}

// parseBareItem bare item 分派（字符首判形态）。
func (p *sfParser) parseBareItem() (sfValue, error) {
	if p.eof() {
		return sfValue{}, fmt.Errorf("sf: bare item expected at offset %d", p.pos)
	}
	c := p.peek()
	switch {
	case c == '"':
		s, err := p.parseString()
		return sfValue{Kind: sfValueString, Str: s}, err
	case c == ':':
		b, err := p.parseByteSequence()
		return sfValue{Kind: sfValueBytes, Bytes: b}, err
	case c == '?':
		v, err := p.parseBool()
		return sfValue{Kind: sfValueBool, Bool: v}, err
	case c == '-' || (c >= '0' && c <= '9'):
		i, err := p.parseInteger()
		return sfValue{Kind: sfValueInteger, Int: i}, err
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '*':
		t, err := p.parseToken()
		return sfValue{Kind: sfValueToken, Str: t}, err
	default:
		return sfValue{}, fmt.Errorf("sf: unsupported bare item type at offset %d (decimal/date/display-string 不在 G1 子集)", p.pos)
	}
}

// parseString RFC 8941 string（转义仅 \" 与 \\；字符集 %x20-21/%x23-5B/%x5D-7E）。
func (p *sfParser) parseString() (string, error) {
	if !p.eat('"') {
		return "", fmt.Errorf("sf: '\"' expected at offset %d", p.pos)
	}
	var sb strings.Builder
	for !p.eof() {
		c := p.s[p.pos]
		p.pos++
		switch {
		case c == '"':
			return sb.String(), nil
		case c == '\\':
			if p.eof() {
				return "", fmt.Errorf("sf: unterminated escape")
			}
			e := p.s[p.pos]
			p.pos++
			if e != '"' && e != '\\' {
				return "", fmt.Errorf("sf: invalid escape \\%c at offset %d", e, p.pos-1)
			}
			sb.WriteByte(e)
		case c >= 0x20 && c <= 0x7e && c != 0x7f:
			sb.WriteByte(c)
		default:
			return "", fmt.Errorf("sf: invalid string char 0x%02x at offset %d", c, p.pos-1)
		}
	}
	return "", fmt.Errorf("sf: unterminated string")
}

// parseToken RFC 8941 token（首字符 ALPHA/*；后续 tchar/:/ /）。
func (p *sfParser) parseToken() (string, error) {
	start := p.pos
	for !p.eof() && isSFTailChar(p.s[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", fmt.Errorf("sf: token expected at offset %d", start)
	}
	return p.s[start:p.pos], nil
}

// parseKey RFC 8941 key（首字符 lcalpha/*；后续 lcalpha/DIGIT/_/-/./*）。
func (p *sfParser) parseKey() (string, error) {
	if p.eof() || !isSFKeyStart(p.s[p.pos]) {
		return "", fmt.Errorf("sf: key expected at offset %d", p.pos)
	}
	start := p.pos
	p.pos++
	for !p.eof() && isSFKeyTail(p.s[p.pos]) {
		p.pos++
	}
	return p.s[start:p.pos], nil
}

// parseInteger RFC 8941 integer（["-"] 1*15 DIGIT——位宽上限即类型边界）。
func (p *sfParser) parseInteger() (int64, error) {
	start := p.pos
	if !p.eof() && p.s[p.pos] == '-' {
		p.pos++
	}
	digits := 0
	for !p.eof() && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
		digits++
		if digits > 15 {
			return 0, fmt.Errorf("sf: integer too long at offset %d", start)
		}
	}
	if digits == 0 {
		return 0, fmt.Errorf("sf: integer expected at offset %d", start)
	}
	var v int64
	for _, c := range p.s[start:p.pos] {
		if c == '-' {
			continue
		}
		v = v*10 + int64(c-'0')
	}
	if strings.HasPrefix(p.s[start:p.pos], "-") {
		v = -v
	}
	return v, nil
}

// parseByteSequence RFC 8941 byte sequence（:base64: 标准字母表）。
func (p *sfParser) parseByteSequence() ([]byte, error) {
	if !p.eat(':') {
		return nil, fmt.Errorf("sf: ':' expected at offset %d", p.pos)
	}
	start := p.pos
	for !p.eof() && p.s[p.pos] != ':' {
		p.pos++
	}
	if p.eof() {
		return nil, fmt.Errorf("sf: unterminated byte sequence at offset %d", start)
	}
	raw := p.s[start:p.pos]
	p.pos++ // 收尾 ':'
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("sf: invalid byte sequence base64 at offset %d", start)
	}
	return b, nil
}

// parseBool RFC 8941 boolean（?1/?0）。
func (p *sfParser) parseBool() (bool, error) {
	p.pos++ // '?'
	if p.eof() {
		return false, fmt.Errorf("sf: unterminated boolean")
	}
	switch p.s[p.pos] {
	case '1':
		p.pos++
		return true, nil
	case '0':
		p.pos++
		return false, nil
	default:
		return false, fmt.Errorf("sf: invalid boolean at offset %d", p.pos)
	}
}

func (p *sfParser) skipOWS() {
	for !p.eof() && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *sfParser) skipSP() {
	for !p.eof() && p.s[p.pos] == ' ' {
		p.pos++
	}
}

func (p *sfParser) eof() bool { return p.pos >= len(p.s) }

func (p *sfParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.pos]
}

func (p *sfParser) eat(c byte) bool {
	if !p.eof() && p.s[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

// isSFTailChar token 尾字符（tchar + : + /）。
func isSFTailChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
		c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
		c == '`' || c == '|' || c == '~' || c == ':' || c == '/'
}

func isSFKeyStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c == '*'
}

func isSFKeyTail(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '*'
}

// renderSFParams 参数序列按原序重现（基线重构保序承载；值渲染：string 加引号
// 转义、integer 裸十进制、token 裸、bytes :base64:、bool ?1/?0、裸名（None）
// 仅 ;key 形态）。
func renderSFParams(params []sfParam) string {
	var sb strings.Builder
	for _, pr := range params {
		sb.WriteByte(';')
		sb.WriteString(pr.Name)
		if pr.Value.Kind == sfValueNone {
			continue
		}
		sb.WriteByte('=')
		sb.WriteString(renderSFValue(pr.Value))
	}
	return sb.String()
}

// renderSFValue bare item 重现。
func renderSFValue(v sfValue) string {
	switch v.Kind {
	case sfValueString:
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v.Str) + `"`
	case sfValueToken:
		return v.Str
	case sfValueInteger:
		return itoa64(v.Int)
	case sfValueBytes:
		return ":" + base64.StdEncoding.EncodeToString(v.Bytes) + ":"
	case sfValueBool:
		if v.Bool {
			return "?1"
		}
		return "?0"
	default:
		return ""
	}
}

// itoa64 int64 十进制（避免 strconv 语义差异——与 SF 整数形态一致）。
func itoa64(v int64) string {
	neg := v < 0
	var u uint64
	if neg {
		u = uint64(-(v + 1)) + 1
	} else {
		u = uint64(v)
	}
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
		if u == 0 {
			break
		}
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
