// spec_protobuf.go Protobuf / gRPC（.proto）规范导入解析。
// 支持 proto2 / proto3 / edition 语法：解析 package、message（含嵌套 message、oneof、map<K,V>）、
// service / rpc（含 google.api.http REST 注解映射）；不依赖第三方 proto 解析库（go.mod 最小引入原则）。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	protoMaxDepth  = 64
	protoMaxTokens = 200000
)

type protoToken struct {
	kind byte   // 'i' ident/number, 's' string, 'p' punct
	val  string // raw value (strings unescaped)
}

type protoField struct {
	Name     string
	Type     string
	Required bool
}

type protoMessage struct {
	FullName string
	Short    string
	Fields   []protoField
}

type protoHTTPBinding struct {
	Method string
	Path   string
	Body   string
}

type protoRPC struct {
	Service      string
	Name         string
	RequestType  string
	HTTPBindings []protoHTTPBinding
}

type protoParsedFile struct {
	Package  string
	Messages map[string]*protoMessage // key: full name and short name
	Order    []string                 // deterministic message order (full names)
	RPCs     []protoRPC
}

var protoPathParamRe = regexp.MustCompile(`\{([a-zA-Z0-9_.]+)(?:=[^}]*)?\}`)

// looksLikeProtobuf 粗判文本是否具有 .proto 规范形态（避免普通文本误报 Protobuf 错误）。
func looksLikeProtobuf(s string) bool {
	toks, err := protoLex(s)
	if err != nil || len(toks) < 3 {
		return false
	}
	for i := 0; i < len(toks); i++ {
		if toks[i].kind != 'i' {
			continue
		}
		switch toks[i].val {
		case "syntax", "edition":
			if i+2 < len(toks) && toks[i+1].kind == 'p' && toks[i+1].val == "=" && toks[i+2].kind == 's' {
				return true
			}
		case "service", "message":
			if i+2 < len(toks) && toks[i+1].kind == 'i' && toks[i+2].kind == 'p' && toks[i+2].val == "{" {
				return true
			}
		}
	}
	return false
}

// ParseProtobuf 解析单个 .proto 源码文件为操作清单，并返回派生标题（package 或首个 service/message 名）。
func ParseProtobuf(src string) ([]SpecOperation, string, error) {
	return ParseProtobufSet([]string{src})
}

// ParseProtobufSet 解析一个或多个关联的 .proto 源码（用于 .zip 多文件归档时跨文件解析请求 message 字段）。
func ParseProtobufSet(sources []string) ([]SpecOperation, string, error) {
	allMsgs := map[string]*protoMessage{}
	shortMsgs := map[string]*protoMessage{}
	msgOrder := []string{}
	seenMsg := map[string]bool{}
	allRPCs := []protoRPC{}
	title := ""

	for _, src := range sources {
		pf, err := parseProtoFile(src)
		if err != nil {
			return nil, "", err
		}
		if title == "" && pf.Package != "" {
			title = pf.Package
		}
		for _, full := range pf.Order {
			m := pf.Messages[full]
			if m == nil {
				continue
			}
			allMsgs[full] = m
			if _, exists := shortMsgs[m.Short]; !exists {
				shortMsgs[m.Short] = m
			}
			if !seenMsg[full] {
				seenMsg[full] = true
				msgOrder = append(msgOrder, full)
			}
		}
		for _, r := range pf.RPCs {
			if title == "" && r.Service != "" {
				title = r.Service
			}
			allRPCs = append(allRPCs, r)
		}
	}

	if title == "" && len(msgOrder) > 0 {
		title = msgOrder[0]
	}

	ops := []SpecOperation{}
	if len(allRPCs) > 0 {
		for _, rpc := range allRPCs {
			reqMsg := lookupProtoMessage(rpc.RequestType, rpc.Service, allMsgs, shortMsgs)
			if len(rpc.HTTPBindings) > 0 {
				for _, b := range rpc.HTTPBindings {
					ops = append(ops, buildProtoHTTPOp(b, reqMsg))
				}
				continue
			}
			path := "/" + rpc.Service + "/" + rpc.Name
			params := protoFieldsToParams(reqMsg, "BODY", nil)
			ops = append(ops, SpecOperation{
				Method: "GRPC",
				Path:   path,
				Key:    "GRPC " + path,
				Params: params,
			})
		}
	} else if len(msgOrder) > 0 {
		// 仅有 message 定义（无 service）的 .proto 文件：按 SCHEMA 端点输出字段模型（同 JSON Schema）
		for _, full := range msgOrder {
			m := allMsgs[full]
			if m == nil || len(m.Fields) == 0 {
				continue
			}
			path := "/_proto/" + full
			ops = append(ops, SpecOperation{
				Method: "SCHEMA",
				Path:   path,
				Key:    "SCHEMA " + path,
				Params: protoFieldsToParams(m, "BODY", nil),
			})
		}
	}

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: 未找到有效的 service/rpc 或带字段的 message 定义", ErrSpecInvalidProtobuf)
	}
	return ops, title, nil
}

func lookupProtoMessage(reqType, fullService string, allMsgs, shortMsgs map[string]*protoMessage) *protoMessage {
	cleaned := strings.TrimPrefix(strings.TrimSpace(reqType), ".")
	if cleaned == "" {
		return nil
	}
	if m, ok := allMsgs[cleaned]; ok {
		return m
	}
	// 若同包省略包前缀，拼接 service 所在 package 查找
	if idx := strings.LastIndex(fullService, "."); idx > 0 {
		pkg := fullService[:idx]
		if m, ok := allMsgs[pkg+"."+cleaned]; ok {
			return m
		}
	}
	if m, ok := shortMsgs[cleaned]; ok {
		return m
	}
	if idx := strings.LastIndex(cleaned, "."); idx >= 0 {
		if m, ok := shortMsgs[cleaned[idx+1:]]; ok {
			return m
		}
	}
	return nil
}

func buildProtoHTTPOp(b protoHTTPBinding, reqMsg *protoMessage) SpecOperation {
	method := strings.ToUpper(strings.TrimSpace(b.Method))
	if method == "" {
		method = "POST"
	}
	rawPath := strings.TrimSpace(b.Path)
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	pathParamSet := map[string]bool{}
	params := []SpecParam{}
	normPath := protoPathParamRe.ReplaceAllStringFunc(rawPath, func(match string) string {
		sub := protoPathParamRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		name := sub[1]
		if !pathParamSet[name] {
			pathParamSet[name] = true
			params = append(params, SpecParam{Name: name, In: "PATH", Type: "string", Required: true})
		}
		return "{" + name + "}"
	})
	defaultIn := "BODY"
	if method == "GET" || method == "DELETE" || method == "HEAD" {
		defaultIn = "QUERY"
	}
	if b.Body == "" && (method == "GET" || method == "DELETE") {
		defaultIn = "QUERY"
	}
	params = append(params, protoFieldsToParams(reqMsg, defaultIn, pathParamSet)...)
	return SpecOperation{
		Method: method,
		Path:   normPath,
		Key:    method + " " + normPath,
		Params: sortAndDedupeSpecParams(params),
	}
}

func protoFieldsToParams(m *protoMessage, in string, skip map[string]bool) []SpecParam {
	if m == nil {
		return []SpecParam{}
	}
	out := make([]SpecParam, 0, len(m.Fields))
	for _, f := range m.Fields {
		if skip != nil && skip[f.Name] {
			continue
		}
		out = append(out, SpecParam{
			Name:     f.Name,
			In:       in,
			Type:     f.Type,
			Required: f.Required,
		})
	}
	return sortAndDedupeSpecParams(out)
}

func protoScalarType(t string, repeated bool) string {
	if repeated {
		return "array"
	}
	switch t {
	case "string", "bytes":
		return "string"
	case "bool":
		return "boolean"
	case "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64":
		return "integer"
	case "float", "double":
		return "number"
	default:
		return "object"
	}
}

func protoLex(src string) ([]protoToken, error) {
	s := strings.TrimPrefix(src, "\ufeff")
	toks := make([]protoToken, 0, 128)
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		// 单行注释 //
		if c == '/' && i+1 < n && s[i+1] == '/' {
			i += 2
			for i < n && s[i] != '\n' {
				i++
			}
			continue
		}
		// 块注释 /* ... */
		if c == '/' && i+1 < n && s[i+1] == '*' {
			i += 2
			closed := false
			for i+1 < n {
				if s[i] == '*' && s[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: 块注释未闭合", ErrSpecInvalidProtobuf)
			}
			continue
		}
		// 字符串 "..." 或 '...'
		if c == '"' || c == '\'' {
			quote := c
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				ch := s[i]
				if ch == '\\' && i+1 < n {
					sb.WriteByte(s[i+1])
					i += 2
					continue
				}
				if ch == quote {
					i++
					closed = true
					break
				}
				sb.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: 字符串字面量未闭合", ErrSpecInvalidProtobuf)
			}
			toks = append(toks, protoToken{kind: 's', val: sb.String()})
			if len(toks) > protoMaxTokens {
				return nil, fmt.Errorf("%w: Protobuf 词法单元数超过 %d", ErrSpecTooComplex, protoMaxTokens)
			}
			continue
		}
		// 标点
		if strings.IndexByte("{}()[]<>=;,.:", c) >= 0 {
			toks = append(toks, protoToken{kind: 'p', val: string(c)})
			i++
			if len(toks) > protoMaxTokens {
				return nil, fmt.Errorf("%w: Protobuf 词法单元数超过 %d", ErrSpecTooComplex, protoMaxTokens)
			}
			continue
		}
		// 标识符/数字/带符号常量
		if isProtoIdentChar(c) || c == '-' || c == '+' {
			start := i
			i++
			for i < n && isProtoIdentChar(s[i]) {
				i++
			}
			toks = append(toks, protoToken{kind: 'i', val: s[start:i]})
			if len(toks) > protoMaxTokens {
				return nil, fmt.Errorf("%w: Protobuf 词法单元数超过 %d", ErrSpecTooComplex, protoMaxTokens)
			}
			continue
		}
		i++
	}
	return toks, nil
}

func isProtoIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

type protoParser struct {
	toks []protoToken
	pos  int
	file *protoParsedFile
}

func parseProtoFile(src string) (*protoParsedFile, error) {
	toks, err := protoLex(src)
	if err != nil {
		return nil, err
	}
	p := &protoParser{
		toks: toks,
		file: &protoParsedFile{Messages: map[string]*protoMessage{}},
	}
	for p.pos < len(p.toks) {
		t := p.peek()
		if t.kind == 'p' && t.val == ";" {
			p.pos++
			continue
		}
		if t.kind != 'i' {
			p.pos++
			continue
		}
		switch t.val {
		case "syntax", "edition", "import", "option":
			if err := p.skipStatement(); err != nil {
				return nil, err
			}
		case "package":
			p.pos++
			pkg := p.readQualifiedName()
			if pkg != "" {
				p.file.Package = pkg
			}
			p.consumeIf('p', ";")
		case "message":
			if err := p.parseMessage("", 0); err != nil {
				return nil, err
			}
		case "service":
			if err := p.parseService(); err != nil {
				return nil, err
			}
		case "enum", "extend":
			p.pos++
			p.readQualifiedName()
			if p.match('p', "{") {
				if err := p.skipBlock(0); err != nil {
					return nil, err
				}
			} else {
				_ = p.skipStatement()
			}
		default:
			if err := p.skipStatement(); err != nil {
				return nil, err
			}
		}
	}
	return p.file, nil
}

func (p *protoParser) peek() protoToken {
	if p.pos >= len(p.toks) {
		return protoToken{}
	}
	return p.toks[p.pos]
}

func (p *protoParser) match(kind byte, val string) bool {
	t := p.peek()
	return t.kind == kind && t.val == val
}

func (p *protoParser) consumeIf(kind byte, val string) bool {
	if p.match(kind, val) {
		p.pos++
		return true
	}
	return false
}

func (p *protoParser) readQualifiedName() string {
	var sb strings.Builder
	for p.pos < len(p.toks) {
		t := p.peek()
		if t.kind == 'p' && t.val == "." {
			sb.WriteByte('.')
			p.pos++
			continue
		}
		if t.kind == 'i' {
			sb.WriteString(t.val)
			p.pos++
			if p.match('p', ".") {
				continue
			}
			break
		}
		break
	}
	return sb.String()
}

func (p *protoParser) skipBlock(depth int) error {
	if depth > protoMaxDepth {
		return fmt.Errorf("%w: Protobuf 嵌套深度超过 %d", ErrSpecTooComplex, protoMaxDepth)
	}
	if !p.consumeIf('p', "{") {
		return fmt.Errorf("%w: 期望 '{'", ErrSpecInvalidProtobuf)
	}
	for p.pos < len(p.toks) {
		if p.consumeIf('p', "}") {
			return nil
		}
		if p.match('p', "{") {
			if err := p.skipBlock(depth + 1); err != nil {
				return err
			}
			continue
		}
		p.pos++
	}
	return fmt.Errorf("%w: 代码块 '{' 未闭合", ErrSpecInvalidProtobuf)
}

func (p *protoParser) skipStatement() error {
	for p.pos < len(p.toks) {
		if p.consumeIf('p', ";") {
			return nil
		}
		if p.match('p', "{") {
			if err := p.skipBlock(0); err != nil {
				return err
			}
			p.consumeIf('p', ";")
			return nil
		}
		if p.match('p', "}") {
			return nil
		}
		p.pos++
	}
	return nil
}

func (p *protoParser) parseMessage(parentPrefix string, depth int) error {
	if depth > protoMaxDepth {
		return fmt.Errorf("%w: Protobuf message 嵌套深度超过 %d", ErrSpecTooComplex, protoMaxDepth)
	}
	p.pos++ // consume "message"
	nameTok := p.peek()
	if nameTok.kind != 'i' {
		return fmt.Errorf("%w: message 缺少名称", ErrSpecInvalidProtobuf)
	}
	p.pos++
	if !p.consumeIf('p', "{") {
		return fmt.Errorf("%w: message %s 缺少 '{'", ErrSpecInvalidProtobuf, nameTok.val)
	}
	fullName := nameTok.val
	if parentPrefix != "" {
		fullName = parentPrefix + "." + nameTok.val
	} else if p.file.Package != "" {
		fullName = p.file.Package + "." + nameTok.val
	}
	msg := &protoMessage{FullName: fullName, Short: nameTok.val}

	for p.pos < len(p.toks) {
		if p.consumeIf('p', "}") {
			p.file.Messages[fullName] = msg
			p.file.Order = append(p.file.Order, fullName)
			return nil
		}
		if p.consumeIf('p', ";") {
			continue
		}
		t := p.peek()
		if t.kind != 'i' {
			p.pos++
			continue
		}
		switch t.val {
		case "message":
			if err := p.parseMessage(fullName, depth+1); err != nil {
				return err
			}
		case "enum", "extend":
			p.pos++
			p.readQualifiedName()
			if p.match('p', "{") {
				if err := p.skipBlock(depth + 1); err != nil {
					return err
				}
			} else {
				_ = p.skipStatement()
			}
		case "reserved", "extensions", "option":
			if err := p.skipStatement(); err != nil {
				return err
			}
		case "oneof":
			p.pos++
			if p.peek().kind == 'i' {
				p.pos++ // oneof name
			}
			if !p.consumeIf('p', "{") {
				return fmt.Errorf("%w: oneof 缺少 '{'", ErrSpecInvalidProtobuf)
			}
			for p.pos < len(p.toks) && !p.match('p', "}") {
				if p.consumeIf('p', ";") {
					continue
				}
				if p.peek().kind == 'i' && p.peek().val == "option" {
					if err := p.skipStatement(); err != nil {
						return err
					}
					continue
				}
				if f, ok := p.parseField(false); ok {
					msg.Fields = append(msg.Fields, f)
				}
			}
			if !p.consumeIf('p', "}") {
				return fmt.Errorf("%w: oneof 未闭合", ErrSpecInvalidProtobuf)
			}
		case "map":
			p.pos++
			// map<K, V> field_name = N [opts];
			if p.consumeIf('p', "<") {
				for p.pos < len(p.toks) && !p.consumeIf('p', ">") {
					p.pos++
				}
			}
			if p.peek().kind == 'i' {
				fname := p.peek().val
				p.pos++
				msg.Fields = append(msg.Fields, protoField{Name: fname, Type: "object"})
			}
			_ = p.skipStatement()
		default:
			if f, ok := p.parseField(true); ok {
				msg.Fields = append(msg.Fields, f)
			}
		}
	}
	return fmt.Errorf("%w: message %s 未闭合", ErrSpecInvalidProtobuf, nameTok.val)
}

func (p *protoParser) parseField(allowLabel bool) (protoField, bool) {
	required := false
	repeated := false
	if allowLabel && p.peek().kind == 'i' {
		switch p.peek().val {
		case "required":
			required = true
			p.pos++
		case "repeated":
			repeated = true
			p.pos++
		case "optional":
			p.pos++
		}
	}
	fieldType := p.readQualifiedName()
	if fieldType == "" || p.peek().kind != 'i' {
		_ = p.skipStatement()
		return protoField{}, false
	}
	fieldName := p.peek().val
	p.pos++
	// 跳过 = tag [options];
	_ = p.skipStatement()
	return protoField{
		Name:     fieldName,
		Type:     protoScalarType(fieldType, repeated),
		Required: required,
	}, true
}

func (p *protoParser) parseService() error {
	p.pos++ // consume "service"
	svcTok := p.peek()
	if svcTok.kind != 'i' {
		return fmt.Errorf("%w: service 缺少名称", ErrSpecInvalidProtobuf)
	}
	p.pos++
	if !p.consumeIf('p', "{") {
		return fmt.Errorf("%w: service %s 缺少 '{'", ErrSpecInvalidProtobuf, svcTok.val)
	}
	fullSvc := svcTok.val
	if p.file.Package != "" {
		fullSvc = p.file.Package + "." + svcTok.val
	}
	for p.pos < len(p.toks) {
		if p.consumeIf('p', "}") {
			return nil
		}
		if p.consumeIf('p', ";") {
			continue
		}
		t := p.peek()
		if t.kind == 'i' && t.val == "rpc" {
			rpc, err := p.parseRPC(fullSvc)
			if err != nil {
				return err
			}
			p.file.RPCs = append(p.file.RPCs, rpc)
			continue
		}
		if err := p.skipStatement(); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: service %s 未闭合", ErrSpecInvalidProtobuf, svcTok.val)
}

func (p *protoParser) parseRPC(fullSvc string) (protoRPC, error) {
	p.pos++ // consume "rpc"
	nameTok := p.peek()
	if nameTok.kind != 'i' {
		return protoRPC{}, fmt.Errorf("%w: rpc 缺少方法名", ErrSpecInvalidProtobuf)
	}
	p.pos++
	if !p.consumeIf('p', "(") {
		return protoRPC{}, fmt.Errorf("%w: rpc %s 缺少请求参数 '('", ErrSpecInvalidProtobuf, nameTok.val)
	}
	if p.peek().kind == 'i' && p.peek().val == "stream" {
		p.pos++
	}
	reqType := p.readQualifiedName()
	if !p.consumeIf('p', ")") {
		return protoRPC{}, fmt.Errorf("%w: rpc %s 缺少 ')'", ErrSpecInvalidProtobuf, nameTok.val)
	}
	if p.peek().kind != 'i' || p.peek().val != "returns" {
		return protoRPC{}, fmt.Errorf("%w: rpc %s 缺少 returns", ErrSpecInvalidProtobuf, nameTok.val)
	}
	p.pos++
	if !p.consumeIf('p', "(") {
		return protoRPC{}, fmt.Errorf("%w: rpc %s returns 缺少 '('", ErrSpecInvalidProtobuf, nameTok.val)
	}
	if p.peek().kind == 'i' && p.peek().val == "stream" {
		p.pos++
	}
	_ = p.readQualifiedName()
	if !p.consumeIf('p', ")") {
		return protoRPC{}, fmt.Errorf("%w: rpc %s returns 缺少 ')'", ErrSpecInvalidProtobuf, nameTok.val)
	}
	rpc := protoRPC{Service: fullSvc, Name: nameTok.val, RequestType: reqType}
	if p.consumeIf('p', "{") {
		for p.pos < len(p.toks) {
			if p.consumeIf('p', "}") {
				break
			}
			if p.consumeIf('p', ";") {
				continue
			}
			if p.peek().kind == 'i' && p.peek().val == "option" {
				bindings, err := p.parseRPCOption()
				if err != nil {
					return protoRPC{}, err
				}
				rpc.HTTPBindings = append(rpc.HTTPBindings, bindings...)
				continue
			}
			if err := p.skipStatement(); err != nil {
				return protoRPC{}, err
			}
		}
		p.consumeIf('p', ";")
	} else {
		p.consumeIf('p', ";")
	}
	return rpc, nil
}

// parseRPCOption 解析 rpc 块内 option，提取 (google.api.http) REST 绑定。
func (p *protoParser) parseRPCOption() ([]protoHTTPBinding, error) {
	p.pos++ // consume "option"
	isHTTP := false
	for p.pos < len(p.toks) && !p.match('p', "=") && !p.match('p', ";") && !p.match('p', "}") {
		if p.peek().kind == 'i' && (p.peek().val == "http" || strings.HasSuffix(p.peek().val, ".http")) {
			isHTTP = true
		}
		p.pos++
	}
	if !p.consumeIf('p', "=") {
		_ = p.skipStatement()
		return nil, nil
	}
	if !isHTTP || !p.match('p', "{") {
		return nil, p.skipStatement()
	}
	bindings, err := p.parseHTTPBlock(0)
	if err != nil {
		return nil, err
	}
	p.consumeIf('p', ";")
	return bindings, nil
}

func (p *protoParser) parseHTTPBlock(depth int) ([]protoHTTPBinding, error) {
	if depth > protoMaxDepth {
		return nil, fmt.Errorf("%w: google.api.http 嵌套深度超过 %d", ErrSpecTooComplex, protoMaxDepth)
	}
	if !p.consumeIf('p', "{") {
		return nil, nil
	}
	var current protoHTTPBinding
	var extra []protoHTTPBinding
	for p.pos < len(p.toks) {
		if p.consumeIf('p', "}") {
			out := []protoHTTPBinding{}
			if current.Method != "" && current.Path != "" {
				out = append(out, current)
			}
			out = append(out, extra...)
			return out, nil
		}
		if p.consumeIf('p', ";") || p.consumeIf('p', ",") {
			continue
		}
		key := p.peek()
		if key.kind != 'i' {
			p.pos++
			continue
		}
		p.pos++
		p.consumeIf('p', ":")
		switch strings.ToLower(key.val) {
		case "get", "post", "put", "delete", "patch":
			if p.peek().kind == 's' {
				current.Method = strings.ToUpper(key.val)
				current.Path = p.peek().val
				p.pos++
			}
		case "body":
			if p.peek().kind == 's' {
				current.Body = p.peek().val
				p.pos++
			}
		case "additional_bindings":
			if p.match('p', "{") {
				sub, err := p.parseHTTPBlock(depth + 1)
				if err != nil {
					return nil, err
				}
				extra = append(extra, sub...)
			}
		default:
			if p.match('p', "{") {
				if err := p.skipBlock(depth + 1); err != nil {
					return nil, err
				}
			} else if p.pos < len(p.toks) {
				p.pos++
			}
		}
	}
	return nil, fmt.Errorf("%w: google.api.http 块未闭合", ErrSpecInvalidProtobuf)
}

// sortAndDedupeSpecOps 规范化操作列表：按 Key 排序并去重（同 Key 合并参数）。
func sortAndDedupeSpecOps(ops []SpecOperation) []SpecOperation {
	if len(ops) == 0 {
		return []SpecOperation{}
	}
	byKey := make(map[string]SpecOperation, len(ops))
	for _, op := range ops {
		op.Method = strings.ToUpper(strings.TrimSpace(op.Method))
		if len(op.Method) > 16 {
			op.Method = op.Method[:16]
		}
		op.Path = strings.TrimSpace(op.Path)
		if op.Path == "" {
			continue
		}
		if len(op.Path) > 512 {
			op.Path = op.Path[:512]
		}
		op.Key = op.Method + " " + op.Path
		if existing, ok := byKey[op.Key]; ok {
			existing.Params = sortAndDedupeSpecParams(append(existing.Params, op.Params...))
			byKey[op.Key] = existing
		} else {
			op.Params = sortAndDedupeSpecParams(op.Params)
			byKey[op.Key] = op
		}
	}
	out := make([]SpecOperation, 0, len(byKey))
	for _, op := range byKey {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// sortAndDedupeSpecParams 按 (In, Name) 排序并去重（同键取已有非空类型及 required=true 优先）。
func sortAndDedupeSpecParams(params []SpecParam) []SpecParam {
	if len(params) == 0 {
		return []SpecParam{}
	}
	type pk struct{ in, name string }
	byKey := make(map[pk]SpecParam, len(params))
	for _, p := range params {
		p.In = strings.ToUpper(strings.TrimSpace(p.In))
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			continue
		}
		k := pk{p.In, p.Name}
		if existing, ok := byKey[k]; ok {
			if existing.Type == "" && p.Type != "" {
				existing.Type = p.Type
			}
			if p.Required {
				existing.Required = true
			}
			byKey[k] = existing
		} else {
			byKey[k] = p
		}
	}
	out := make([]SpecParam, 0, len(byKey))
	for _, p := range byKey {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].In != out[j].In {
			return out[i].In < out[j].In
		}
		return out[i].Name < out[j].Name
	})
	return out
}
