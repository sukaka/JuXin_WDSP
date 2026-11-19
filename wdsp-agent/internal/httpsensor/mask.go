// 脱敏（Phase 3 契约 §5：离主机前 Agent 侧强制执行）。
//
// 无旁路证明：所有 HTTP 记录唯一构造出口为 conn.emit → buildMessage，
// headers/URI query/表单 Body/JSON Body/multipart 字段全部经本包函数脱敏后
// 才写入 events.HTTPRecord；transport/agent 发送路径不接触未脱敏数据。
package httpsensor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// maskValue 脱敏占位值（契约 §5）。
const maskValue = "********"

// maskHeaders 对 Header map 就地应用脱敏规则（大小写不敏感；headers 已为小写键）。
// NONE=不动 | MASK=替换 | HASH=sha256:<hex 前16位> | DROP=整行删除。
// 返回实际脱敏的字段数（masked 指标，P1-03 §5.7）。
func maskHeaders(headers map[string]string, rule config.MaskRule) int {
	if rule.Mode == config.MaskModeNone || len(rule.Names) == 0 {
		return 0
	}
	names := lowerSet(rule.Names)
	masked := 0
	for k, v := range headers {
		if _, hit := names[k]; !hit {
			continue
		}
		masked++
		switch rule.Mode {
		case config.MaskModeDrop:
			delete(headers, k)
		case config.MaskModeHash:
			headers[k] = hashValue(v)
		default: // MASK
			headers[k] = maskValue
		}
	}
	return masked
}

// maskQueryString 对 query/form 字符串（k=v&k=v）按参数名脱敏（大小写不敏感；
// 匹配前先对参数名做 URL 解码，防 %70assword 编码绕过）。
// 保持原有分隔与顺序；DROP 删除该段。返回脱敏后字符串与实际脱敏的参数数。
func maskQueryString(qs string, rule config.MaskRule) (string, int) {
	if rule.Mode == config.MaskModeNone || qs == "" || len(rule.Names) == 0 {
		return qs, 0
	}
	names := lowerSet(rule.Names)
	segs := strings.Split(qs, "&")
	out := segs[:0]
	masked := 0
	for _, seg := range segs {
		k := seg
		v := ""
		if i := strings.IndexByte(seg, '='); i >= 0 {
			k, v = seg[:i], seg[i+1:]
		}
		decodedKey := k
		if unescaped, err := url.QueryUnescape(k); err == nil {
			decodedKey = unescaped
		}
		_, hitRaw := names[strings.ToLower(k)]
		_, hitDecoded := names[strings.ToLower(decodedKey)]
		if !hitRaw && !hitDecoded {
			out = append(out, seg)
			continue
		}
		masked++
		switch rule.Mode {
		case config.MaskModeDrop:
			continue // 段删除
		case config.MaskModeHash:
			out = append(out, k+"="+hashValue(v))
		default: // MASK
			out = append(out, k+"="+maskValue)
		}
	}
	return strings.Join(out, "&"), masked
}

// MaskURI 对请求 URI 的 query 部分脱敏（路径不动）；供 L0（flow）与 L1+（httpsensor）共用。
func MaskURI(uri string, rule config.MaskRule) (string, int) {
	return maskURI(uri, rule)
}

// maskURI 对请求 URI 的 query 部分脱敏（路径不动）。返回脱敏后 URI 与脱敏参数数。
func maskURI(uri string, rule config.MaskRule) (string, int) {
	i := strings.IndexByte(uri, '?')
	if i < 0 {
		return uri, 0
	}
	qs, n := maskQueryString(uri[i+1:], rule)
	return uri[:i+1] + qs, n
}

func isJSONMediaType(mt string) bool {
	return mt == "application/json" || mt == "text/json" ||
		(strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

func isXMLMediaType(mt string) bool {
	return mt == "application/xml" || mt == "text/xml" ||
		(strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+xml"))
}

// maskBodyParams 对 Body 按内容类型做敏感参数脱敏（契约 §5 增强）：
//   - application/x-www-form-urlencoded → 同 query 规则（URL 解码参数名）；
//   - application/json / text/json / application/*+json → 递归脱敏对象与数组，
//     截断或不可解析 JSON 采用 fail-closed 脱敏防止明文泄漏；
//   - application/graphql → 支持 JSON 封装与原始 GraphQL 参数脱敏；
//   - application/xml / text/xml / application/*+xml → 元素内容与属性脱敏；
//   - text/plain 等文本类型 → 自动识别内嵌 JSON 或 key=value / key: value 敏感字段脱敏。
func maskBodyParams(body, mediaType string, rule config.MaskRule) (string, int) {
	if rule.Mode == config.MaskModeNone || body == "" || len(rule.Names) == 0 {
		return body, 0
	}
	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return maskQueryString(body, rule)
	case isJSONMediaType(mediaType):
		return maskJSON(body, rule)
	case mediaType == "application/graphql":
		return maskGraphQL(body, rule)
	case isXMLMediaType(mediaType):
		return maskXML(body, rule)
	case mediaType == "text/plain" || strings.HasPrefix(mediaType, "text/") || mediaType == "application/javascript":
		return maskPlainText(body, rule)
	}
	return body, 0
}

// maskJSON 递归脱敏 JSON 对象和数组；遇到截断或无法解析的 JSON 时 fail-closed 脱敏。
func maskJSON(body string, rule config.MaskRule) (string, int) {
	var val any
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&val); err == nil {
		var trailing any
		if dec.Decode(&trailing) == io.EOF {
			names := lowerSet(rule.Names)
			maskedVal, masked := maskJSONValue(val, names, rule.Mode)
			if masked == 0 {
				return body, 0
			}
			out, merr := json.Marshal(maskedVal)
			if merr == nil {
				return string(out), masked
			}
		}
	}
	// 截断或非法 JSON：fail-closed 整段脱敏，杜绝凭据明文泄漏
	return redactRawValue(body, rule.Mode), 1
}

// maskJSONValue 递归遍历 JSON 对象/数组并按敏感字段名脱敏。
func maskJSONValue(val any, names map[string]struct{}, mode string) (any, int) {
	switch typed := val.(type) {
	case map[string]any:
		masked := 0
		for k, v := range typed {
			if _, hit := names[strings.ToLower(k)]; hit {
				masked++
				switch mode {
				case config.MaskModeDrop:
					delete(typed, k)
				case config.MaskModeHash:
					typed[k] = hashValue(jsonValueString(v))
				default: // MASK
					typed[k] = maskValue
				}
				continue
			}
			nv, n := maskJSONValue(v, names, mode)
			if n > 0 {
				typed[k] = nv
				masked += n
			}
		}
		return typed, masked
	case []any:
		masked := 0
		for i, elem := range typed {
			nv, n := maskJSONValue(elem, names, mode)
			if n > 0 {
				typed[i] = nv
				masked += n
			}
		}
		return typed, masked
	default:
		return val, 0
	}
}

// maskGraphQL 处理 application/graphql（JSON 封装或原始 GraphQL 文档）。
func maskGraphQL(body string, rule config.MaskRule) (string, int) {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var val any
		dec := json.NewDecoder(strings.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&val); err == nil {
			var trailing any
			if dec.Decode(&trailing) == io.EOF {
				names := lowerSet(rule.Names)
				maskedVal, masked := maskJSONValue(val, names, rule.Mode)
				// 同时对 JSON 内 query 字符串中的内联敏感参数脱敏
				if obj, ok := maskedVal.(map[string]any); ok {
					if q, ok := obj["query"].(string); ok && q != "" {
						mq, n := maskKeyValueText(q, rule, true)
						if n > 0 {
							obj["query"] = mq
							masked += n
						}
					}
				}
				if masked == 0 {
					return body, 0
				}
				out, merr := json.Marshal(maskedVal)
				if merr == nil {
					return string(out), masked
				}
			}
		}
		return redactRawValue(body, rule.Mode), 1
	}
	return maskKeyValueText(body, rule, true)
}

// maskXML 脱敏 XML 元素正文与属性（大小写不敏感，支持命名空间前缀与截断未闭合标签）。
func maskXML(body string, rule config.MaskRule) (string, int) {
	names := lowerSet(rule.Names)
	var b strings.Builder
	b.Grow(len(body))
	masked := 0
	i := 0
	for i < len(body) {
		lt := strings.IndexByte(body[i:], '<')
		if lt < 0 {
			b.WriteString(body[i:])
			break
		}
		b.WriteString(body[i : i+lt])
		i += lt

		// 跳过注释 / CDATA / 处理指令 / 声明
		if strings.HasPrefix(body[i:], "<!--") {
			end := strings.Index(body[i+4:], "-->")
			if end < 0 {
				b.WriteString(body[i:])
				break
			}
			b.WriteString(body[i : i+4+end+3])
			i += 4 + end + 3
			continue
		}
		if strings.HasPrefix(body[i:], "<![CDATA[") {
			end := strings.Index(body[i+9:], "]]>")
			if end < 0 {
				b.WriteString(body[i:])
				break
			}
			b.WriteString(body[i : i+9+end+3])
			i += 9 + end + 3
			continue
		}
		gt := findXMLTagEnd(body, i+1)
		if gt < 0 {
			// 未闭合起始标签：对其中的敏感属性做脱敏
			attrOut, n := maskXMLAttributes(body[i:], names, rule.Mode)
			masked += n
			b.WriteString(attrOut)
			break
		}
		tagContent := body[i+1 : gt]
		if len(tagContent) == 0 || tagContent[0] == '/' || tagContent[0] == '?' || tagContent[0] == '!' {
			b.WriteString(body[i : gt+1])
			i = gt + 1
			continue
		}
		selfClosing := strings.HasSuffix(strings.TrimSpace(tagContent), "/")
		// 提取标签名（去命名空间前缀匹配）
		nameEnd := 0
		for nameEnd < len(tagContent) && !isXMLSpace(tagContent[nameEnd]) && tagContent[nameEnd] != '/' {
			nameEnd++
		}
		fullTagName := tagContent[:nameEnd]
		localName := xmlLocalName(fullTagName)
		restAttrs := tagContent[nameEnd:]

		// 脱敏标签上的敏感属性
		maskedAttrs, attrMasked := maskXMLAttributes(restAttrs, names, rule.Mode)
		masked += attrMasked

		_, hitElem := names[strings.ToLower(localName)]
		if !hitElem || selfClosing {
			b.WriteByte('<')
			b.WriteString(fullTagName)
			b.WriteString(maskedAttrs)
			b.WriteByte('>')
			i = gt + 1
			continue
		}

		// 命中敏感元素：查找对应闭合标签（大小写不敏感）；若截断无闭合标签则 fail-closed 脱敏至末尾
		afterOpen := gt + 1
		closeStart, closeEnd := findXMLClosingTag(body, afterOpen, fullTagName, localName)
		if closeStart < 0 {
			rawVal := body[afterOpen:]
			masked++
			if rule.Mode != config.MaskModeDrop {
				b.WriteByte('<')
				b.WriteString(fullTagName)
				b.WriteString(maskedAttrs)
				b.WriteByte('>')
				b.WriteString(redactRawValue(rawVal, rule.Mode))
			}
			break
		}
		rawVal := body[afterOpen:closeStart]
		masked++
		if rule.Mode != config.MaskModeDrop {
			b.WriteByte('<')
			b.WriteString(fullTagName)
			b.WriteString(maskedAttrs)
			b.WriteByte('>')
			b.WriteString(redactRawValue(rawVal, rule.Mode))
			b.WriteString(body[closeStart:closeEnd])
		}
		i = closeEnd
	}
	if masked == 0 {
		return body, 0
	}
	return b.String(), masked
}

func findXMLTagEnd(s string, start int) int {
	var quote byte
	for i := start; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			return i
		}
	}
	return -1
}

func xmlLocalName(name string) string {
	if idx := strings.LastIndexByte(name, ':'); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func findXMLClosingTag(body string, start int, fullTagName, localName string) (int, int) {
	lowerFull := strings.ToLower(fullTagName)
	lowerLocal := strings.ToLower(localName)
	pos := start
	for pos < len(body) {
		idx := strings.Index(body[pos:], "</")
		if idx < 0 {
			return -1, -1
		}
		tagStart := pos + idx
		gt := strings.IndexByte(body[tagStart+2:], '>')
		if gt < 0 {
			return -1, -1
		}
		closeName := strings.TrimSpace(body[tagStart+2 : tagStart+2+gt])
		lc := strings.ToLower(closeName)
		if lc == lowerFull || strings.ToLower(xmlLocalName(closeName)) == lowerLocal {
			return tagStart, tagStart + 2 + gt + 1
		}
		pos = tagStart + 2 + gt + 1
	}
	return -1, -1
}

func maskXMLAttributes(attrs string, names map[string]struct{}, mode string) (string, int) {
	if attrs == "" {
		return attrs, 0
	}
	var b strings.Builder
	b.Grow(len(attrs))
	masked := 0
	i := 0
	for i < len(attrs) {
		// 复制空白或 /
		wsStart := i
		for i < len(attrs) && (isXMLSpace(attrs[i]) || attrs[i] == '/') {
			i++
		}
		if i >= len(attrs) {
			b.WriteString(attrs[wsStart:i])
			break
		}
		nameStart := i
		for i < len(attrs) && !isXMLSpace(attrs[i]) && attrs[i] != '=' && attrs[i] != '/' {
			i++
		}
		attrName := attrs[nameStart:i]
		eqSearch := i
		for eqSearch < len(attrs) && isXMLSpace(attrs[eqSearch]) {
			eqSearch++
		}
		if eqSearch >= len(attrs) || attrs[eqSearch] != '=' {
			b.WriteString(attrs[wsStart:i])
			continue
		}
		valStart := eqSearch + 1
		for valStart < len(attrs) && isXMLSpace(attrs[valStart]) {
			valStart++
		}
		if valStart >= len(attrs) || (attrs[valStart] != '"' && attrs[valStart] != '\'') {
			b.WriteString(attrs[wsStart:valStart])
			i = valStart
			continue
		}
		quote := attrs[valStart]
		valEnd := strings.IndexByte(attrs[valStart+1:], quote)
		var rawVal string
		var nextIdx int
		if valEnd < 0 {
			rawVal = attrs[valStart+1:]
			nextIdx = len(attrs)
		} else {
			rawVal = attrs[valStart+1 : valStart+1+valEnd]
			nextIdx = valStart + 1 + valEnd + 1
		}
		if _, hit := names[strings.ToLower(xmlLocalName(attrName))]; !hit {
			b.WriteString(attrs[wsStart:nextIdx])
			i = nextIdx
			continue
		}
		masked++
		if mode != config.MaskModeDrop {
			b.WriteString(attrs[wsStart : valStart+1])
			b.WriteString(redactRawValue(rawVal, mode))
			if valEnd >= 0 {
				b.WriteByte(quote)
			}
		}
		i = nextIdx
	}
	if masked == 0 {
		return attrs, 0
	}
	return b.String(), masked
}

// maskPlainText 处理 text/plain 等文本正文：支持内嵌 JSON、表单及常见 key=value / key: value 格式。
func maskPlainText(body string, rule config.MaskRule) (string, int) {
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return maskJSON(body, rule)
	}
	return maskKeyValueText(body, rule, false)
}

// maskKeyValueText 对一般文本/GraphQL 中的 key=value、key: value、"key": "value" 做敏感字段脱敏。
func maskKeyValueText(body string, rule config.MaskRule, allowColon bool) (string, int) {
	names := lowerSet(rule.Names)
	var b strings.Builder
	b.Grow(len(body))
	masked := 0
	i := 0
	for i < len(body) {
		if !isKeyBoundary(body, i) {
			b.WriteByte(body[i])
			i++
			continue
		}
		// 跳过可选起始引号（"password": "secret" / 'password': 'secret'）
		tokStart := i
		var keyQuote byte
		if body[i] == '"' || body[i] == '\'' {
			keyQuote = body[i]
			i++
		}
		keyStart := i
		for i < len(body) && isParamKeyChar(body[i]) {
			i++
		}
		keyEnd := i
		if keyEnd == keyStart {
			b.WriteString(body[tokStart:i])
			if i == tokStart {
				b.WriteByte(body[i])
				i++
			}
			continue
		}
		if keyQuote != 0 {
			if i >= len(body) || body[i] != keyQuote {
				b.WriteString(body[tokStart:i])
				continue
			}
			i++
		}
		sepPos := i
		for sepPos < len(body) && (body[sepPos] == ' ' || body[sepPos] == '\t') {
			sepPos++
		}
		if sepPos >= len(body) || (body[sepPos] != '=' && body[sepPos] != ':') {
			b.WriteString(body[tokStart:i])
			continue
		}
		sep := body[sepPos]
		// 非 GraphQL 下冒号仅匹配 key: value（后有空白或引号）避免误伤 http:// 等
		if sep == ':' && !allowColon {
			if sepPos+1 >= len(body) || (body[sepPos+1] != ' ' && body[sepPos+1] != '\t' && body[sepPos+1] != '"' && body[sepPos+1] != '\'') {
				b.WriteString(body[tokStart:i])
				continue
			}
		}
		rawKey := body[keyStart:keyEnd]
		decodedKey := rawKey
		if unescaped, err := url.QueryUnescape(rawKey); err == nil {
			decodedKey = unescaped
		}
		_, hitRaw := names[strings.ToLower(rawKey)]
		_, hitDecoded := names[strings.ToLower(decodedKey)]
		if !hitRaw && !hitDecoded {
			b.WriteString(body[tokStart : sepPos+1])
			i = sepPos + 1
			continue
		}
		valStart := sepPos + 1
		for valStart < len(body) && (body[valStart] == ' ' || body[valStart] == '\t') {
			valStart++
		}
		valEnd, innerStart, innerEnd, hasCloseQuote, valQuote := scanTextValue(body, valStart, sep)
		rawVal := body[innerStart:innerEnd]
		masked++
		if rule.Mode == config.MaskModeDrop {
			// 若处于 query/form 风格以 & 衔接，吞掉后续紧跟的 & 或留空占位
			if sep == '=' && valEnd < len(body) && body[valEnd] == '&' {
				valEnd++
			}
		} else {
			b.WriteString(body[tokStart:valStart])
			if valQuote != 0 {
				b.WriteByte(valQuote)
				b.WriteString(redactRawValue(rawVal, rule.Mode))
				if hasCloseQuote {
					b.WriteByte(valQuote)
				}
			} else {
				b.WriteString(redactRawValue(rawVal, rule.Mode))
			}
		}
		i = valEnd
	}
	if masked == 0 {
		return body, 0
	}
	return b.String(), masked
}

func isKeyBoundary(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	prev := s[pos-1]
	return !isParamKeyChar(prev)
}

func isParamKeyChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '%' || c == '+'
}

func scanTextValue(s string, start int, sep byte) (valEnd, innerStart, innerEnd int, closed bool, quote byte) {
	if start >= len(s) {
		return start, start, start, false, 0
	}
	if s[start] == '"' || s[start] == '\'' {
		quote = s[start]
		innerStart = start + 1
		for i := innerStart; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if s[i] == quote {
				return i + 1, innerStart, i, true, quote
			}
		}
		return len(s), innerStart, len(s), false, quote
	}
	innerStart = start
	i := start
	for i < len(s) {
		c := s[i]
		if c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == '&' || c == ';' || c == ',' || c == ')' || c == '}' || c == ']' {
			break
		}
		if sep == ':' && c == '"' {
			break
		}
		i++
	}
	return i, innerStart, i, false, 0
}

func redactRawValue(val, mode string) string {
	switch mode {
	case config.MaskModeDrop:
		return ""
	case config.MaskModeHash:
		return hashValue(val)
	default:
		return maskValue
	}
}

// maskParamValue 单个参数值按名脱敏（multipart 字段用）。masked=true 表示命中规则。
func maskParamValue(name, value string, rule config.MaskRule) (string, bool) {
	if rule.Mode == config.MaskModeNone || len(rule.Names) == 0 {
		return value, false
	}
	if _, hit := lowerSet(rule.Names)[strings.ToLower(name)]; !hit {
		return value, false
	}
	switch rule.Mode {
	case config.MaskModeDrop:
		return "", true
	case config.MaskModeHash:
		return hashValue(value), true
	default:
		return maskValue, true
	}
}

// hashValue HASH 模式：sha256:<hex 前16位>（契约 §5）。
func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// jsonValueString JSON 值转字符串（HASH 输入）：字符串原样，其余按 JSON 序列化。
func jsonValueString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// lowerSet 名字集合转小写 set（匹配大小写不敏感，契约 §5）。
func lowerSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}
