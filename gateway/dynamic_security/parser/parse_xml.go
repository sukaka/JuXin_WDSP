package parser

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// extractXMLFields 流式解析 XML（xml.Decoder 逐 token，不建树）：元素路径 -> 叶子类型。
// 防御与上限：
//   - 遇 DOCTYPE 立即停止并置 XMLDTDBlocked（XXE 防御：禁止 DTD/实体展开）；
//   - 嵌套深度超 MaxXMLDepth 置 XMLTruncated 并停止；
//   - 字段数受 MaxFieldCount 限制（超限置 FieldCapped）。
func (p *Parsed) extractXMLFields(raw []byte, limits dsctx.ParseLimits) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	stack := make([]string, 0, 8)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			return // 格式错误：保留已解析部分，结束
		}
		switch t := tok.(type) {
		case xml.Directive:
			// Go 解码器本身不展开外部实体；此处按任务书在协议层直接拒绝 DTD
			if bytes.HasPrefix(bytes.ToUpper(bytes.TrimSpace(t)), []byte("DOCTYPE")) {
				p.XMLDTDBlocked = true
				return
			}
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if len(stack) > limits.MaxXMLDepth {
				p.XMLTruncated = true
				return
			}
		case xml.EndElement:
			if n := len(stack); n > 0 {
				stack = stack[:n-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" || len(stack) == 0 {
				continue
			}
			path := strings.Join(stack, ".")
			if _, ok := p.XMLFields[path]; ok {
				continue // 重复兄弟元素共享路径，只记录一次
			}
			if p.FieldCount >= limits.MaxFieldCount {
				p.FieldCapped = true
				return
			}
			p.XMLFields[path] = inferScalarType(text)
			p.FieldCount++
		}
	}
}
