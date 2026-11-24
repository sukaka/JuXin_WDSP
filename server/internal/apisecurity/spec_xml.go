// spec_xml.go SOAP/WSDL（.wsdl/.xml）与 XML Schema（.xsd/.xml）规范导入解析。
// 安全基线：严禁 <!DOCTYPE 与 <!ENTITY（防 XXE / 实体扩展炸弹）、限制 XML 深度与词元预算、
// 绝不跟随外部 schemaLocation/location 发起网络或文件访问。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	xmlMaxDepth  = 64
	xmlMaxTokens = 200000
)

type xmlNode struct {
	Local    string
	Space    string
	Attrs    map[string]string
	Children []*xmlNode
}

func (n *xmlNode) attr(name string) string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(n.Attrs[name])
}

// parseSpecXML 解析 XML 族规范（WSDL 1.1 / WSDL 2.0 / XSD），返回格式标识、规范化存储文档与操作清单。
func parseSpecXML(body []byte) (string, map[string]any, []SpecOperation, error) {
	root, err := safeParseXMLTree(body)
	if err != nil {
		return "", nil, nil, err
	}
	if root == nil {
		return "", nil, nil, fmt.Errorf("%w: 空 XML 文档", ErrSpecInvalidXML)
	}

	switch strings.ToLower(root.Local) {
	case "definitions":
		// WSDL 1.1
		ops, title, err := parseWSDL11(root)
		if err != nil {
			return "", nil, nil, err
		}
		return SpecFormatWSDL, wrapRawSpecDoc(SpecFormatWSDL, title, string(body)), ops, nil
	case "description":
		// WSDL 2.0（限定 wsdl 命名空间或含 interface 子元素，避免误认任意 XML）
		if strings.Contains(strings.ToLower(root.Space), "wsdl") || hasChildLocal(root, "interface") {
			ops, title, err := parseWSDL20(root)
			if err != nil {
				return "", nil, nil, err
			}
			return SpecFormatWSDL, wrapRawSpecDoc(SpecFormatWSDL, title, string(body)), ops, nil
		}
	case "schema":
		// XSD（XML Schema）
		if strings.Contains(strings.ToLower(root.Space), "xmlschema") ||
			hasChildLocal(root, "element") || hasChildLocal(root, "complexType") {
			ops, title, err := parseXSD(root)
			if err != nil {
				return "", nil, nil, err
			}
			return SpecFormatXSD, wrapRawSpecDoc(SpecFormatXSD, title, string(body)), ops, nil
		}
	}
	return "", nil, nil, fmt.Errorf("%w: 不支持的 XML 根元素 <%s>（仅支持 WSDL / XSD）", ErrSpecUnsupportedFormat, root.Local)
}

func wrapRawSpecDoc(format, title, raw string) map[string]any {
	doc := map[string]any{
		"x-wdsp-spec-format": format,
		"raw":                raw,
	}
	if strings.TrimSpace(title) != "" {
		doc["info"] = map[string]any{"title": strings.TrimSpace(title)}
	}
	return doc
}

func hasChildLocal(n *xmlNode, local string) bool {
	for _, c := range n.Children {
		if strings.EqualFold(c.Local, local) {
			return true
		}
	}
	return false
}

// safeParseXMLTree 安全 XML 树解析：拒绝 DOCTYPE/ENTITY，限制嵌套深度与总词元数。
func safeParseXMLTree(body []byte) (*xmlNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	dec.Entity = map[string]string{} // 禁止自定义实体映射

	var stack []*xmlNode
	var root *xmlNode
	tokens := 0

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSpecInvalidXML, err)
		}
		tokens++
		if tokens > xmlMaxTokens {
			return nil, fmt.Errorf("%w: XML 节点/词元数超过 %d", ErrSpecTooComplex, xmlMaxTokens)
		}
		switch t := tok.(type) {
		case xml.Directive:
			upper := strings.ToUpper(string(t))
			if strings.Contains(upper, "DOCTYPE") || strings.Contains(upper, "ENTITY") {
				return nil, fmt.Errorf("%w: 出于安全限制禁止 XML DOCTYPE/ENTITY 声明", ErrSpecInvalidXML)
			}
		case xml.StartElement:
			if len(stack)+1 > xmlMaxDepth {
				return nil, fmt.Errorf("%w: XML 嵌套深度超过 %d", ErrSpecTooComplex, xmlMaxDepth)
			}
			attrs := make(map[string]string, len(t.Attr))
			for _, a := range t.Attr {
				attrs[a.Name.Local] = a.Value
			}
			node := &xmlNode{
				Local: t.Name.Local,
				Space: t.Name.Space,
				Attrs: attrs,
			}
			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root, nil
}

// ---------- WSDL 1.1 解析 ----------

func parseWSDL11(root *xmlNode) ([]SpecOperation, string, error) {
	title := root.attr("name")

	// 1. 提取 <types><schema> 内联 XSD 类型，便于将 message part(element=...) 展开为字段参数
	xsdElements := map[string][]SpecParam{}
	xsdTypes := map[string][]SpecParam{}
	for _, c := range root.Children {
		if strings.EqualFold(c.Local, "types") {
			for _, sc := range c.Children {
				if strings.EqualFold(sc.Local, "schema") {
					collectXSDDefinitions(sc, xsdElements, xsdTypes)
				}
			}
		}
	}

	// 2. 提取 <message name="..."><part .../>
	messages := map[string][]SpecParam{}
	for _, c := range root.Children {
		if !strings.EqualFold(c.Local, "message") {
			continue
		}
		mName := c.attr("name")
		if mName == "" {
			continue
		}
		params := []SpecParam{}
		for _, part := range c.Children {
			if !strings.EqualFold(part.Local, "part") {
				continue
			}
			elemRef := stripXMLPrefix(part.attr("element"))
			if elemRef != "" {
				if expanded, ok := xsdElements[elemRef]; ok && len(expanded) > 0 {
					params = append(params, expanded...)
					continue
				}
				if expanded, ok := xsdTypes[elemRef]; ok && len(expanded) > 0 {
					params = append(params, expanded...)
					continue
				}
			}
			pName := part.attr("name")
			if pName == "" {
				pName = elemRef
			}
			if pName != "" {
				pType := xsdTypeToSpecType(part.attr("type"))
				params = append(params, SpecParam{Name: pName, In: "BODY", Type: pType})
			}
		}
		messages[mName] = params
	}

	// 3. 提取 <service><port><address location="..."/> 路径前缀（优先首个有效路径）
	servicePath := ""
	for _, c := range root.Children {
		if !strings.EqualFold(c.Local, "service") {
			continue
		}
		if title == "" {
			title = c.attr("name")
		}
		for _, port := range c.Children {
			if !strings.EqualFold(port.Local, "port") {
				continue
			}
			for _, addr := range port.Children {
				if strings.EqualFold(addr.Local, "address") {
					if loc := addr.attr("location"); loc != "" && servicePath == "" {
						servicePath = extractURLPathOrDefault(loc)
					}
				}
			}
		}
	}

	// 4. 提取 <portType><operation>
	ops := []SpecOperation{}
	for _, c := range root.Children {
		if !strings.EqualFold(c.Local, "portType") {
			continue
		}
		ptName := c.attr("name")
		if title == "" {
			title = ptName
		}
		base := servicePath
		if base == "" {
			if ptName != "" {
				base = "/soap/" + ptName
			} else {
				base = "/soap"
			}
		}
		base = strings.TrimRight(base, "/")
		for _, opNode := range c.Children {
			if !strings.EqualFold(opNode.Local, "operation") {
				continue
			}
			opName := opNode.attr("name")
			if opName == "" {
				continue
			}
			params := []SpecParam{}
			for _, ioNode := range opNode.Children {
				if strings.EqualFold(ioNode.Local, "input") {
					msgRef := stripXMLPrefix(ioNode.attr("message"))
					if ps, ok := messages[msgRef]; ok {
						params = append(params, ps...)
					}
				}
			}
			p := base + "/" + opName
			ops = append(ops, SpecOperation{
				Method: "SOAP",
				Path:   p,
				Key:    "SOAP " + p,
				Params: params,
			})
		}
	}

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: WSDL 1.1 文档缺少有效的 portType/operation 定义", ErrSpecInvalidXML)
	}
	return ops, title, nil
}

// ---------- WSDL 2.0 解析 ----------

func parseWSDL20(root *xmlNode) ([]SpecOperation, string, error) {
	title := root.attr("name")
	xsdElements := map[string][]SpecParam{}
	xsdTypes := map[string][]SpecParam{}
	for _, c := range root.Children {
		if strings.EqualFold(c.Local, "types") {
			for _, sc := range c.Children {
				if strings.EqualFold(sc.Local, "schema") {
					collectXSDDefinitions(sc, xsdElements, xsdTypes)
				}
			}
		}
	}

	servicePath := ""
	for _, c := range root.Children {
		if strings.EqualFold(c.Local, "service") {
			if title == "" {
				title = c.attr("name")
			}
			for _, ep := range c.Children {
				if strings.EqualFold(ep.Local, "endpoint") {
					if addr := ep.attr("address"); addr != "" && servicePath == "" {
						servicePath = extractURLPathOrDefault(addr)
					}
				}
			}
		}
	}

	ops := []SpecOperation{}
	for _, c := range root.Children {
		if !strings.EqualFold(c.Local, "interface") {
			continue
		}
		ifName := c.attr("name")
		if title == "" {
			title = ifName
		}
		base := servicePath
		if base == "" {
			if ifName != "" {
				base = "/soap/" + ifName
			} else {
				base = "/soap"
			}
		}
		base = strings.TrimRight(base, "/")
		for _, opNode := range c.Children {
			if !strings.EqualFold(opNode.Local, "operation") {
				continue
			}
			opName := opNode.attr("name")
			if opName == "" {
				continue
			}
			params := []SpecParam{}
			for _, ioNode := range opNode.Children {
				if strings.EqualFold(ioNode.Local, "input") {
					elem := stripXMLPrefix(ioNode.attr("element"))
					if elem != "" {
						if ps, ok := xsdElements[elem]; ok {
							params = append(params, ps...)
						} else if ps, ok := xsdTypes[elem]; ok {
							params = append(params, ps...)
						}
					}
				}
			}
			p := base + "/" + opName
			ops = append(ops, SpecOperation{
				Method: "SOAP",
				Path:   p,
				Key:    "SOAP " + p,
				Params: params,
			})
		}
	}

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: WSDL 2.0 文档缺少有效的 interface/operation 定义", ErrSpecInvalidXML)
	}
	return ops, title, nil
}

// ---------- XSD 解析 ----------

func parseXSD(root *xmlNode) ([]SpecOperation, string, error) {
	elements := map[string][]SpecParam{}
	types := map[string][]SpecParam{}
	collectXSDDefinitions(root, elements, types)

	ops := []SpecOperation{}
	seen := map[string]bool{}
	for name, params := range elements {
		seen[name] = true
		p := "/_xsd/" + jsonSchemaSlug(name)
		ops = append(ops, SpecOperation{
			Method: "SCHEMA",
			Path:   p,
			Key:    "SCHEMA " + p,
			Params: params,
		})
	}
	for name, params := range types {
		if seen[name] {
			continue
		}
		p := "/_xsd/" + jsonSchemaSlug(name)
		ops = append(ops, SpecOperation{
			Method: "SCHEMA",
			Path:   p,
			Key:    "SCHEMA " + p,
			Params: params,
		})
	}
	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: XSD 文档缺少可解析的 element 或 complexType 定义", ErrSpecInvalidXML)
	}
	title := ""
	if ns := root.attr("targetNamespace"); ns != "" {
		if u, err := url.Parse(ns); err == nil && strings.Trim(u.Path, "/") != "" {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			title = parts[len(parts)-1]
		}
	}
	if title == "" {
		title = strings.TrimPrefix(ops[0].Path, "/_xsd/")
	}
	return ops, title, nil
}

func collectXSDDefinitions(schema *xmlNode, elements, types map[string][]SpecParam) {
	// 第一遍：收集所有具名 complexType
	for _, c := range schema.Children {
		if strings.EqualFold(c.Local, "complexType") {
			if name := c.attr("name"); name != "" {
				types[name] = extractXSDComplexParams(c)
			}
		}
	}
	// 第二遍：收集顶层 element（支持内联 complexType 或引用 type="..."）
	for _, c := range schema.Children {
		if !strings.EqualFold(c.Local, "element") {
			continue
		}
		name := c.attr("name")
		if name == "" {
			continue
		}
		var params []SpecParam
		for _, sub := range c.Children {
			if strings.EqualFold(sub.Local, "complexType") {
				params = append(params, extractXSDComplexParams(sub)...)
			}
		}
		if len(params) == 0 {
			if refType := stripXMLPrefix(c.attr("type")); refType != "" {
				if tp, ok := types[refType]; ok {
					params = append(params, tp...)
				} else {
					params = append(params, SpecParam{
						Name:     name,
						In:       "BODY",
						Type:     xsdTypeToSpecType(refType),
						Required: c.attr("minOccurs") != "0",
					})
				}
			}
		}
		elements[name] = sortAndDedupeSpecParams(params)
	}
}

func extractXSDComplexParams(ct *xmlNode) []SpecParam {
	out := []SpecParam{}
	var walk func(n *xmlNode, depth int)
	walk = func(n *xmlNode, depth int) {
		if depth > 16 {
			return
		}
		for _, c := range n.Children {
			switch strings.ToLower(c.Local) {
			case "sequence", "all", "choice", "complexcontent", "simplecontent", "extension", "restriction":
				walk(c, depth+1)
			case "element":
				name := c.attr("name")
				if name == "" {
					name = stripXMLPrefix(c.attr("ref"))
				}
				if name == "" {
					continue
				}
				t := xsdTypeToSpecType(c.attr("type"))
				if maxOccurs := c.attr("maxOccurs"); maxOccurs == "unbounded" || (maxOccurs != "" && maxOccurs != "0" && maxOccurs != "1") {
					t = "array"
				}
				out = append(out, SpecParam{
					Name:     name,
					In:       "BODY",
					Type:     t,
					Required: c.attr("minOccurs") != "0",
				})
			case "attribute":
				if name := c.attr("name"); name != "" {
					out = append(out, SpecParam{
						Name:     name,
						In:       "BODY",
						Type:     xsdTypeToSpecType(c.attr("type")),
						Required: strings.EqualFold(c.attr("use"), "required"),
					})
				}
			}
		}
	}
	walk(ct, 0)
	return sortAndDedupeSpecParams(out)
}

func stripXMLPrefix(qname string) string {
	qname = strings.TrimSpace(qname)
	if idx := strings.IndexByte(qname, ':'); idx >= 0 {
		return qname[idx+1:]
	}
	return qname
}

func xsdTypeToSpecType(raw string) string {
	local := strings.ToLower(stripXMLPrefix(raw))
	switch local {
	case "", "string", "normalizedstring", "token", "date", "datetime", "time", "anyuri", "base64binary", "hexbinary":
		return "string"
	case "boolean":
		return "boolean"
	case "int", "integer", "long", "short", "byte", "unsignedint", "unsignedlong", "positiveinteger", "nonnegativeinteger":
		return "integer"
	case "float", "double", "decimal":
		return "number"
	default:
		return "object"
	}
}

func extractURLPathOrDefault(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(u.Path)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
