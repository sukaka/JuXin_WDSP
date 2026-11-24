// spec_raml.go RAML 0.8 / 1.0（.raml）规范导入解析。
// RAML 为 YAML 子集（首行 #%RAML 1.0 / #%RAML 0.8），解码复用 decodeSpecYAML（保留自定义标签/
// 别名炸弹/深度/节点预算安全防线，绝不解析 !include 外部文件）。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const ramlMaxDepth = 32

var ramlHTTPMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true,
}

// isRAMLHeader 判断去除空白与 BOM 后的文档是否以 #%RAML 头开头。
func isRAMLHeader(trimmed []byte) bool {
	return strings.HasPrefix(string(trimmed), "#%RAML")
}

// parseRAMLContent 解析 RAML 原文（校验 #%RAML 0.8/1.0 头 + 安全 YAML 解码 + 资源树提取）。
func parseRAMLContent(trimmed []byte) (string, map[string]any, []SpecOperation, error) {
	firstLine := string(trimmed)
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	firstLine = strings.TrimSpace(firstLine)
	if !strings.HasPrefix(firstLine, "#%RAML 1.0") && !strings.HasPrefix(firstLine, "#%RAML 0.8") {
		return "", nil, nil, fmt.Errorf("%w: 仅支持 RAML 1.0 与 RAML 0.8（头声明=%q）", ErrSpecInvalidRAML, truncateRefValue(firstLine))
	}
	doc, err := decodeSpecYAML(trimmed)
	if err != nil {
		return "", nil, nil, err
	}
	if err := rejectExternalRefs(doc); err != nil {
		return "", nil, nil, err
	}
	ops, title, err := ParseRAML(doc)
	if err != nil {
		return "", nil, nil, err
	}
	normalized := map[string]any{
		"x-wdsp-spec-format": SpecFormatRAML,
		"raml_version":       strings.TrimPrefix(firstLine, "#%RAML "),
		"doc":                doc,
	}
	if title != "" {
		normalized["info"] = map[string]any{"title": title}
	}
	return SpecFormatRAML, normalized, ops, nil
}

// ParseRAML 从已安全解码的 RAML 文档映射提取操作清单。
func ParseRAML(doc map[string]any) ([]SpecOperation, string, error) {
	if doc == nil {
		return nil, "", fmt.Errorf("%w: 文档为空", ErrSpecInvalidRAML)
	}
	title, _ := doc["title"].(string)
	title = strings.TrimSpace(title)

	basePrefix := ramlBasePath(doc)
	typesMap, _ := doc["types"].(map[string]any)

	ops := []SpecOperation{}
	for k, v := range doc {
		if !strings.HasPrefix(k, "/") {
			continue
		}
		resMap, ok := v.(map[string]any)
		if !ok {
			continue
		}
		walkRAMLResource(basePrefix+k, resMap, nil, typesMap, &ops, 0)
	}
	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: 未找到有效的资源路径与 HTTP 方法定义", ErrSpecInvalidRAML)
	}
	return ops, title, nil
}

func ramlBasePath(doc map[string]any) string {
	baseURI, _ := doc["baseUri"].(string)
	baseURI = strings.TrimSpace(baseURI)
	if baseURI == "" {
		return ""
	}
	if ver, _ := doc["version"].(string); ver != "" {
		baseURI = strings.ReplaceAll(baseURI, "{version}", strings.TrimSpace(ver))
	}
	// 替换残留模板变量以便 url.Parse 提取 path，随后还原
	sanitized := strings.NewReplacer("{", "__L__", "}", "__R__").Replace(baseURI)
	u, err := url.Parse(sanitized)
	if err != nil {
		return ""
	}
	p := strings.NewReplacer("__L__", "{", "__R__", "}").Replace(u.Path)
	p = strings.TrimRight(p, "/")
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func walkRAMLResource(fullPath string, node map[string]any, inheritedPathParams []SpecParam, typesMap map[string]any, ops *[]SpecOperation, depth int) {
	if depth > ramlMaxDepth {
		return
	}
	pathParams := append([]SpecParam{}, inheritedPathParams...)
	pathParams = append(pathParams, ramlNamedParams(node["uriParameters"], "PATH", true)...)
	// 路径模板中出现但未在 uriParameters 声明的 {param} 自动补全
	for _, m := range specPathPlaceholderPattern.FindAllStringSubmatch(fullPath, -1) {
		pathParams = append(pathParams, SpecParam{Name: m[1], In: "PATH", Type: "string", Required: true})
	}

	for k, v := range node {
		if strings.HasPrefix(k, "/") {
			if sub, ok := v.(map[string]any); ok {
				walkRAMLResource(strings.TrimRight(fullPath, "/")+k, sub, pathParams, typesMap, ops, depth+1)
			}
			continue
		}
		lower := strings.ToLower(k)
		if !ramlHTTPMethods[lower] {
			continue
		}
		method := strings.ToUpper(lower)
		params := append([]SpecParam{}, pathParams...)
		if opMap, ok := v.(map[string]any); ok {
			params = append(params, ramlNamedParams(opMap["queryParameters"], "QUERY", false)...)
			params = append(params, ramlNamedParams(opMap["headers"], "HEADER", false)...)
			params = append(params, ramlBodyParams(opMap["body"], typesMap)...)
		}
		*ops = append(*ops, SpecOperation{
			Method: method,
			Path:   fullPath,
			Key:    method + " " + fullPath,
			Params: sortAndDedupeSpecParams(params),
		})
	}
}

func ramlNamedParams(raw any, in string, defaultRequired bool) []SpecParam {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make([]SpecParam, 0, len(m))
	for name, val := range m {
		optional := strings.HasSuffix(name, "?")
		cleanName := strings.TrimSuffix(strings.TrimSpace(name), "?")
		if cleanName == "" {
			continue
		}
		pType := "string"
		req := defaultRequired
		if !defaultRequired && !optional {
			// RAML 1.0 属性默认 required=true，参数若显式给 required 字段则以显式为准
			req = false
		}
		switch tv := val.(type) {
		case string:
			pType = ramlTypeName(tv)
		case map[string]any:
			if t, ok := tv["type"].(string); ok {
				pType = ramlTypeName(t)
			}
			if r, has := tv["required"].(bool); has {
				req = r
			} else if defaultRequired {
				req = true
			}
		}
		out = append(out, SpecParam{Name: cleanName, In: in, Type: pType, Required: req})
	}
	return out
}

func ramlBodyParams(raw any, typesMap map[string]any) []SpecParam {
	bodyMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	// RAML body 既可直接写 type/properties，也可按 mediaType（如 application/json）分层
	var media map[string]any
	if _, hasProps := bodyMap["properties"]; hasProps {
		media = bodyMap
	} else if _, hasType := bodyMap["type"]; hasType {
		media = bodyMap
	} else if _, hasSchema := bodyMap["schema"]; hasSchema {
		media = bodyMap
	} else {
		for k, v := range bodyMap {
			if strings.Contains(strings.ToLower(k), "json") {
				if mm, ok := v.(map[string]any); ok {
					media = mm
					break
				}
			}
		}
		if media == nil {
			for _, v := range bodyMap {
				if mm, ok := v.(map[string]any); ok {
					media = mm
					break
				}
			}
		}
	}
	if media == nil {
		return nil
	}
	// 1. RAML 1.0 properties
	if props, ok := media["properties"].(map[string]any); ok {
		return ramlPropertiesToParams(props)
	}
	// 2. RAML 1.0 引用顶层 types
	if typeRef, ok := media["type"].(string); ok && typesMap != nil {
		if def, ok := typesMap[strings.TrimSpace(typeRef)].(map[string]any); ok {
			if props, ok := def["properties"].(map[string]any); ok {
				return ramlPropertiesToParams(props)
			}
		}
	}
	// 3. RAML 0.8 schema（JSON Schema 字符串）
	if schemaStr, ok := media["schema"].(string); ok {
		var js map[string]any
		if err := json.Unmarshal([]byte(schemaStr), &js); err == nil && js != nil {
			if op, ok := jsonSchemaOp("body", js); ok {
				return op.Params
			}
		}
	}
	return nil
}

func ramlPropertiesToParams(props map[string]any) []SpecParam {
	out := make([]SpecParam, 0, len(props))
	for name, val := range props {
		optional := strings.HasSuffix(name, "?")
		cleanName := strings.TrimSuffix(strings.TrimSpace(name), "?")
		if cleanName == "" {
			continue
		}
		pType := "string"
		req := !optional
		switch tv := val.(type) {
		case string:
			pType = ramlTypeName(tv)
		case map[string]any:
			if t, ok := tv["type"].(string); ok {
				pType = ramlTypeName(t)
			}
			if r, has := tv["required"].(bool); has {
				req = r
			}
		}
		out = append(out, SpecParam{Name: cleanName, In: "BODY", Type: pType, Required: req})
	}
	return out
}

func ramlTypeName(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasSuffix(s, "[]") || s == "array" {
		return "array"
	}
	switch s {
	case "string", "date-only", "time-only", "datetime-only", "datetime", "file":
		return "string"
	case "integer":
		return "integer"
	case "number":
		return "number"
	case "boolean":
		return "boolean"
	case "object":
		return "object"
	default:
		return "object"
	}
}
