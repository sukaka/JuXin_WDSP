// spec_apib.go API Blueprint（.apib）规范导入解析。
// 支持 FORMAT: 1A 声明、Resource（## Name [/path{?q1,q2}]）与 Action（### Action [GET] / ## Action [POST /path]）、
// + Parameters、+ Request (+ Headers / + Attributes / JSON body)。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	apibFormatHeaderRe = regexp.MustCompile(`(?i)^FORMAT:\s*1A\b`)
	// 匹配 Markdown 标题末尾的 [METHOD /path]、[/path] 或 [METHOD]
	apibHeadingRe = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*$`)
	apibBracketRe = regexp.MustCompile(`\[([^\[\]]+)\]\s*$`)
	// 匹配 RFC 6570 查询展开 {?a,b} 或 {&a,b}
	apibQueryExprRe = regexp.MustCompile(`\{[?&]([^{}]+)\}`)
	// 匹配 + Parameters / + Attributes 列表项：+ name: example (type, required) - desc
	apibParamItemRe = regexp.MustCompile(`^\s*[+\-*]\s+([A-Za-z0-9_.-]+)(?:\s*:\s*[^(\n]*)?(?:\(([^)]*)\))?`)
)

// hasAPIBFormatHeader 判断文档首行是否显式声明 FORMAT: 1A（在 YAML 解码前优先路由，防被误解为单键映射）。
func hasAPIBFormatHeader(trimmed []byte) bool {
	s := string(trimmed)
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	return apibFormatHeaderRe.MatchString(strings.TrimSpace(s))
}

// looksLikeAPIB 粗判文本是否为 API Blueprint（含 FORMAT: 1A 或资源/动作标题）。
func looksLikeAPIB(s string) bool {
	if hasAPIBFormatHeader([]byte(s)) {
		return true
	}
	for _, line := range strings.Split(s, "\n") {
		m := apibHeadingRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) < 3 {
			continue
		}
		bm := apibBracketRe.FindStringSubmatch(m[2])
		if len(bm) < 2 {
			continue
		}
		inside := strings.TrimSpace(bm[1])
		if strings.HasPrefix(inside, "/") {
			return true
		}
		fields := strings.Fields(inside)
		if len(fields) == 2 && openAPI3Methods[strings.ToLower(fields[0])] && strings.HasPrefix(fields[1], "/") {
			return true
		}
	}
	return false
}

// parseAPIBContent 解析 API Blueprint 原文并返回规范化存储文档与操作清单。
func parseAPIBContent(raw []byte) (string, map[string]any, []SpecOperation, error) {
	ops, title, err := ParseAPIB(string(raw))
	if err != nil {
		return "", nil, nil, err
	}
	return SpecFormatAPIB, wrapRawSpecDoc(SpecFormatAPIB, title, string(raw)), ops, nil
}

// ParseAPIB 解析 API Blueprint 文本为操作清单与标题。
func ParseAPIB(src string) ([]SpecOperation, string, error) {
	lines := strings.Split(strings.ReplaceAll(strings.TrimPrefix(src, "\ufeff"), "\r\n", "\n"), "\n")
	title := ""
	currentResourcePath := ""
	var currentResourceParams []SpecParam

	type activeOp struct {
		method string
		path   string
		params []SpecParam
	}
	var currentOp *activeOp
	ops := []SpecOperation{}

	flushOp := func() {
		if currentOp == nil {
			return
		}
		ops = append(ops, SpecOperation{
			Method: currentOp.method,
			Path:   currentOp.path,
			Key:    currentOp.method + " " + currentOp.path,
			Params: sortAndDedupeSpecParams(currentOp.params),
		})
		currentOp = nil
	}

	section := "" // "", "parameters", "request", "headers", "attributes", "body", "response"
	inRequest := false
	var bodyBuf strings.Builder
	flushBody := func() {
		if bodyBuf.Len() == 0 || currentOp == nil {
			bodyBuf.Reset()
			return
		}
		raw := strings.TrimSpace(bodyBuf.String())
		bodyBuf.Reset()
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err == nil && obj != nil {
			for k, v := range obj {
				currentOp.params = append(currentOp.params, SpecParam{
					Name: k,
					In:   "BODY",
					Type: jsonValueType(v),
				})
			}
		}
	}

	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			if section == "body" && bodyBuf.Len() > 0 {
				bodyBuf.WriteByte('\n')
			}
			continue
		}

		// Markdown 标题：区分文档标题、Group、Resource [/path]、Action [METHOD] 或 [METHOD /path]
		if hm := apibHeadingRe.FindStringSubmatch(trimmed); len(hm) == 3 {
			flushBody()
			level := len(hm[1])
			headingText := strings.TrimSpace(hm[2])
			section = ""
			inRequest = false

			if bm := apibBracketRe.FindStringSubmatch(headingText); len(bm) == 2 {
				inside := strings.TrimSpace(bm[1])
				fields := strings.Fields(inside)
				switch {
				case len(fields) == 2 && openAPI3Methods[strings.ToLower(fields[0])] && strings.HasPrefix(fields[1], "/"):
					// ## Create User [POST /users]
					flushOp()
					normPath, uriParams := parseAPIBURITemplate(fields[1])
					currentOp = &activeOp{
						method: strings.ToUpper(fields[0]),
						path:   normPath,
						params: uriParams,
					}
					continue
				case len(fields) == 1 && openAPI3Methods[strings.ToLower(fields[0])]:
					// ### List Users [GET]（继承当前 Resource 路径与参数）
					flushOp()
					if currentResourcePath != "" {
						currentOp = &activeOp{
							method: strings.ToUpper(fields[0]),
							path:   currentResourcePath,
							params: append([]SpecParam{}, currentResourceParams...),
						}
					}
					continue
				case strings.HasPrefix(inside, "/"):
					// ## Users [/users/{id}{?page}]
					flushOp()
					currentResourcePath, currentResourceParams = parseAPIBURITemplate(inside)
					continue
				}
			}
			if level == 1 && title == "" && !strings.HasPrefix(strings.ToLower(headingText), "group ") {
				title = headingText
			}
			continue
		}

		// 节头：+ Parameters / + Request / + Response / + Headers / + Attributes / + Body
		if strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "*") {
			lower := strings.ToLower(strings.TrimSpace(trimmed[1:]))
			switch {
			case strings.HasPrefix(lower, "parameters"):
				flushBody()
				section = "parameters"
				continue
			case strings.HasPrefix(lower, "request"):
				flushBody()
				inRequest = true
				section = "request"
				continue
			case strings.HasPrefix(lower, "response"):
				flushBody()
				inRequest = false
				section = "response"
				continue
			case strings.HasPrefix(lower, "headers"):
				flushBody()
				if inRequest {
					section = "headers"
				} else {
					section = "response"
				}
				continue
			case strings.HasPrefix(lower, "attributes"):
				flushBody()
				if inRequest || section == "request" {
					section = "attributes"
				}
				continue
			case strings.HasPrefix(lower, "body"):
				flushBody()
				if inRequest {
					section = "body"
				} else {
					section = "response"
				}
				continue
			}
		}

		switch section {
		case "parameters":
			if pm := apibParamItemRe.FindStringSubmatch(rawLine); len(pm) >= 2 {
				pName := pm[1]
				pType, req := parseAPIBMeta(pm[2])
				in := "QUERY"
				if currentOp != nil && strings.Contains(currentOp.path, "{"+pName+"}") {
					in = "PATH"
					req = true
				} else if currentOp == nil && strings.Contains(currentResourcePath, "{"+pName+"}") {
					in = "PATH"
					req = true
				}
				sp := SpecParam{Name: pName, In: in, Type: pType, Required: req}
				if currentOp != nil {
					currentOp.params = append(currentOp.params, sp)
				} else {
					currentResourceParams = append(currentResourceParams, sp)
				}
			}
		case "attributes":
			if currentOp != nil {
				if pm := apibParamItemRe.FindStringSubmatch(rawLine); len(pm) >= 2 {
					pType, req := parseAPIBMeta(pm[2])
					currentOp.params = append(currentOp.params, SpecParam{
						Name:     pm[1],
						In:       "BODY",
						Type:     pType,
						Required: req,
					})
				}
			}
		case "headers":
			if currentOp != nil && (strings.HasPrefix(rawLine, "    ") || strings.HasPrefix(rawLine, "\t")) {
				if idx := strings.IndexByte(trimmed, ':'); idx > 0 {
					hName := strings.TrimSpace(trimmed[:idx])
					if hName != "" && !strings.EqualFold(hName, "content-type") {
						currentOp.params = append(currentOp.params, SpecParam{
							Name: hName,
							In:   "HEADER",
							Type: "string",
						})
					}
				}
			}
		case "request", "body":
			if currentOp != nil && (strings.HasPrefix(rawLine, "    ") || strings.HasPrefix(rawLine, "\t")) {
				section = "body"
				bodyBuf.WriteString(trimmed)
				bodyBuf.WriteByte('\n')
			}
		}
	}
	flushBody()
	flushOp()

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, "", fmt.Errorf("%w: 未找到有效的资源与动作定义（如 ## Resource [/path] / ### Action [GET]）", ErrSpecInvalidAPIB)
	}
	return ops, title, nil
}

func parseAPIBURITemplate(tpl string) (string, []SpecParam) {
	params := []SpecParam{}
	cleaned := apibQueryExprRe.ReplaceAllStringFunc(strings.TrimSpace(tpl), func(match string) string {
		sub := apibQueryExprRe.FindStringSubmatch(match)
		if len(sub) >= 2 {
			for _, part := range strings.Split(sub[1], ",") {
				name := strings.TrimSpace(strings.TrimSuffix(part, "*"))
				if name != "" {
					params = append(params, SpecParam{Name: name, In: "QUERY", Type: "string"})
				}
			}
		}
		return ""
	})
	if cleaned == "" {
		cleaned = "/"
	}
	for _, m := range specPathPlaceholderPattern.FindAllStringSubmatch(cleaned, -1) {
		params = append(params, SpecParam{Name: m[1], In: "PATH", Type: "string", Required: true})
	}
	return cleaned, sortAndDedupeSpecParams(params)
}

func parseAPIBMeta(meta string) (string, bool) {
	pType := "string"
	req := false
	for _, part := range strings.Split(meta, ",") {
		tok := strings.ToLower(strings.TrimSpace(part))
		switch tok {
		case "required":
			req = true
		case "optional":
			req = false
		case "string", "number", "integer", "boolean", "array", "object":
			pType = tok
		}
	}
	return pType, req
}
