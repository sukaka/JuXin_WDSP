// spec_postman.go 阶段8 §33：Postman Collection v2.1 规范导入解析。
// item 树（支持嵌套文件夹）→ method + path + header/query/path 参数 + body 字段模型。
// 仅支持 v2.1（info.schema 指向 schema.getpostman.com/json/collection/v2.1），
// 其余版本明确报 ErrSpecUnsupportedPostmanVersion（HTTP 层 400）。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ErrSpecUnsupportedPostmanVersion info.schema 缺失或非 Collection v2.1。
var ErrSpecUnsupportedPostmanVersion = errors.New("unsupported postman collection version")

// postmanCollectionV21Schema v2.1 集合的 schema 标识子串。
const postmanCollectionV21Schema = "schema.getpostman.com/json/collection/v2.1"

// ParsePostmanCollection 解析 Postman Collection v2.1 文档为操作清单。
// 返回的 normalized 即源文档（落库 spec_json；重读时按 format=postman 重新解析）。
func ParsePostmanCollection(doc map[string]any) ([]SpecOperation, error) {
	info, _ := doc["info"].(map[string]any)
	schema, _ := info["schema"].(string)
	if !strings.Contains(schema, postmanCollectionV21Schema) {
		return nil, fmt.Errorf("%w: 仅支持 Collection v2.1（info.schema=%q）", ErrSpecUnsupportedPostmanVersion, truncateRefValue(schema))
	}
	items, ok := doc["item"].([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("%w: item 必须为非空数组", ErrSpecNoPaths)
	}
	ops := []SpecOperation{}
	if err := walkPostmanItems(items, &ops); err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: 集合中没有可解析的请求项", ErrSpecNoPaths)
	}
	for i := range ops {
		sort.Slice(ops[i].Params, func(a, b int) bool {
			if ops[i].Params[a].In != ops[i].Params[b].In {
				return ops[i].Params[a].In < ops[i].Params[b].In
			}
			return ops[i].Params[a].Name < ops[i].Params[b].Name
		})
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key < ops[j].Key })
	return ops, nil
}

// walkPostmanItems 递归遍历 item 树：含 item 子数组的节点为文件夹，含 request 的为请求叶子。
func walkPostmanItems(items []any, ops *[]SpecOperation) error {
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if sub, ok := item["item"].([]any); ok {
			if err := walkPostmanItems(sub, ops); err != nil {
				return err
			}
			continue
		}
		reqRaw, ok := item["request"]
		if !ok {
			continue // 无 request 的节点（纯文件夹占位）跳过
		}
		op, err := parsePostmanRequest(reqRaw)
		if err != nil {
			return err
		}
		if op != nil {
			*ops = append(*ops, *op)
		}
	}
	return nil
}

// parsePostmanRequest 解析单个请求项：request 可为 URL 字符串（缺省 GET）或对象。
func parsePostmanRequest(reqRaw any) (*SpecOperation, error) {
	if s, ok := reqRaw.(string); ok {
		path := postmanURLPath(s)
		if path == "" {
			return nil, fmt.Errorf("%w: request URL 无法解析 %q", ErrSpecNoPaths, truncateRefValue(s))
		}
		return &SpecOperation{Method: "GET", Path: path, Key: "GET " + path}, nil
	}
	req, ok := reqRaw.(map[string]any)
	if !ok {
		return nil, nil // 无法识别的 request 形态跳过（文档化宽容）
	}
	method, _ := req["method"].(string)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	if len(method) > 16 {
		return nil, fmt.Errorf("%w: HTTP 方法 %q 超长", ErrSpecNoPaths, truncateRefValue(method))
	}
	path, params := postmanURLParts(req["url"])
	if path == "" {
		return nil, fmt.Errorf("%w: 请求缺少有效 URL", ErrSpecNoPaths)
	}
	params = append(params, postmanHeaderParams(req["header"])...)
	params = append(params, postmanBodyParams(req["body"])...)
	return &SpecOperation{Method: method, Path: path, Key: method + " " + path, Params: params}, nil
}

// postmanURLParts 从 url 字段（字符串或对象）提取路径与 query/path 参数。
// path 段中 Postman 风格的 :param 与 {{var}} 统一归一为 {param}。
func postmanURLParts(raw any) (string, []SpecParam) {
	if s, ok := raw.(string); ok {
		return postmanURLPath(s), nil
	}
	u, ok := raw.(map[string]any)
	if !ok {
		return "", nil
	}
	path := ""
	if segs, ok := u["path"].([]any); ok && len(segs) > 0 {
		parts := make([]string, 0, len(segs))
		for _, segRaw := range segs {
			seg, _ := segRaw.(string)
			parts = append(parts, normalizePostmanSegment(seg))
		}
		path = "/" + strings.Join(parts, "/")
	} else if rawStr, _ := u["raw"].(string); rawStr != "" {
		path = postmanURLPath(rawStr)
	}
	params := []SpecParam{}
	for _, qRaw := range postmanKVList(u["query"]) {
		params = append(params, SpecParam{Name: qRaw, In: "QUERY"})
	}
	for _, vRaw := range postmanKVList(u["variable"]) {
		params = append(params, SpecParam{Name: vRaw, In: "PATH"})
	}
	return path, params
}

// postmanURLPath 从原始 URL 字符串提取路径部分（去掉协议/host/query）。
// Postman 变量 host（{{baseUrl}} 等）同样剥离；解析失败返回空串。
func postmanURLPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// {{var}} host 前缀会导致 url.Parse 失败，先剥到第一个 "/"
	if strings.HasPrefix(raw, "{{") {
		if i := strings.Index(raw, "/"); i >= 0 {
			raw = raw[i:]
		} else {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = u.Opaque // 兜底
	}
	if path == "" {
		path = "/"
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		segs[i] = normalizePostmanSegment(seg)
	}
	return strings.Join(segs, "/")
}

// normalizePostmanSegment 路径段归一：":id" / "{{id}}" → "{id}"。
func normalizePostmanSegment(seg string) string {
	if strings.HasPrefix(seg, ":") && len(seg) > 1 {
		return "{" + seg[1:] + "}"
	}
	if strings.HasPrefix(seg, "{{") && strings.HasSuffix(seg, "}}") && len(seg) > 4 {
		return "{" + seg[2:len(seg)-2] + "}"
	}
	return seg
}

// postmanKVList 提取 Postman key-value 列表（query/variable/header/formdata 等同构）
// 中未禁用项的 key。跳过 disabled=true 与空 key。
func postmanKVList(raw any) []string {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, itemRaw := range list {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue
		}
		if disabled, _ := item["disabled"].(bool); disabled {
			continue
		}
		key, _ := item["key"].(string)
		if key = strings.TrimSpace(key); key != "" {
			out = append(out, key)
		}
	}
	return out
}

// postmanHeaderParams 请求头 → HEADER 参数。
func postmanHeaderParams(raw any) []SpecParam {
	out := []SpecParam{}
	for _, key := range postmanKVList(raw) {
		out = append(out, SpecParam{Name: key, In: "HEADER"})
	}
	return out
}

// postmanBodyParams 请求体 → BODY 参数：
// mode=raw 且内容为 JSON 对象时逐字段提取（类型按 JSON 值推断）；
// urlencoded/formdata 按键提取；graphql 模式取 query 单字段；其余忽略。
func postmanBodyParams(raw any) []SpecParam {
	body, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	mode, _ := body["mode"].(string)
	switch mode {
	case "raw":
		rawStr, _ := body["raw"].(string)
		var obj map[string]any
		if err := json.Unmarshal([]byte(rawStr), &obj); err != nil || obj == nil {
			return nil // 非 JSON 对象（纯文本/XML 等）不展开字段
		}
		out := make([]SpecParam, 0, len(obj))
		for k, v := range obj {
			out = append(out, SpecParam{Name: k, In: "BODY", Type: jsonValueType(v)})
		}
		return out
	case "urlencoded", "formdata":
		out := []SpecParam{}
		for _, key := range postmanKVList(body[mode]) {
			out = append(out, SpecParam{Name: key, In: "BODY"})
		}
		return out
	}
	return nil
}

// jsonValueType JSON 值的类型名（用于 Postman raw body 字段类型标注）。
func jsonValueType(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	}
	return ""
}
