package parser

import (
	"sort"
	"strings"
)

// extractGraphQLQuery 处理 application/graphql：body 即查询文档，识别操作类型与命名操作。
func (p *Parsed) extractGraphQLQuery(query string) {
	p.GraphQLQuery = query
	p.GraphQLOperation = graphQLOperationType(query)
	p.GraphQLOperationName = graphQLOperationName(query)
}

// extractGraphQLJSON 处理 /graphql 路径上的 JSON 请求体：含 query 字段时提取
// 操作类型、operationName 与 variables 顶层键名（不存变量值；键名排序保证确定性）。
// v 为 JSON 一次解析的解码根值（extractJSONFields 产物复用，不再二次 Unmarshal）；
// 字段类型不符按缺失容忍（与窄结构 Unmarshal 失败的整体跳过口径差异：畸形字段不影响
// 其余字段提取，OBSERVE 级观测可接受）。
func (p *Parsed) extractGraphQLJSON(v any) {
	if !strings.Contains(strings.ToLower(p.RawPath), "/graphql") {
		return
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return
	}
	query, _ := obj["query"].(string)
	if query == "" {
		return
	}
	p.GraphQLQuery = query
	p.GraphQLOperation = graphQLOperationType(query)
	p.GraphQLOperationNameSpecified, _ = obj["operationName"].(string)
	p.GraphQLOperationName = p.GraphQLOperationNameSpecified
	if p.GraphQLOperationName == "" {
		p.GraphQLOperationName = graphQLOperationName(query)
	}
	variables, _ := obj["variables"].(map[string]any)
	vars := make([]string, 0, len(variables))
	for k := range variables {
		vars = append(vars, k)
	}
	sort.Strings(vars)
	p.GraphQLVariables = vars
}

// graphQLOperationType 从查询文本前缀判断操作类型：query|mutation|subscription；无法识别为 unknown。
func graphQLOperationType(query string) string {
	s := stripGraphQLComments(query)
	switch {
	case strings.HasPrefix(s, "{"):
		return "query" // 简写形式即 query
	case hasKeywordPrefix(s, "mutation"):
		return "mutation"
	case hasKeywordPrefix(s, "subscription"):
		return "subscription"
	case hasKeywordPrefix(s, "query"):
		return "query"
	default:
		return "unknown"
	}
}

// graphQLOperationName 从查询文本提取命名操作名（如 "query GetUser {" -> "GetUser"；匿名返回空）。
func graphQLOperationName(query string) string {
	s := stripGraphQLComments(query)
	for _, kw := range []string{"query", "mutation", "subscription"} {
		if !hasKeywordPrefix(s, kw) {
			continue
		}
		rest := strings.TrimLeft(s[len(kw):], " \t\r\n")
		if rest == "" || rest[0] == '{' || rest[0] == '(' {
			return ""
		}
		if end := strings.IndexAny(rest, " \t\r\n{("); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	return ""
}

// stripGraphQLComments 去掉前导空白与 # 注释行。
func stripGraphQLComments(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "#") {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			return ""
		}
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

// hasKeywordPrefix 关键字边界匹配（避免 "mutationFoo" 之类误判）。
func hasKeywordPrefix(s, kw string) bool {
	if !strings.HasPrefix(s, kw) {
		return false
	}
	if len(s) == len(kw) {
		return true
	}
	switch s[len(kw)] {
	case ' ', '\t', '\r', '\n', '{', '(':
		return true
	}
	return false
}
