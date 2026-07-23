package parser

import (
	"encoding/json"
	"sort"
	"strings"
)

// extractGraphQLQuery 处理 application/graphql：body 即查询文档，识别操作类型与命名操作。
func (p *Parsed) extractGraphQLQuery(query string) {
	p.GraphQLOperation = graphQLOperationType(query)
	p.GraphQLOperationName = graphQLOperationName(query)
}

// extractGraphQLJSON 处理 /graphql 路径上的 JSON 请求体：含 query 字段时提取
// 操作类型、operationName 与 variables 顶层键名（不存变量值；键名排序保证确定性）。
func (p *Parsed) extractGraphQLJSON(raw []byte) {
	if !strings.Contains(strings.ToLower(p.RawPath), "/graphql") {
		return
	}
	var g struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(raw, &g); err != nil || g.Query == "" {
		return
	}
	p.GraphQLOperation = graphQLOperationType(g.Query)
	p.GraphQLOperationName = g.OperationName
	if p.GraphQLOperationName == "" {
		p.GraphQLOperationName = graphQLOperationName(g.Query)
	}
	vars := make([]string, 0, len(g.Variables))
	for k := range g.Variables {
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
