package parser

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestParseRequestGraphQLJSONBody(t *testing.T) {
	body := `{"operationName":"CreateUser","query":"mutation CreateUser($name: String!, $age: Int) { createUser(name: $name) { id } }","variables":{"name":"alice","age":30}}`
	r, err := http.NewRequest(http.MethodPost, "http://x/graphql", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 既有 JSON 字段解析行为不变
	if !p.IsJSON || p.JSONFields["query"] != "string" || p.JSONFields["variables"] != "object" {
		t.Fatalf("json fields broken: %v", p.JSONFields)
	}
	if p.GraphQLOperation != "mutation" || p.GraphQLOperationName != "CreateUser" {
		t.Fatalf("operation=%q name=%q", p.GraphQLOperation, p.GraphQLOperationName)
	}
	if !reflect.DeepEqual(p.GraphQLVariables, []string{"age", "name"}) {
		t.Fatalf("variables=%v", p.GraphQLVariables)
	}
	if ctx.Extensions[ExtGraphQLOperation] != "mutation" {
		t.Fatalf("ctx extension missing: %v", ctx.Extensions)
	}
	vars, ok := ctx.Extensions[ExtGraphQLVariables].([]string)
	if !ok || !reflect.DeepEqual(vars, []string{"age", "name"}) {
		t.Fatalf("ctx variables: %v", ctx.Extensions)
	}
}

func TestParseRequestGraphQLRawQuery(t *testing.T) {
	cases := []struct {
		body string
		op   string
		name string
	}{
		{"query GetUser {\n  user(id: 1) { name }\n}", "query", "GetUser"},
		{"{ user { id } }", "query", ""}, // 简写形式（以 "{" 开头不得被 sniff 成 JSON）
		{"subscription OnEvent {\n  evt { id }\n}", "subscription", "OnEvent"},
		{"# comment\nmutation DoIt($x: Int) { do(x: $x) }", "mutation", "DoIt"},
	}
	for _, tc := range cases {
		r, err := http.NewRequest(http.MethodPost, "http://x/graphql", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/graphql")
		p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
		if err != nil {
			t.Fatal(err)
		}
		if p.GraphQLOperation != tc.op || p.GraphQLOperationName != tc.name {
			t.Fatalf("body=%q: op=%q name=%q, want %q/%q", tc.body, p.GraphQLOperation, p.GraphQLOperationName, tc.op, tc.name)
		}
		if p.IsJSON {
			t.Fatalf("graphql document must not be marked JSON: %q", tc.body)
		}
	}
}

func TestParseRequestGraphQLNegative(t *testing.T) {
	// /graphql 路径但 JSON body 无 query 字段：不识别为 GraphQL
	r, err := http.NewRequest(http.MethodPost, "http://x/graphql", strings.NewReader(`{"foo":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p.GraphQLOperation != "" || len(p.GraphQLVariables) != 0 {
		t.Fatalf("must not detect graphql: op=%q vars=%v", p.GraphQLOperation, p.GraphQLVariables)
	}
}

// TestParseRequestGraphQLMalformedFields 一次解析复用后的畸形字段容忍口径：
// variables/operationName 类型不符按缺失处理（query 有效仍识别操作）；query 非字符串不识别。
func TestParseRequestGraphQLMalformedFields(t *testing.T) {
	// variables 非对象：操作仍识别，variables 为空（旧窄结构 Unmarshal 失败会整体跳过，
	// 复用根值后按缺失容忍——OBSERVE 级观测可接受，见 parse_graphql.go 注释）
	r, err := http.NewRequest(http.MethodPost, "http://x/graphql",
		strings.NewReader(`{"query":"mutation DoIt($x: Int) { do(x: $x) }","variables":"oops"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p.GraphQLOperation != "mutation" || p.GraphQLOperationName != "DoIt" || len(p.GraphQLVariables) != 0 {
		t.Fatalf("malformed variables tolerated: op=%q name=%q vars=%v", p.GraphQLOperation, p.GraphQLOperationName, p.GraphQLVariables)
	}
	// query 非字符串：不识别为 GraphQL
	r2, err := http.NewRequest(http.MethodPost, "http://x/graphql", strings.NewReader(`{"query":123}`))
	if err != nil {
		t.Fatal(err)
	}
	r2.Header.Set("Content-Type", "application/json")
	p2, err := ParseRequest(r2, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p2.GraphQLOperation != "" || len(p2.GraphQLVariables) != 0 {
		t.Fatalf("non-string query must not detect graphql: op=%q vars=%v", p2.GraphQLOperation, p2.GraphQLVariables)
	}
}
