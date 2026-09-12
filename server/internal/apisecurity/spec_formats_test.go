// spec_formats_test.go 阶段8 §33 规范导入扩展测试：
// 统一入口 ParseSpecContent（JSON/YAML/GraphQL SDL）、YAML 安全解码（自定义标签/炸弹/循环/合并键）、
// JSON Schema / Postman v2.1 / GraphQL SDL 正反对照、外部 $ref 拒绝、大小/深度限制。
package apisecurity

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- 统一入口与格式识别 ----------

func TestParseSpecContentOpenAPI3YAML(t *testing.T) {
	yamlDoc := `
openapi: 3.0.1
info:
  title: Demo API
paths:
  /users:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
`
	format, _, ops, err := ParseSpecContent([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("YAML OpenAPI3 应解析成功: %v", err)
	}
	if format != SpecFormatOpenAPI3 {
		t.Fatalf("format = %q, 期望 openapi3", format)
	}
	if len(ops) != 2 || ops[0].Key != "GET /users" || ops[1].Key != "POST /users" {
		t.Fatalf("ops 不符合预期: %+v", ops)
	}
	if len(ops[0].Params) != 1 || ops[0].Params[0].Name != "limit" || ops[0].Params[0].Type != "integer" {
		t.Fatalf("YAML 标量类型应保留（integer）: %+v", ops[0].Params)
	}
	if len(ops[1].Params) != 1 || ops[1].Params[0].In != "BODY" || ops[1].Params[0].Name != "name" {
		t.Fatalf("requestBody 字段提取失败: %+v", ops[1].Params)
	}
}

func TestParseSpecContentSwagger2YAML(t *testing.T) {
	yamlDoc := `
swagger: "2.0"
host: api.example.com
basePath: /v1
paths:
  /items/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          type: string
`
	format, normalized, ops, err := ParseSpecContent([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("YAML Swagger2 应解析成功: %v", err)
	}
	if format != SpecFormatSwagger2 {
		t.Fatalf("format = %q, 期望 swagger2", format)
	}
	if v, _ := normalized["openapi"].(string); !strings.HasPrefix(v, "3.") {
		t.Fatalf("normalized 应为 OAS3: %v", normalized["openapi"])
	}
	if len(ops) != 1 || ops[0].Key != "GET /items/{id}" {
		t.Fatalf("ops 不符合预期: %+v", ops)
	}
}

func TestParseSpecContentYAMLMergeKey(t *testing.T) {
	yamlDoc := `
openapi: 3.0.0
paths:
  /a:
    get:
      parameters:
        - &base
          name: q
          in: query
          schema:
            type: string
  /b:
    get:
      parameters:
        - <<: *base
          name: page
`
	_, _, ops, err := ParseSpecContent([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("合并键 YAML 应解析成功: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("ops 数量错误: %+v", ops)
	}
	// /b 的 page 参数应继承 base 的 in/schema
	b := ops[0]
	if b.Key == "GET /a" {
		b = ops[1]
	}
	if len(b.Params) != 1 || b.Params[0].Name != "page" || b.Params[0].In != "QUERY" || b.Params[0].Type != "string" {
		t.Fatalf("合并键继承失败: %+v", b.Params)
	}
}

func TestParseSpecContentRejectBadYAML(t *testing.T) {
	cases := map[string]struct {
		doc string
		err error
	}{
		"自定义标签":    {"openapi: 3.0.0\npaths: !ruby/object {}\n", ErrSpecInvalidYAML},
		"binary标签": {"openapi: 3.0.0\npayload: !!binary aGVsbG8=\n", ErrSpecInvalidYAML},
		"别名循环":     {"a: &x\n  b: *x\n", ErrSpecInvalidYAML},
		"多文档":      {"openapi: 3.0.0\n---\nopenapi: 3.0.0\n", ErrSpecInvalidYAML},
		"非字符串键":    {"1: a\n", ErrSpecInvalidYAML},
		"语法错误":     {"openapi: 3.0.0\npaths:\n - [unclosed\n", ErrSpecInvalidYAML},
		"顶层标量非SDL": {"just some text\n", ErrSpecUnsupportedFormat},
	}
	for name, tc := range cases {
		if _, _, _, err := ParseSpecContent([]byte(tc.doc)); !errors.Is(err, tc.err) {
			t.Errorf("%s: 期望 %v，实际 %v", name, tc.err, err)
		}
	}
}

func TestParseSpecContentYAMLAliasBomb(t *testing.T) {
	// 指数级别名展开（billion laughs）：预算限制必须拦截
	var sb strings.Builder
	sb.WriteString("a0: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
	for i := 1; i <= 8; i++ {
		prev := "a" + string(rune('0'+i-1))
		cur := "a" + string(rune('0'+i))
		sb.WriteString(cur + ": &" + cur + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("*" + prev)
		}
		sb.WriteString("]\n")
	}
	_, _, _, err := ParseSpecContent([]byte(sb.String()))
	if !errors.Is(err, ErrSpecTooComplex) {
		t.Fatalf("别名炸弹应报 ErrSpecTooComplex，实际 %v", err)
	}
}

func TestParseSpecContentRejectExternalRef(t *testing.T) {
	cases := map[string]string{
		"http引用": `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"https://evil.example.com/x.json#/P"}]}}}}`,
		"文件引用":   `{"openapi":"3.0.0","paths":{"/a":{"get":{"responses":{"200":{"$ref":"./common.yaml"}}}}}}`,
		"协议相对引用": `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"//evil.example.com/x"}]}}}}`,
	}
	for name, doc := range cases {
		if _, _, _, err := ParseSpecContent([]byte(doc)); !errors.Is(err, ErrSpecExternalRef) {
			t.Errorf("%s: 期望 ErrSpecExternalRef，实际 %v", name, err)
		}
	}
	// 文档内引用允许（$ref 参数跳过为既有行为，不报错）
	internal := `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#/components/parameters/X"}]}}}}`
	if _, _, ops, err := ParseSpecContent([]byte(internal)); err != nil || len(ops) != 1 {
		t.Errorf("内部 $ref 应允许: ops=%+v err=%v", ops, err)
	}
}

func TestParseSpecContentLimits(t *testing.T) {
	// 超大文档
	big := append([]byte(`{"openapi":"3.0.0","paths":{"/a":{"get":{}}},"padding":"`), bytes.Repeat([]byte("x"), specImportMaxBytes)...)
	big = append(big, []byte(`"}`)...)
	if _, _, _, err := ParseSpecContent(big); !errors.Is(err, ErrSpecTooLarge) {
		t.Errorf("超大文档: 期望 ErrSpecTooLarge，实际 %v", err)
	}
	// 超深 JSON 嵌套
	deep := []byte(strings.Repeat("[", specJSONMaxDepth+10) + strings.Repeat("]", specJSONMaxDepth+10))
	if _, _, _, err := ParseSpecContent(deep); !errors.Is(err, ErrSpecTooComplex) {
		t.Errorf("超深嵌套: 期望 ErrSpecTooComplex，实际 %v", err)
	}
	// 深度限制不误伤字符串中的括号
	inStr := `{"openapi":"3.0.0","paths":{"/a":{"get":{"summary":"` + strings.Repeat("{[", specJSONMaxDepth+10) + `"}}}}`
	if _, _, _, err := ParseSpecContent([]byte(inStr)); err != nil {
		t.Errorf("字符串中的括号不应触发深度限制: %v", err)
	}
	// 空文档
	if _, _, _, err := ParseSpecContent([]byte("  \n ")); !errors.Is(err, ErrSpecUnsupportedFormat) {
		t.Errorf("空文档: 期望 ErrSpecUnsupportedFormat，实际 %v", err)
	}
	// 无法识别的 JSON 对象
	if _, _, _, err := ParseSpecContent([]byte(`{"foo":"bar"}`)); !errors.Is(err, ErrSpecUnsupportedFormat) {
		t.Errorf("未知格式: 期望 ErrSpecUnsupportedFormat，实际 %v", err)
	}
	// 畸形 JSON
	if _, _, _, err := ParseSpecContent([]byte(`{"openapi":`)); !errors.Is(err, ErrSpecInvalidJSON) {
		t.Errorf("畸形 JSON: 期望 ErrSpecInvalidJSON，实际 %v", err)
	}
}

// ---------- JSON Schema ----------

func TestParseSpecContentJSONSchemaDraft07(t *testing.T) {
	doc := `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "title": "User",
	  "type": "object",
	  "properties": {
	    "id": {"type": "integer"},
	    "name": {"type": "string"}
	  },
	  "required": ["id"],
	  "definitions": {
	    "Order": {"type": "object", "properties": {"total": {"type": "number"}}},
	    "Ignored": {"type": "string"}
	  }
	}`
	format, _, ops, err := ParseSpecContent([]byte(doc))
	if err != nil {
		t.Fatalf("draft-07 应解析成功: %v", err)
	}
	if format != SpecFormatJSONSchema {
		t.Fatalf("format = %q, 期望 jsonschema", format)
	}
	if len(ops) != 2 {
		t.Fatalf("ops 数量错误（Ignored 非 object 应跳过）: %+v", ops)
	}
	if ops[0].Key != "SCHEMA /_schema/Order" || ops[1].Key != "SCHEMA /_schema/User" {
		t.Fatalf("合成端点不符合预期: %+v", ops)
	}
	user := ops[1]
	if len(user.Params) != 2 || user.Params[0].Name != "id" || !user.Params[0].Required ||
		user.Params[0].Type != "integer" || user.Params[1].Name != "name" || user.Params[1].Required {
		t.Fatalf("字段模型不符合预期: %+v", user.Params)
	}
}

func TestParseSpecContentJSONSchema202012YAML(t *testing.T) {
	doc := `
$schema: "https://json-schema.org/draft/2020-12/schema"
title: Product
type: object
properties:
  sku:
    type: string
  price:
    type: number
required:
  - sku
$defs:
  Category:
    type: object
    properties:
      label:
        type: string
`
	format, _, ops, err := ParseSpecContent([]byte(doc))
	if err != nil {
		t.Fatalf("2020-12 YAML 应解析成功: %v", err)
	}
	if format != SpecFormatJSONSchema {
		t.Fatalf("format = %q", format)
	}
	if len(ops) != 2 || ops[0].Key != "SCHEMA /_schema/Category" || ops[1].Key != "SCHEMA /_schema/Product" {
		t.Fatalf("ops 不符合预期: %+v", ops)
	}
}

func TestParseSpecContentJSONSchemaReject(t *testing.T) {
	cases := map[string]struct {
		doc string
		err error
	}{
		"draft-04不支持":  {`{"$schema":"http://json-schema.org/draft-04/schema#","type":"object","properties":{"a":{"type":"string"}}}`, ErrSpecUnsupportedJSONSchemaDraft},
		"缺少properties": {`{"$schema":"http://json-schema.org/draft-07/schema#","type":"string"}`, ErrSpecInvalidJSONSchema},
		"外部ref":        {`{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"a":{"$ref":"https://x.example.com/s.json"}}}`, ErrSpecExternalRef},
	}
	for name, tc := range cases {
		if _, _, _, err := ParseSpecContent([]byte(tc.doc)); !errors.Is(err, tc.err) {
			t.Errorf("%s: 期望 %v，实际 %v", name, tc.err, err)
		}
	}
}

// ---------- Postman Collection ----------

const postmanV21Sample = `{
  "info": {
    "_postman_id": "abc-123",
    "name": "Shop API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Users",
      "item": [
        {
          "name": "List users",
          "request": {
            "method": "GET",
            "url": {
              "raw": "{{baseUrl}}/api/users?limit=10",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users"],
              "query": [
                {"key": "limit", "value": "10"},
                {"key": "debug", "disabled": true}
              ]
            },
            "header": [{"key": "X-Token", "value": "x"}]
          }
        },
        {
          "name": "Get user",
          "request": {
            "method": "GET",
            "url": {
              "raw": "{{baseUrl}}/api/users/:id",
              "host": ["{{baseUrl}}"],
              "path": ["api", "users", ":id"],
              "variable": [{"key": "id"}]
            }
          }
        }
      ]
    },
    {
      "name": "Create user",
      "request": {
        "method": "POST",
        "url": "https://api.example.com/api/users",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "body": {"mode": "raw", "raw": "{\"name\":\"x\",\"age\":1}"}
      }
    },
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "url": "https://api.example.com/login",
        "body": {"mode": "formdata", "formdata": [{"key": "user"}, {"key": "pass"}, {"key": "otp", "disabled": true}]}
      }
    }
  ]
}`

func TestParseSpecContentPostmanV21(t *testing.T) {
	format, _, ops, err := ParseSpecContent([]byte(postmanV21Sample))
	if err != nil {
		t.Fatalf("Postman v2.1 应解析成功: %v", err)
	}
	if format != SpecFormatPostman {
		t.Fatalf("format = %q, 期望 postman", format)
	}
	if len(ops) != 4 {
		t.Fatalf("ops 数量错误: %+v", ops)
	}
	byKey := map[string]SpecOperation{}
	for _, op := range ops {
		byKey[op.Key] = op
	}
	list := byKey["GET /api/users"]
	if len(list.Params) != 2 || list.Params[0].In != "HEADER" || list.Params[0].Name != "X-Token" ||
		list.Params[1].In != "QUERY" || list.Params[1].Name != "limit" {
		t.Fatalf("GET /api/users 参数错误（disabled 应跳过）: %+v", list.Params)
	}
	get := byKey["GET /api/users/{id}"]
	if len(get.Params) != 1 || get.Params[0].In != "PATH" || get.Params[0].Name != "id" {
		t.Fatalf("GET /api/users/{id} 路径参数错误: %+v", get.Params)
	}
	create := byKey["POST /api/users"]
	if len(create.Params) != 3 {
		t.Fatalf("POST /api/users 参数数量错误: %+v", create.Params)
	}
	body := map[string]string{}
	for _, p := range create.Params {
		if p.In == "BODY" {
			body[p.Name] = p.Type
		}
	}
	if body["name"] != "string" || body["age"] != "number" {
		t.Fatalf("raw JSON body 字段提取错误: %+v", create.Params)
	}
	login := byKey["POST /login"]
	if len(login.Params) != 2 || login.Params[0].Name != "pass" || login.Params[1].Name != "user" {
		t.Fatalf("formdata 字段提取错误（otp disabled 应跳过）: %+v", login.Params)
	}
}

func TestParseSpecContentPostmanYAML(t *testing.T) {
	doc := `
info:
  name: Mini
  schema: https://schema.getpostman.com/json/collection/v2.1.0/collection.json
item:
  - name: ping
    request:
      method: GET
      url: https://api.example.com/ping
`
	format, _, ops, err := ParseSpecContent([]byte(doc))
	if err != nil {
		t.Fatalf("Postman YAML 应解析成功: %v", err)
	}
	if format != SpecFormatPostman || len(ops) != 1 || ops[0].Key != "GET /ping" {
		t.Fatalf("ops 不符合预期: format=%q ops=%+v", format, ops)
	}
}

func TestParseSpecContentPostmanReject(t *testing.T) {
	v20 := `{"info":{"name":"Old","schema":"https://schema.getpostman.com/json/collection/v2.0.0/collection.json"},"item":[{"name":"a","request":"https://x.example.com/a"}]}`
	if _, _, _, err := ParseSpecContent([]byte(v20)); !errors.Is(err, ErrSpecUnsupportedPostmanVersion) {
		t.Errorf("v2.0: 期望 ErrSpecUnsupportedPostmanVersion，实际 %v", err)
	}
	noSchema := `{"info":{"name":"NoSchema"},"item":[{"name":"a","request":"https://x.example.com/a"}]}`
	if _, _, _, err := ParseSpecContent([]byte(noSchema)); !errors.Is(err, ErrSpecUnsupportedPostmanVersion) {
		t.Errorf("缺 schema: 期望 ErrSpecUnsupportedPostmanVersion，实际 %v", err)
	}
	emptyItem := `{"info":{"name":"E","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[]}`
	if _, _, _, err := ParseSpecContent([]byte(emptyItem)); !errors.Is(err, ErrSpecNoPaths) {
		t.Errorf("空 item: 期望 ErrSpecNoPaths，实际 %v", err)
	}
}

// ---------- GraphQL SDL ----------

const graphQLSample = `
"""根查询"""
type Query {
  # 用户列表
  users(first: Int = 10, filter: UserFilter): [User!]!
  user(id: ID!): User @deprecated(reason: "use users")
}

type Mutation {
  createUser(input: CreateUserInput!): User!
}

extend type Query {
  health: String
}

input UserFilter {
  name: String
}
`

func TestParseSpecContentGraphQL(t *testing.T) {
	format, normalized, ops, err := ParseSpecContent([]byte(graphQLSample))
	if err != nil {
		t.Fatalf("GraphQL SDL 应解析成功: %v", err)
	}
	if format != SpecFormatGraphQL {
		t.Fatalf("format = %q, 期望 graphql", format)
	}
	if sdl, _ := normalized["sdl"].(string); sdl == "" {
		t.Fatalf("normalized 应携带 sdl 包装: %v", normalized)
	}
	if len(ops) != 4 {
		t.Fatalf("ops 数量错误: %+v", ops)
	}
	byKey := map[string]SpecOperation{}
	for _, op := range ops {
		byKey[op.Key] = op
	}
	user := byKey["QUERY /graphql/user"]
	if len(user.Params) != 1 || user.Params[0].Name != "id" || user.Params[0].In != "ARG" ||
		user.Params[0].Type != "ID" || !user.Params[0].Required {
		t.Fatalf("user 字段参数错误: %+v", user.Params)
	}
	users := byKey["QUERY /graphql/users"]
	if len(users.Params) != 2 || users.Params[0].Name != "filter" || users.Params[0].Type != "UserFilter" ||
		users.Params[0].Required || users.Params[1].Name != "first" || users.Params[1].Required {
		t.Fatalf("users 字段参数错误: %+v", users.Params)
	}
	create := byKey["MUTATION /graphql/createUser"]
	if len(create.Params) != 1 || !create.Params[0].Required || create.Params[0].Type != "CreateUserInput" {
		t.Fatalf("createUser 参数错误: %+v", create.Params)
	}
	if _, ok := byKey["QUERY /graphql/health"]; !ok {
		t.Fatalf("extend type Query 字段应解析: %+v", ops)
	}
}

func TestParseSpecContentGraphQLCustomRoot(t *testing.T) {
	sdl := `
schema {
  query: RootQ
  mutation: RootM
}
type RootQ { ping: String }
type RootM { noop: Boolean }
`
	_, _, ops, err := ParseSpecContent([]byte(sdl))
	if err != nil {
		t.Fatalf("自定义根类型应解析成功: %v", err)
	}
	if len(ops) != 2 || ops[0].Key != "MUTATION /graphql/noop" || ops[1].Key != "QUERY /graphql/ping" {
		t.Fatalf("ops 不符合预期: %+v", ops)
	}
}

func TestParseSpecContentGraphQLReject(t *testing.T) {
	// SDL 形态但无 Query/Mutation
	if _, _, _, err := ParseSpecContent([]byte("schema {\n  query:\n}")); !errors.Is(err, ErrSpecInvalidGraphQL) {
		t.Errorf("无字段 SDL: 期望 ErrSpecInvalidGraphQL，实际 %v", err)
	}
	if _, _, _, err := ParseSpecContent([]byte("type Query {\n  users: [User]\n")); !errors.Is(err, ErrSpecInvalidGraphQL) {
		t.Errorf("未闭合 SDL: 期望 ErrSpecInvalidGraphQL，实际 %v", err)
	}
}

// ---------- 包装形式与存储重解析 ----------

func TestDecodeSpecImportWrapper(t *testing.T) {
	// 对象包装
	wrap := `{"spec": {"openapi":"3.0.0","paths":{"/a":{"get":{}}}}, "file_name": "a.json", "name": "wrapped"}`
	r := httptest.NewRequest("POST", "/x", nil)
	w := httptest.NewRecorder()
	format, _, ops, fileName, reqName, ok := decodeSpecImport(w, r, []byte(wrap))
	if !ok || format != SpecFormatOpenAPI3 || len(ops) != 1 || fileName != "a.json" || reqName != "wrapped" {
		t.Fatalf("对象包装解析失败: ok=%v format=%q ops=%+v file=%q name=%q", ok, format, ops, fileName, reqName)
	}
	// 字符串包装（内嵌 YAML）
	wrapStr := `{"spec": "openapi: 3.0.0\npaths:\n  /b:\n    get: {}\n", "name": "yaml-wrap"}`
	w2 := httptest.NewRecorder()
	format, _, ops, _, reqName, ok = decodeSpecImport(w2, r, []byte(wrapStr))
	if !ok || format != SpecFormatOpenAPI3 || len(ops) != 1 || ops[0].Key != "GET /b" || reqName != "yaml-wrap" {
		t.Fatalf("字符串包装解析失败: ok=%v format=%q ops=%+v name=%q", ok, format, ops, reqName)
	}
	// spec 非对象非字符串 → 400
	bad := `{"spec": 42}`
	w3 := httptest.NewRecorder()
	if _, _, _, _, _, ok := decodeSpecImport(w3, r, []byte(bad)); ok || w3.Code != 400 {
		t.Fatalf("非法 spec 字段应 400: ok=%v code=%d", ok, w3.Code)
	}
}

func TestParseStoredSpecOperationsExtendedFormats(t *testing.T) {
	// postman：落库源文档可重解析（跨版本 diff 依赖）
	postmanSpec := &ImportSpec{Format: SpecFormatPostman, SpecJSON: []byte(postmanV21Sample)}
	ops, err := parseStoredSpecOperations(postmanSpec)
	if err != nil || len(ops) != 4 {
		t.Fatalf("postman 重解析失败: ops=%+v err=%v", ops, err)
	}
	// graphql：从 sdl 包装重解析
	format, normalized, gqlOps, err := ParseSpecContent([]byte(graphQLSample))
	if err != nil || format != SpecFormatGraphQL {
		t.Fatalf("graphql 解析失败: %v", err)
	}
	sdl, _ := normalized["sdl"].(string)
	gqlSpec := &ImportSpec{Format: SpecFormatGraphQL, SpecJSON: []byte(`{"x-wdsp-spec-format":"graphql","sdl":` + mustJSONString(t, sdl) + `}`)}
	reOps, err := parseStoredSpecOperations(gqlSpec)
	if err != nil || len(reOps) != len(gqlOps) {
		t.Fatalf("graphql 重解析失败: ops=%+v err=%v", reOps, err)
	}
	// jsonschema：源文档重解析
	jsDoc := `{"$schema":"http://json-schema.org/draft-07/schema#","title":"T","type":"object","properties":{"a":{"type":"string"}}}`
	jsSpec := &ImportSpec{Format: SpecFormatJSONSchema, SpecJSON: []byte(jsDoc)}
	if ops, err := parseStoredSpecOperations(jsSpec); err != nil || len(ops) != 1 {
		t.Fatalf("jsonschema 重解析失败: ops=%+v err=%v", ops, err)
	}
	// 跨格式 diff 不崩溃：postman 旧版 vs 新版少一个端点
	changedOps, err := parseStoredSpecOperations(&ImportSpec{Format: SpecFormatPostman, SpecJSON: []byte(postmanV21Sample)})
	if err != nil {
		t.Fatal(err)
	}
	changes := DiffSpecOperations(changedOps[:3], changedOps)
	found := false
	for _, c := range changes {
		if c.ChangeType == ChangeEndpointAdded {
			found = true
		}
	}
	if !found {
		t.Fatalf("跨版本 diff 应检出新增端点: %+v", changes)
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b := strings.Builder{}
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
