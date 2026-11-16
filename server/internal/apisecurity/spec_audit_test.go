package apisecurity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAuditStoredSpecRulesSortingAndMetadata(t *testing.T) {
	specID := uuid.New()
	spec := &ImportSpec{
		ID:     specID,
		Format: SpecFormatOpenAPI3,
		SpecJSON: json.RawMessage(`{
			"openapi":"3.0.3",
			"info":{"title":"audit","version":"1.0.0"},
			"paths":{
				"/z/{missing}/{optional}":{"get":{"parameters":[
					{"name":"optional","in":"path","required":false,"schema":{"type":"string","example":"path-value-do-not-return"}},
					{"name":"orphan","in":"path","required":true,"schema":{"type":"string"}},
					{"name":"Access-Token","in":"query","schema":{"type":"string","example":"query-value-do-not-return"}}
				],"responses":{"default":{"description":"error"}}}},
				"/a/{id}":{"delete":{"parameters":[
					{"name":"id","in":"path","required":true,"schema":{"type":"integer"}},
					{"name":"api.key","in":"query","schema":{"type":"string"}}
				],"responses":{"200":{"description":"ok"}}}},
				"/z":{"post":{"parameters":[
					{"name":"password","in":"query","schema":{"type":"string"}}
				],"responses":{}}}
			}
		}`),
	}
	result, err := auditStoredSpec(spec)
	if err != nil {
		t.Fatalf("审计已存规范失败: %v", err)
	}
	if result.SpecID != specID || result.Format != SpecFormatOpenAPI3 {
		t.Fatalf("规范元数据不符: %+v", result)
	}
	if result.OperationCount != 3 || result.IssueCount != 9 || result.HighCount != 5 || result.MediumCount != 4 {
		t.Fatalf("审计计数不符: %+v", result)
	}
	if result.Truncated || len(result.Items) != 9 {
		t.Fatalf("不应截断: truncated=%v items=%d", result.Truncated, len(result.Items))
	}
	want := []struct {
		ruleID, severity, endpointKey, paramIn, paramName string
	}{
		{SpecAuditErrorResponseMissing, "MEDIUM", "DELETE /a/{id}", "", ""},
		{SpecAuditSensitiveQueryParameter, "HIGH", "DELETE /a/{id}", "QUERY", "api.key"},
		{SpecAuditPathParameterMissing, "HIGH", "GET /z/{missing}/{optional}", "PATH", "missing"},
		{SpecAuditPathParameterNotRequired, "MEDIUM", "GET /z/{missing}/{optional}", "PATH", "optional"},
		{SpecAuditPathParameterUndeclared, "MEDIUM", "GET /z/{missing}/{optional}", "PATH", "orphan"},
		{SpecAuditSensitiveQueryParameter, "HIGH", "GET /z/{missing}/{optional}", "QUERY", "Access-Token"},
		{SpecAuditSuccessResponseMissing, "HIGH", "GET /z/{missing}/{optional}", "", ""},
		{SpecAuditErrorResponseMissing, "MEDIUM", "POST /z", "", ""},
		{SpecAuditSuccessResponseMissing, "HIGH", "POST /z", "", ""},
	}
	for i, expected := range want {
		item := result.Items[i]
		if item.RuleID != expected.ruleID || item.Severity != expected.severity ||
			item.EndpointKey != expected.endpointKey || item.ParamIn != expected.paramIn ||
			item.ParamName != expected.paramName || item.Message == "" {
			t.Errorf("items[%d] = %+v, want %+v", i, item, expected)
		}
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("序列化审计结果失败: %v", err)
	}
	if strings.Contains(string(encoded), "do-not-return") || strings.Contains(string(encoded), "spec_json") {
		t.Fatalf("审计结果泄露参数值或完整规范: %s", encoded)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("审计结果不是 JSON 对象: %v", err)
	}
	if len(payload) != 8 {
		t.Fatalf("审计响应字段数 = %d, want 8: %v", len(payload), payload)
	}
	for _, raw := range payload["items"].([]any) {
		if item := raw.(map[string]any); len(item) != 6 {
			t.Fatalf("审计 item 字段数 = %d, want 6: %v", len(item), item)
		}
	}
}

func TestAuditStoredSpecSecurityRequirements(t *testing.T) {
	result, err := auditStoredSpec(&ImportSpec{
		ID: uuid.New(), Format: SpecFormatOpenAPI3,
		SpecJSON: json.RawMessage(`{
			"openapi":"3.0.3",
			"security":[{"globalQuery":[]},{"globalMissing":[]}],
			"components":{"securitySchemes":{
				"globalQuery":{"type":"apiKey","in":"query","name":"global_key","x-key-value":"global-key-value-do-not-return"},
				"headerKey":{"type":"apiKey","in":"header","name":"X-API-Key"},
				"unusedQuery":{"type":"apiKey","in":"query","name":"unused_key","x-key-value":"unused-key-value-do-not-return"}
			}},
			"paths":{
				"/inherited":{"get":{"responses":{"200":{},"default":{}}}},
				"/public":{"get":{"security":[],"responses":{"200":{},"default":{}}}},
				"/anonymous":{"get":{"security":[{}],"responses":{"200":{},"default":{}}}},
				"/override":{"get":{"security":[{"headerKey":[]},{"operationMissing":[]}],"responses":{"200":{},"default":{}}}}
			}
		}`),
	})
	if err != nil {
		t.Fatalf("鉴权安全审计解析失败: %v", err)
	}
	if result.OperationCount != 4 || result.IssueCount != 3 || result.HighCount != 3 || result.MediumCount != 0 {
		t.Fatalf("鉴权安全审计计数不符: %+v", result)
	}
	want := []struct {
		ruleID, endpointKey, paramIn, paramName string
	}{
		{SpecAuditAPIKeyInQuery, "GET /inherited", "QUERY", "globalQuery"},
		{SpecAuditSecuritySchemeUndefined, "GET /inherited", "", "globalMissing"},
		{SpecAuditSecuritySchemeUndefined, "GET /override", "", "operationMissing"},
	}
	if len(result.Items) != len(want) {
		t.Fatalf("鉴权安全审计 items = %+v", result.Items)
	}
	for i, expected := range want {
		item := result.Items[i]
		if item.RuleID != expected.ruleID || item.Severity != "HIGH" ||
			item.EndpointKey != expected.endpointKey || item.ParamIn != expected.paramIn ||
			item.ParamName != expected.paramName || item.Message == "" {
			t.Errorf("items[%d] = %+v, want %+v", i, item, expected)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"do-not-return", "global_key", "unused_key", "X-API-Key", "unusedQuery", "spec_json",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("鉴权安全审计返回了不应暴露的内容 %q: %s", forbidden, encoded)
		}
	}
}

func TestAuditStoredSpecOpenAPIPublicAndUndefinedWithoutComponents(t *testing.T) {
	cases := []struct {
		name         string
		global       string
		operation    string
		wantIssues   int
		wantSchemeID string
	}{
		{name: "未配置 security 且缺 components", operation: `{}`},
		{name: "全局公开且缺 components", global: `,"security":[]`, operation: `{}`},
		{name: "操作公开覆盖全局未知方案", global: `,"security":[{"missing":[]}]`, operation: `{"security":[]}`},
		{
			name: "OpenAPI3 缺 components 可判定方案未定义", global: `,"security":[{"missing":[]}]`,
			operation: `{}`, wantIssues: 1, wantSchemeID: "missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"openapi":"3.0.3"%s,"paths":{"/items":{"get":%s}}}`, tc.global, tc.operation)
			// 所有用例补齐响应，隔离鉴权规则计数。
			raw = strings.Replace(raw, `"get":{}`, `"get":{"responses":{"200":{},"default":{}}}`, 1)
			raw = strings.Replace(raw, `"get":{"security":[]}`, `"get":{"security":[],"responses":{"200":{},"default":{}}}`, 1)
			result, err := auditStoredSpec(&ImportSpec{
				ID: uuid.New(), Format: SpecFormatOpenAPI3, SpecJSON: json.RawMessage(raw),
			})
			if err != nil {
				t.Fatalf("审计解析失败: %v; raw=%s", err, raw)
			}
			if result.OperationCount != 1 || result.IssueCount != tc.wantIssues ||
				result.HighCount != tc.wantIssues || result.MediumCount != 0 || len(result.Items) != tc.wantIssues {
				t.Fatalf("公开/未定义方案计数不符: %+v", result)
			}
			if tc.wantIssues == 1 {
				item := result.Items[0]
				if item.RuleID != SpecAuditSecuritySchemeUndefined || item.ParamName != tc.wantSchemeID ||
					item.ParamIn != "" || item.EndpointKey != "GET /items" {
					t.Fatalf("未定义方案发现不符: %+v", item)
				}
			}
		})
	}
}

func TestAuditStoredSpecSwaggerSecuritySemanticsUnknown(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "原始 Swagger 不转换认证目录",
			raw: `{
				"swagger":"2.0",
				"securityDefinitions":{"queryKey":{"type":"apiKey","in":"query","name":"api_key"}},
				"security":[{"queryKey":[]},{"missing":[]}],
				"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"},"default":{"description":"error"}}}}}
			}`,
		},
		{
			name: "落库规范化 Swagger 不把新增 OAS3 字段当作已知目录",
			raw: `{
				"openapi":"3.0.0",
				"security":[{"queryKey":[]},{"missing":[]}],
				"components":{"securitySchemes":{"queryKey":{"type":"apiKey","in":"query","name":"api_key"}}},
				"paths":{"/items":{"get":{"responses":{"200":{},"default":{}}}}}
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := auditStoredSpec(&ImportSpec{
				ID: uuid.New(), Format: SpecFormatSwagger2, SpecJSON: json.RawMessage(tc.raw),
			})
			if err != nil {
				t.Fatalf("Swagger 鉴权目录未知审计失败: %v", err)
			}
			if result.OperationCount != 1 || result.IssueCount != 0 || len(result.Items) != 0 {
				t.Fatalf("Swagger 认证目录未知不得产生鉴权发现: %+v", result)
			}
		})
	}
}

func TestAuditSpecOperationsSecurityIssueSortingAndTruncation(t *testing.T) {
	ops := make([]SpecOperation, 251)
	for i := range ops {
		path := fmt.Sprintf("/security/%03d", i)
		ops[i] = SpecOperation{
			Method: "GET", Path: path, Key: "GET " + path,
			SecuritySemanticsKnown: true,
			SecurityRequirements:   []string{"zMissing", "aQuery", "aQuery"},
			SecuritySchemes: map[string]SpecSecurityScheme{
				"aQuery": {Type: "apiKey", In: "query"},
			},
		}
	}
	result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, ops)
	if result.OperationCount != 251 || result.IssueCount != 502 || result.HighCount != 502 || result.MediumCount != 0 {
		t.Fatalf("鉴权问题截断前完整计数不符: %+v", result)
	}
	if !result.Truncated || len(result.Items) != specAuditMaxItems {
		t.Fatalf("鉴权问题截断结果不符: truncated=%v items=%d", result.Truncated, len(result.Items))
	}
	if result.Items[0].RuleID != SpecAuditAPIKeyInQuery || result.Items[0].ParamName != "aQuery" ||
		result.Items[1].RuleID != SpecAuditSecuritySchemeUndefined || result.Items[1].ParamName != "zMissing" {
		t.Fatalf("鉴权规则排序或重复方案去重不符: %+v", result.Items[:2])
	}
	last := result.Items[len(result.Items)-1]
	if last.RuleID != SpecAuditSecuritySchemeUndefined || last.EndpointKey != "GET /security/249" {
		t.Fatalf("鉴权问题截断边界不符: %+v", last)
	}
	exact := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, ops[:250])
	if exact.Truncated || exact.IssueCount != specAuditMaxItems || len(exact.Items) != specAuditMaxItems {
		t.Fatalf("鉴权问题恰好 500 条不应截断: %+v", exact)
	}
}

func TestAuditStoredSpecResponseDeclarationRules(t *testing.T) {
	cases := []struct {
		name              string
		operation         string
		wantIssueCount    int
		wantHighCount     int
		wantMediumCount   int
		wantResponseRules []string
	}{
		{name: "缺少 responses 时语义未知", operation: `{}`},
		{name: "responses null 时语义未知", operation: `{"responses":null}`},
		{name: "responses 非对象时语义未知", operation: `{"responses":[]}`},
		{
			name: "已解析空响应", operation: `{"responses":{}}`,
			wantIssueCount: 2, wantHighCount: 1, wantMediumCount: 1,
			wantResponseRules: []string{SpecAuditErrorResponseMissing, SpecAuditSuccessResponseMissing},
		},
		{
			name: "default 不属于明确成功响应", operation: `{"responses":{"default":{}}}`,
			wantIssueCount: 1, wantHighCount: 1,
			wantResponseRules: []string{SpecAuditSuccessResponseMissing},
		},
		{
			name: "仅有成功响应缺少错误声明", operation: `{"responses":{"200":{}}}`,
			wantIssueCount: 1, wantMediumCount: 1,
			wantResponseRules: []string{SpecAuditErrorResponseMissing},
		},
		{name: "精确 2xx 与 4xx 完整", operation: `{"responses":{"200":{},"400":{}}}`},
		{name: "空 204 与精确 5xx 完整", operation: `{"responses":{"204":{},"500":{}}}`},
		{name: "空 205 与 default 完整", operation: `{"responses":{"205":{},"default":{}}}`},
		{name: "响应类别通配完整", operation: `{"responses":{"2XX":{},"4XX":{}}}`},
		{name: "小写响应类别通配完整", operation: `{"responses":{"2xx":{},"5xx":{}}}`},
		{
			name: "3xx 与 default 仍缺成功响应", operation: `{"responses":{"302":{},"default":{}}}`,
			wantIssueCount: 1, wantHighCount: 1,
			wantResponseRules: []string{SpecAuditSuccessResponseMissing},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"openapi":"3.0.3","paths":{"/items":{"post":%s}}}`, tc.operation)
			result, err := auditStoredSpec(&ImportSpec{
				ID: uuid.New(), Format: SpecFormatOpenAPI3, SpecJSON: json.RawMessage(raw),
			})
			if err != nil {
				t.Fatalf("响应声明审计解析失败: %v", err)
			}
			if result.OperationCount != 1 || result.IssueCount != tc.wantIssueCount ||
				result.HighCount != tc.wantHighCount || result.MediumCount != tc.wantMediumCount ||
				len(result.Items) != len(tc.wantResponseRules) {
				t.Fatalf("响应声明审计计数不符: %+v", result)
			}
			for i, ruleID := range tc.wantResponseRules {
				item := result.Items[i]
				if item.RuleID != ruleID || item.EndpointKey != "POST /items" ||
					item.ParamIn != "" || item.ParamName != "" {
					t.Errorf("items[%d] = %+v, want rule=%s", i, item, ruleID)
				}
			}
		})
	}
}

func TestAuditStoredSpecSwaggerResponseDeclarations(t *testing.T) {
	result, err := auditStoredSpec(&ImportSpec{
		ID: uuid.New(), Format: SpecFormatSwagger2,
		SpecJSON: json.RawMessage(`{
			"swagger":"2.0",
			"info":{"title":"legacy","version":"1.0.0"},
			"paths":{
				"/swagger-default":{"get":{"responses":{"default":{"description":"error"}}}},
				"/swagger-success":{"post":{"responses":{"201":{"description":"created"}}}},
				"/swagger-complete":{"put":{"responses":{"204":{"description":"empty"},"400":{"description":"bad"}}}},
				"/swagger-unknown":{"delete":{}}
			}
		}`),
	})
	if err != nil {
		t.Fatalf("Swagger 响应声明审计失败: %v", err)
	}
	if result.OperationCount != 4 || result.IssueCount != 2 || result.HighCount != 1 || result.MediumCount != 1 {
		t.Fatalf("Swagger 响应声明计数不符: %+v", result)
	}
	want := []struct{ ruleID, endpointKey string }{
		{SpecAuditSuccessResponseMissing, "GET /swagger-default"},
		{SpecAuditErrorResponseMissing, "POST /swagger-success"},
	}
	for i, expected := range want {
		if result.Items[i].RuleID != expected.ruleID || result.Items[i].EndpointKey != expected.endpointKey {
			t.Errorf("items[%d] = %+v, want %+v", i, result.Items[i], expected)
		}
	}
}

func TestAuditSpecSemanticsUnknownForExtendedFormats(t *testing.T) {
	cases := []struct {
		name, wantFormat, raw string
	}{
		{
			name: "Postman", wantFormat: SpecFormatPostman,
			raw: `{"info":{"name":"Mini","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[{"name":"ping","request":{"method":"GET","url":"https://api.example.com/ping"}}]}`,
		},
		{
			name: "JSON Schema", wantFormat: SpecFormatJSONSchema,
			raw: `{"$schema":"http://json-schema.org/draft-07/schema#","title":"Thing","type":"object","properties":{"name":{"type":"string"}}}`,
		},
		{name: "GraphQL", wantFormat: SpecFormatGraphQL, raw: "type Query {\n  ping: String\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			format, _, ops, err := ParseSpecContent([]byte(tc.raw))
			if err != nil {
				t.Fatalf("扩展格式解析失败: %v", err)
			}
			if format != tc.wantFormat || len(ops) != 1 {
				t.Fatalf("扩展格式操作不符: format=%s ops=%+v", format, ops)
			}
			if ops[0].ResponseSemanticsKnown || len(ops[0].ResponseStatuses) != 0 ||
				ops[0].SecuritySemanticsKnown || len(ops[0].SecurityRequirements) != 0 {
				t.Fatalf("扩展格式不应具备 HTTP 响应或认证目录语义: %+v", ops[0])
			}
			ops[0].SecurityRequirements = []string{"missing"}
			result := AuditSpecOperations(uuid.New(), format, ops)
			if result.IssueCount != 0 {
				t.Fatalf("响应/认证目录语义未知不得产生审计发现: %+v", result)
			}
		})
	}
}

func TestAuditSpecOperationsResponseIssueFullCountsBeforeTruncation(t *testing.T) {
	ops := make([]SpecOperation, 251)
	for i := range ops {
		path := fmt.Sprintf("/resource/%03d", i)
		ops[i] = SpecOperation{
			Method: "GET", Path: path, Key: "GET " + path,
			ResponseSemanticsKnown: true, ResponseStatuses: []string{},
		}
	}
	result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, ops)
	if result.OperationCount != 251 || result.IssueCount != 502 || result.HighCount != 251 || result.MediumCount != 251 {
		t.Fatalf("响应问题截断前完整计数不符: %+v", result)
	}
	if !result.Truncated || len(result.Items) != specAuditMaxItems {
		t.Fatalf("响应问题截断结果不符: truncated=%v items=%d", result.Truncated, len(result.Items))
	}
	if result.Items[0].RuleID != SpecAuditErrorResponseMissing || result.Items[0].EndpointKey != "GET /resource/000" ||
		result.Items[1].RuleID != SpecAuditSuccessResponseMissing || result.Items[1].EndpointKey != "GET /resource/000" {
		t.Fatalf("响应问题排序不符: %+v", result.Items[:2])
	}
	last := result.Items[len(result.Items)-1]
	if last.RuleID != SpecAuditSuccessResponseMissing || last.EndpointKey != "GET /resource/249" {
		t.Fatalf("响应问题截断边界不符: %+v", last)
	}
}

func TestAuditSpecOperationsEmptyItems(t *testing.T) {
	result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, []SpecOperation{{
		Method: "GET", Path: "/health", Key: "GET /health", Params: []SpecParam{},
	}})
	if result.IssueCount != 0 || result.HighCount != 0 || result.MediumCount != 0 || result.Truncated {
		t.Fatalf("空审计结果计数不符: %+v", result)
	}
	if result.Items == nil || len(result.Items) != 0 {
		t.Fatalf("空结果 items 必须为非 nil 空数组: %#v", result.Items)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"items":[]`) {
		t.Fatalf("空结果 items 未编码为 []: %s", encoded)
	}
}

func TestSensitiveQueryParameterNameNormalization(t *testing.T) {
	sensitive := []string{
		"password", "PASSWORD", "passwd", "pwd", "token", "access_token",
		"access-token", "Access.Token", "accessToken", "secret", "api_key",
		"API-KEY", "apikey", " api key ",
	}
	for _, name := range sensitive {
		if !isSensitiveQueryParameterName(name) {
			t.Errorf("敏感参数名未命中: %q", name)
		}
	}
	for _, name := range []string{"password_hint", "tokenizer", "secretary", "api_keys", "authorization", ""} {
		if isSensitiveQueryParameterName(name) {
			t.Errorf("保守精确词表不应命中: %q", name)
		}
	}
}

func TestAuditSensitiveQueryParameterOnlyGetDelete(t *testing.T) {
	for _, method := range []string{"GET", "DELETE"} {
		result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, []SpecOperation{{
			Method: method, Path: "/credentials", Key: method + " /credentials",
			Params: []SpecParam{{Name: "token", In: "QUERY"}},
		}})
		if result.IssueCount != 1 || result.HighCount != 1 {
			t.Errorf("%s 敏感 QUERY 参数应命中: %+v", method, result)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, []SpecOperation{{
			Method: method, Path: "/credentials", Key: method + " /credentials",
			Params: []SpecParam{{Name: "token", In: "QUERY"}},
		}})
		if result.IssueCount != 0 {
			t.Errorf("%s QUERY 参数不在本规则范围内: %+v", method, result)
		}
	}
}

func TestAuditSpecOperationsTruncation(t *testing.T) {
	ops := make([]SpecOperation, 501)
	for i := range ops {
		path := fmt.Sprintf("/resource/{p%03d}", i)
		ops[i] = SpecOperation{Method: "GET", Path: path, Key: "GET " + path}
	}
	result := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, ops)
	if result.OperationCount != 501 || result.IssueCount != 501 || result.HighCount != 501 || result.MediumCount != 0 {
		t.Fatalf("截断前完整计数不符: %+v", result)
	}
	if !result.Truncated || len(result.Items) != specAuditMaxItems {
		t.Fatalf("截断结果不符: truncated=%v items=%d", result.Truncated, len(result.Items))
	}
	if got := result.Items[len(result.Items)-1].ParamName; got != "p499" {
		t.Fatalf("截断边界参数 = %q, want p499", got)
	}

	exact := AuditSpecOperations(uuid.New(), SpecFormatOpenAPI3, ops[:specAuditMaxItems])
	if exact.Truncated || len(exact.Items) != specAuditMaxItems || exact.IssueCount != specAuditMaxItems {
		t.Fatalf("恰好 500 条不应截断: %+v", exact)
	}
}

func TestAuditStoredSpecParseFailures(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"无效 JSON", `{`, ErrSpecInvalidJSON},
		{"缺少 paths", `{"openapi":"3.0.0","paths":{}}`, ErrSpecNoPaths},
		{"外部引用", `{"openapi":"3.0.0","paths":{"/a":{"get":{"parameters":[{"$ref":"https://example.com/p.json"}]}}}}`, ErrSpecExternalRef},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := auditStoredSpec(&ImportSpec{ID: uuid.New(), Format: SpecFormatOpenAPI3, SpecJSON: json.RawMessage(tc.raw)})
			if !errors.Is(err, tc.want) {
				t.Fatalf("错误 = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuditStoredSpecPreservesImportedFormat(t *testing.T) {
	result, err := auditStoredSpec(&ImportSpec{
		ID: uuid.New(), Format: SpecFormatSwagger2,
		SpecJSON: json.RawMessage(`{"openapi":"3.0.0","paths":{"/a/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true}]}}}}`),
	})
	if err != nil {
		t.Fatalf("解析规范化 Swagger 文档失败: %v", err)
	}
	if result.Format != SpecFormatSwagger2 || result.OperationCount != 1 || result.IssueCount != 0 {
		t.Fatalf("规范化 Swagger 审计结果不符: %+v", result)
	}
}
