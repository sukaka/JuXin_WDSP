// spec_version_test.go W3-C 规范中心增强单元测试（不依赖数据库）：
// 解析矩阵（OAS3 参数 / Swagger 2.0 转换 / 坏文档）、CHANGED 级跨版本对比、
// SSRF 拦截矩阵、规范名解析。YAML 未支持（go.mod 无 yaml.v3），HTTP 层 400 拒绝。
package apisecurity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// opByKey 操作列表按键索引（断言辅助）。
func opByKey(ops []SpecOperation) map[string]SpecOperation {
	out := make(map[string]SpecOperation, len(ops))
	for _, op := range ops {
		out[op.Key] = op
	}
	return out
}

// paramOf 取操作指定 (in, name) 参数。
func paramOf(t *testing.T, op SpecOperation, in, name string) SpecParam {
	t.Helper()
	for _, p := range op.Params {
		if p.In == in && p.Name == name {
			return p
		}
	}
	t.Fatalf("参数不存在: %s %s %s", op.Key, in, name)
	return SpecParam{}
}

// ---------- 解析矩阵 ----------

func TestParseSpecOperationsOAS3(t *testing.T) {
	doc := mustDoc(t, `{
		"openapi": "3.0.3",
		"info": {"title": "demo"},
		"paths": {
			"/pets/{id}": {
				"parameters": [
					{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
					{"name": "trace", "in": "header", "schema": {"type": "string"}}
				],
				"get": {
					"parameters": [
						{"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
						{"name": "trace", "in": "header", "required": true, "schema": {"type": "integer"}}
					]
				},
				"put": {
					"requestBody": {"content": {"application/json": {"schema": {
						"type": "object",
						"properties": {"name": {"type": "string"}, "tag": {"type": "string"}},
						"required": ["name"]
					}}}}
				}
			}
		}
	}`)
	ops, err := ParseSpecOperations(doc)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("操作数不符: got=%d", len(ops))
	}
	byKey := opByKey(ops)
	get := byKey["GET /pets/{id}"]
	// 路径级 path 参数继承；操作级同 (in,name) 覆盖路径级（trace 由 string→integer 且 required）
	if got := paramOf(t, get, "PATH", "id"); got.Type != "integer" || !got.Required {
		t.Fatalf("路径级参数继承失败: %+v", got)
	}
	if got := paramOf(t, get, "HEADER", "trace"); got.Type != "integer" || !got.Required {
		t.Fatalf("操作级覆盖路径级失败: %+v", got)
	}
	if got := paramOf(t, get, "QUERY", "verbose"); got.Type != "boolean" || got.Required {
		t.Fatalf("query 参数解析失败: %+v", got)
	}
	put := byKey["PUT /pets/{id}"]
	if got := paramOf(t, put, "BODY", "name"); got.Type != "string" || !got.Required {
		t.Fatalf("requestBody required 解析失败: %+v", got)
	}
	if got := paramOf(t, put, "BODY", "tag"); got.Type != "string" || got.Required {
		t.Fatalf("requestBody 可选属性解析失败: %+v", got)
	}
	// 参数排序确定（In, Name）
	for _, op := range ops {
		for i := 1; i < len(op.Params); i++ {
			a, b := op.Params[i-1], op.Params[i]
			if a.In > b.In || (a.In == b.In && a.Name >= b.Name) {
				t.Fatalf("参数未按 (In,Name) 排序: %+v", op.Params)
			}
		}
	}
}

func TestParseSpecOperationsRefAndBadItems(t *testing.T) {
	doc := mustDoc(t, `{
		"openapi": "3.0.0",
		"paths": {"/a": {"get": {"parameters": [
			{"$ref": "#/components/parameters/X"},
			"bad",
			{"name": "q", "in": "query", "schema": {"$ref": "#/definitions/T"}}
		]}}}
	}`)
	ops, err := ParseSpecOperations(doc)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("操作数不符: %d", len(ops))
	}
	// $ref 参数跳过；schema.$ref 类型标记为 "$ref"
	if len(ops[0].Params) != 1 {
		t.Fatalf("$ref 参数应跳过: %+v", ops[0].Params)
	}
	if ops[0].Params[0].Type != "$ref" {
		t.Fatalf("schema.$ref 类型标记失败: %+v", ops[0].Params[0])
	}
}

func TestConvertSwagger2Basic(t *testing.T) {
	doc := mustDoc(t, `{
		"swagger": "2.0",
		"info": {"title": "legacy", "version": "1.0"},
		"host": "api.example.com",
		"basePath": "/v1",
		"schemes": ["https"],
		"paths": {
			"/users/{id}": {
				"get": {
					"operationId": "getUser",
					"parameters": [
						{"name": "id", "in": "path", "required": true, "type": "integer", "format": "int64"},
						{"name": "detail", "in": "query", "type": "boolean"}
					],
					"responses": {"200": {"description": "ok", "schema": {"type": "object"}}}
				}
			}
		}
	}`)
	format, normalized, ops, err := ParseSpecDocument(doc)
	if err != nil {
		t.Fatalf("转换解析失败: %v", err)
	}
	if format != SpecFormatSwagger2 {
		t.Fatalf("格式识别失败: %s", format)
	}
	if normalized["openapi"] != "3.0.0" {
		t.Fatalf("openapi 版本映射失败: %v", normalized["openapi"])
	}
	// host/basePath/schemes → servers
	servers, ok := normalized["servers"].([]any)
	if !ok || len(servers) != 1 {
		t.Fatalf("servers 映射失败: %v", normalized["servers"])
	}
	if u, _ := servers[0].(map[string]any)["url"].(string); u != "https://api.example.com/v1" {
		t.Fatalf("server url 不符: %s", u)
	}
	// 端点与参数（扁平 type 收拢 schema）
	if len(ops) != 1 || ops[0].Key != "GET /users/{id}" {
		t.Fatalf("端点映射失败: %+v", ops)
	}
	if got := paramOf(t, ops[0], "PATH", "id"); got.Type != "integer" || !got.Required {
		t.Fatalf("path 参数转换失败: %+v", got)
	}
	if got := paramOf(t, ops[0], "QUERY", "detail"); got.Type != "boolean" || got.Required {
		t.Fatalf("query 参数转换失败: %+v", got)
	}
}

func TestConvertSwagger2BodyAndFormData(t *testing.T) {
	doc := mustDoc(t, `{
		"swagger": "2.0",
		"paths": {
			"/users": {
				"post": {"parameters": [
					{"name": "payload", "in": "body", "required": true, "schema": {
						"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]
					}}
				]},
				"put": {"parameters": [
					{"name": "avatar", "in": "formData", "type": "file", "required": true},
					{"name": "nick", "in": "formData", "type": "string"}
				]}
			}
		}
	}`)
	_, _, ops, err := ParseSpecDocument(doc)
	if err != nil {
		t.Fatalf("转换解析失败: %v", err)
	}
	byKey := opByKey(ops)
	// body 参数 → requestBody object 一级属性
	post := byKey["POST /users"]
	if got := paramOf(t, post, "BODY", "name"); got.Type != "string" || !got.Required {
		t.Fatalf("body 参数转换失败: %+v", got)
	}
	// formData → 表单对象属性；type:file → string
	put := byKey["PUT /users"]
	if got := paramOf(t, put, "BODY", "avatar"); got.Type != "string" || !got.Required {
		t.Fatalf("formData file 转换失败: %+v", got)
	}
	if got := paramOf(t, put, "BODY", "nick"); got.Type != "string" || got.Required {
		t.Fatalf("formData 可选字段转换失败: %+v", got)
	}
}

func TestParseSpecDocumentRejectBadDocs(t *testing.T) {
	cases := map[string]string{
		"缺少版本声明":       `{"paths": {"/a": {"get": {}}}}`,
		"openapi 2.x":  `{"openapi": "2.0", "paths": {"/a": {"get": {}}}}`,
		"swagger 1.x":  `{"swagger": "1.2", "paths": {"/a": {"get": {}}}}`,
		"openapi 非字符串": `{"openapi": 3, "paths": {"/a": {"get": {}}}}`,
	}
	for name, raw := range cases {
		if _, _, _, err := ParseSpecDocument(mustDoc(t, raw)); !errors.Is(err, ErrSpecNotOpenAPI3) {
			t.Errorf("%s: 期望 ErrSpecNotOpenAPI3，实际 %v", name, err)
		}
	}
	// 版本合法但 paths 缺失
	if _, _, _, err := ParseSpecDocument(mustDoc(t, `{"openapi": "3.0.0"}`)); !errors.Is(err, ErrSpecNoPaths) {
		t.Errorf("缺少 paths: 期望 ErrSpecNoPaths，实际 %v", err)
	}
	if _, _, _, err := ParseSpecDocument(mustDoc(t, `{"swagger": "2.0"}`)); !errors.Is(err, ErrSpecNoPaths) {
		t.Errorf("swagger2 缺少 paths: 期望 ErrSpecNoPaths，实际 %v", err)
	}
	// ConvertSwagger2ToOpenAPI3 直接调用版本校验
	if _, err := ConvertSwagger2ToOpenAPI3(mustDoc(t, `{"swagger": "1.2"}`)); !errors.Is(err, ErrSpecNotSwagger2) {
		t.Errorf("非 swagger2: 期望 ErrSpecNotSwagger2，实际 %v", err)
	}
}

func TestDetectSpecFormat(t *testing.T) {
	cases := map[string]string{
		`{"openapi": "3.0.0"}`: SpecFormatOpenAPI3,
		`{"openapi": "3.1.0"}`: SpecFormatOpenAPI3,
		`{"swagger": "2.0"}`:   SpecFormatSwagger2,
		`{"openapi": "2.0"}`:   "",
		`{}`:                   "",
	}
	for raw, want := range cases {
		if got := DetectSpecFormat(mustDoc(t, raw)); got != want {
			t.Errorf("%s: got=%q want=%q", raw, got, want)
		}
	}
}

// ---------- CHANGED 级跨版本对比 ----------

func TestDiffSpecOperationsChanged(t *testing.T) {
	oldDoc := mustDoc(t, `{
		"openapi": "3.0.0",
		"paths": {
			"/a": {"get": {"parameters": [
				{"name": "keep", "in": "query", "schema": {"type": "string"}},
				{"name": "typed", "in": "query", "schema": {"type": "string"}},
				{"name": "req", "in": "query", "required": false, "schema": {"type": "integer"}},
				{"name": "gone", "in": "header", "schema": {"type": "string"}}
			]}},
			"/removed": {"delete": {}}
		}
	}`)
	newDoc := mustDoc(t, `{
		"openapi": "3.0.0",
		"paths": {
			"/a": {"get": {"parameters": [
				{"name": "keep", "in": "query", "schema": {"type": "string"}},
				{"name": "typed", "in": "query", "schema": {"type": "integer"}},
				{"name": "req", "in": "query", "required": true, "schema": {"type": "integer"}},
				{"name": "fresh", "in": "query", "schema": {"type": "boolean"}}
			]}},
			"/added": {"post": {}}
		}
	}`)
	oldOps, err := ParseSpecOperations(oldDoc)
	if err != nil {
		t.Fatalf("解析旧版失败: %v", err)
	}
	newOps, err := ParseSpecOperations(newDoc)
	if err != nil {
		t.Fatalf("解析新版失败: %v", err)
	}
	changes := DiffSpecOperations(oldOps, newOps)
	// 期望：/added ENDPOINT_ADDED、/removed ENDPOINT_REMOVED、
	// /a: fresh PARAM_ADDED、gone PARAM_REMOVED、typed TYPE_CHANGED、req REQUIRED_CHANGED
	type key struct{ ep, ct, in, name string }
	got := map[key]SpecChange{}
	for _, c := range changes {
		got[key{c.EndpointKey, c.ChangeType, c.ParamIn, c.ParamName}] = c
	}
	want := []struct {
		key           key
		before, after string
	}{
		{key{"POST /added", ChangeEndpointAdded, "", ""}, "", ""},
		{key{"DELETE /removed", ChangeEndpointRemoved, "", ""}, "", ""},
		{key{"GET /a", ChangeParamAdded, "QUERY", "fresh"}, "", "boolean"},
		{key{"GET /a", ChangeParamRemoved, "HEADER", "gone"}, "string", ""},
		{key{"GET /a", ChangeTypeChanged, "QUERY", "typed"}, "string", "integer"},
		{key{"GET /a", ChangeRequiredChanged, "QUERY", "req"}, "false", "true"},
	}
	if len(changes) != len(want) {
		t.Fatalf("变化数不符: got=%d want=%d (%+v)", len(changes), len(want), changes)
	}
	for _, w := range want {
		c, ok := got[w.key]
		if !ok {
			t.Fatalf("缺少变化: %+v", w.key)
		}
		if c.Before != w.before || c.After != w.after {
			t.Fatalf("%+v: before/after 不符 got=(%q,%q) want=(%q,%q)",
				w.key, c.Before, c.After, w.before, w.after)
		}
	}
	// 排序确定（EndpointKey 升序）
	for i := 1; i < len(changes); i++ {
		if changes[i-1].EndpointKey > changes[i].EndpointKey {
			t.Fatalf("变化未按 EndpointKey 排序: %+v", changes)
		}
	}
	// 无变化场景
	if again := DiffSpecOperations(newOps, newOps); len(again) != 0 {
		t.Fatalf("同版本对比应为空: %+v", again)
	}
}

// ---------- SSRF 防护 ----------

func TestValidateSpecFetchURLDenyMatrix(t *testing.T) {
	deny := []string{
		"file:///etc/passwd",
		"ftp://example.com/spec.json",
		"gopher://example.com/",
		"http://127.0.0.1/spec.json",
		"http://127.0.0.1:8080/spec.json",
		"http://10.0.0.1/spec.json",
		"http://172.16.0.1/spec.json",
		"http://172.31.255.255/spec.json",
		"http://192.168.1.1/spec.json",
		"http://169.254.169.254/latest/meta-data", // 云元数据
		"http://0.0.0.0/spec.json",
		"http://[::1]/spec.json",
		"http://[fe80::1]/spec.json",
		"http://[fd00::1]/spec.json", // IPv6 ULA 私网
		"http://100.64.0.1/spec.json",
		"http://198.18.0.1/spec.json",
		"http://224.0.0.1/spec.json",
		"http://localhost/spec.json", // 域名解析为回环
		"http://[::ffff:127.0.0.1]/spec.json",
		"not-a-url",
		"",
	}
	for _, raw := range deny {
		if _, err := validateSpecFetchURL(raw); !errors.Is(err, ErrSpecFetchDenied) {
			t.Errorf("%q: 期望 ErrSpecFetchDenied，实际 %v", raw, err)
		}
	}
	// 公网字面量 IP 放行（域名正向用例依赖外部 DNS，不在单测覆盖）
	if _, err := validateSpecFetchURL("http://93.184.216.34/spec.json"); err != nil {
		t.Errorf("公网 IP 应放行: %v", err)
	}
	if _, err := validateSpecFetchURL("https://93.184.216.34/spec.json"); err != nil {
		t.Errorf("公网 HTTPS IP 应放行: %v", err)
	}
}

func TestCheckPublicIPMatrix(t *testing.T) {
	deny := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1",
		"0.0.0.0", "100.64.0.1", "198.18.0.1", "240.0.0.1", "224.0.0.1",
		"::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1",
	}
	for _, s := range deny {
		if err := checkPublicIP(net.ParseIP(s)); err == nil {
			t.Errorf("%s 应被拒绝", s)
		}
	}
	allow := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allow {
		if err := checkPublicIP(net.ParseIP(s)); err != nil {
			t.Errorf("%s 应放行: %v", s, err)
		}
	}
}

// TestFetchSpecDocumentDenyLoopback 本地 httptest 服务真实存在，但 SSRF 防护必须拒绝。
func TestFetchSpecDocumentDenyLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"openapi": "3.0.0", "paths": {"/a": {"get": {}}}}`))
	}))
	defer srv.Close()
	// httptest 监听 127.0.0.1，validateSpecFetchURL 应在发请求前拦截
	if _, err := fetchSpecDocument(context.Background(), srv.URL, nil); !errors.Is(err, ErrSpecFetchDenied) {
		t.Fatalf("回环地址应被拒绝: %v", err)
	}
}

// ---------- 规范名解析 ----------

func TestResolveSpecName(t *testing.T) {
	doc := mustDoc(t, `{"info": {"title": "支付网关"}}`)
	hash := HashSpecContent([]byte("x"))
	cases := []struct {
		reqName, fileName string
		doc               map[string]any
		want              string
	}{
		{"订单中心", "a.json", doc, "订单中心"},                   // 显式 name 优先
		{"  ", "a.json", doc, "a.json"},                   // 空白 name 回退 file_name
		{"", "", doc, "支付网关"},                             // 再回退 info.title
		{"", "", map[string]any{}, "unnamed-" + hash[:8]}, // 最终回退哈希
	}
	for i, c := range cases {
		if got := resolveSpecName(c.reqName, c.fileName, c.doc, hash); got != c.want {
			t.Errorf("用例%d: got=%q want=%q", i, got, c.want)
		}
	}
	// 超长 name 截断至 255
	long := strings.Repeat("a", 300)
	if got := resolveSpecName(long, "", nil, hash); len(got) != 255 {
		t.Errorf("超长 name 应截断至 255: %d", len(got))
	}
}

// ---------- 目录派生 ----------

func TestSpecDirectoryOf(t *testing.T) {
	cases := map[string]string{
		"/test/php/login": "/test/php",
		"/users/{id}":     "/users",
		"/health":         "",
		"/":               "",
	}
	for in, want := range cases {
		if got := specDirectoryOf(in); got != want {
			t.Errorf("%s: got=%q want=%q", in, got, want)
		}
	}
}
