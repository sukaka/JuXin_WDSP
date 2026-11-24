// spec_extended_formats_test.go 扩展规范格式（Protobuf/gRPC、WSDL/XSD、RAML、API Blueprint、
// HAR 脱敏、AsyncAPI 2.x/3.x、安全 ZIP 多文件归档）、UTF-8 BOM 兼容、存储重解析/审计与
// multipart/form-data 文件直传测试。
package apisecurity

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func buildTestZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("创建 zip 条目 %s 失败: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("写入 zip 条目 %s 失败: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	return buf.Bytes()
}

func newMultipartRequest(t *testing.T, fields map[string]string, files []struct {
	field, filename string
	content         []byte
}) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %s: %v", k, err)
		}
	}
	for _, f := range files {
		pw, err := mw.CreateFormFile(f.field, f.filename)
		if err != nil {
			t.Fatalf("CreateFormFile %s: %v", f.field, err)
		}
		if _, err := pw.Write(f.content); err != nil {
			t.Fatalf("write file %s: %v", f.filename, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close multipart: %v", err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

// ---------- UTF-8 BOM ----------

func TestParseSpecContentUTF8BOM(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"JSON+BOM", append(append([]byte{}, bom...), []byte(`{"openapi":"3.0.1","paths":{"/ping":{"get":{}}}}`)...), SpecFormatOpenAPI3},
		{"YAML+BOM", append(append([]byte{}, bom...), []byte("openapi: 3.0.1\npaths:\n  /ping:\n    get: {}\n")...), SpecFormatOpenAPI3},
		{"GraphQL+BOM", append(append([]byte{}, bom...), []byte("type Query {\n  ping: String\n}\n")...), SpecFormatGraphQL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			format, _, ops, err := ParseSpecContent(tc.raw)
			if err != nil || format != tc.want || len(ops) != 1 {
				t.Fatalf("BOM 解析失败: format=%q ops=%+v err=%v", format, ops, err)
			}
		})
	}
}

// ---------- Protobuf / gRPC ----------

func TestParseSpecContentProtobufGRPCAndHTTP(t *testing.T) {
	protoSrc := `
syntax = "proto3";
package acme.user.v1;

/* block comment */
message GetUserRequest {
  string user_id = 1;
  bool include_roles = 2;
  repeated string tags = 3;
  map<string, string> labels = 4;
  oneof selector {
    string email = 5;
    int64 numeric_id = 6;
  }
}

message CreateUserRequest {
  string username = 1;
  int32 age = 2;
}

message UserResponse {
  string id = 1;
}

service UserService {
  // 标准 gRPC
  rpc CreateUser (CreateUserRequest) returns (UserResponse);
  // 带 google.api.http 注解
  rpc GetUser (GetUserRequest) returns (UserResponse) {
    option (google.api.http) = {
      get: "/v1/users/{user_id}"
    };
  }
}
`
	format, normalized, ops, err := ParseSpecContent([]byte(protoSrc))
	if err != nil {
		t.Fatalf("Protobuf 解析失败: %v", err)
	}
	if format != SpecFormatProtobuf {
		t.Fatalf("format = %q, want protobuf", format)
	}
	if len(ops) != 2 {
		t.Fatalf("期望 2 个操作，实际 %+v", ops)
	}
	// GET /v1/users/{user_id} 与 GRPC /acme.user.v1.UserService/CreateUser（按 Key 排序）
	if ops[0].Key != "GET /v1/users/{user_id}" {
		t.Fatalf("ops[0].Key = %q", ops[0].Key)
	}
	if ops[1].Key != "GRPC /acme.user.v1.UserService/CreateUser" {
		t.Fatalf("ops[1].Key = %q", ops[1].Key)
	}
	if len(ops[1].Params) != 2 || ops[1].Params[0].Name != "age" || ops[1].Params[0].Type != "integer" {
		t.Fatalf("CreateUser 请求字段解析异常: %+v", ops[1].Params)
	}
	info, _ := normalized["info"].(map[string]any)
	if info["title"] != "acme.user.v1" {
		t.Fatalf("派生标题应为 package 名，实际 %+v", info)
	}
}

func TestParseSpecContentProtobufMessageOnlyAndReject(t *testing.T) {
	msgOnly := `
syntax = "proto2";
package billing;
message Invoice {
  required string invoice_id = 1;
  optional double amount = 2;
}
`
	format, _, ops, err := ParseSpecContent([]byte(msgOnly))
	if err != nil || format != SpecFormatProtobuf || len(ops) != 1 || ops[0].Key != "SCHEMA /_proto/billing.Invoice" {
		t.Fatalf("纯 message proto 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
	if len(ops[0].Params) != 2 || !ops[0].Params[1].Required {
		t.Fatalf("proto2 required 字段未识别: %+v", ops[0].Params)
	}

	if _, _, _, err := ParseSpecContent([]byte(`syntax = "proto3"; service Broken {`)); !errors.Is(err, ErrSpecInvalidProtobuf) {
		t.Fatalf("未闭合 proto 应报 ErrSpecInvalidProtobuf，实际 %v", err)
	}
}

// ---------- WSDL 1.1 / WSDL 2.0 / XSD & XXE 防护 ----------

func TestParseSpecContentWSDL11(t *testing.T) {
	wsdl := `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions name="OrderSoapService"
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:tns="http://example.com/order">
  <wsdl:types>
    <xs:schema targetNamespace="http://example.com/order">
      <xs:element name="GetOrderRequest">
        <xs:complexType>
          <xs:sequence>
            <xs:element name="orderId" type="xs:string"/>
            <xs:element name="includeItems" type="xs:boolean" minOccurs="0"/>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
    </xs:schema>
  </wsdl:types>
  <wsdl:message name="GetOrderInput">
    <wsdl:part name="parameters" element="tns:GetOrderRequest"/>
  </wsdl:message>
  <wsdl:portType name="OrderPortType">
    <wsdl:operation name="GetOrder">
      <wsdl:input message="tns:GetOrderInput"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:service name="OrderService">
    <wsdl:port name="OrderPort" binding="tns:OrderBinding">
      <soap:address location="https://api.example.com/ws/orders"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

	format, normalized, ops, err := ParseSpecContent([]byte(wsdl))
	if err != nil {
		t.Fatalf("WSDL 1.1 解析失败: %v", err)
	}
	if format != SpecFormatWSDL || len(ops) != 1 || ops[0].Key != "SOAP /ws/orders/GetOrder" {
		t.Fatalf("WSDL 1.1 结果不符: format=%q ops=%+v", format, ops)
	}
	if len(ops[0].Params) != 2 || ops[0].Params[0].Name != "includeItems" || ops[0].Params[0].Required ||
		ops[0].Params[1].Name != "orderId" || !ops[0].Params[1].Required {
		t.Fatalf("WSDL 内联 XSD 参数展开不符: %+v", ops[0].Params)
	}
	if info, _ := normalized["info"].(map[string]any); info["title"] != "OrderSoapService" {
		t.Fatalf("WSDL 标题不符: %+v", info)
	}
}

func TestParseSpecContentWSDL20AndXSDAndXXE(t *testing.T) {
	wsdl2 := `<?xml version="1.0"?>
<description xmlns="http://www.w3.org/ns/wsdl" xmlns:tns="http://example.com/v2">
  <interface name="BillingInterface">
    <operation name="Charge">
      <input element="tns:ChargeRequest"/>
    </operation>
  </interface>
  <service name="BillingService">
    <endpoint name="BillingEndpoint" address="https://example.com/soap/v2"/>
  </service>
</description>`
	format, _, ops, err := ParseSpecContent([]byte(wsdl2))
	if err != nil || format != SpecFormatWSDL || len(ops) != 1 || ops[0].Key != "SOAP /soap/v2/Charge" {
		t.Fatalf("WSDL 2.0 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}

	xsd := `<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="http://example.com/schema/customer">
  <xs:complexType name="CustomerType">
    <xs:sequence>
      <xs:element name="id" type="xs:long"/>
      <xs:element name="tags" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="tenant" type="xs:string" use="required"/>
  </xs:complexType>
  <xs:element name="Customer" type="CustomerType"/>
</xs:schema>`
	format, _, ops, err = ParseSpecContent([]byte(xsd))
	if err != nil || format != SpecFormatXSD || len(ops) != 2 {
		t.Fatalf("XSD 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
	if ops[0].Key != "SCHEMA /_xsd/Customer" || len(ops[0].Params) != 3 {
		t.Fatalf("XSD 字段展开不符: %+v", ops[0])
	}

	// 安全底线：禁止 DOCTYPE / ENTITY（防 XXE 与实体扩展炸弹）
	xxe := `<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="P"><operation name="O"/></portType></definitions>`
	if _, _, _, err := ParseSpecContent([]byte(xxe)); !errors.Is(err, ErrSpecInvalidXML) {
		t.Fatalf("XXE DOCTYPE 应被拒绝并报 ErrSpecInvalidXML，实际 %v", err)
	}

	// 未知 XML 根元素应报 ErrSpecUnsupportedFormat
	if _, _, _, err := ParseSpecContent([]byte(`<html><body>hi</body></html>`)); !errors.Is(err, ErrSpecUnsupportedFormat) {
		t.Fatalf("未知 XML 根元素应报 ErrSpecUnsupportedFormat，实际 %v", err)
	}
}

// ---------- RAML 1.0 / 0.8 ----------

func TestParseSpecContentRAMLAndSecurity(t *testing.T) {
	raml10 := `#%RAML 1.0
title: Inventory API
version: v1
baseUri: https://api.example.com/{version}
types:
  CreateItem:
    type: object
    properties:
      sku: string
      qty?: integer
/items:
  get:
    queryParameters:
      keyword:
        type: string
        required: false
  post:
    headers:
      X-Tenant-Id:
        type: string
        required: true
    body:
      application/json:
        type: CreateItem
  /{itemId}:
    uriParameters:
      itemId:
        type: string
    delete:
      description: remove item
`
	format, normalized, ops, err := ParseSpecContent([]byte(raml10))
	if err != nil {
		t.Fatalf("RAML 1.0 解析失败: %v", err)
	}
	if format != SpecFormatRAML || len(ops) != 3 {
		t.Fatalf("RAML 1.0 结果不符: format=%q ops=%+v", format, ops)
	}
	if ops[0].Key != "DELETE /v1/items/{itemId}" || ops[1].Key != "GET /v1/items" || ops[2].Key != "POST /v1/items" {
		t.Fatalf("RAML 路径/方法不符: %+v", ops)
	}
	if info, _ := normalized["info"].(map[string]any); info["title"] != "Inventory API" {
		t.Fatalf("RAML 标题不符: %+v", info)
	}

	// RAML 0.8 + 内嵌 JSON Schema
	raml08 := `#%RAML 0.8
title: Legacy API
/orders:
  post:
    body:
      application/json:
        schema: '{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}'
`
	format, _, ops, err = ParseSpecContent([]byte(raml08))
	if err != nil || format != SpecFormatRAML || len(ops) != 1 || len(ops[0].Params) != 1 {
		t.Fatalf("RAML 0.8 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}

	// 安全底线：!include 自定义标签必须被 YAML 解码器拒绝，防本地文件读取
	ramlInclude := "#%RAML 1.0\ntitle: Evil\n/x: !include /etc/passwd\n"
	if _, _, _, err := ParseSpecContent([]byte(ramlInclude)); !errors.Is(err, ErrSpecInvalidYAML) {
		t.Fatalf("RAML !include 应被拒绝，实际 %v", err)
	}
}

// ---------- API Blueprint ----------

func TestParseSpecContentAPIB(t *testing.T) {
	apib := `FORMAT: 1A
HOST: https://api.example.com

# Account API

## Users [/users/{id}{?page,limit}]

+ Parameters
    + id: 42 (integer, required) - User ID
    + page: 1 (integer, optional)

### Get User [GET]

+ Response 200 (application/json)

## Create User [POST /users]

+ Request (application/json)
    + Headers

            X-Request-Id: req-123

    + Body

            {"email": "a@example.com", "age": 20}

+ Response 201
`
	format, normalized, ops, err := ParseSpecContent([]byte(apib))
	if err != nil {
		t.Fatalf("API Blueprint 解析失败: %v", err)
	}
	if format != SpecFormatAPIB || len(ops) != 2 {
		t.Fatalf("APIB 结果不符: format=%q ops=%+v", format, ops)
	}
	if ops[0].Key != "GET /users/{id}" || ops[1].Key != "POST /users" {
		t.Fatalf("APIB 端点键不符: %+v", ops)
	}
	if info, _ := normalized["info"].(map[string]any); info["title"] != "Account API" {
		t.Fatalf("APIB 标题不符: %+v", info)
	}
	// 无 FORMAT: 1A 头但具备 APIB 资源/动作标题
	noHeader := "# Mini API\n\n## Health [/health]\n\n### Check [GET]\n"
	format, _, ops, err = ParseSpecContent([]byte(noHeader))
	if err != nil || format != SpecFormatAPIB || len(ops) != 1 || ops[0].Key != "GET /health" {
		t.Fatalf("无头 APIB 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
}

// ---------- HAR（含敏感凭据/响应体脱敏断言） ----------

func TestParseSpecContentHARAndRedaction(t *testing.T) {
	har := `{
	  "log": {
	    "version": "1.2",
	    "creator": {"name": "Browser", "version": "1.0"},
	    "pages": [{"id": "p1", "title": "Checkout Flow"}],
	    "entries": [
	      {
	        "request": {
	          "method": "POST",
	          "url": "https://shop.example.com/api/v1/checkout?currency=CNY&token=SECRET_QUERY_TOKEN",
	          "headers": [
	            {"name": "Authorization", "value": "Bearer SUPER_SECRET_JWT_VALUE"},
	            {"name": "Cookie", "value": "session=SUPER_SECRET_COOKIE"},
	            {"name": "X-Tenant-Id", "value": "tenant-secret-42"},
	            {"name": "User-Agent", "value": "Mozilla/5.0"}
	          ],
	          "queryString": [
	            {"name": "currency", "value": "CNY"}
	          ],
	          "postData": {
	            "mimeType": "application/json",
	            "text": "{\"password\":\"TOP_SECRET_PASSWORD\",\"amount\":99.5}"
	          }
	        },
	        "response": {
	          "status": 200,
	          "content": {"text": "{\"ssn\":\"123-45-6789\"}"}
	        }
	      },
	      {
	        "request": {
	          "method": "POST",
	          "url": "https://shop.example.com/api/v1/checkout?coupon=VIP",
	          "headers": [],
	          "queryString": [{"name": "coupon", "value": "VIP"}]
	        }
	      }
	    ]
	  }
	}`
	format, normalized, ops, err := ParseSpecContent([]byte(har))
	if err != nil {
		t.Fatalf("HAR 解析失败: %v", err)
	}
	if format != SpecFormatHAR || len(ops) != 1 || ops[0].Key != "POST /api/v1/checkout" {
		t.Fatalf("HAR 去重结果不符: format=%q ops=%+v", format, ops)
	}
	// 安全红线：落库规范化文档绝不得残留任何请求值、Cookie、Authorization 凭据或响应体
	stored, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	storedStr := string(stored)
	for _, secret := range []string{
		"SUPER_SECRET_JWT_VALUE",
		"SUPER_SECRET_COOKIE",
		"SECRET_QUERY_TOKEN",
		"TOP_SECRET_PASSWORD",
		"tenant-secret-42",
		"123-45-6789",
	} {
		if strings.Contains(storedStr, secret) {
			t.Fatalf("HAR 落库文档泄露了敏感运行时值 %q: %s", secret, storedStr)
		}
	}
}

// ---------- AsyncAPI 2.x / 3.x ----------

func TestParseSpecContentAsyncAPI(t *testing.T) {
	async2YAML := `
asyncapi: 2.6.0
info:
  title: Order Events
channels:
  orders/{orderId}/created:
    parameters:
      orderId:
        schema:
          type: string
    publish:
      message:
        $ref: '#/components/messages/OrderCreated'
    subscribe:
      message:
        payload:
          type: object
          properties:
            ack:
              type: boolean
components:
  messages:
    OrderCreated:
      payload:
        type: object
        required: [order_id]
        properties:
          order_id:
            type: string
          total:
            type: number
`
	format, _, ops, err := ParseSpecContent([]byte(async2YAML))
	if err != nil || format != SpecFormatAsyncAPI || len(ops) != 2 {
		t.Fatalf("AsyncAPI 2.x 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
	if ops[0].Key != "PUBLISH /orders/{orderId}/created" || ops[1].Key != "SUBSCRIBE /orders/{orderId}/created" {
		t.Fatalf("AsyncAPI 2.x 端点键不符: %+v", ops)
	}

	async3JSON := `{
	  "asyncapi": "3.0.0",
	  "info": {"title": "Notify Bus"},
	  "channels": {
	    "userSignedup": {
	      "address": "user/signedup",
	      "messages": {
	        "UserSignedUp": {
	          "payload": {
	            "type": "object",
	            "properties": {"email": {"type": "string"}}
	          }
	        }
	      }
	    }
	  },
	  "operations": {
	    "sendUserSignedup": {
	      "action": "send",
	      "channel": {"$ref": "#/channels/userSignedup"}
	    }
	  }
	}`
	format, _, ops, err = ParseSpecContent([]byte(async3JSON))
	if err != nil || format != SpecFormatAsyncAPI || len(ops) != 1 || ops[0].Key != "SEND /user/signedup" {
		t.Fatalf("AsyncAPI 3.x 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
	if len(ops[0].Params) != 1 || ops[0].Params[0].Name != "email" {
		t.Fatalf("AsyncAPI 3.x payload 提取失败: %+v", ops[0].Params)
	}
}

// ---------- 安全 ZIP 多文件归档 ----------

func TestParseSpecContentZipOpenAPIMultiFileAndProto(t *testing.T) {
	// 1. 多文件 OpenAPI 3（跨文件相对 $ref + 子文件内部 #/... $ref + __MACOSX 跳过）
	oaZip := buildTestZip(t, map[string][]byte{
		"__MACOSX/._openapi.yaml": []byte("junk"),
		"openapi.yaml": []byte(`
openapi: 3.0.3
info:
  title: Bundled Store API
paths:
  /users:
    $ref: ./paths/users.yaml
`),
		"paths/users.yaml": []byte(`
post:
  requestBody:
    content:
      application/json:
        schema:
          $ref: ../components/schemas.yaml#/CreateUser
`),
		"components/schemas.yaml": []byte(`
CreateUser:
  type: object
  required: [name]
  properties:
    name:
      type: string
    addr:
      $ref: '#/Address'
Address:
  type: object
  properties:
    city:
      type: string
`),
	})
	format, normalized, ops, err := ParseSpecContent(oaZip)
	if err != nil {
		t.Fatalf("多文件 OpenAPI ZIP 解析失败: %v", err)
	}
	if format != SpecFormatOpenAPI3 || len(ops) != 1 || ops[0].Key != "POST /users" {
		t.Fatalf("多文件 OpenAPI ZIP 结果不符: format=%q ops=%+v", format, ops)
	}
	if len(ops[0].Params) != 2 {
		t.Fatalf("跨文件 $ref 参数展开失败: %+v", ops[0].Params)
	}
	// 展开后的文档应完全自包含，不含任何外部 $ref
	if err := rejectExternalRefs(normalized); err != nil {
		t.Fatalf("展开后规范仍含外部引用: %v", err)
	}

	// 2. 多文件 .proto 归档（service 引用另一文件中的 message）
	protoZip := buildTestZip(t, map[string][]byte{
		"common.proto": []byte(`syntax = "proto3"; package demo; message PingReq { string trace_id = 1; } message PingResp {}`),
		"svc.proto":    []byte(`syntax = "proto3"; package demo; import "common.proto"; service Health { rpc Ping (PingReq) returns (PingResp); }`),
	})
	format, _, ops, err = ParseSpecContent(protoZip)
	if err != nil || format != SpecFormatProtobuf || len(ops) != 1 || ops[0].Key != "GRPC /demo.Health/Ping" {
		t.Fatalf("多文件 Protobuf ZIP 解析失败: format=%q ops=%+v err=%v", format, ops, err)
	}
	if len(ops[0].Params) != 1 || ops[0].Params[0].Name != "trace_id" {
		t.Fatalf("跨文件 proto message 字段解析失败: %+v", ops[0].Params)
	}
}

func TestParseSpecContentZipSecurityDefenses(t *testing.T) {
	// 1. Zip Slip 路径穿越
	slipZip := buildTestZip(t, map[string][]byte{
		"../../etc/evil.json": []byte(`{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`),
	})
	if _, _, _, err := ParseSpecContent(slipZip); !errors.Is(err, ErrSpecInvalidZip) {
		t.Fatalf("Zip Slip 应报 ErrSpecInvalidZip，实际 %v", err)
	}

	// 2. ZIP 内含 https:// 外部 $ref → 必须拒绝（抗 SSRF）
	ssrfZip := buildTestZip(t, map[string][]byte{
		"openapi.json": []byte(`{"openapi":"3.0.0","paths":{"/a":{"$ref":"https://evil.example.com/p.json"}}}`),
	})
	if _, _, _, err := ParseSpecContent(ssrfZip); !errors.Is(err, ErrSpecExternalRef) {
		t.Fatalf("ZIP 内外部 URL 引用应报 ErrSpecExternalRef，实际 %v", err)
	}

	// 3. ZIP 内循环 $ref → 必须判环拦截
	cycleZip := buildTestZip(t, map[string][]byte{
		"openapi.yaml": []byte("openapi: 3.0.0\npaths:\n  /a:\n    $ref: ./a.yaml\n"),
		"a.yaml":       []byte("$ref: ./b.yaml\n"),
		"b.yaml":       []byte("$ref: ./a.yaml\n"),
	})
	if _, _, _, err := ParseSpecContent(cycleZip); !errors.Is(err, ErrSpecTooComplex) {
		t.Fatalf("ZIP 内循环引用应报 ErrSpecTooComplex，实际 %v", err)
	}

	// 4. Zip 炸弹（压缩体很小但解压超 16MiB 单文件上限）
	bombPayload := bytes.Repeat([]byte("A"), specImportMaxBytes+1024)
	bombZip := buildTestZip(t, map[string][]byte{
		"openapi.json": bombPayload,
	})
	if len(bombZip) >= specImportMaxBytes {
		t.Fatalf("测试构造的 zip 压缩体应小于 16MiB，实际 %d", len(bombZip))
	}
	if _, _, _, err := ParseSpecContent(bombZip); !errors.Is(err, ErrSpecTooLarge) {
		t.Fatalf("Zip 炸弹应报 ErrSpecTooLarge，实际 %v", err)
	}
}

// ---------- 存储重解析与规范审计全格式往返 ----------

func TestStoredSpecRoundTripAndAuditAllNewFormats(t *testing.T) {
	samples := []struct {
		name   string
		raw    []byte
		format string
	}{
		{"GraphQL", []byte("type Query {\n  ping: String\n}\n"), SpecFormatGraphQL},
		{"Protobuf", []byte("syntax = \"proto3\";\npackage p;\nmessage R { string id = 1; }\nservice S { rpc Call(R) returns (R); }\n"), SpecFormatProtobuf},
		{"WSDL", []byte(`<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="P"><operation name="Ping"/></portType></definitions>`), SpecFormatWSDL},
		{"XSD", []byte(`<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:complexType name="Item"><xs:sequence><xs:element name="id" type="xs:string"/></xs:sequence></xs:complexType></xs:schema>`), SpecFormatXSD},
		{"RAML", []byte("#%RAML 1.0\ntitle: T\n/ping:\n  get: {}\n"), SpecFormatRAML},
		{"APIB", []byte("FORMAT: 1A\n# T\n## Ping [/ping]\n### Get [GET]\n"), SpecFormatAPIB},
		{"HAR", []byte(`{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://example.com/ping"}}]}}`), SpecFormatHAR},
		{"AsyncAPI", []byte("asyncapi: 2.6.0\ninfo:\n  title: T\nchannels:\n  ping:\n    publish: {}\n"), SpecFormatAsyncAPI},
	}
	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			format, normalized, ops, err := ParseSpecContent(tc.raw)
			if err != nil || format != tc.format || len(ops) == 0 {
				t.Fatalf("ParseSpecContent 失败: format=%q ops=%+v err=%v", format, ops, err)
			}
			storedBytes, err := json.Marshal(normalized)
			if err != nil {
				t.Fatalf("序列化规范化文档失败: %v", err)
			}
			storedSpec := &ImportSpec{ID: uuid.New(), Format: format, SpecJSON: storedBytes}
			reOps, err := parseStoredSpecOperations(storedSpec)
			if err != nil || len(reOps) != len(ops) {
				t.Fatalf("parseStoredSpecOperations 往返失败: got=%+v want=%+v err=%v", reOps, ops, err)
			}
			auditRes, err := auditStoredSpec(storedSpec)
			if err != nil || auditRes.OperationCount != len(ops) || auditRes.Format != format {
				t.Fatalf("auditStoredSpec 失败: res=%+v err=%v", auditRes, err)
			}
		})
	}
}

// ---------- multipart/form-data 上传解码 ----------

func TestDecodeSpecMultipart(t *testing.T) {
	// 1. 正常上传 .yaml 文件，文件名含路径穿越时清洗为 basename
	ct, body := newMultipartRequest(t,
		map[string]string{"name": "order-spec"},
		[]struct {
			field, filename string
			content         []byte
		}{
			{field: "file", filename: "../../evil/orders.yaml", content: []byte("openapi: 3.0.1\npaths:\n  /orders:\n    get: {}\n")},
		},
	)
	req := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	format, _, ops, fileName, reqName, ok := decodeSpecMultipart(w, req)
	if !ok || format != SpecFormatOpenAPI3 || len(ops) != 1 || fileName != "orders.yaml" || reqName != "order-spec" {
		t.Fatalf("multipart YAML 上传失败: ok=%v format=%q file=%q name=%q ops=%+v code=%d body=%s",
			ok, format, fileName, reqName, ops, w.Code, w.Body.String())
	}

	// 2. 显式 file_name 覆盖上传文件名，上传 .zip 包
	zipBytes := buildTestZip(t, map[string][]byte{
		"api.proto": []byte(`syntax = "proto3"; package shop; message Req { string id = 1; } service Shop { rpc Get(Req) returns (Req); }`),
	})
	ct2, body2 := newMultipartRequest(t,
		map[string]string{"file_name": "shop-bundle.zip"},
		[]struct {
			field, filename string
			content         []byte
		}{
			{field: "file", filename: "raw.zip", content: zipBytes},
		},
	)
	req2 := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", ct2)
	w2 := httptest.NewRecorder()
	format, _, ops, fileName, _, ok = decodeSpecMultipart(w2, req2)
	if !ok || format != SpecFormatProtobuf || len(ops) != 1 || fileName != "shop-bundle.zip" {
		t.Fatalf("multipart ZIP 上传失败: ok=%v format=%q file=%q ops=%+v body=%s", ok, format, fileName, ops, w2.Body.String())
	}

	// 3. 缺少 file 字段 → 400
	ct3, body3 := newMultipartRequest(t, map[string]string{"file_name": "empty.yaml"}, nil)
	req3 := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body3))
	req3.Header.Set("Content-Type", ct3)
	w3 := httptest.NewRecorder()
	if _, _, _, _, _, ok := decodeSpecMultipart(w3, req3); ok || w3.Code != 400 {
		t.Fatalf("缺少 file 应返回 400，实际 ok=%v code=%d", ok, w3.Code)
	}

	// 4. 多文件 part → 400
	ct4, body4 := newMultipartRequest(t, nil, []struct {
		field, filename string
		content         []byte
	}{
		{field: "file", filename: "a.yaml", content: []byte("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n")},
		{field: "file", filename: "b.yaml", content: []byte("openapi: 3.0.0\npaths:\n  /b:\n    get: {}\n")},
	})
	req4 := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body4))
	req4.Header.Set("Content-Type", ct4)
	w4 := httptest.NewRecorder()
	if _, _, _, _, _, ok := decodeSpecMultipart(w4, req4); ok || w4.Code != 400 {
		t.Fatalf("多个 file part 应返回 400，实际 ok=%v code=%d", ok, w4.Code)
	}

	// 5. 超过 16MiB 上限的单文件 → 400
	ct5, body5 := newMultipartRequest(t, nil, []struct {
		field, filename string
		content         []byte
	}{
		{field: "file", filename: "huge.json", content: bytes.Repeat([]byte("x"), specImportMaxBytes+10)},
	})
	req5 := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body5))
	req5.Header.Set("Content-Type", ct5)
	w5 := httptest.NewRecorder()
	if _, _, _, _, _, ok := decodeSpecMultipart(w5, req5); ok || w5.Code != 400 {
		t.Fatalf("超限单文件应返回 400，实际 ok=%v code=%d", ok, w5.Code)
	}

	// 6. Handler.ImportSpec 路由到 multipart 分支并输出明确中文解析错误
	ct6, body6 := newMultipartRequest(t, nil, []struct {
		field, filename string
		content         []byte
	}{
		{field: "file", filename: "broken.proto", content: []byte(`syntax = "proto3"; service Broken {`)},
	})
	req6 := httptest.NewRequest("POST", "/api/v1/api-security/specs/import", bytes.NewReader(body6))
	req6.Header.Set("Content-Type", ct6)
	w6 := httptest.NewRecorder()
	(&Handler{}).ImportSpec(w6, req6)
	if w6.Code != 400 || !strings.Contains(w6.Body.String(), "Protobuf") {
		t.Fatalf("ImportSpec multipart 解析错误映射不符: code=%d body=%s", w6.Code, w6.Body.String())
	}
}
