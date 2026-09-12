// fields_test.go 响应 JSON 解析测试：ParseJSON 一次解析产物（字段表 + 解码根值）复用口径。
package response

import (
	"encoding/json"
	"reflect"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// TestParseJSONReusableRoot 一次解析：字段表与 WalkJSONFields 完全一致，
// 解码根值可直接窄提取（UseNumber 保留数字字面量）；非 JSON 返回 isJSON=false。
func TestParseJSONReusableRoot(t *testing.T) {
	body := []byte(`{"model":"m1","usage":{"total_tokens":20},"tags":["a"],"ok":true}`)
	fields, root, ok := ParseJSON(body, dsctx.DefaultParseLimits())
	if !ok {
		t.Fatal("must parse json body")
	}
	wantFields, ok2 := WalkJSONFields(body, dsctx.DefaultParseLimits())
	if !ok2 {
		t.Fatal("WalkJSONFields must parse same body")
	}
	if !reflect.DeepEqual(fields, wantFields) {
		t.Fatalf("fields mismatch: %v vs %v", fields, wantFields)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		t.Fatalf("root must be object: %T", root)
	}
	if obj["model"] != "m1" {
		t.Fatalf("root model = %v", obj["model"])
	}
	usage, ok := obj["usage"].(map[string]any)
	if !ok {
		t.Fatalf("root usage = %T", obj["usage"])
	}
	if n, ok := usage["total_tokens"].(json.Number); !ok || n.String() != "20" {
		t.Fatalf("total_tokens must stay json.Number literal: %T %v", usage["total_tokens"], usage["total_tokens"])
	}
	// 非 JSON：isJSON=false，字段表与根值均为 nil
	fields2, root2, ok2 := ParseJSON([]byte("not-json"), dsctx.DefaultParseLimits())
	if ok2 || fields2 != nil || root2 != nil {
		t.Fatalf("non-json must fail cleanly: %v/%v/%v", fields2, root2, ok2)
	}
}
