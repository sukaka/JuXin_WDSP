package response

import (
	"encoding/json"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func planOf(path, algo string, keepHead, keepTail int) []dsctx.FieldTransform {
	return []dsctx.FieldTransform{{FieldPath: path, Algorithm: algo, KeepHead: keepHead, KeepTail: keepTail}}
}

// MASK 默认值语义：保留前 3 后 4，中间星号按原长度。
func TestApplyJSON_MaskDefault(t *testing.T) {
	body := []byte(`{"user":{"phone":"13800138000"}}`)
	res, err := ApplyJSON(body, planOf("user.phone", "MASK", DefaultKeepHead, DefaultKeepTail))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	phone := got["user"].(map[string]any)["phone"].(string)
	if phone != "138****8000" {
		t.Fatalf("masked phone = %q", phone)
	}
	if res.AppliedFields != 1 || res.SkippedFields != 0 {
		t.Fatalf("counts: %+v", res)
	}
}

// MASK 自定义 keep_head/keep_tail；短值整体 "****"。
func TestApplyJSON_MaskCustomAndShort(t *testing.T) {
	body := []byte(`{"a":"1234567890","b":"12345"}`)
	plan := []dsctx.FieldTransform{
		{FieldPath: "a", Algorithm: "MASK", KeepHead: 1, KeepTail: 2},
		{FieldPath: "b", Algorithm: "MASK", KeepHead: 3, KeepTail: 4},
	}
	res, err := ApplyJSON(body, plan)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if got["a"] != "1*******90" {
		t.Fatalf("a = %q", got["a"])
	}
	if got["b"] != "****" {
		t.Fatalf("short value must be fully masked, got %q", got["b"])
	}
}

// HASH：sha256 hex；REMOVE：删字段。
func TestApplyJSON_HashAndRemove(t *testing.T) {
	body := []byte(`{"token":"abc123","keep":"yes"}`)
	res, err := ApplyJSON(body, planOf("token", "HASH", 0, 0))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	v, ok := got["token"].(string)
	if !ok || len(v) != 64 {
		t.Fatalf("hash must be 64 hex chars, got %v", got["token"])
	}
	if strings.Contains(string(res.Body), "abc123") {
		t.Fatal("plaintext must not survive hashing")
	}

	res2, err := ApplyJSON(body, planOf("token", "REMOVE", 0, 0))
	if err != nil {
		t.Fatalf("apply remove: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(res2.Body, &got2); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if _, exists := got2["token"]; exists {
		t.Fatal("REMOVE must delete the field")
	}
	if got2["keep"] != "yes" {
		t.Fatalf("unrelated field changed: %v", got2["keep"])
	}
}

// 数组通配：users[].phone 逐元素脱敏；数组标量 users[] 逐元素处理；REMOVE 逐元素移除。
func TestApplyJSON_ArrayWildcard(t *testing.T) {
	body := []byte(`{"users":[{"phone":"13800138000","name":"a"},{"phone":"13900139000","name":"b"}]}`)
	res, err := ApplyJSON(body, planOf("users[].phone", "MASK", 3, 4))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	users := got["users"].([]any)
	if users[0].(map[string]any)["phone"] != "138****8000" {
		t.Fatalf("elem0 = %v", users[0])
	}
	if users[1].(map[string]any)["phone"] != "139****9000" {
		t.Fatalf("elem1 = %v", users[1])
	}
	if res.AppliedFields != 2 {
		t.Fatalf("applied = %d, want 2", res.AppliedFields)
	}
	if strings.Contains(string(res.Body), "13800138000") || strings.Contains(string(res.Body), "13900139000") {
		t.Fatal("plaintext leaked in masked body")
	}

	// 标量数组元素 MASK
	res2, err := ApplyJSON([]byte(`{"tags":["13800138000","x"]}`), planOf("tags[]", "MASK", 3, 4))
	if err != nil {
		t.Fatalf("apply scalar array: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(res2.Body, &got2); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	tags := got2["tags"].([]any)
	if tags[0] != "138****8000" || tags[1] != "****" {
		t.Fatalf("tags = %v", tags)
	}

	// 数组元素 REMOVE：元素从数组移除
	res3, err := ApplyJSON([]byte(`{"ids":[1,2,3]}`), planOf("ids[]", "REMOVE", 0, 0))
	if err != nil {
		t.Fatalf("apply remove array: %v", err)
	}
	var got3 map[string]any
	if err := json.Unmarshal(res3.Body, &got3); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if n := len(got3["ids"].([]any)); n != 0 {
		t.Fatalf("ids len = %d, want 0", n)
	}
	if res3.AppliedFields != 3 {
		t.Fatalf("applied = %d, want 3", res3.AppliedFields)
	}
}

// 嵌套点路径 + 数字/布尔标量（数字字面量不受影响字段保持原样）。
func TestApplyJSON_NestedAndScalarTypes(t *testing.T) {
	body := []byte(`{"a":{"b":{"c":"secret-value"}},"big":123456789012345678901234567890,"exp":1e2,"ok":true}`)
	res, err := ApplyJSON(body, planOf("a.b.c", "MASK", 2, 2))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if got["a"].(map[string]any)["b"].(map[string]any)["c"] != "se********ue" {
		t.Fatalf("nested = %v", got["a"])
	}
	// 未命中字段的数字字面量保持原样（UseNumber 防精度/记数法漂移）
	if !strings.Contains(string(res.Body), "123456789012345678901234567890") {
		t.Fatalf("big number literal drifted: %s", res.Body)
	}
	if !strings.Contains(string(res.Body), "1e2") {
		t.Fatalf("exponent literal drifted: %s", res.Body)
	}

	// 数字标量 MASK：按字符串形式处理（结果变为字符串，语义见规则注释）
	res2, err := ApplyJSON([]byte(`{"phone":13800138000}`), planOf("phone", "MASK", 3, 4))
	if err != nil {
		t.Fatalf("apply number: %v", err)
	}
	if !strings.Contains(string(res2.Body), `"138****8000"`) {
		t.Fatalf("number mask = %s", res2.Body)
	}
}

// 非标量目标：MASK/HASH 不适用跳过计数；REMOVE 删子树。
func TestApplyJSON_NonScalarTargets(t *testing.T) {
	body := []byte(`{"obj":{"x":1},"arr":[1,2]}`)
	res, err := ApplyJSON(body, []dsctx.FieldTransform{
		{FieldPath: "obj", Algorithm: "MASK", KeepHead: 3, KeepTail: 4},
		{FieldPath: "arr", Algorithm: "HASH"},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.AppliedFields != 0 || res.SkippedFields != 2 {
		t.Fatalf("counts: %+v", res)
	}
	if string(res.Body) == string(body) {
		// 重新编码但内容等价（键序按字典序，此处单键对象不变）
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if got["obj"].(map[string]any)["x"].(float64) != 1 {
		t.Fatalf("obj must be unchanged: %v", got["obj"])
	}

	res2, err := ApplyJSON(body, planOf("obj", "REMOVE", 0, 0))
	if err != nil {
		t.Fatalf("apply remove subtree: %v", err)
	}
	var got2 map[string]any
	if err := json.Unmarshal(res2.Body, &got2); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if _, exists := got2["obj"]; exists {
		t.Fatal("REMOVE must delete subtree")
	}
}

// 非 JSON 输入返回错误（调用方按失败策略处理，不得 panic）；空计划原样返回。
func TestApplyJSON_Errors(t *testing.T) {
	if _, err := ApplyJSON([]byte(`not json`), planOf("a", "MASK", 3, 4)); err == nil {
		t.Fatal("expect decode error")
	}
	body := []byte(`{"a":1}`)
	res, err := ApplyJSON(body, nil)
	if err != nil {
		t.Fatalf("empty plan must be no-op: %v", err)
	}
	if string(res.Body) != string(body) {
		t.Fatalf("empty plan must return original body, got %s", res.Body)
	}
}

// CJK 多字节字符按 rune 掩码（不得按字节截断产生乱码）。
func TestApplyJSON_CJKRuneSafe(t *testing.T) {
	body := []byte(`{"name":"张三四五六七八"}`)
	res, err := ApplyJSON(body, planOf("name", "MASK", 2, 2))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if got["name"] != "张三***七八" {
		t.Fatalf("cjk mask = %q", got["name"])
	}
}

// 尾随数据回归（LOW-G11）：首个 JSON 值之后存在尾随数据时必须按解析失败返回错误
// （重编码只输出第一个值，尾随字节会被静默丢弃；调用方走 FAIL_OPEN 直通原响应）。
// 仅余空白为合法尾随。
func TestApplyJSON_TrailingData(t *testing.T) {
	for _, body := range []string{
		`{"a":1} {"b":2}`,   // 第二个 JSON 值
		`{"a":1} garbage`,   // 垃圾字节
		`{"a":1}{`,          // 半个值
		`[1,2] [3]`,         // 数组尾随
		`{"a":1} ` + "\x00", // NUL 等非空白字节
	} {
		if _, err := ApplyJSON([]byte(body), planOf("a", "MASK", 1, 1)); err == nil {
			t.Fatalf("trailing data must fail closed to FAIL_OPEN path: %q", body)
		}
	}
	// 仅尾随空白：合法，改写照常执行
	res, err := ApplyJSON([]byte("{\"a\":123456}\n  \t"), planOf("a", "MASK", 1, 1))
	if err != nil {
		t.Fatalf("trailing whitespace must be accepted: %v", err)
	}
	if !strings.Contains(string(res.Body), `"a":"1****6"`) {
		t.Fatalf("mask not applied on whitespace-trailing body: %s", res.Body)
	}
}
