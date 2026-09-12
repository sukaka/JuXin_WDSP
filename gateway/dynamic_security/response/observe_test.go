package response

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 类型矩阵：六类一级字段全收录；更深层路径不收录；数组元素形态（[]）属一级。
func TestBuildObservation_TypeMatrix(t *testing.T) {
	body := []byte(`{
		"s": "text",
		"n": 12.5,
		"b": true,
		"o": {"inner": "x"},
		"a": [1, 2],
		"z": null,
		"users": [{"phone": "13800138000", "addr": {"city": "beijing"}}]
	}`)
	fields, isJSON := WalkJSONFields(body, dsctx.DefaultParseLimits())
	if !isJSON {
		t.Fatal("body must parse as JSON")
	}
	obs := BuildObservation(200, "application/json", int64(len(body)), fields)
	if obs == nil {
		t.Fatal("observation must be produced")
	}
	want := map[string]string{
		"s":       "string",
		"n":       "number",
		"b":       "bool",
		"o":       "object",
		"a":       "array",
		"a[]":     "number",
		"z":       "null",
		"users":   "array",
		"users[]": "object",
	}
	if fmt.Sprintf("%v", obs.Fields) != fmt.Sprintf("%v", want) {
		t.Fatalf("fields = %v, want %v", obs.Fields, want)
	}
	if obs.FieldCount != len(want) || obs.Truncated {
		t.Fatalf("count=%d truncated=%v", obs.FieldCount, obs.Truncated)
	}
	if obs.StatusCode != 200 || obs.ContentType != "application/json" || obs.BodySize != int64(len(body)) {
		t.Fatalf("meta = %+v", obs)
	}
	// 不落值：观测 JSON 中绝不含报文值
	data, _ := json.Marshal(obs)
	for _, v := range []string{"13800138000", "beijing", "text"} {
		if strings.Contains(string(data), v) {
			t.Fatalf("observation must not contain value %q: %s", v, data)
		}
	}
}

// 根数组：元素形态 "[]" 为一级；元素字段（[].id）不收录。
func TestBuildObservation_RootArray(t *testing.T) {
	fields, isJSON := WalkJSONFields([]byte(`[{"id": 1}, {"id": 2}]`), dsctx.DefaultParseLimits())
	if !isJSON {
		t.Fatal("array body must parse as JSON")
	}
	obs := BuildObservation(200, "application/json", 18, fields)
	if obs == nil || len(obs.Fields) != 1 || obs.Fields["[]"] != "object" {
		t.Fatalf("root array obs = %+v", obs)
	}
}

// 根标量 / 空对象 / 空输入：无一级字段，不产生观测（事件零变化）。
func TestBuildObservation_NoFields(t *testing.T) {
	for name, body := range map[string]string{
		"root scalar":  `"hello"`,
		"empty object": `{}`,
		"empty array":  `[]`,
	} {
		fields, isJSON := WalkJSONFields([]byte(body), dsctx.DefaultParseLimits())
		if !isJSON {
			t.Fatalf("%s must parse", name)
		}
		if obs := BuildObservation(200, "application/json", int64(len(body)), fields); obs != nil {
			t.Fatalf("%s must produce no observation, got %+v", name, obs)
		}
	}
	if obs := BuildObservation(200, "", 0, nil); obs != nil {
		t.Fatalf("nil fields must produce no observation, got %+v", obs)
	}
}

// 护栏：一级字段数超 64 按路径排序确定性截断，FieldCount 记截断前总数。
func TestBuildObservation_FieldCap(t *testing.T) {
	fields := make(map[string]string, 70)
	for i := 0; i < 70; i++ {
		fields[fmt.Sprintf("f%03d", i)] = "string"
	}
	obs := BuildObservation(200, "application/json", 1024, fields)
	if obs == nil {
		t.Fatal("observation must be produced")
	}
	if len(obs.Fields) != MaxObservedFields {
		t.Fatalf("fields len = %d, want %d", len(obs.Fields), MaxObservedFields)
	}
	if obs.FieldCount != 70 || !obs.Truncated {
		t.Fatalf("count=%d truncated=%v", obs.FieldCount, obs.Truncated)
	}
	// 排序截断：保留 f000..f063，f064 起被截断
	if _, ok := obs.Fields["f063"]; !ok {
		t.Fatal("f063 must be kept")
	}
	if _, ok := obs.Fields["f064"]; ok {
		t.Fatal("f064 must be truncated")
	}
}

// 护栏：单路径超长（>512）跳过并置 Truncated；全部超长时无有效观测。
func TestBuildObservation_LongPath(t *testing.T) {
	longKey := strings.Repeat("k", 600)
	fields := map[string]string{"ok": "string", longKey: "string"}
	obs := BuildObservation(200, "application/json", 2048, fields)
	if obs == nil || len(obs.Fields) != 1 || obs.Fields["ok"] != "string" || !obs.Truncated {
		t.Fatalf("long path obs = %+v", obs)
	}
	if obs := BuildObservation(200, "application/json", 2048, map[string]string{longKey: "string"}); obs != nil {
		t.Fatalf("all-long-paths must produce no observation, got %+v", obs)
	}
}
