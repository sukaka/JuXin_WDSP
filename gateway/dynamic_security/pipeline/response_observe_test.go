package pipeline

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// 响应相位结构观测（P0-06）：合法 JSON 产出观测（一级字段+类型+元信息），动作不受影响。
func TestProcessResponse_ObservationProduced(t *testing.T) {
	ctx := dsctx.New("rid-obs-1", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json; charset=utf-8",
		Body:        []byte(`{"code":0,"data":{"items":[1]},"msg":"ok"}`),
		BodySize:    41,
	}
	act, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeProtect})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionAllow {
		t.Fatalf("observation must not change action, got %s", act)
	}
	rc := ctx.GetResponse()
	if rc == nil || rc.Observation == nil {
		t.Fatalf("observation missing: %+v", rc)
	}
	obs := rc.Observation
	want := map[string]string{"code": "number", "data": "object", "msg": "string"}
	for k, v := range want {
		if obs.Fields[k] != v {
			t.Fatalf("field %s = %q, want %q (obs=%+v)", k, obs.Fields[k], v, obs)
		}
	}
	if _, ok := obs.Fields["data.items"]; ok {
		t.Fatalf("nested path must not be observed: %+v", obs.Fields)
	}
	if obs.StatusCode != 200 || obs.ContentType != in.ContentType || obs.BodySize != 41 || obs.Truncated {
		t.Fatalf("obs meta = %+v", obs)
	}
}

// 非 JSON / 截断 / 流式：无观测，事件零变化。
func TestProcessResponse_ObservationSkipped(t *testing.T) {
	cases := map[string]ResponseInput{
		"non-json":     {Status: 200, ContentType: "text/plain", Body: []byte("hello")},
		"invalid json": {Status: 200, ContentType: "application/json", Body: []byte(`{"a":`)},
		"truncated":    {Status: 200, ContentType: "application/json", Body: []byte(`{"a":1}`), Truncated: true},
		"streamed":     {Status: 200, ContentType: "application/json", Streamed: true},
		"empty body":   {Status: 204, ContentType: "application/json"},
		"scalar root":  {Status: 200, ContentType: "application/json", Body: []byte(`"ok"`)},
	}
	for name, in := range cases {
		ctx := dsctx.New("rid-obs-skip", dsctx.DefaultParseLimits())
		act, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeProtect})
		if err != nil {
			t.Fatalf("%s process: %v", name, err)
		}
		if act != dsctx.ActionAllow {
			t.Fatalf("%s action = %s, want ALLOW", name, act)
		}
		if rc := ctx.GetResponse(); rc == nil || rc.Observation != nil {
			t.Fatalf("%s must not produce observation: %+v", name, rc)
		}
	}
	// 根数组元素为标量时仍有元素形态观测（"[]" → 元素类型）
	ctx := dsctx.New("rid-obs-arr", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(`[1,2]`), BodySize: 5,
	}, ResponseConfig{Mode: decision.ModeProtect}); err != nil {
		t.Fatalf("array process: %v", err)
	}
	if obs := ctx.GetResponse().Observation; obs == nil || obs.Fields["[]"] != "number" {
		t.Fatalf("root scalar-array obs = %+v", obs)
	}
}
