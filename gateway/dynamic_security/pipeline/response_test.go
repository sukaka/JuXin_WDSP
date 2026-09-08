package pipeline

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

// 完整响应相位：JSON 解析 + 敏感字段检测 + transform plan + PROTECT 决策 MASK_RESPONSE。
func TestProcessResponse_MaskPlanProtect(t *testing.T) {
	ctx := dsctx.New("rid-resp-1", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"user":{"phone":"13800138000","name":"x"}}`),
		BodySize:    48,
	}
	cfg := ResponseConfig{
		Mode: decision.ModeProtect,
		MaskRules: []response.MaskRule{
			{EndpointKey: "GET /v1/users", FieldPath: "user.phone", DataType: "phone", Algorithm: response.AlgorithmMask, KeepHead: 3, KeepTail: 4},
		},
	}
	act, err := ProcessResponse(ctx, in, cfg)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionMaskResp {
		t.Fatalf("action = %s, want MASK_RESPONSE", act)
	}
	rc := ctx.GetResponse()
	if rc == nil || !rc.IsJSON || rc.Status != 200 {
		t.Fatalf("response ctx: %+v", rc)
	}
	if len(rc.TransformPlan) != 1 || rc.TransformPlan[0].FieldPath != "user.phone" {
		t.Fatalf("plan: %+v", rc.TransformPlan)
	}
	if len(rc.SensitiveFields) != 1 || rc.SensitiveFields[0].DataType != "phone" {
		t.Fatalf("sensitive: %+v", rc.SensitiveFields)
	}
	// 事件明细：敏感字段 + mask_plan，证据不含明文值
	var foundSensitive, foundPlan bool
	for _, m := range ctx.CopyMatches() {
		switch m.RuleID {
		case "sensitive.response_field":
			foundSensitive = true
			if m.Evidence["direction"] != "RESPONSE" {
				t.Fatalf("response-side sensitive evidence must carry direction=RESPONSE: %+v", m.Evidence)
			}
			for _, v := range m.Evidence {
				if v == "13800138000" {
					t.Fatalf("evidence must not contain value: %+v", m.Evidence)
				}
			}
		case "response.mask_plan":
			foundPlan = true
		}
	}
	if !foundSensitive || !foundPlan {
		t.Fatalf("matches: %+v", ctx.CopyMatches())
	}
}

// OBSERVE 模式：计划仅记录，动作保持 OBSERVE。
func TestProcessResponse_MaskPlanObserve(t *testing.T) {
	ctx := dsctx.New("rid-resp-2", dsctx.DefaultParseLimits())
	in := ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"phone":"13800138000"}`)}
	cfg := ResponseConfig{
		Mode:      decision.ModeObserve,
		MaskRules: []response.MaskRule{{EndpointKey: "ek", FieldPath: "phone", Algorithm: response.AlgorithmHash}},
	}
	act, err := ProcessResponse(ctx, in, cfg)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionObserve {
		t.Fatalf("OBSERVE mode must not mask, got %s", act)
	}
	if len(ctx.GetResponse().TransformPlan) != 1 {
		t.Fatal("plan must be recorded in observe mode")
	}
}

// 非 JSON 响应：跳过解析，无计划，无敏感检测，动作不受响应相位影响。
func TestProcessResponse_NonJSONSkipped(t *testing.T) {
	ctx := dsctx.New("rid-resp-3", dsctx.DefaultParseLimits())
	in := ResponseInput{Status: 200, ContentType: "text/plain", Body: []byte("password=maybe-here")}
	cfg := ResponseConfig{
		Mode:      decision.ModeProtect,
		MaskRules: []response.MaskRule{{EndpointKey: "ek", FieldPath: "password", Algorithm: response.AlgorithmRemove}},
	}
	act, err := ProcessResponse(ctx, in, cfg)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionAllow {
		t.Fatalf("non-json must not produce mask action, got %s", act)
	}
	rc := ctx.GetResponse()
	if rc.IsJSON || len(rc.TransformPlan) != 0 || len(rc.SensitiveFields) != 0 {
		t.Fatalf("non-json must skip parse/detect/plan: %+v", rc)
	}
}

// 截断/流式：不解析、不生成计划（由挂点侧按失败策略处理）。
func TestProcessResponse_TruncatedAndStreamed(t *testing.T) {
	rules := []response.MaskRule{{EndpointKey: "ek", FieldPath: "phone", Algorithm: response.AlgorithmMask}}
	in := ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"phone":"138`), Truncated: true, BodySize: 1 << 21}
	ctx := dsctx.New("rid-resp-4", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeProtect, MaskRules: rules})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionAllow {
		t.Fatalf("truncated must not mask, got %s", act)
	}
	if rc := ctx.GetResponse(); !rc.Truncated || rc.IsJSON || len(rc.TransformPlan) != 0 {
		t.Fatalf("truncated ctx: %+v", rc)
	}

	ctx2 := dsctx.New("rid-resp-5", dsctx.DefaultParseLimits())
	act2, err := ProcessResponse(ctx2, ResponseInput{Status: 200, ContentType: "text/event-stream", Streamed: true, BodySize: 128}, ResponseConfig{Mode: decision.ModeProtect, MaskRules: rules})
	if err != nil {
		t.Fatalf("process streamed: %v", err)
	}
	if act2 != dsctx.ActionAllow {
		t.Fatalf("streamed must not mask, got %s", act2)
	}
	if rc := ctx2.GetResponse(); !rc.Streamed || rc.BodySize != 128 {
		t.Fatalf("streamed ctx: %+v", rc)
	}
}

// 5xx + 堆栈特征：错误签名入上下文与事件明细。
func TestProcessResponse_ErrorSignatures(t *testing.T) {
	ctx := dsctx.New("rid-resp-6", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      500,
		ContentType: "application/json",
		Body:        []byte(`{"error":"boom","trace":"panic: runtime error"}`),
	}
	act, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeProtect})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionObserve {
		t.Fatalf("error signature is OBSERVE class, got %s", act)
	}
	rc := ctx.GetResponse()
	if len(rc.ErrorSignatures) != 2 || rc.ErrorSignatures[0] != "http_5xx" || rc.ErrorSignatures[1] != "stack.go_panic" {
		t.Fatalf("signatures: %v", rc.ErrorSignatures)
	}
	found := false
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "response.error_signature" && m.Severity == "MEDIUM" {
			found = true
		}
	}
	if !found {
		t.Fatalf("error_signature match missing: %+v", ctx.CopyMatches())
	}
}

// nil 上下文防御 + 无规则无异常时 ALLOW。
func TestProcessResponse_NilAndClean(t *testing.T) {
	act, err := ProcessResponse(nil, ResponseInput{Status: 200}, ResponseConfig{})
	if err != nil || act != dsctx.ActionAllow {
		t.Fatalf("nil ctx: %v %s", err, act)
	}
	ctx := dsctx.New("rid-resp-7", dsctx.DefaultParseLimits())
	act, err = ProcessResponse(ctx, ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`)}, ResponseConfig{Mode: decision.ModeProtect})
	if err != nil || act != dsctx.ActionAllow {
		t.Fatalf("clean: %v %s", err, act)
	}
}
