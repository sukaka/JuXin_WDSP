// response_deviation_test.go 响应偏离检测的响应相位接线（W9-GW）：
// 基线经 ResponseConfig.ResponseBaselines 注入，三类偏离正反、无基线零行为。
package pipeline

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func deviationBaselines() []detectors.ResponseBaseline {
	return []detectors.ResponseBaseline{{
		EndpointKey: "GET /v1/users/{id}",
		StatusCode:  200,
		Fields:      map[string]string{"id": "number", "name": "string"},
	}}
}

func deviationRules(res *dsctx.RequestContext) map[string]int {
	out := map[string]int{}
	for _, m := range res.CopyMatches() {
		out[m.RuleID]++
	}
	return out
}

// 基线外新字段 → response.schema_new_field（OBSERVE/MEDIUM），证据不落值；动作不受偏离影响。
func TestProcessResponse_DeviationNewField(t *testing.T) {
	ctx := dsctx.New("rid-rd-1", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"id":7,"name":"alice","email":"a@example.com"}`),
	}
	act, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode: decision.ModeProtect, ResponseBaselines: deviationBaselines(),
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionObserve {
		t.Fatalf("deviation is OBSERVE class, got %s", act)
	}
	rules := deviationRules(ctx)
	if rules["response.schema_new_field"] != 1 {
		t.Fatalf("new_field missing: %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "response.schema_new_field" {
			continue
		}
		if m.Evidence["field"] != "email" || m.Evidence["status"] != "200" {
			t.Fatalf("bad evidence: %+v", m.Evidence)
		}
		for _, v := range m.Evidence {
			if v == "a@example.com" || v == "alice" {
				t.Fatalf("evidence must not contain response value: %+v", m.Evidence)
			}
		}
	}
}

// 基线字段缺失 → response.schema_missing_field（OBSERVE/LOW）。
func TestProcessResponse_DeviationMissingField(t *testing.T) {
	ctx := dsctx.New("rid-rd-2", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"id":7}`),
	}
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode: decision.ModeObserve, ResponseBaselines: deviationBaselines(),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	rules := deviationRules(ctx)
	if rules["response.schema_missing_field"] != 1 {
		t.Fatalf("missing_field missing: %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "response.schema_missing_field" && m.Evidence["field"] != "name" {
			t.Fatalf("bad missing_field evidence: %+v", m.Evidence)
		}
	}
}

// 未见状态码 → response.schema_new_status（OBSERVE/INFO），不再比对字段。
func TestProcessResponse_DeviationNewStatus(t *testing.T) {
	ctx := dsctx.New("rid-rd-3", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      404,
		ContentType: "application/json",
		Body:        []byte(`{"error":"not_found"}`),
	}
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode: decision.ModeObserve, ResponseBaselines: deviationBaselines(),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	rules := deviationRules(ctx)
	if rules["response.schema_new_status"] != 1 {
		t.Fatalf("new_status missing: %+v", ctx.CopyMatches())
	}
	if rules["response.schema_new_field"] != 0 || rules["response.schema_missing_field"] != 0 {
		t.Fatalf("new status must not compare fields: %+v", ctx.CopyMatches())
	}
}

// 基线内响应（字段集合与状态码一致）→ 零偏离明细；无基线下发 → 完全零行为。
func TestProcessResponse_DeviationNegative(t *testing.T) {
	// 基线内：无偏离
	ctx := dsctx.New("rid-rd-4", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"id":7,"name":"alice"}`),
	}
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode: decision.ModeObserve, ResponseBaselines: deviationBaselines(),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	for _, m := range ctx.CopyMatches() {
		if m.Detector == "api_response" {
			t.Fatalf("in-baseline response must not deviate: %+v", m)
		}
	}

	// 无基线：同样的偏离报文零行为（与无基线无观测纪律一致）
	ctx = dsctx.New("rid-rd-5", dsctx.DefaultParseLimits())
	in.Body = []byte(`{"unexpected":"shape","extra":1}`)
	if _, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeObserve}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("no baseline must be zero behavior: %+v", ctx.CopyMatches())
	}
}
