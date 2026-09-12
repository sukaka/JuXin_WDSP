// respdeviation_test.go 响应偏离检测（W9-GW）单测：
// 三类偏离正反（新字段/字段缺失/未见状态码）、无基线零行为、仅一级字段参与比对、
// 证据不落响应值、装配期校验与按端点归组。
package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func respBaselineFixture() []ResponseBaseline {
	return []ResponseBaseline{{
		EndpointKey: "GET /v1/users/{id}",
		StatusCode:  200,
		Fields:      map[string]string{"id": "number", "name": "string"},
	}}
}

func deviationMatches(ctx *dsctx.RequestContext, ruleID string) []dsctx.DetectorMatch {
	var out []dsctx.DetectorMatch
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			out = append(out, m)
		}
	}
	return out
}

// 基线外新字段 → response.schema_new_field（OBSERVE/MEDIUM）；证据只含字段路径与状态码。
func TestCheckResponseDeviation_NewField(t *testing.T) {
	ctx := dsctx.New("rid-dev-1", dsctx.DefaultParseLimits())
	fields := map[string]string{"id": "number", "name": "string", "email": "string"}
	CheckResponseDeviation(ctx, 200, true, fields, respBaselineFixture())

	ms := deviationMatches(ctx, "response.schema_new_field")
	if len(ms) != 1 {
		t.Fatalf("want 1 new_field match, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.Detector != "api_response" || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("bad meta: %+v", m)
	}
	if m.Evidence["field"] != "email" || m.Evidence["status"] != "200" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 类型一致且无缺失：不再有其他偏离明细
	if len(ctx.CopyMatches()) != 1 {
		t.Fatalf("unexpected extra matches: %+v", ctx.CopyMatches())
	}
}

// 基线字段缺失 → response.schema_missing_field（OBSERVE/LOW）。
func TestCheckResponseDeviation_MissingField(t *testing.T) {
	ctx := dsctx.New("rid-dev-2", dsctx.DefaultParseLimits())
	fields := map[string]string{"id": "number"}
	CheckResponseDeviation(ctx, 200, true, fields, respBaselineFixture())

	ms := deviationMatches(ctx, "response.schema_missing_field")
	if len(ms) != 1 {
		t.Fatalf("want 1 missing_field match, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.Category != "OBSERVE" || m.Severity != "LOW" {
		t.Fatalf("bad meta: %+v", m)
	}
	if m.Evidence["field"] != "name" || m.Evidence["status"] != "200" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

// 未见状态码 → response.schema_new_status（OBSERVE/INFO），不再比对字段。
func TestCheckResponseDeviation_NewStatus(t *testing.T) {
	ctx := dsctx.New("rid-dev-3", dsctx.DefaultParseLimits())
	fields := map[string]string{"totally": "string", "different": "number"}
	CheckResponseDeviation(ctx, 500, true, fields, respBaselineFixture())

	ms := deviationMatches(ctx, "response.schema_new_status")
	if len(ms) != 1 {
		t.Fatalf("want 1 new_status match, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.Category != "OBSERVE" || m.Severity != "INFO" || m.Evidence["status"] != "500" {
		t.Fatalf("bad new_status match: %+v", m)
	}
	if len(ctx.CopyMatches()) != 1 {
		t.Fatalf("new status must not compare fields: %+v", ctx.CopyMatches())
	}
}

// 完全一致（字段集合与状态码均在基线内）→ 零明细。
func TestCheckResponseDeviation_ExactMatch(t *testing.T) {
	ctx := dsctx.New("rid-dev-4", dsctx.DefaultParseLimits())
	fields := map[string]string{"id": "number", "name": "string"}
	CheckResponseDeviation(ctx, 200, true, fields, respBaselineFixture())
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("exact match must be zero behavior: %+v", ctx.CopyMatches())
	}
}

// 无基线下发 → 零行为（基线缺失不判）；nil 上下文防御。
func TestCheckResponseDeviation_NoBaseline(t *testing.T) {
	ctx := dsctx.New("rid-dev-5", dsctx.DefaultParseLimits())
	fields := map[string]string{"anything": "string"}
	CheckResponseDeviation(ctx, 200, true, fields, nil)
	CheckResponseDeviation(ctx, 999, true, fields, []ResponseBaseline{})
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("no baseline must be zero behavior: %+v", ctx.CopyMatches())
	}
	CheckResponseDeviation(nil, 200, true, fields, respBaselineFixture()) // 不 panic
}

// 非 JSON 响应：仅做状态码判定，字段比对跳过（已知状态码 → 零明细；未见状态码 → new_status）。
func TestCheckResponseDeviation_NonJSON(t *testing.T) {
	ctx := dsctx.New("rid-dev-6", dsctx.DefaultParseLimits())
	CheckResponseDeviation(ctx, 200, false, nil, respBaselineFixture())
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("non-json known status must not judge fields: %+v", ctx.CopyMatches())
	}
	CheckResponseDeviation(ctx, 418, false, nil, respBaselineFixture())
	if ms := deviationMatches(ctx, "response.schema_new_status"); len(ms) != 1 {
		t.Fatalf("non-json unseen status must still be observed: %+v", ctx.CopyMatches())
	}
}

// 仅一级字段参与比对：根占位与含 "." 的深层路径不算新字段（与学习生产方同一口径）。
func TestCheckResponseDeviation_TopLevelOnly(t *testing.T) {
	baselines := []ResponseBaseline{{
		EndpointKey: "GET /v1/users/{id}",
		StatusCode:  200,
		Fields:      map[string]string{"user": "object"},
	}}
	ctx := dsctx.New("rid-dev-7", dsctx.DefaultParseLimits())
	fields := map[string]string{"": "object", "user": "object", "user.phone": "string"}
	CheckResponseDeviation(ctx, 200, true, fields, baselines)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("nested/root paths must not be judged: %+v", ctx.CopyMatches())
	}
}

// 证据不落响应值：响应中的敏感值不得出现在任何明细证据中。
func TestCheckResponseDeviation_EvidenceNoValues(t *testing.T) {
	ctx := dsctx.New("rid-dev-8", dsctx.DefaultParseLimits())
	// fields 只含路径→类型标签（调用方纪律）；此处验证证据只回写路径与状态码
	fields := map[string]string{"id": "number", "name": "string", "secret_token": "string"}
	CheckResponseDeviation(ctx, 200, true, fields, respBaselineFixture())
	for _, m := range ctx.CopyMatches() {
		for k := range m.Evidence {
			if k != "field" && k != "status" {
				t.Fatalf("evidence keys must be field/status only: %+v", m.Evidence)
			}
		}
	}
}

// 明细封顶：单响应每类偏离至多 maxResponseDeviationFindings 条（防超大报文撑爆事件）。
func TestCheckResponseDeviation_Cap(t *testing.T) {
	ctx := dsctx.New("rid-dev-9", dsctx.DefaultParseLimits())
	fields := map[string]string{}
	for i := 0; i < maxResponseDeviationFindings+10; i++ {
		fields[string(rune('a'+i%26))+string(rune('a'+i/26))] = "string"
	}
	CheckResponseDeviation(ctx, 200, true, fields, respBaselineFixture())
	if n := len(deviationMatches(ctx, "response.schema_new_field")); n != maxResponseDeviationFindings {
		t.Fatalf("new_field findings = %d, want cap %d", n, maxResponseDeviationFindings)
	}
	if n := len(deviationMatches(ctx, "response.schema_missing_field")); n != 2 {
		t.Fatalf("missing_field findings = %d, want 2", n)
	}
}

// 装配期校验：endpoint_key 非空、status_code 合法、fields 非空；错误显式返回。
func TestValidateResponseBaselines(t *testing.T) {
	if err := ValidateResponseBaselines(nil); err != nil {
		t.Fatalf("nil must be accepted: %v", err)
	}
	if err := ValidateResponseBaselines(respBaselineFixture()); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}
	cases := map[string]ResponseBaseline{
		"empty endpoint": {EndpointKey: "", StatusCode: 200, Fields: map[string]string{"a": "string"}},
		"bad status low": {EndpointKey: "ek", StatusCode: 99, Fields: map[string]string{"a": "string"}},
		"bad status hi":  {EndpointKey: "ek", StatusCode: 600, Fields: map[string]string{"a": "string"}},
		"empty fields":   {EndpointKey: "ek", StatusCode: 200, Fields: map[string]string{}},
	}
	for name, b := range cases {
		if err := ValidateResponseBaselines([]ResponseBaseline{b}); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

// 按端点归组：运行期按端点 O(1) 选取。
func TestGroupResponseBaselines(t *testing.T) {
	if got := GroupResponseBaselines(nil); got != nil {
		t.Fatalf("nil in must yield nil: %+v", got)
	}
	in := []ResponseBaseline{
		{EndpointKey: "GET /a", StatusCode: 200, Fields: map[string]string{"x": "string"}},
		{EndpointKey: "GET /a", StatusCode: 404, Fields: map[string]string{"error": "string"}},
		{EndpointKey: "POST /b", StatusCode: 200, Fields: map[string]string{"y": "number"}},
	}
	got := GroupResponseBaselines(in)
	if len(got) != 2 || len(got["GET /a"]) != 2 || len(got["POST /b"]) != 1 {
		t.Fatalf("grouping wrong: %+v", got)
	}
}
