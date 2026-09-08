// response_authz_test.go 响应方向字段权限的响应相位接线（W11-RAUTHZ，P0-17 响应侧防越权读取）：
// 权限行经 ResponseConfig.FieldPermissions 注入、请求角色经 RequestRoles 注入；
// FORBIDDEN/SENSITIVE 正反、role 覆盖行、与脱敏计划/敏感检测去重、证据不落值、无下发零行为。
package pipeline

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func authzPerms(direction, attribute, field, role string) []detectors.FieldPermission {
	return []detectors.FieldPermission{{
		EndpointKey: "GET /v1/orders", FieldPath: field, Direction: direction, Attribute: attribute, Role: role,
	}}
}

// FORBIDDEN 字段随响应返回 → authz.response_forbidden_field（OBSERVE/MEDIUM；不定案，动作 OBSERVE 类）；
// 证据只含字段路径/属性/角色名，不落响应值。
func TestProcessResponse_AuthzForbiddenField(t *testing.T) {
	ctx := dsctx.New("rid-ra-1", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"role":"admin","name":"alice"}`),
	}
	act, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeProtect,
		EndpointKey:      "GET /v1/orders",
		RequestRoles:     []string{"ops"},
		FieldPermissions: authzPerms("RESPONSE", "FORBIDDEN", "json.role", ""),
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionObserve {
		t.Fatalf("response authz is OBSERVE class, got %s", act)
	}
	rules := deviationRules(ctx)
	if rules["authz.response_forbidden_field"] != 1 {
		t.Fatalf("forbidden finding missing: %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "authz.response_forbidden_field" {
			continue
		}
		if m.Evidence["field"] != "role" || m.Evidence["attribute"] != "FORBIDDEN" ||
			m.Evidence["location"] != "response_json" || m.Evidence["roles"] != "ops" ||
			m.Evidence["endpoint_key"] != "GET /v1/orders" {
			t.Fatalf("bad evidence: %+v", m.Evidence)
		}
		for _, v := range m.Evidence {
			if v == "admin" || v == "alice" {
				t.Fatalf("evidence must not contain response value: %+v", m.Evidence)
			}
		}
	}
}

// FORBIDDEN 字段同被 REMOVE 脱敏规则覆盖：脱敏治理优先，不重复产出越权明细；
// 计划非空且 PROTECT → MASK_RESPONSE（脱敏链路不受影响）。
func TestProcessResponse_AuthzForbiddenMaskedDedup(t *testing.T) {
	ctx := dsctx.New("rid-ra-2", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"role":"admin","name":"alice"}`),
	}
	act, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:        decision.ModeProtect,
		EndpointKey: "GET /v1/orders",
		MaskRules: []response.MaskRule{
			{EndpointKey: "GET /v1/orders", FieldPath: "role", DataType: "role", Algorithm: response.AlgorithmRemove},
		},
		FieldPermissions: authzPerms("RESPONSE", "FORBIDDEN", "json.role", ""),
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if act != dsctx.ActionMaskResp {
		t.Fatalf("mask plan must still finalize MASK_RESPONSE, got %s", act)
	}
	rules := deviationRules(ctx)
	if rules["authz.response_forbidden_field"] != 0 {
		t.Fatalf("masked forbidden field must be deduped: %+v", ctx.CopyMatches())
	}
	if rules["response.mask_plan"] != 1 {
		t.Fatalf("mask plan must be generated: %+v", ctx.CopyMatches())
	}
}

// SENSITIVE 属性字段：未被敏感字段检测命中 → authz.response_sensitive_field（OBSERVE/LOW）；
// 已被敏感检测命中（同路径）→ 不重复产出（仅 sensitive.response_field）。
func TestProcessResponse_AuthzSensitiveField(t *testing.T) {
	// internal_note 不在内置敏感词表：权限行独立产出
	ctx := dsctx.New("rid-ra-3", dsctx.DefaultParseLimits())
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"internal_note":"vip","ok":true}`),
	}
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		FieldPermissions: authzPerms("RESPONSE", "SENSITIVE", "json.internal_note", ""),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	rules := deviationRules(ctx)
	if rules["authz.response_sensitive_field"] != 1 {
		t.Fatalf("sensitive finding missing: %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "authz.response_sensitive_field" {
			if m.Severity != "LOW" || m.Evidence["attribute"] != "SENSITIVE" {
				t.Fatalf("bad sensitive finding: %+v", m)
			}
			for _, v := range m.Evidence {
				if v == "vip" {
					t.Fatalf("evidence must not contain response value: %+v", m.Evidence)
				}
			}
		}
	}
	// password 命中内置 credential 词表：敏感检测已产出，权限行不重复
	ctx = dsctx.New("rid-ra-4", dsctx.DefaultParseLimits())
	in.Body = []byte(`{"password":"p@ss"}`)
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		FieldPermissions: authzPerms("RESPONSE", "SENSITIVE", "json.password", ""),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	rules = deviationRules(ctx)
	if rules["sensitive.response_field"] != 1 {
		t.Fatalf("sensitive detector must fire: %+v", ctx.CopyMatches())
	}
	if rules["authz.response_sensitive_field"] != 0 {
		t.Fatalf("detector-covered field must be deduped: %+v", ctx.CopyMatches())
	}
}

// role 覆盖行在响应侧按请求角色判定：行内角色命中才产出。
func TestProcessResponse_AuthzRoleOverride(t *testing.T) {
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"role":"admin"}`),
	}
	perms := authzPerms("RESPONSE", "FORBIDDEN", "json.role", "guest")
	// 请求角色 ops：覆盖行不适用 → 零行为
	ctx := dsctx.New("rid-ra-5", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		RequestRoles:     []string{"ops"},
		FieldPermissions: perms,
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if deviationRules(ctx)["authz.response_forbidden_field"] != 0 {
		t.Fatalf("role-scoped row must not fire for other roles: %+v", ctx.CopyMatches())
	}
	// 请求角色 guest：覆盖行适用 → 产出
	ctx = dsctx.New("rid-ra-6", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		RequestRoles:     []string{"guest"},
		FieldPermissions: perms,
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	m := deviationRules(ctx)
	if m["authz.response_forbidden_field"] != 1 {
		t.Fatalf("role-scoped row must fire for the scoped role: %+v", ctx.CopyMatches())
	}
}

// 零行为边界：无权限下发 / 仅 REQUEST 方向行 / 非 JSON 响应（无解析产物）→ 无 api_authz 明细。
func TestProcessResponse_AuthzZeroBehavior(t *testing.T) {
	in := ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"role":"admin"}`),
	}
	// 无权限下发
	ctx := dsctx.New("rid-ra-7", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, in, ResponseConfig{Mode: decision.ModeObserve, EndpointKey: "GET /v1/orders"}); err != nil {
		t.Fatalf("process: %v", err)
	}
	for _, m := range ctx.CopyMatches() {
		if m.Detector == "api_authz" {
			t.Fatalf("no perms must be zero behavior: %+v", m)
		}
	}
	// 仅 REQUEST 方向行（响应侧不消费）
	ctx = dsctx.New("rid-ra-8", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, in, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		FieldPermissions: authzPerms("REQUEST", "FORBIDDEN", "json.role", ""),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	for _, m := range ctx.CopyMatches() {
		if m.Detector == "api_authz" {
			t.Fatalf("REQUEST rows must be skipped on response side: %+v", m)
		}
	}
	// 非 JSON 响应：无解析产物，权限行不可判定
	ctx = dsctx.New("rid-ra-9", dsctx.DefaultParseLimits())
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "text/plain", Body: []byte(`role=admin`),
	}, ResponseConfig{
		Mode:             decision.ModeObserve,
		EndpointKey:      "GET /v1/orders",
		FieldPermissions: authzPerms("RESPONSE", "FORBIDDEN", "json.role", ""),
	}); err != nil {
		t.Fatalf("process: %v", err)
	}
	for _, m := range ctx.CopyMatches() {
		if m.Detector == "api_authz" {
			t.Fatalf("non-JSON response must be zero behavior: %+v", m)
		}
	}
}
