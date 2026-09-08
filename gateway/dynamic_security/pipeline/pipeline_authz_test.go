package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// authzJWTReq 构造带未验签 JWT（指定角色）的 JSON POST 请求（仅测试用）。
func authzJWTReq(t *testing.T, role, body string) *http.Request {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"role": role})
	if err != nil {
		t.Fatal(err)
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	tok := hdr + "." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// TestProcessForbiddenFieldProtectEscalates FORBIDDEN 字段：PROTECT 定案 BLOCK，OBSERVE 维持 OBSERVE。
func TestProcessForbiddenFieldProtectEscalates(t *testing.T) {
	perms := []detectors.FieldPermission{{
		EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN",
	}}
	// PROTECT：BLOCK 类违例定案阻断
	res, err := Process(authzJWTReq(t, "ops", `{"role":"admin","note":"n"}`), Config{
		Enabled: true, Mode: "PROTECT", FieldPermissions: perms,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "authz.forbidden_field") {
		t.Fatalf("expected authz.forbidden_field, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("PROTECT final=%s, want BLOCK", res.FinalAction)
	}
	// OBSERVE：同一违例维持观察（证据不落请求值：body 中 "admin" 字样不得出现在证据里）
	res, err = Process(authzJWTReq(t, "ops", `{"role":"admin","note":"n"}`), Config{
		Enabled: true, Mode: "OBSERVE", FieldPermissions: perms,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "authz.forbidden_field") {
		t.Fatalf("expected authz.forbidden_field, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("OBSERVE final=%s, must not block", res.FinalAction)
	}
	for _, m := range res.Context.CopyMatches() {
		if strings.HasPrefix(m.RuleID, "authz.") {
			for k, v := range m.Evidence {
				if strings.Contains(v, "admin") {
					t.Fatalf("evidence must not carry request values: %s=%s", k, v)
				}
			}
		}
	}
}

// TestProcessBFLABaseline 角色基线经管线：匿名 → bfla_anonymous；角色无匹配 → mismatch；命中 → 无明细。
func TestProcessBFLABaseline(t *testing.T) {
	baselines := []detectors.RoleBaseline{{
		EndpointKey: "POST /v1/orders", Role: "ops", Method: "POST", Action: "WRITE", Allowed: true,
	}}
	// 匿名访问有基线端点
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "OBSERVE", RoleBaselines: baselines}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "authz.bfla_anonymous") {
		t.Fatalf("expected authz.bfla_anonymous, got %+v", res.Context.CopyMatches())
	}
	// 角色无匹配 allowed 基线
	res, err = Process(authzJWTReq(t, "viewer", `{"a":1}`), Config{
		Enabled: true, Mode: "OBSERVE", RoleBaselines: baselines,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "authz.bfla_role_mismatch") {
		t.Fatalf("expected authz.bfla_role_mismatch, got %+v", res.Context.CopyMatches())
	}
	// 命中 allowed 基线 → 无 authz 明细
	res, err = Process(authzJWTReq(t, "ops", `{"a":1}`), Config{
		Enabled: true, Mode: "OBSERVE", RoleBaselines: baselines,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Context.CopyMatches() {
		if strings.HasPrefix(m.RuleID, "authz.") {
			t.Fatalf("allowed role must not produce authz match: %+v", m)
		}
	}
}

// TestProcessNoAuthzKeysZeroBehavior 无下发键：无任何 authz.* 明细（行为与现状完全一致）。
func TestProcessNoAuthzKeysZeroBehavior(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders", strings.NewReader(`{"role":"admin"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Context.CopyMatches() {
		if strings.HasPrefix(m.RuleID, "authz.") {
			t.Fatalf("no authz keys must be zero behavior: %+v", m)
		}
	}
}
