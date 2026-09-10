// guard_authz_test.go 授权基线下发键（api_role_baselines / api_field_permissions）注入单测（W4-GW）：
// 仅 WDSP 开启且非空时注入；关闭或空时 JSON 不出现对应键（json tag 为跨分片契约，不得改动）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestBuildGuardHandlerAuthzRules 授权基线两段：开启且有值时按契约键注入；
// WDSP 关闭或空切片时一律不注入（与既有下发面最小纪律一致）。
func TestBuildGuardHandlerAuthzRules(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIRoleBaselines = []GuardRoleBaseline{{
			EndpointKey: "GET /v1/orders", Role: "ops", Method: "GET", Action: "READ", Allowed: true,
		}}
		g.APIFieldPermissions = []GuardFieldPermission{{
			EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN",
		}}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启：两段注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_role_baselines"`, `"endpoint_key":"GET /v1/orders"`, `"role":"ops"`,
		`"method":"GET"`, `"action":"READ"`, `"allowed":true`,
		`"api_field_permissions"`, `"endpoint_key":"POST /v1/orders"`, `"field_path":"json.role"`,
		`"direction":"REQUEST"`, `"attribute":"FORBIDDEN"`, `"role":""`, `"tenant":""`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：两段一律不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	j = string(raw)
	for _, key := range []string{"api_role_baselines", "api_field_permissions"} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must not be injected when api dynamic protection disabled", key)
		}
	}

	// 开启但空：不注入（网关无下发键时行为与现状完全一致）
	empty := testGuardConfig()
	empty.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	j = string(raw)
	for _, key := range []string{"api_role_baselines", "api_field_permissions"} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must be omitted when empty", key)
		}
	}
}

func TestBuildGuardHandlerAuthzBFLAOnly(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIAuthzRoleBaselines = []GuardAuthzRoleBaseline{{
		EndpointKey: "GET /v1/admin", Role: "support", Action: "READ", Allowed: true,
	}}

	raw, err := json.Marshal(buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	var handler map[string]any
	if err := json.Unmarshal(raw, &handler); err != nil {
		t.Fatal(err)
	}
	if _, ok := handler["api_authz_role_baselines"]; !ok {
		t.Fatalf("BFLA-only authorization snapshot must be rendered: %s", raw)
	}
	if _, ok := handler["api_authz_models"]; ok {
		t.Fatalf("BFLA-only authorization snapshot must not render empty models: %s", raw)
	}
	if _, ok := handler["api_authz_object_hmac_key_hex"]; ok {
		t.Fatalf("BFLA-only authorization snapshot must not render an object HMAC key: %s", raw)
	}
}

func TestBuildGuardHandlerAuthzPreviousValidSnapshot(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIAuthzSnapshotStale = true
	currentKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	oldKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	g.APIAuthzObjectHMACKeyHex = currentKey
	expiresAt := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	g.APIAuthzPreviousValid = &GuardAuthzSnapshot{
		Models: []GuardAuthzObjectModel{{
			ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", Method: "GET",
			PathTemplate: "/v1/orders/{id}", ObjectType: "ORDER",
			Identifiers:      []GuardAuthzObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
			RequiredRelation: "owner", OwnerExclusive: true, Publishable: true,
			UniqueEndpointTemplate: true, PolicyVersion: "previous-v1", ModelVersion: "model-7",
			SnapshotExpiresAt: &expiresAt,
		}},
		Relations: []GuardAuthzObjectRelation{{
			ApplicationID: "app-1", PrincipalID: "user-7", ObjectType: "ORDER", ObjectRef: "order-9",
			Relation: "owner", Status: "confirmed", TenantID: "tenant-1",
			ValidUntil: &expiresAt,
		}},
		RoleBaselines: []GuardAuthzRoleBaseline{{
			ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", Method: "GET",
			Role: "support", Action: "READ", Allowed: true, Confirmed: true,
		}},
		ObjectHMACKeyHex:  oldKey,
		PolicyVersion:     "previous-v1",
		Stale:             true,
		SnapshotExpiresAt: &expiresAt,
	}
	raw, err := json.Marshal(buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0))
	if err != nil {
		t.Fatal(err)
	}
	var handler map[string]any
	if err := json.Unmarshal(raw, &handler); err != nil {
		t.Fatal(err)
	}
	if handler["api_authz_snapshot_stale"] != true {
		t.Fatalf("stale marker missing: %s", raw)
	}
	previous, ok := handler["api_authz_previous_valid"].(map[string]any)
	if !ok {
		t.Fatalf("previous snapshot missing: %s", raw)
	}
	if previous["object_hmac_key_hex"] != currentKey {
		t.Fatalf("previous snapshot key must be replaced with current runtime secret: %s", raw)
	}
	if previous["object_hmac_key_hex"] == oldKey {
		t.Fatalf("previous snapshot must not render the historical secret: %s", raw)
	}
	if previous["policy_version"] != "previous-v1" || previous["stale"] != true {
		t.Fatalf("previous snapshot metadata must be preserved: %s", raw)
	}
	if previous["snapshot_expires_at"] != expiresAt.Format(time.RFC3339Nano) {
		t.Fatalf("previous snapshot expiry must be preserved: %s", raw)
	}
	models, ok := previous["models"].([]any)
	if !ok || len(models) != 1 {
		t.Fatalf("previous snapshot model must be rendered: %s", raw)
	}
	model, ok := models[0].(map[string]any)
	if !ok || model["required_relation"] != "owner" || model["model_version"] != "model-7" {
		t.Fatalf("previous snapshot model fields must be preserved: %s", raw)
	}
	identifiers, ok := model["identifiers"].([]any)
	if !ok || len(identifiers) != 1 || identifiers[0].(map[string]any)["name"] != "id" {
		t.Fatalf("previous snapshot identifiers must be rendered: %s", raw)
	}
	relations, ok := previous["relations"].([]any)
	if !ok || len(relations) != 1 || relations[0].(map[string]any)["object_ref"] != "order-9" {
		t.Fatalf("previous snapshot relations must be rendered: %s", raw)
	}
	roles, ok := previous["role_baselines"].([]any)
	if !ok || len(roles) != 1 || roles[0].(map[string]any)["role"] != "support" {
		t.Fatalf("previous snapshot role baselines must be rendered: %s", raw)
	}
	redacted, err := RedactConfigSecrets(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redacted, currentKey) || strings.Contains(redacted, oldKey) || !strings.Contains(redacted, `"object_hmac_key_hex":"***"`) {
		t.Fatalf("previous snapshot key must be redacted: %s", redacted)
	}
}
