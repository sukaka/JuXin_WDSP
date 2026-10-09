// apiauthz_az3_test.go NG-AZ-03 装配面测试：enforcement 线字段解析（模型四要素 +
// 角色基线 + previous_valid 随行）、旧快照序列化零变化、az/3 能力自报、
// disposition authz_enforcement 证据挂载。
package jiuzhang_guard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// enforcement 线字段解析：模型 enforcement/enforcement_owner/evidence_source/
// on_unknown 与角色基线 enforcement 随发布通道 JSON 进入 Guard 配置（含
// previous_valid 快照随行）；缺省（旧配置无字段）解析为零值。
func TestGuardConfigAPIAuthzEnforcementJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "PROTECT",
		"api_authz_models": [{
			"endpoint_key": "GET /v1/orders/{id}", "path_template": "/v1/orders/{id}",
			"object_type": "ORDER", "identifiers": [{"location": "path", "name": "id", "primary": true}],
			"required_relation": "OWNER", "owner_exclusive": true, "publishable": true,
			"unique_endpoint_template": true,
			"enforcement": "PROTECT", "enforcement_owner": "zhang.lei@example.com",
			"evidence_source": "AUTHORITY_SYNC", "on_unknown": "ALLOW_UNKNOWN"
		}],
		"api_authz_role_baselines": [
			{"endpoint_key": "GET /v1/orders", "role": "ops", "allowed": false, "confirmed": true, "enforcement": "PROTECT"},
			{"endpoint_key": "GET /v1/orders", "role": "reader", "allowed": true, "confirmed": true}
		],
		"api_authz_previous_valid": {
			"models": [{"endpoint_key": "GET /v1/orders/{id}", "object_type": "ORDER",
				"identifiers": [{"location": "path", "name": "id", "primary": true}],
				"required_relation": "OWNER", "owner_exclusive": true, "publishable": true,
				"unique_endpoint_template": true, "enforcement": "OBSERVE"}],
			"object_hmac_key_hex": "3031323334353637383930313233343536373839303132333435363738393031"
		}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIAuthzModels) != 1 {
		t.Fatalf("models = %+v", g.APIAuthzModels)
	}
	m := g.APIAuthzModels[0]
	if m.Enforcement != "PROTECT" || m.EnforcementOwner != "zhang.lei@example.com" ||
		m.EvidenceSource != "AUTHORITY_SYNC" || m.OnUnknown != "ALLOW_UNKNOWN" {
		t.Fatalf("模型 enforcement 四要素未解析: %+v", m)
	}
	if g.APIAuthzRoleBaselines[0].Enforcement != "PROTECT" {
		t.Fatalf("角色基线 enforcement 未解析: %+v", g.APIAuthzRoleBaselines[0])
	}
	if g.APIAuthzRoleBaselines[1].Enforcement != "" {
		t.Fatalf("无行级配置基线 enforcement 应为零值: %+v", g.APIAuthzRoleBaselines[1])
	}
	if g.APIAuthzPreviousValid == nil || len(g.APIAuthzPreviousValid.Models) != 1 ||
		g.APIAuthzPreviousValid.Models[0].Enforcement != "OBSERVE" {
		t.Fatalf("previous_valid 模型 enforcement 未随行: %+v", g.APIAuthzPreviousValid)
	}

	// 旧配置（无 enforcement 字段）：全部零值，行为不变
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log","api_authz_models":[{"endpoint_key":"GET /x/{id}","object_type":"X"}]}`), &legacy); err != nil {
		t.Fatal(err)
	}
	lm := legacy.APIAuthzModels[0]
	if lm.Enforcement != "" || lm.EnforcementOwner != "" || lm.EvidenceSource != "" || lm.OnUnknown != "" {
		t.Fatalf("旧快照 enforcement 字段必须零值: %+v", lm)
	}
}

// 序列化零变化：无 enforcement 字段的模型/基线重新序列化后不出现 enforcement
// 键（omitempty——v1/v2 旧快照经 Guard 配置链往返逐字节不引入新键）。
func TestGuardConfigAPIAuthzEnforcementRoundTripZeroChange(t *testing.T) {
	var model detectors.ObjectModel
	if err := json.Unmarshal([]byte(`{
		"endpoint_key": "GET /v1/orders/{id}", "object_type": "ORDER",
		"required_relation": "OWNER", "owner_exclusive": true, "publishable": true,
		"unique_endpoint_template": true, "on_lease_expired": "degraded"
	}`), &model); err != nil {
		t.Fatal(err)
	}
	g := Guard{AppID: "app-1", APIAuthzModels: []detectors.ObjectModel{model}}
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"enforcement"`, `"enforcement_owner"`, `"evidence_source"`, `"on_unknown"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("零值 enforcement 字段不得出现在序列化输出: %s 含 %s", raw, key)
		}
	}
	// 既有字段（on_lease_expired）不受影响照常序列化
	if !strings.Contains(string(raw), `"on_lease_expired":"degraded"`) {
		t.Fatalf("既有字段序列化不得受影响: %s", raw)
	}
}

// az/3 能力自报：detectors.authzdecide 升 az/3（VERIFIED_VIOLATION 判定与实断执行
// 是新能力——az/2 节点不认识 enforcement 资格判定与阻断执行路径，能力门 fail-closed）。
func TestCapabilityAuthzdecideAz3(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-t1"}, time.Now())
	found := ""
	for _, d := range m.Detectors {
		if d.Name == "authzdecide" {
			found = d.Version
		}
	}
	if found != "az/3" {
		t.Fatalf("detectors.authzdecide 应自报 az/3: %q（manifest %+v）", found, m.Detectors)
	}
	if msg := m.Validate(); msg != "" {
		t.Fatalf("az/3 清单契约校验失败: %s", msg)
	}
}

// disposition authz_enforcement 挂载：证据随 final_decision JSON 输出；
// 先到先得；未挂载路径键省略零变化。
func TestDispositionAuthzEnforcement(t *testing.T) {
	ev := &dsevents.AuthzEnforcementEvidence{
		Decision: "VERIFIED_VIOLATION", ReasonCode: "AUTHZ-BOLA-001", Enforced: true,
		EndpointKey: "GET /v1/orders/{id}", ModelVersion: "model-v9", PolicyVersion: "authz-v3",
		RevocationWatermark: dsevents.AuthzEnforcementWatermark{ManualSeq: 7, Sources: map[string]int64{"src-a": 3}},
		PrincipalSource:     "JWT_VERIFIED",
		ObjectRef:           "objref:abc",
		Eligibility: map[string]bool{"trusted_identity": true, "model_applicable": true, "relation_valid": true,
			"no_conflict": true, "tenant_consistent": true, "evidence_fresh": true, "other_owner": true, "owner_exclusive": true},
		LeaseSeconds: 60, AppliedAtAgeSeconds: 12,
		EnforcementOwner: "zhang.lei@example.com", EvidenceSource: "AUTHORITY_SYNC", RecordedAt: "2026-10-05T00:00:00Z",
	}
	_, d := WithDisposition(t.Context(), "gw-t1")
	d.SetAuthzEnforcement(ev)
	// 先到先得：第二次写入忽略
	d.SetAuthzEnforcement(&dsevents.AuthzEnforcementEvidence{Decision: "VERIFIED_VIOLATION", ReasonCode: "AUTHZ-BFLA-001"})
	d.RecordTerminal(ExecutorAPI, DisActionBlock, 403, true, []string{"AUTHZ_VIOLATION_DENIED"}, nil)
	raw := d.JSON()
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	az, ok := decoded["authz_enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("final_decision 缺 authz_enforcement: %s", raw)
	}
	if az["decision"] != "VERIFIED_VIOLATION" || az["reason_code"] != "AUTHZ-BOLA-001" || az["enforced"] != true {
		t.Fatalf("证据决策头不符: %v", az)
	}
	if az["endpoint_key"] != "GET /v1/orders/{id}" || az["enforcement_owner"] != "zhang.lei@example.com" {
		t.Fatalf("证据伴随字段不符: %v", az)
	}
	// 十五冻结键完整性
	wantKeys := []string{"decision", "reason_code", "enforced", "endpoint_key", "model_version", "policy_version",
		"revocation_watermark", "principal_source", "object_ref", "eligibility", "lease_seconds",
		"applied_at_age_seconds", "enforcement_owner", "evidence_source", "recorded_at"}
	for _, k := range wantKeys {
		if _, present := az[k]; !present {
			t.Fatalf("final_decision.authz_enforcement 缺冻结键 %s: %s", k, raw)
		}
	}
	elig, ok := az["eligibility"].(map[string]any)
	if !ok || len(elig) != 8 {
		t.Fatalf("eligibility 八因子缺失: %v", az["eligibility"])
	}

	// 未挂载路径：final_decision JSON 无 authz_enforcement 键（零变化）
	_, d2 := WithDisposition(t.Context(), "gw-t1")
	d2.RecordTerminal(ExecutorAPI, DisActionBlock, 403, true, []string{"API_ADMISSION_DENIED"}, nil)
	raw2 := d2.JSON()
	if strings.Contains(string(raw2), "authz_enforcement") {
		t.Fatalf("非授权实断路径 final_decision 必须零变化: %s", raw2)
	}

	// nil 接收者与 nil 证据安全
	var nilD *Disposition
	nilD.SetAuthzEnforcement(ev)
	_, d3 := WithDisposition(t.Context(), "gw-t1")
	d3.SetAuthzEnforcement(nil)
	if d3.AuthzEnforcement != nil {
		t.Fatal("nil 证据不得挂载")
	}
}
