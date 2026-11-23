// runtime_test.go 运行时主事件（api_runtime_events）读取侧投影单测：
// jwt_verification 列（迁移 000127，WDSP P0-03）经 ListRuntimeEvents 投影为
// RuntimeEvent.JWTVerification（JSONB 原文透传；NULL/历史事件键省略）。
package apisecurity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRuntimeEventJWTVerificationProjection jwt_verification 投影契约：
// 非 NULL 时原文对象随事件序列化（字段与网关 dynamic_security/events.JWTVerification
// json tag 一致）；NULL 时键省略（omitempty），前端按可选对象做空态。
func TestRuntimeEventJWTVerificationProjection(t *testing.T) {
	base := RuntimeEvent{
		ID:                  uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RequestID:           "req-jwt-1",
		EndpointKey:         "GET /v1/users/{id}",
		RiskScore:           10,
		RiskLevel:           "LOW",
		FinalAction:         "ALLOW",
		Details:             json.RawMessage(`[]`),
		OccurredAt:          time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		IdentityFingerprint: "fp-1",
		AuthType:            "bearer_or_basic",
	}

	// 历史事件：jwt_verification 为 NULL → JSON 键省略（不得回填空对象）
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal legacy event: %v", err)
	}
	if strings.Contains(string(b), "jwt_verification") {
		t.Fatalf("NULL jwt_verification must be omitted, got %s", b)
	}

	// 新事件：JSONB 原文透传（status/reason_code/policy_version/issuer_config_id/
	// keyset_version/verified_principal_id/verified_tenant_id/evaluated_at）
	ev := base
	raw := `{"status":"VERIFIED","reason_code":"VALID","policy_version":"pv-7",` +
		`"issuer_config_id":"iss-1","keyset_version":"ks-3",` +
		`"verified_principal_id":"prin-hmac-abc","verified_tenant_id":"tenant-hmac-def",` +
		`"evaluated_at":"2026-08-01T09:59:58Z"}`
	ev.JWTVerification = json.RawMessage(raw)
	b, err = json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event with jwt_verification: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	jwt, ok := decoded["jwt_verification"].(map[string]any)
	if !ok {
		t.Fatalf("jwt_verification must be an embedded object, got %s", b)
	}
	want := map[string]string{
		"status":                "VERIFIED",
		"reason_code":           "VALID",
		"policy_version":        "pv-7",
		"issuer_config_id":      "iss-1",
		"keyset_version":        "ks-3",
		"verified_principal_id": "prin-hmac-abc",
		"verified_tenant_id":    "tenant-hmac-def",
		"evaluated_at":          "2026-08-01T09:59:58Z",
	}
	for k, v := range want {
		if jwt[k] != v {
			t.Errorf("jwt_verification.%s = %v, want %q", k, jwt[k], v)
		}
	}
}

func TestListViolationsTimeParamValidation(t *testing.T) {
	h := NewHandler(nil, nil)
	cases := []struct {
		name string
		url  string
	}{
		{"invalid start_time", "/api/v1/api-security/violations?start_time=not-a-time"},
		{"invalid end_time", "/api/v1/api-security/violations?end_time=2026-99-99"},
		{"start_time after end_time", "/api/v1/api-security/violations?start_time=2026-08-02T00:00:00Z&end_time=2026-08-01T00:00:00Z"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		rr := httptest.NewRecorder()
		h.ListViolations(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400 (body=%s)", tc.name, rr.Code, rr.Body.String())
		}
	}
}
