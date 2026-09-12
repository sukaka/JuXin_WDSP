// apirevokedcred_test.go api_revoked_credentials 发布字段反序列化、装配校验与端到端管线命中（§35 第10项）。
package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// api_revoked_credentials 发布字段反序列化（条目粒度：credential_type + fingerprint +
// expires_at）；旧版配置无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIRevokedCredentialsJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_revoked_credentials": [
			{"credential_type": "auth", "fingerprint": "` + strings.Repeat("a", 32) + `"},
			{"credential_type": "key", "fingerprint": "` + strings.Repeat("b", 32) + `", "expires_at": "2026-12-31T23:59:59Z"},
			{"credential_type": "sess", "fingerprint": "` + strings.Repeat("c", 32) + `"}
		],
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIRevokedCredentials) != 3 {
		t.Fatalf("revoked credentials = %+v", g.APIRevokedCredentials)
	}
	if g.APIRevokedCredentials[0].CredentialType != "auth" || g.APIRevokedCredentials[0].ExpiresAt != "" {
		t.Fatalf("entry 0 = %+v", g.APIRevokedCredentials[0])
	}
	if g.APIRevokedCredentials[1].ExpiresAt != "2026-12-31T23:59:59Z" {
		t.Fatalf("entry 1 = %+v", g.APIRevokedCredentials[1])
	}
	// 装配校验（与 Provision/Validate 同一路径）
	if err := detectors.ValidateRevokedCredentials(g.APIRevokedCredentials); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIRevokedCredentials != nil {
		t.Fatal("legacy config must leave revoked credentials nil")
	}
}

// 非法清单装配期拒绝（Guard.Validate 经 detectors.ValidateRevokedCredentials；
// 不静默吞错——错误须指明条目下标与原因）。
func TestGuardConfigAPIRevokedCredentialsRejectInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"类型词表外", `{"credential_type":"token","fingerprint":"` + strings.Repeat("a", 32) + `"}`, "credential_type 非法"},
		{"指纹长度非法", `{"credential_type":"auth","fingerprint":"abcd"}`, "32 位 hex"},
		{"指纹非 hex", `{"credential_type":"auth","fingerprint":"` + strings.Repeat("g", 32) + `"}`, "非 hex"},
		{"指纹大写", `{"credential_type":"auth","fingerprint":"` + strings.Repeat("A", 32) + `"}`, "小写"},
		{"expires_at 非法", `{"credential_type":"key","fingerprint":"` + strings.Repeat("b", 32) + `","expires_at":"soon"}`, "expires_at 非 RFC3339"},
	}
	for _, tc := range cases {
		var g Guard
		raw := `{"app_id":"a","events_log":"/tmp/e.log","api_dynamic_protection":true,"api_revoked_credentials":[` + tc.raw + `]}`
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		err := g.Validate()
		if err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "api_revoked_credentials[0]") {
			t.Errorf("%s: 错误 %q 未含段名/下标与 %q", tc.name, err.Error(), tc.want)
		}
	}
}

// 端到端：请求 Authorization 凭据指纹命中下发吊销清单 → 经统一管线产出
// auth.credential_revoked（OBSERVE/HIGH）并注入请求上下文；证据不含凭据明文。
func TestServeNext_RevokedCredentialHit(t *testing.T) {
	const token = "Bearer revoked-token-e2e-1"
	// newAPITestGuard 未配置 identity_salt → CredentialKey 走固定域分隔前缀口径
	fp := detectors.Fingerprint("", token)
	g, _ := newAPITestGuard(t, "OBSERVE", nil)
	g.APIRevokedCredentials = []detectors.RevokedCredential{
		{CredentialType: "auth", Fingerprint: fp},
	}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", token)
	req.Header.Set("X-Request-Id", "req-revoked-e2e")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("RequestContext not injected into request context")
	}
	var found *bool
	for _, m := range rc.CopyMatches() {
		if m.RuleID != "auth.credential_revoked" {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "HIGH" {
			t.Fatalf("bad attrs: %+v", m)
		}
		if m.Evidence["credential_type"] != "auth" || m.Evidence["fingerprint"] != fp {
			t.Fatalf("bad evidence: %+v", m.Evidence)
		}
		for _, v := range m.Evidence {
			if strings.Contains(v, "revoked-token-e2e") {
				t.Fatalf("credential plaintext leaked into evidence: %+v", m.Evidence)
			}
		}
		ok := true
		found = &ok
	}
	if found == nil {
		t.Fatalf("expected auth.credential_revoked match, got %+v", rc.CopyMatches())
	}
}

// 端到端负例：凭据未在吊销清单 / 未下发清单（nil）均不产该明细。
func TestServeNext_RevokedCredentialMiss(t *testing.T) {
	g, _ := newAPITestGuard(t, "OBSERVE", nil)
	g.APIRevokedCredentials = []detectors.RevokedCredential{
		{CredentialType: "auth", Fingerprint: strings.Repeat("0", 32)},
	}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "Bearer legit-token-e2e-2")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	rc := RequestContextFrom(req)
	for _, m := range rc.CopyMatches() {
		if m.RuleID == "auth.credential_revoked" {
			t.Fatalf("non-revoked credential must not match, got %+v", rc.CopyMatches())
		}
	}

	g2, _ := newAPITestGuard(t, "OBSERVE", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req2.Header.Set("Authorization", "Bearer legit-token-e2e-3")
	if err := g2.serveNext(httptest.NewRecorder(), req2, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	for _, m := range RequestContextFrom(req2).CopyMatches() {
		if m.RuleID == "auth.credential_revoked" {
			t.Fatalf("nil revoked list must not match")
		}
	}
}
