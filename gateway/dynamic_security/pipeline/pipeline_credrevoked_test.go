// pipeline_credrevoked_test.go 已吊销凭据检测管线挂接（§35 第10项）。
package pipeline

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// revokedPipeRequest 构造携带指定 Authorization 头的 API 请求。
func revokedPipeRequest(authz string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/revoked-check", nil)
	r.Header.Set("X-Request-Id", "pipe-revoked")
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

// 命中：清单吊销条目（credential_type + 指纹）与请求凭据键全等 → 管线产出
// auth.credential_revoked（OBSERVE/HIGH），证据不含凭据明文。
func TestProcessRevokedCredentialHit(t *testing.T) {
	const token = "Bearer revoked-token-pipe-1"
	fp := detectors.Fingerprint("pipe-salt", token)
	cfg := Config{
		Enabled:      true,
		Mode:         "OBSERVE",
		IdentitySalt: "pipe-salt",
		RevokedCredentials: []detectors.RevokedCredential{
			{CredentialType: "auth", Fingerprint: fp},
		},
	}
	res, err := Process(revokedPipeRequest(token), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "auth.credential_revoked") {
		t.Fatalf("expected auth.credential_revoked, got %+v", res.Context.CopyMatches())
	}
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID != "auth.credential_revoked" {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "HIGH" {
			t.Fatalf("bad attrs: %+v", m)
		}
		for _, v := range m.Evidence {
			if strings.Contains(v, "revoked-token-pipe") {
				t.Fatalf("credential plaintext leaked into evidence: %+v", m.Evidence)
			}
		}
	}
}

// 未命中：清单内指纹与请求凭据不符 → 无该明细；空清单零行为。
func TestProcessRevokedCredentialMissAndEmptyList(t *testing.T) {
	const token = "Bearer legit-token-pipe-2"
	cfg := Config{
		Enabled:      true,
		Mode:         "OBSERVE",
		IdentitySalt: "pipe-salt",
		RevokedCredentials: []detectors.RevokedCredential{
			{CredentialType: "auth", Fingerprint: strings.Repeat("0", 32)},
		},
	}
	res, err := Process(revokedPipeRequest(token), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "auth.credential_revoked") {
		t.Fatalf("non-revoked credential must not match, got %+v", res.Context.CopyMatches())
	}
	// 空清单（未下发）零行为
	res2, err := Process(revokedPipeRequest(token), Config{Enabled: true, Mode: "OBSERVE", IdentitySalt: "pipe-salt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res2, "auth.credential_revoked") {
		t.Fatalf("empty revoked list must not match, got %+v", res2.Context.CopyMatches())
	}
}

// 过期跳过：expires_at 已过条目经管线不判定。
func TestProcessRevokedCredentialExpiredSkipped(t *testing.T) {
	const token = "Bearer revoked-token-pipe-3"
	fp := detectors.Fingerprint("pipe-salt", token)
	cfg := Config{
		Enabled:      true,
		Mode:         "OBSERVE",
		IdentitySalt: "pipe-salt",
		RevokedCredentials: []detectors.RevokedCredential{
			{CredentialType: "auth", Fingerprint: fp, ExpiresAt: time.Now().Add(-time.Hour).Format(time.RFC3339)},
		},
	}
	res, err := Process(revokedPipeRequest(token), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "auth.credential_revoked") {
		t.Fatalf("expired entry must not match, got %+v", res.Context.CopyMatches())
	}
}

// 匿名零行为：无凭据请求即使清单非空也不判定。
func TestProcessRevokedCredentialAnonymous(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		Mode:         "OBSERVE",
		IdentitySalt: "pipe-salt",
		RevokedCredentials: []detectors.RevokedCredential{
			{CredentialType: "auth", Fingerprint: strings.Repeat("1", 32)},
		},
	}
	res, err := Process(revokedPipeRequest(""), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "auth.credential_revoked") {
		t.Fatalf("anonymous request must not match, got %+v", res.Context.CopyMatches())
	}
}

// 非法清单：管线如实返回配置错误，不静默吞错。
func TestProcessRevokedCredentialInvalidListFails(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Mode:    "OBSERVE",
		RevokedCredentials: []detectors.RevokedCredential{
			{CredentialType: "token", Fingerprint: strings.Repeat("a", 32)},
		},
	}
	if _, err := Process(revokedPipeRequest("Bearer x"), cfg, nil); err == nil {
		t.Fatal("invalid revoked list must surface as config error")
	}
}
