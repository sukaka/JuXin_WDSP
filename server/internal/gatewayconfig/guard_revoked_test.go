// api_revoked_credentials 仅 WDSP 开启且有生效吊销记录时注入；关闭/为空时 JSON 不出现
// 该键（与 api_flow_baselines 同一纪律）；stripAPIGuardSections 一并剥除。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerAPIRevokedCredentials(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIRevokedCredentials = []GuardRevokedCredential{
			{CredentialType: "auth", Fingerprint: "0123456789abcdef0123456789abcdef"},
			{CredentialType: "sess", Fingerprint: "fedcba9876543210fedcba9876543210",
				ExpiresAt: "2027-01-01T00:00:00Z"},
		}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启：注入且指纹载荷原样下发（无凭据明文）
	h := buildGuardHandler(newCfg(), app, 0)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{`"api_revoked_credentials"`, `"credential_type":"auth"`,
		`"fingerprint":"0123456789abcdef0123456789abcdef"`,
		`"credential_type":"sess"`, `"expires_at":"2027-01-01T00:00:00Z"`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// 有清单但 WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), "api_revoked_credentials") {
		t.Error("revoked credentials must not be injected when api dynamic protection disabled")
	}

	// 开启但无生效记录：不注入
	empty := newCfg()
	empty.APIRevokedCredentials = nil
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	if strings.Contains(string(raw), "api_revoked_credentials") {
		t.Error("revoked credentials key must be omitted when empty")
	}

	// 回滚门控：stripAPIGuardSections 剥除该段（快照为 WDSP 开启期产物）
	stripped := stripAPIGuardSections(newCfg())
	if stripped.APIRevokedCredentials != nil {
		t.Error("stripAPIGuardSections must drop api_revoked_credentials")
	}
	raw, _ = json.Marshal(buildGuardHandler(stripped, app, 0))
	if strings.Contains(string(raw), "api_revoked_credentials") {
		t.Error("stripped config must not emit api_revoked_credentials")
	}
}
