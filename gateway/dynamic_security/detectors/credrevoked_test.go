package detectors

import (
	"strings"
	"testing"
	"time"
)

// revokedTestNow 固定的判定时刻（过期边界确定性）。
var revokedTestNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func revokedTestIndex(t *testing.T, list []RevokedCredential) map[string]time.Time {
	t.Helper()
	idx, err := IndexRevokedCredentials(list)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	return idx
}

// ---------- 装配期校验 ----------

// 合法清单通过校验；nil/空清单零错误（未下发 = 合法零行为）。
func TestValidateRevokedCredentials_Valid(t *testing.T) {
	if err := ValidateRevokedCredentials(nil); err != nil {
		t.Fatalf("nil list must be valid: %v", err)
	}
	list := []RevokedCredential{
		{CredentialType: "auth", Fingerprint: strings.Repeat("a", 32)},
		{CredentialType: "key", Fingerprint: strings.Repeat("0123456789abcdef", 2), ExpiresAt: "2026-12-31T23:59:59Z"},
		{CredentialType: "sess", Fingerprint: strings.Repeat("0", 32)},
	}
	if err := ValidateRevokedCredentials(list); err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
}

// 非法条目逐项拒绝：类型词表外、指纹长度、非 hex、大写 hex（请求侧恒为小写，
// 大写永远不可能命中，属配置错误）、expires_at 非 RFC3339。错误须指明下标与原因。
func TestValidateRevokedCredentials_RejectInvalid(t *testing.T) {
	cases := []struct {
		name string
		item RevokedCredential
		want string
	}{
		{"类型词表外", RevokedCredential{CredentialType: "token", Fingerprint: strings.Repeat("a", 32)}, "credential_type 非法"},
		{"空类型", RevokedCredential{CredentialType: "", Fingerprint: strings.Repeat("a", 32)}, "credential_type 非法"},
		{"指纹过短", RevokedCredential{CredentialType: "auth", Fingerprint: "abcd"}, "32 位 hex"},
		{"指纹非 hex", RevokedCredential{CredentialType: "auth", Fingerprint: strings.Repeat("g", 32)}, "非 hex"},
		{"指纹大写", RevokedCredential{CredentialType: "auth", Fingerprint: strings.Repeat("A", 32)}, "小写"},
		{"expires_at 非法", RevokedCredential{CredentialType: "auth", Fingerprint: strings.Repeat("a", 32), ExpiresAt: "tomorrow"}, "expires_at 非 RFC3339"},
	}
	for _, tc := range cases {
		err := ValidateRevokedCredentials([]RevokedCredential{tc.item})
		if err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "[0]") {
			t.Errorf("%s: 错误 %q 未含下标与 %q", tc.name, err.Error(), tc.want)
		}
	}
	// Index 复用同一校验：非法清单建索引同样报错，不静默吞错
	if _, err := IndexRevokedCredentials([]RevokedCredential{{CredentialType: "bad", Fingerprint: "x"}}); err == nil {
		t.Fatal("index on invalid list must fail")
	}
}

// ---------- 比对命中 ----------

// 命中：auth 类型永久吊销（无 expires_at）→ OBSERVE/HIGH，ScoreDelta 30；
// 证据只含 credential_type 与 fingerprint 两项。
func TestCredentialRevoked_Hit(t *testing.T) {
	fp := strings.Repeat("b", 32)
	idx := revokedTestIndex(t, []RevokedCredential{{CredentialType: "auth", Fingerprint: fp}})
	ctx := authTestCtx()
	CheckCredentialRevoked(ctx, "auth:"+fp, idx, revokedTestNow)
	m := findMatch(ctx, "auth.credential_revoked")
	if m == nil {
		t.Fatalf("revoked credential must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["credential_type"] != "auth" || m.Evidence["fingerprint"] != fp {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	if len(m.Evidence) != 2 {
		t.Fatalf("evidence must only carry type and fingerprint: %+v", m.Evidence)
	}
}

// 未过期条目（expires_at 在判定时刻之后）仍命中；三种类型各自命中。
func TestCredentialRevoked_HitBeforeExpiryAndTypes(t *testing.T) {
	future := revokedTestNow.Add(time.Hour).Format(time.RFC3339)
	for _, typ := range []string{"auth", "key", "sess"} {
		fp := strings.Repeat("c", 32)
		idx := revokedTestIndex(t, []RevokedCredential{{CredentialType: typ, Fingerprint: fp, ExpiresAt: future}})
		ctx := authTestCtx()
		CheckCredentialRevoked(ctx, typ+":"+fp, idx, revokedTestNow)
		if m := findMatch(ctx, "auth.credential_revoked"); m == nil {
			t.Fatalf("%s: unexpired revoked credential must match", typ)
		} else if m.Evidence["credential_type"] != typ {
			t.Fatalf("%s: bad evidence type: %+v", typ, m.Evidence)
		}
	}
}

// ---------- 负例 ----------

// 未命中：清单中无该凭据键；类型相同但指纹不同、指纹相同但类型不同均不判（全等匹配）。
func TestCredentialRevoked_Miss(t *testing.T) {
	fp := strings.Repeat("d", 32)
	idx := revokedTestIndex(t, []RevokedCredential{{CredentialType: "auth", Fingerprint: fp}})
	for _, key := range []string{"auth:" + strings.Repeat("e", 32), "key:" + fp, "sess:" + fp} {
		ctx := authTestCtx()
		CheckCredentialRevoked(ctx, key, idx, revokedTestNow)
		if ctx.MatchCount() != 0 {
			t.Fatalf("%s must not match, got %+v", key, ctx.CopyMatches())
		}
	}
}

// 过期跳过：expires_at 已过的条目不判定（发布间隙自行失效）；边界 now == expires_at 同样视为过期。
func TestCredentialRevoked_ExpiredSkipped(t *testing.T) {
	fp := strings.Repeat("f", 32)
	past := revokedTestNow.Add(-time.Second).Format(time.RFC3339)
	idx := revokedTestIndex(t, []RevokedCredential{{CredentialType: "auth", Fingerprint: fp, ExpiresAt: past}})
	ctx := authTestCtx()
	CheckCredentialRevoked(ctx, "auth:"+fp, idx, revokedTestNow)
	if ctx.MatchCount() != 0 {
		t.Fatalf("expired entry must not match, got %+v", ctx.CopyMatches())
	}
	exact := revokedTestNow.Format(time.RFC3339)
	idx2 := revokedTestIndex(t, []RevokedCredential{{CredentialType: "auth", Fingerprint: fp, ExpiresAt: exact}})
	ctx2 := authTestCtx()
	CheckCredentialRevoked(ctx2, "auth:"+fp, idx2, revokedTestNow)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("entry expired at now must not match, got %+v", ctx2.CopyMatches())
	}
}

// 空清单零行为：nil 与空集合均不判定。
func TestCredentialRevoked_EmptyListZeroBehavior(t *testing.T) {
	ctx := authTestCtx()
	CheckCredentialRevoked(ctx, "auth:"+strings.Repeat("1", 32), nil, revokedTestNow)
	if ctx.MatchCount() != 0 {
		t.Fatalf("nil index must not match, got %+v", ctx.CopyMatches())
	}
	ctx2 := authTestCtx()
	CheckCredentialRevoked(ctx2, "auth:"+strings.Repeat("1", 32), map[string]time.Time{}, revokedTestNow)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("empty index must not match, got %+v", ctx2.CopyMatches())
	}
}

// 匿名零行为：无凭据键直接跳过（身份维度不得由 IP 冒充，匿名流量无吊销语义）。
func TestCredentialRevoked_AnonymousZeroBehavior(t *testing.T) {
	fp := strings.Repeat("2", 32)
	idx := revokedTestIndex(t, []RevokedCredential{{CredentialType: "auth", Fingerprint: fp}})
	ctx := authTestCtx()
	CheckCredentialRevoked(ctx, "", idx, revokedTestNow)
	if ctx.MatchCount() != 0 {
		t.Fatalf("anonymous must not match, got %+v", ctx.CopyMatches())
	}
}
