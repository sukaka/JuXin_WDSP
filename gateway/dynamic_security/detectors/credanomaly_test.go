package detectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// resetCredAnomalyForTest 重置本文件检测器的追踪器（fakeClock 保证窗口边界确定性）。
func resetCredAnomalyForTest(clk *fakeClock) {
	defaultAppSpreadTracker = newIPSpreadTracker(envAnomalyMaxKeys, clk.Now)
	defaultDeviceSpreadTracker = newIPSpreadTracker(envAnomalyMaxKeys, clk.Now)
}

// uaRequest 构造携带指定 UA 的请求。
func uaRequest(ua string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	return r
}

// ---------- Token 跨应用 ----------

// 跨应用：滑窗 distinct 应用达到默认阈值 2 → OBSERVE/MEDIUM，ScoreDelta 20；
// 证据只含 distinct 数与窗口，不含应用 ID。
func TestAuthCredentialCrossApp_ThresholdHit(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:crossapp-token-1"
	apps := []string{"app-id-alpha", "app-id-beta"}
	for i, app := range apps {
		ctx := authTestCtx()
		CheckCredentialCrossApp(ctx, credKey, app, 0) // 0 → 默认阈值 2
		m := findMatch(ctx, "auth.credential_cross_app")
		if i == 0 && m != nil {
			t.Fatalf("distinct 1 below threshold must not match")
		}
		if i == 1 {
			if m == nil {
				t.Fatalf("distinct 2 at threshold must match, got %+v", ctx.CopyMatches())
			}
			if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 20 {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["distinct_apps"] != "2" || m.Evidence["window"] != "1m" {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
			// 证据只允许计数与窗口，不得含应用 ID
			if len(m.Evidence) != 2 {
				t.Fatalf("evidence must only carry distinct count and window: %+v", m.Evidence)
			}
			for _, v := range m.Evidence {
				for _, app := range apps {
					if strings.Contains(v, app) {
						t.Fatalf("application id leaked into evidence: %+v", m.Evidence)
					}
				}
			}
		}
	}
}

// 负例：同应用重复访问去重不报；匿名（credKey 空）与未识别应用（appID 空）跳过且不入追踪器。
func TestAuthCredentialCrossApp_BelowThresholdAndSkipped(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:crossapp-token-2"
	for i := 0; i < 3; i++ {
		ctx := authTestCtx()
		CheckCredentialCrossApp(ctx, credKey, "app-id-gamma", 0)
		if ctx.MatchCount() != 0 {
			t.Fatalf("same app repeated must not match, got %+v", ctx.CopyMatches())
		}
	}
	for _, tc := range [][2]string{{"", "app-id-gamma"}, {credKey, ""}} {
		ctx := authTestCtx()
		CheckCredentialCrossApp(ctx, tc[0], tc[1], 0)
		if ctx.MatchCount() != 0 {
			t.Fatalf("empty credKey/appID must not match, got %+v", ctx.CopyMatches())
		}
	}
	if n := defaultAppSpreadTracker.entries.ll.Len(); n != 1 {
		t.Fatalf("only the real credential key may populate tracker, got %d entries", n)
	}
}

// 窗口滚动：跨自然分钟后 distinct 应用集合重置。
func TestAuthCredentialCrossApp_WindowRolls(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:crossapp-token-3"
	CheckCredentialCrossApp(authTestCtx(), credKey, "app-id-delta", 0)
	clk.Advance(time.Minute) // 新窗口：distinct 重置
	ctx := authTestCtx()
	CheckCredentialCrossApp(ctx, credKey, "app-id-epsilon", 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("new window distinct 1 must not match, got %+v", ctx.CopyMatches())
	}
}

// 自定义阈值 3：第三个不同应用才命中。
func TestAuthCredentialCrossApp_CustomLimit(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:crossapp-token-4"
	apps := []string{"app-1", "app-2", "app-3"}
	for i, app := range apps {
		ctx := authTestCtx()
		CheckCredentialCrossApp(ctx, credKey, app, 3)
		m := findMatch(ctx, "auth.credential_cross_app")
		if i < 2 && m != nil {
			t.Fatalf("distinct %d below custom limit 3 must not match", i+1)
		}
		if i == 2 && (m == nil || m.Evidence["distinct_apps"] != "3") {
			t.Fatalf("distinct 3 at custom limit must match, got %+v", ctx.CopyMatches())
		}
	}
}

// ---------- 同一凭据多设备异常（窗口 distinct UA 族） ----------

// 多设备：滑窗 distinct UA 族达到默认阈值 3 → OBSERVE/LOW，ScoreDelta 10。
func TestAuthCredentialDeviceSpread_ThresholdHit(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:device-token-1"
	uas := []string{
		"Mozilla/5.0 Chrome/120.0",  // browser
		"python-requests/2.31",      // script
		"Googlebot/2.1",             // bot
		"Mozilla/5.0 Firefox/121.0", // browser（去重，distinct 仍为 3）
	}
	for i, ua := range uas {
		ctx := authTestCtx()
		CheckCredentialDeviceSpread(ctx, uaRequest(ua), credKey, 0)
		m := findMatch(ctx, "auth.credential_device_spread")
		if i < 2 && m != nil {
			t.Fatalf("distinct %d below threshold must not match", i+1)
		}
		if i >= 2 {
			if m == nil {
				t.Fatalf("distinct 3 at threshold must match, got %+v", ctx.CopyMatches())
			}
			if m.Category != "OBSERVE" || m.Severity != "LOW" || m.ScoreDelta != 10 {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["distinct_families"] != "3" || m.Evidence["window"] != "1m" {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
		}
	}
}

// 负例：同族重复去重不报；匿名跳过且不入追踪器；窗口滚动后重置。
func TestAuthCredentialDeviceSpread_BelowThresholdAnonymousAndWindowRoll(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	const credKey = "auth:device-token-2"
	for _, ua := range []string{"Mozilla/5.0 Chrome/120.0", "curl/8.4.0", "Mozilla/5.0 Safari/17.0"} {
		ctx := authTestCtx()
		CheckCredentialDeviceSpread(ctx, uaRequest(ua), credKey, 0)
		if ctx.MatchCount() != 0 {
			t.Fatalf("distinct 2 below threshold 3 must not match, got %+v", ctx.CopyMatches())
		}
	}
	// 匿名跳过
	ctx := authTestCtx()
	CheckCredentialDeviceSpread(ctx, uaRequest("curl/8.4.0"), "", 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("anonymous must not match, got %+v", ctx.CopyMatches())
	}
	if n := defaultDeviceSpreadTracker.entries.ll.Len(); n != 1 {
		t.Fatalf("anonymous must not populate tracker, got %d entries", n)
	}
	// 窗口滚动：新窗口 distinct 从 1 重新开始
	clk.Advance(time.Minute)
	ctx2 := authTestCtx()
	CheckCredentialDeviceSpread(ctx2, uaRequest("Googlebot/2.1"), credKey, 0)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("new window distinct 1 must not match, got %+v", ctx2.CopyMatches())
	}
	// 自定义阈值 2：新窗口内第二族即命中
	ctx3 := authTestCtx()
	CheckCredentialDeviceSpread(ctx3, uaRequest("curl/8.4.0"), credKey, 2)
	if m := findMatch(ctx3, "auth.credential_device_spread"); m == nil || m.Evidence["distinct_families"] != "2" {
		t.Fatalf("custom limit 2 must match at distinct 2, got %+v", ctx3.CopyMatches())
	}
}

// ---------- 凭据位置异常（URL query 凭据形态） ----------

// scheme 前缀值出现在 query → OBSERVE/MEDIUM，ScoreDelta 15；证据不含凭据值。
func TestAuthCredentialLocationAnomaly_BearerInQuery(t *testing.T) {
	resetCredAnomalyForTest(&fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x?next=Bearer%20secret-token-value-123", nil)
	CheckCredentialLocationAnomaly(ctx, r)
	m := findMatch(ctx, "auth.credential_in_url")
	if m == nil {
		t.Fatalf("bearer in query must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["location"] != "query" || m.Evidence["param"] != "next" || m.Evidence["shape"] != "scheme_prefixed" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	for _, v := range m.Evidence {
		if strings.Contains(v, "secret-token-value") {
			t.Fatalf("credential value leaked into evidence: %+v", m.Evidence)
		}
	}
}

// JWT 形态值出现在 query → shape=jwt；多参数命中时每请求至多一条明细（确定性）。
func TestAuthCredentialLocationAnomaly_JWTShapeAndSingleMatch(t *testing.T) {
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet,
		"/v1/x?b=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln&a=Bearer%20tok123456", nil)
	CheckCredentialLocationAnomaly(ctx, r)
	if ctx.MatchCount() != 1 {
		t.Fatalf("multiple credential params must yield exactly one match, got %+v", ctx.CopyMatches())
	}
	m := findMatch(ctx, "auth.credential_in_url")
	if m == nil {
		t.Fatal("expected auth.credential_in_url")
	}
	// 键序排序后 a 先命中
	if m.Evidence["param"] != "a" || m.Evidence["shape"] != "scheme_prefixed" {
		t.Fatalf("deterministic first-hit expected on sorted key a, got %+v", m.Evidence)
	}
	for _, v := range m.Evidence {
		if strings.Contains(v, "eyJhbGci") || strings.Contains(v, "tok123456") {
			t.Fatalf("credential value leaked into evidence: %+v", m.Evidence)
		}
	}
}

// 负例：普通 query 值（含 ey 开头但非 JWT 形态、含 bearer 但非前缀）不报；空 query 不报。
func TestAuthCredentialLocationAnomaly_NoMatch(t *testing.T) {
	cases := []string{
		"/v1/x?next=/home&page=2",
		"/v1/x?state=eyJabc",          // 单段非 JWT
		"/v1/x?q=remove+bearer+token", // bearer 非前缀形态
		"/v1/x",
	}
	for _, target := range cases {
		ctx := authTestCtx()
		CheckCredentialLocationAnomaly(ctx, httptest.NewRequest(http.MethodGet, target, nil))
		if ctx.MatchCount() != 0 {
			t.Fatalf("%s must not match, got %+v", target, ctx.CopyMatches())
		}
	}
}

// ---------- HMAC 签名识别（§35 识别项） ----------

// AWS SigV4 / Hawk / HMAC 结构化签名凭据：不判 malformed，记 INFO 识别明细，
// AuthenticationType 精确化为 hmac_signature；证据不含签名值。
func TestAuthentication_HMACSignatureRecognized(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		scheme string
		secret string // 不得入证据的凭据片段
	}{
		{"aws sigv4", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260911/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=fe5f80f77d5fa3befa1b2c94ec", "aws4-hmac-sha256", "fe5f80f77d5fa3befa1b2c94ec"},
		{"hawk", `Hawk id="dh37fgj492je", ts="1726000000", nonce="x3jkm7", mac="bh7y26kdo92mdy26kk87"`, "hawk", "bh7y26kdo92mdy26kk87"},
		{"generic hmac", "HMAC keyId=k1, signature=sha256sigvalue9", "hmac", "sha256sigvalue9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := authTestCtx()
			r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
			r.Header.Set("Authorization", tc.value)
			CheckAuthentication(ctx, r, true)
			if m := findMatch(ctx, "auth.malformed_credential"); m != nil {
				t.Fatalf("hmac signature scheme must not be malformed: %+v", m)
			}
			m := findMatch(ctx, "identity.hmac_signature_present")
			if m == nil {
				t.Fatalf("expected hmac identification match, got %+v", ctx.CopyMatches())
			}
			if m.Category != "INFO" || m.Severity != "INFO" || m.ScoreDelta != 0 {
				t.Fatalf("hmac identification must be informational only: %+v", m)
			}
			if m.Evidence["scheme"] != tc.scheme {
				t.Fatalf("bad scheme evidence: %+v", m.Evidence)
			}
			if ctx.AuthenticationType != "hmac_signature" {
				t.Fatalf("authentication type must be hmac_signature, got %q", ctx.AuthenticationType)
			}
			for _, v := range m.Evidence {
				if strings.Contains(v, tc.secret) {
					t.Fatalf("signature value leaked into evidence: %+v", m.Evidence)
				}
			}
		})
	}
}

// HMAC scheme 结构异常：空凭据 → weak/empty_token；非 k=v 对 → weak/not_key_value_pairs。
func TestAuthentication_HMACSignatureMalformed(t *testing.T) {
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 ") // 空凭据
	CheckAuthentication(ctx, r, true)
	m := findMatch(ctx, "auth.weak_credential")
	if m == nil || m.Evidence["reason"] != "empty_token" || m.Evidence["scheme"] != "aws4-hmac-sha256" {
		t.Fatalf("empty hmac credentials must be weak empty_token, got %+v", ctx.CopyMatches())
	}
	if findMatch(ctx, "identity.hmac_signature_present") != nil {
		t.Fatal("empty credentials must not record identification match")
	}
	if ctx.AuthenticationType == "hmac_signature" {
		t.Fatal("malformed hmac credential must not set authentication type")
	}

	ctx2 := authTestCtx()
	r2 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r2.Header.Set("Authorization", "HMAC abcdefghijklmnop") // 非 k=v 结构
	CheckAuthentication(ctx2, r2, true)
	m2 := findMatch(ctx2, "auth.weak_credential")
	if m2 == nil || m2.Evidence["reason"] != "not_key_value_pairs" || m2.Evidence["scheme"] != "hmac" {
		t.Fatalf("non-kv hmac credentials must be weak not_key_value_pairs, got %+v", ctx2.CopyMatches())
	}
}

// 回归：未知 scheme 仍判 malformed/unsupported_scheme（HMAC 识别不误伤其他 scheme）。
func TestAuthentication_UnsupportedSchemeStillMalformed(t *testing.T) {
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Token abcdef123456")
	CheckAuthentication(ctx, r, true)
	m := findMatch(ctx, "auth.malformed_credential")
	if m == nil || m.Evidence["reason"] != "unsupported_scheme" {
		t.Fatalf("unknown scheme must stay malformed, got %+v", ctx.CopyMatches())
	}
	if findMatch(ctx, "identity.hmac_signature_present") != nil {
		t.Fatal("non-hmac scheme must not record hmac identification")
	}
}

// ---------- 多信号叠加 ----------

// 叠加：跨应用与多设备同属凭据环境异常信号，≥2 个同请求叠加 → auth.env_anomaly_stack。
func TestEnvAnomalyStack_IncludesNewCredentialSignals(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetCredAnomalyForTest(clk)
	ctx := authTestCtx()
	const credKey = "auth:stack-token-1"
	CheckCredentialCrossApp(ctx, credKey, "app-x", 0)
	CheckCredentialCrossApp(ctx, credKey, "app-y", 0)
	for _, ua := range []string{"Mozilla/5.0 Chrome/120.0", "curl/8.4.0", "Googlebot/2.1"} {
		CheckCredentialDeviceSpread(ctx, uaRequest(ua), credKey, 0)
	}
	CheckEnvAnomalyStack(ctx)
	m := findMatch(ctx, "auth.env_anomaly_stack")
	if m == nil {
		t.Fatalf("cross_app + device_spread must stack, got %+v", ctx.CopyMatches())
	}
	if m.Evidence["env_signal_count"] != "2" {
		t.Fatalf("stack must count both new signals, got %+v", m.Evidence)
	}
	if m.Category != "OBSERVE" || m.Severity != "HIGH" || m.ScoreDelta != 20 {
		t.Fatalf("bad stack attrs: %+v", m)
	}
}
