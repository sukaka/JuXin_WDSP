package jwtverify

import (
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// JWT-01：合法 RS256/ES256，正确 iss/aud/exp/sub → VERIFIED，可信主体稳定。
func TestVerifyRS256Verified(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)

	token := signToken(t, key, jose.RS256, "rsa-1", validClaims(clock, testIssuer), nil)
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusVerified || res.ReasonCode != ReasonValid {
		t.Fatalf("期望 VERIFIED/VALID，得到 %s/%s", res.Status, res.ReasonCode)
	}
	if res.VerifiedPrincipalID == "" || len(res.VerifiedPrincipalID) != 32 {
		t.Fatalf("可信主体指纹缺失或长度异常: %q", res.VerifiedPrincipalID)
	}
	if res.PolicyVersion != "pol-v1" || res.KeysetVersion == "" || res.IssuerConfigID == "" {
		t.Fatalf("版本标识缺失: %+v", res)
	}
	if res.EnforceAction != EnforceEnforce {
		t.Fatalf("PROTECT 模式 enforce_action 应为 ENFORCE: %s", res.EnforceAction)
	}
	if res.VerifiedTenantID != "" {
		t.Fatalf("未配置 tenant_claim 时 tenant 应为空: %q", res.VerifiedTenantID)
	}
	// 正常续签（同 app/issuer/sub 的新 Token）主体指纹稳定。
	claims2 := validClaims(clock, testIssuer)
	claims2["exp"] = clock.Now().Add(10 * time.Minute).Unix()
	token2 := signToken(t, key, jose.RS256, "rsa-1", claims2, nil)
	res2 := v.Verify(bearer(token2), "POST", "/api/orders")
	if res2.Status != StatusVerified || res2.VerifiedPrincipalID != res.VerifiedPrincipalID {
		t.Fatalf("同主体续签指纹不稳定")
	}
}

func TestVerifyES256Verified(t *testing.T) {
	clock := newFakeClock()
	key := genEC(t, elliptic.P256())
	jwks := jwksJSON(t, ecJWK(key, "ec-1"))
	v := newTestVerifier(t, testPolicy(ModeObserve, staticIssuerCfg(jwks)), clock)

	token := signToken(t, key, jose.ES256, "ec-1", validClaims(clock, testIssuer), nil)
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusVerified || res.ReasonCode != ReasonValid {
		t.Fatalf("期望 VERIFIED，得到 %s/%s", res.Status, res.ReasonCode)
	}
	if res.EnforceAction != EnforceObserve {
		t.Fatalf("OBSERVE 模式 enforce_action 应为 OBSERVE: %s", res.EnforceAction)
	}
}

// JWT-02：伪造签名、none、HS 混淆、错误曲线、短 RSA。
func TestVerifyForgedSignature(t *testing.T) {
	clock := newFakeClock()
	realKey := genRSA(t, 2048)
	attackerKey := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(realKey, "rsa-1"))
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)

	token := signToken(t, attackerKey, jose.RS256, "rsa-1", validClaims(clock, testIssuer), nil)
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusInvalid || res.ReasonCode != ReasonSignatureInvalid {
		t.Fatalf("伪造签名应 INVALID/SIGNATURE_INVALID，得到 %s/%s", res.Status, res.ReasonCode)
	}
	if res.VerifiedPrincipalID != "" {
		t.Fatalf("INVALID 不得产生可信主体")
	}
}

func TestVerifyAlgNoneRejected(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, rsaJWK(key, "rsa-1")))), clock)

	// none Token 携带非空签名段以走到算法检查（空段本身也会被拒）。
	token := manualToken(map[string]any{"alg": "none", "kid": "rsa-1"}, validClaims(clock, testIssuer), "eA")
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusInvalid || res.ReasonCode != ReasonAlgorithmRejected {
		t.Fatalf("none 应 ALGORITHM_REJECTED，得到 %s/%s", res.Status, res.ReasonCode)
	}
}

func TestVerifyHSConfusionRejected(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	pubDER, _ := key.PublicKey.N.MarshalText() // 任意公钥材料作为 HMAC 密钥尝试混淆
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, rsaJWK(key, "rsa-1")))), clock)

	token := signToken(t, pubDER, jose.HS256, "rsa-1", validClaims(clock, testIssuer), nil)
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusInvalid || res.ReasonCode != ReasonAlgorithmRejected {
		t.Fatalf("HS256 混淆应 ALGORITHM_REJECTED，得到 %s/%s", res.Status, res.ReasonCode)
	}
}

func TestVerifyWrongCurveRejected(t *testing.T) {
	clock := newFakeClock()
	p384 := genEC(t, elliptic.P384())
	key := genEC(t, elliptic.P256())
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, ecJWK(key, "ec-1")))), clock)

	// ES384 Token：算法不在白名单。
	token := signToken(t, p384, jose.ES384, "ec-1", validClaims(clock, testIssuer), nil)
	res := v.Verify(bearer(token), "GET", "/api/orders")
	if res.Status != StatusInvalid || res.ReasonCode != ReasonAlgorithmRejected {
		t.Fatalf("ES384 应 ALGORITHM_REJECTED，得到 %s/%s", res.Status, res.ReasonCode)
	}
}

func TestShortRSARejectedAtLoad(t *testing.T) {
	short := genRSA(t, 1024)
	_, err := NewVerifier(VerifierConfig{
		Policy:         testPolicy(ModeObserve, staticIssuerCfg(jwksJSON(t, rsaJWK(short, "weak")))),
		IdentitySecret: testSecret,
	})
	if err == nil {
		t.Fatalf("短 RSA 公钥应在加载期被拒绝")
	}
}

// JWT-03：iss/aud/sub/exp 严格性，aud 字符串/数组，不发生弱类型通过。
func TestVerifyClaimsStrictness(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)

	mutate := func(mut func(c map[string]any)) map[string]any {
		c := validClaims(clock, testIssuer)
		mut(c)
		return c
	}
	cases := []struct {
		name   string
		claims map[string]any
		status Status
		reason ReasonCode
	}{
		{"缺 iss", mutate(func(c map[string]any) { delete(c, "iss") }), StatusInvalid, ReasonUnknownIssuer},
		{"未知 iss", mutate(func(c map[string]any) { c["iss"] = "https://evil.example.com" }), StatusInvalid, ReasonUnknownIssuer},
		{"iss 尾斜杠差异", mutate(func(c map[string]any) { c["iss"] = testIssuer + "/" }), StatusInvalid, ReasonUnknownIssuer},
		{"aud 错误", mutate(func(c map[string]any) { c["aud"] = "api://billing" }), StatusInvalid, ReasonAudienceMismatch},
		{"缺 aud", mutate(func(c map[string]any) { delete(c, "aud") }), StatusInvalid, ReasonAudienceMismatch},
		{"aud 数组含匹配项", mutate(func(c map[string]any) { c["aud"] = []string{"api://other", "api://orders"} }), StatusVerified, ReasonValid},
		{"aud 空数组", mutate(func(c map[string]any) { c["aud"] = []string{} }), StatusInvalid, ReasonMalformedToken},
		{"aud 数字弱类型", mutate(func(c map[string]any) { c["aud"] = 123 }), StatusInvalid, ReasonMalformedToken},
		{"aud 空字符串", mutate(func(c map[string]any) { c["aud"] = "" }), StatusInvalid, ReasonMalformedToken},
		{"缺 sub", mutate(func(c map[string]any) { delete(c, "sub") }), StatusInvalid, ReasonClaimInvalid},
		{"空 sub", mutate(func(c map[string]any) { c["sub"] = "" }), StatusInvalid, ReasonClaimInvalid},
		{"sub 数字弱类型", mutate(func(c map[string]any) { c["sub"] = 42 }), StatusInvalid, ReasonMalformedToken},
		{"缺 exp", mutate(func(c map[string]any) { delete(c, "exp") }), StatusInvalid, ReasonClaimInvalid},
		{"exp 字符串弱类型", mutate(func(c map[string]any) { c["exp"] = "9999999999" }), StatusInvalid, ReasonMalformedToken},
		{"exp 超界数值", mutate(func(c map[string]any) { c["exp"] = 1e100 }), StatusInvalid, ReasonMalformedToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := signToken(t, key, jose.RS256, "rsa-1", tc.claims, nil)
			res := v.Verify(bearer(token), "GET", "/api/orders")
			if res.Status != tc.status || res.ReasonCode != tc.reason {
				t.Fatalf("期望 %s/%s，得到 %s/%s", tc.status, tc.reason, res.Status, res.ReasonCode)
			}
			if res.Status != StatusVerified && res.VerifiedPrincipalID != "" {
				t.Fatalf("非 VERIFIED 不得产生可信主体")
			}
		})
	}
}

// JWT-04：exp/nbf 恰好边界、leeway、时钟跳变；无永久有效缓存。
func TestVerifyTimeBoundaries(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, rsaJWK(key, "rsa-1")))), clock)

	sign := func(claims map[string]any) string {
		return signToken(t, key, jose.RS256, "rsa-1", claims, nil)
	}
	// leeway = 默认 30s。
	t.Run("exp+leeway-1s 仍有效", func(t *testing.T) {
		c := validClaims(clock, testIssuer)
		c["exp"] = clock.Now().Add(29*time.Second - DefaultClockSkewSeconds*time.Second).Unix()
		// exp = now - 1s（now < exp+30s）
		res := v.Verify(bearer(sign(c)), "GET", "/api")
		if res.Status != StatusVerified {
			t.Fatalf("边界内应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
		}
	})
	t.Run("now==exp+leeway 过期", func(t *testing.T) {
		c := validClaims(clock, testIssuer)
		c["exp"] = clock.Now().Add(-DefaultClockSkewSeconds * time.Second).Unix()
		res := v.Verify(bearer(sign(c)), "GET", "/api")
		if res.Status != StatusInvalid || res.ReasonCode != ReasonExpired {
			t.Fatalf("now==exp+leeway 应 EXPIRED: %s/%s", res.Status, res.ReasonCode)
		}
	})
	t.Run("now+leeway==nbf 已生效", func(t *testing.T) {
		c := validClaims(clock, testIssuer)
		c["nbf"] = clock.Now().Add(DefaultClockSkewSeconds * time.Second).Unix()
		res := v.Verify(bearer(sign(c)), "GET", "/api")
		if res.Status != StatusVerified {
			t.Fatalf("now+leeway==nbf 应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
		}
	})
	t.Run("now+leeway<nbf 未生效", func(t *testing.T) {
		c := validClaims(clock, testIssuer)
		c["nbf"] = clock.Now().Add(DefaultClockSkewSeconds*time.Second + time.Second).Unix()
		res := v.Verify(bearer(sign(c)), "GET", "/api")
		if res.Status != StatusInvalid || res.ReasonCode != ReasonNotYetValid {
			t.Fatalf("应 NOT_YET_VALID: %s/%s", res.Status, res.ReasonCode)
		}
	})
	t.Run("时钟前跳后过期、后跳未生效", func(t *testing.T) {
		token := sign(validClaims(clock, testIssuer))
		if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusVerified {
			t.Fatalf("基准应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
		}
		// 前跳 1 小时：Token 过期（不凭“以前验过”复用结果）。
		clock.Advance(time.Hour)
		if res := v.Verify(bearer(token), "GET", "/api"); res.ReasonCode != ReasonExpired {
			t.Fatalf("时钟前跳后应 EXPIRED: %s/%s", res.Status, res.ReasonCode)
		}
		// 后跳回过去：nbf 在未来时未生效。
		clock.Set(newFakeClock().Now().Add(-time.Hour))
		c := validClaims(clock, testIssuer)
		c["nbf"] = clock.Now().Add(time.Hour).Unix()
		c["exp"] = clock.Now().Add(2 * time.Hour).Unix()
		res := v.Verify(bearer(sign(c)), "GET", "/api")
		if res.ReasonCode != ReasonNotYetValid {
			t.Fatalf("nbf 在未来应 NOT_YET_VALID: %s/%s", res.Status, res.ReasonCode)
		}
	})
}

// JWT-06：伪造未验证声明不污染可信主体；跨应用/issuer/tenant 隔离。
func TestVerifyPrincipalIsolation(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))

	issWithTenant := staticIssuerCfg(jwks)
	issWithTenant.TenantClaim = "tid"

	mkVerifier := func(appID string, iss IssuerConfig) *Verifier {
		p := testPolicy(ModeProtect, iss)
		p.ApplicationID = appID
		return newTestVerifier(t, p, clock)
	}

	vApp1 := mkVerifier("app-1", staticIssuerCfg(jwks))
	vApp2 := mkVerifier("app-2", staticIssuerCfg(jwks))
	vTenant := mkVerifier("app-1", issWithTenant)

	claims := validClaims(clock, testIssuer)
	token := signToken(t, key, jose.RS256, "rsa-1", claims, nil)

	p1 := vApp1.Verify(bearer(token), "GET", "/api").VerifiedPrincipalID
	p2 := vApp2.Verify(bearer(token), "GET", "/api").VerifiedPrincipalID
	if p1 == "" || p1 == p2 {
		t.Fatalf("相同 sub 跨应用指纹必须不同")
	}

	// tenant 参与指纹；缺 tenant 声明与有 tenant 的指纹不同。
	claimsT := validClaims(clock, testIssuer)
	claimsT["tid"] = "tenant-a"
	tokenT := signToken(t, key, jose.RS256, "rsa-1", claimsT, nil)
	resT := vTenant.Verify(bearer(tokenT), "GET", "/api")
	if resT.Status != StatusVerified || resT.VerifiedTenantID != "tenant-a" {
		t.Fatalf("tenant 提取失败: %+v", resT)
	}
	resNoT := vTenant.Verify(bearer(token), "GET", "/api")
	if resNoT.Status != StatusVerified || resNoT.VerifiedTenantID != "" {
		t.Fatalf("缺 tenant 声明应 VERIFIED 且 tenant 为空: %+v", resNoT)
	}
	if resT.VerifiedPrincipalID == resNoT.VerifiedPrincipalID {
		t.Fatalf("有无 tenant 的指纹必须区分")
	}

	// 第二个 issuer 同 sub 同密钥源不同 issuer 值 → 指纹不同。
	iss2 := staticIssuerCfg(jwks)
	iss2.Issuer = "https://idp2.example.com"
	pTwo := testPolicy(ModeProtect, staticIssuerCfg(jwks), iss2)
	vTwo := newTestVerifier(t, pTwo, clock)
	claims2 := validClaims(clock, "https://idp2.example.com")
	token2 := signToken(t, key, jose.RS256, "rsa-1", claims2, nil)
	pIss2 := vTwo.Verify(bearer(token2), "GET", "/api").VerifiedPrincipalID
	if pIss2 == "" || pIss2 == p1 {
		t.Fatalf("相同 sub 跨 issuer 指纹必须不同")
	}

	// 伪造签名但带合法 sub 的 Token：不污染可信主体。
	attackerKey := genRSA(t, 2048)
	fake := signToken(t, attackerKey, jose.RS256, "rsa-1", claims, nil)
	res := vApp1.Verify(bearer(fake), "GET", "/api")
	if res.Status == StatusVerified || res.VerifiedPrincipalID != "" {
		t.Fatalf("伪造 Token 不得产生可信主体")
	}
}

// JWT-10（单元部分）：OFF、范围外、optional/required、模式组合、prefix 段匹配。
func TestVerifyModesAndSelectors(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))
	token := signToken(t, key, jose.RS256, "rsa-1", validClaims(clock, testIssuer), nil)

	t.Run("OFF 不校验也不产生主体", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeOff, staticIssuerCfg(jwks)), clock)
		res := v.Verify(bearer(token), "GET", "/api")
		if res.Status != StatusUnverified || res.ReasonCode != ReasonPolicyOff || res.EnforceAction != EnforceNone {
			t.Fatalf("OFF 应 UNVERIFIED/POLICY_OFF/NONE: %+v", res)
		}
	})
	t.Run("范围外", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)
		res := v.Verify(nil, "GET", "/web/index")
		if res.Status != StatusUnverified || res.ReasonCode != ReasonOutOfScope || res.EnforceAction != EnforceNone {
			t.Fatalf("范围外应 UNVERIFIED/OUT_OF_SCOPE/NONE: %+v", res)
		}
	})
	t.Run("prefix 段边界", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)
		if res := v.Verify(nil, "GET", "/apix"); res.ReasonCode != ReasonOutOfScope {
			t.Fatalf("/apix 不应命中 /api 前缀: %+v", res)
		}
		if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusVerified {
			t.Fatalf("/api 精确命中前缀: %+v", res)
		}
		if res := v.Verify(bearer(token), "GET", "/api/orders"); res.Status != StatusVerified {
			t.Fatalf("/api/orders 应命中前缀: %+v", res)
		}
		if res := v.Verify(bearer(token), "DELETE", "/api"); res.ReasonCode != ReasonOutOfScope {
			t.Fatalf("方法不匹配应范围外: %+v", res)
		}
	})
	t.Run("optional 缺 Token 放行", func(t *testing.T) {
		p := testPolicy(ModeProtect, staticIssuerCfg(jwks))
		p.Selectors[0].TokenRequired = false
		v := newTestVerifier(t, p, clock)
		res := v.Verify(nil, "GET", "/api")
		if res.Status != StatusNotPresent || res.ReasonCode != ReasonMissingToken {
			t.Fatalf("optional 缺 Token 应 NOT_PRESENT: %+v", res)
		}
	})
	t.Run("required 缺 Token", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)
		res := v.Verify(nil, "GET", "/api")
		if res.Status != StatusInvalid || res.ReasonCode != ReasonMissingToken || res.EnforceAction != EnforceEnforce {
			t.Fatalf("required 缺 Token 应 INVALID/MISSING_TOKEN/ENFORCE: %+v", res)
		}
	})
	t.Run("重叠 selector token_required 取 true 优先", func(t *testing.T) {
		p := testPolicy(ModeProtect, staticIssuerCfg(jwks))
		p.Selectors = []Selector{
			{PathPrefix: "/api", TokenRequired: false},
			{PathPrefix: "/api/orders", TokenRequired: true},
		}
		v := newTestVerifier(t, p, clock)
		if res := v.Verify(nil, "GET", "/api/orders/1"); res.Status != StatusInvalid || res.ReasonCode != ReasonMissingToken {
			t.Fatalf("重叠范围应 required 优先: %+v", res)
		}
		if res := v.Verify(nil, "GET", "/api/ping"); res.Status != StatusNotPresent {
			t.Fatalf("仅命中 optional 应 NOT_PRESENT: %+v", res)
		}
	})
	t.Run("OBSERVE 的 INVALID 不拦截但记录", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeObserve, staticIssuerCfg(jwks)), clock)
		res := v.Verify(bearer("a.b.c"), "GET", "/api")
		if res.Status != StatusInvalid || res.EnforceAction != EnforceObserve {
			t.Fatalf("OBSERVE INVALID 应 OBSERVE 动作: %+v", res)
		}
	})
	t.Run("evaluated_at 为 RFC3339 UTC", func(t *testing.T) {
		v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)
		res := v.Verify(bearer(token), "GET", "/api")
		parsed, err := time.Parse(time.RFC3339, res.EvaluatedAt)
		if err != nil || !strings.HasSuffix(res.EvaluatedAt, "Z") || parsed.UTC() != parsed {
			t.Fatalf("evaluated_at 非法: %q", res.EvaluatedAt)
		}
	})
}

// 策略/构造期校验：超限、冲突、缺密钥均 fail-closed。
func TestVerifierConfigValidation(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))

	t.Run("PROTECT 缺身份密钥禁用并报错", func(t *testing.T) {
		_, err := NewVerifier(VerifierConfig{Policy: testPolicy(ModeProtect, staticIssuerCfg(jwks)), Clock: clock})
		if err != ErrIdentitySecretRequired {
			t.Fatalf("应报身份密钥缺失: %v", err)
		}
	})
	t.Run("OBSERVE 缺身份密钥可运行但不产可信主体", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.RoleClaims = []string{"roles"}
		v, err := NewVerifier(VerifierConfig{Policy: testPolicy(ModeObserve, iss), Clock: clock})
		if err != nil {
			t.Fatalf("OBSERVE 空密钥应可构造: %v", err)
		}
		claims := validClaims(clock, testIssuer)
		claims["roles"] = []string{"admin"}
		token := signToken(t, key, jose.RS256, "rsa-1", claims, nil)
		res := v.Verify(bearer(token), "GET", "/api/orders")
		if res.Status != StatusVerified {
			t.Fatalf("OBSERVE 空密钥验签应照常 VERIFIED: %+v", res)
		}
		if res.VerifiedPrincipalID != "" || res.VerifiedTenantID != "" {
			t.Fatalf("空密钥不得产出可信主体: %+v", res)
		}
		if len(res.VerifiedRoles) != 0 {
			t.Fatalf("空密钥不得产出可信角色: %+v", res)
		}
	})
	t.Run("OFF 允许无密钥", func(t *testing.T) {
		if _, err := NewVerifier(VerifierConfig{Policy: testPolicy(ModeOff), Clock: clock}); err != nil {
			t.Fatalf("OFF 不应要求密钥: %v", err)
		}
	})
	t.Run("issuers 超 8 项", func(t *testing.T) {
		p := testPolicy(ModeObserve)
		for i := 0; i < 9; i++ {
			iss := staticIssuerCfg(jwks)
			iss.Issuer = "https://idp.example.com/" + string(rune('a'+i))
			p.Issuers = append(p.Issuers, iss)
		}
		if err := p.Validate(); err == nil {
			t.Fatalf("9 个 issuer 应被拒绝")
		}
	})
	t.Run("issuer 精确值重复", func(t *testing.T) {
		p := testPolicy(ModeObserve, staticIssuerCfg(jwks), staticIssuerCfg(jwks))
		if err := p.Validate(); err == nil {
			t.Fatalf("重复 issuer 应被拒绝")
		}
	})
	t.Run("audiences 空", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.Audiences = nil
		p := testPolicy(ModeObserve, iss)
		if err := p.Validate(); err == nil {
			t.Fatalf("空 audiences 应被拒绝")
		}
	})
	t.Run("算法白名单外", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.Algorithms = []Algorithm{"HS256"}
		p := testPolicy(ModeObserve, iss)
		if err := p.Validate(); err == nil {
			t.Fatalf("HS256 应被拒绝")
		}
	})
	t.Run("clock_skew 超界", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.ClockSkewSeconds = 121
		p := testPolicy(ModeObserve, iss)
		if err := p.Validate(); err == nil {
			t.Fatalf("skew 121 应被拒绝")
		}
	})
	t.Run("selector 路径二选一", func(t *testing.T) {
		p := testPolicy(ModeObserve, staticIssuerCfg(jwks))
		p.Selectors[0].PathExact = "/api"
		if err := p.Validate(); err == nil {
			t.Fatalf("同时设置 exact/prefix 应被拒绝")
		}
	})
	t.Run("selector 路径禁 query", func(t *testing.T) {
		p := testPolicy(ModeObserve, staticIssuerCfg(jwks))
		p.Selectors[0].PathExact = "/api?x=1"
		p.Selectors[0].PathPrefix = ""
		if err := p.Validate(); err == nil {
			t.Fatalf("含 query 的 selector 应被拒绝")
		}
	})
	t.Run("方法大写去重", func(t *testing.T) {
		p := testPolicy(ModeObserve, staticIssuerCfg(jwks))
		p.Selectors[0].Methods = []string{"get", "GET", "Post"}
		if err := p.Validate(); err != nil {
			t.Fatalf("方法归一化失败: %v", err)
		}
		got := p.Selectors[0].Methods
		if len(got) != 2 || got[0] != "GET" || got[1] != "POST" {
			t.Fatalf("方法未大写去重: %v", got)
		}
	})
	t.Run("静态与远程互斥", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.RemoteURL = "https://idp.example.com/jwks.json"
		p := testPolicy(ModeObserve, iss)
		if err := p.Validate(); err == nil {
			t.Fatalf("STATIC 不得配置 remote_url")
		}
	})
	t.Run("远程缺 Fetcher 构造失败", func(t *testing.T) {
		iss := IssuerConfig{
			Issuer:     testIssuer,
			Audiences:  []string{"api://orders"},
			Algorithms: []Algorithm{AlgRS256},
			KeySource:  KeySourceRemoteJWKS,
			RemoteURL:  "https://idp.example.com/jwks.json",
		}
		_, err := NewVerifier(VerifierConfig{
			Policy:         testPolicy(ModeObserve, iss),
			IdentitySecret: testSecret,
			Clock:          clock,
		})
		if err == nil {
			t.Fatalf("REMOTE_JWKS 无 Fetcher 应构造失败")
		}
	})
	t.Run("非 OFF 缺 selectors", func(t *testing.T) {
		p := testPolicy(ModeObserve, staticIssuerCfg(jwks))
		p.Selectors = nil
		if err := p.Validate(); err == nil {
			t.Fatalf("非 OFF 缺 selectors 应被拒绝")
		}
	})
}
