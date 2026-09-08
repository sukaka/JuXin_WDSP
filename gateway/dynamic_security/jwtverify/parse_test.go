package jwtverify

import (
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// JWT-05：Token 格式错误/超长/重复 JSON 键/重复 Authorization → 有界拒绝，
// 无 panic、无解析歧义。
func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		present bool
		wantErr bool
	}{
		{"无头", nil, false, false},
		{"正常", []string{"Bearer abc.def.ghi"}, true, false},
		{"小写 scheme", []string{"bearer abc.def.ghi"}, true, false},
		{"重复头", []string{"Bearer a.b.c", "Bearer d.e.f"}, false, true},
		{"多头值单头", []string{"Bearer a.b.c, Bearer d.e.f"}, false, true},
		{"Bearer 后多段", []string{"Bearer a.b.c extra"}, false, true},
		{"非 Bearer", []string{"Basic dXNlcjpwYXNz"}, false, true},
		{"空值", []string{""}, false, true},
		{"仅 scheme", []string{"Bearer"}, false, true},
		{"超长", []string{"Bearer " + strings.Repeat("a", MaxTokenBytes+1)}, false, true},
		{"非法字符", []string{"Bearer ab$.de.fg"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, present, err := extractBearer(tc.values)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if present != tc.present {
				t.Fatalf("present=%v, want %v", present, tc.present)
			}
			if !tc.wantErr && present && token == "" {
				t.Fatalf("present 但 token 为空")
			}
		})
	}
}

func TestParseTokenStrict(t *testing.T) {
	goodHeader := b64JSON(`{"alg":"RS256","kid":"k1"}`)
	goodPayload := b64JSON(`{"iss":"https://idp.example.com","sub":"u","aud":"a","exp":999999999}`)
	sig := "c2ln" // "sig"

	cases := []struct {
		name  string
		token string
	}{
		{"两段", goodHeader + "." + goodPayload},
		{"四段", goodHeader + "." + goodPayload + "." + sig + ".x"},
		{"空签名段", goodHeader + "." + goodPayload + "."},
		{"空 header 段", "." + goodPayload + "." + sig},
		{"header 非 base64url", "!!##." + goodPayload + "." + sig},
		{"header 非 JSON", "aGVsbG8." + goodPayload + "." + sig},
		{"header 顶层数组", b64JSON(`[1,2]`) + "." + goodPayload + "." + sig},
		{"header 重复键", b64JSON(`{"alg":"RS256","alg":"none","kid":"k1"}`) + "." + goodPayload + "." + sig},
		{"payload 重复键", goodHeader + "." + b64JSON(`{"iss":"a","iss":"b","sub":"u","aud":"a","exp":999999999}`) + "." + sig},
		{"payload 嵌套重复键", goodHeader + "." + b64JSON(`{"iss":"a","sub":"u","aud":"a","exp":999999999,"x":{"a":1,"a":2}}`) + "." + sig},
		{"payload 尾部数据", b64JSON(`{"iss":"a"}`) + "e30." + sig[0:0] + "." + sig},
		{"缺 alg", b64JSON(`{"kid":"k1"}`) + "." + goodPayload + "." + sig},
		{"缺 kid", b64JSON(`{"alg":"RS256"}`) + "." + goodPayload + "." + sig},
		{"空 kid", b64JSON(`{"alg":"RS256","kid":""}`) + "." + goodPayload + "." + sig},
		{"kid 超长", b64JSON(`{"alg":"RS256","kid":"`+strings.Repeat("k", MaxKidBytes+1)+`"}`) + "." + goodPayload + "." + sig},
		{"crit 头", b64JSON(`{"alg":"RS256","kid":"k1","crit":["exp"]}`) + "." + goodPayload + "." + sig},
		{"嵌套过深", goodHeader + "." + b64JSON(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}`) + "." + sig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTokenStrict(tc.token)
			if err == nil {
				t.Fatalf("应拒绝: %s", tc.token)
			}
			te, ok := err.(*tokenError)
			if !ok {
				t.Fatalf("错误类型应为 tokenError: %T", err)
			}
			if te.reason != ReasonMalformedToken {
				t.Fatalf("reason 应为 MALFORMED_TOKEN: %s", te.reason)
			}
		})
	}

	t.Run("合法解析", func(t *testing.T) {
		pt, err := parseTokenStrict(goodHeader + "." + goodPayload + "." + sig)
		if err != nil {
			t.Fatalf("合法 Token 解析失败: %v", err)
		}
		if pt.alg != "RS256" || pt.kid != "k1" || pt.claims.issuer != "https://idp.example.com" {
			t.Fatalf("解析结果错误: %+v", pt)
		}
	})
}

// 端到端有界拒绝：畸形输入经完整 Verify 路径不 panic、状态为 INVALID。
func TestVerifyMalformedBounded(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, rsaJWK(key, "rsa-1")))), clock)

	tokens := []string{
		"",
		".",
		"..",
		"a.b.c",
		strings.Repeat("a", MaxTokenBytes+1),
		b64JSON(`{"alg":"RS256","kid":"rsa-1"}`) + "." + b64JSON(`not-json`) + ".c2ln",
		manualToken(map[string]any{"alg": "RS256", "kid": "rsa-1"}, map[string]any{"exp": 1e300, "iss": testIssuer, "sub": "u", "aud": "api://orders"}, "c2ln"),
	}
	for _, tok := range tokens {
		res := v.Verify(bearer(tok), "GET", "/api")
		if res.Status == StatusVerified || res.VerifiedPrincipalID != "" {
			t.Fatalf("畸形 Token 不得通过: %q", tok)
		}
	}
	// 重复 Authorization 头经完整路径。
	res := v.Verify([]string{"Bearer a.b.c", "Bearer d.e.f"}, "GET", "/api")
	if res.Status != StatusInvalid || res.ReasonCode != ReasonMalformedToken {
		t.Fatalf("重复 Authorization 应有界拒绝: %+v", res)
	}
}

// NumericDate 严格性专项。
func TestParseNumericDate(t *testing.T) {
	good := []string{`0`, `9999999999`, `1757000000.5`, `-1`}
	for _, g := range good {
		if _, err := parseNumericDate([]byte(g)); err != nil {
			t.Fatalf("合法 NumericDate 被拒: %s: %v", g, err)
		}
	}
	bad := []string{`"9999999999"`, `"2026-01-01"`, `true`, `null`, `[]`, `{}`, `1e300`, `NaN`, `1.2.3`}
	for _, b := range bad {
		if _, err := parseNumericDate([]byte(b)); err == nil {
			t.Fatalf("非法 NumericDate 被接受: %s", b)
		}
	}
}

// jku/x5u header 出现时不影响本地验证且绝不触发网络（JWT-09 的一部分，
// 网络断言见 fetcher_test.go 的计数拨号器）。
func TestTokenJkuX5uIgnored(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwksJSON(t, rsaJWK(key, "rsa-1")))), clock)

	token := signToken(t, key, jose.RS256, "rsa-1", validClaims(clock, testIssuer), map[string]any{
		"jku": "https://attacker.example.com/jwks.json",
		"x5u": "https://attacker.example.com/cert.pem",
	})
	res := v.Verify(bearer(token), "GET", "/api")
	if res.Status != StatusVerified {
		t.Fatalf("jku/x5u 应被忽略按本地密钥验签: %s/%s", res.Status, res.ReasonCode)
	}
}
