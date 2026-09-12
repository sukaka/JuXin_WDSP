// jwks_test.go 静态 JWKS 公钥校验单元测试（WDSP P0-03；本地生成专用测试密钥）。
package jwttrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// b64u base64url 无填充编码（JWK 约定）。
func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// rsaJWK 生成指定位数 RSA 公钥 JWK JSON 片段。
func rsaJWK(t *testing.T, bits int, kid string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return fmt.Sprintf(`{"kty":"RSA","kid":%q,"alg":"RS256","n":%q,"e":%q}`,
		kid, b64u(key.N.Bytes()), b64u(big.NewInt(int64(key.E)).Bytes()))
}

// ecJWK 生成指定曲线 EC 公钥 JWK JSON 片段。
func ecJWK(t *testing.T, curve elliptic.Curve, crv, kid string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	size := (curve.Params().BitSize + 7) / 8
	x := key.X.Bytes()
	y := key.Y.Bytes()
	return fmt.Sprintf(`{"kty":"EC","kid":%q,"alg":"ES256","crv":%q,"x":%q,"y":%q}`,
		kid, crv,
		b64u(append(make([]byte, size-len(x)), x...)),
		b64u(append(make([]byte, size-len(y)), y...)))
}

func wrapKeys(keys ...string) string { return `{"keys":[` + strings.Join(keys, ",") + `]}` }

// TestValidateJWKSAccept 合法 RS256/ES256 公钥集通过。
func TestValidateJWKSAccept(t *testing.T) {
	raw := wrapKeys(rsaJWK(t, 2048, "rsa-1"), ecJWK(t, elliptic.P256(), "P-256", "ec-1"))
	sums, err := ValidateJWKS(raw, map[string]bool{AlgRS256: true, AlgES256: true})
	if err != nil {
		t.Fatalf("valid JWKS rejected: %v", err)
	}
	if len(sums) != 2 || sums[0].KID != "rsa-1" || sums[1].Crv != "P-256" {
		t.Errorf("summaries = %+v", sums)
	}
}

// TestValidateJWKSRejectMatrix 拒绝矩阵：私钥参数/对称密钥/短 RSA/错曲线/重复 kid/
// 空 kid/算法越白名单/kty-alg 不匹配/自带地址参数/重复 JSON 键/数量超限。
func TestValidateJWKSRejectMatrix(t *testing.T) {
	goodRSA := rsaJWK(t, 2048, "rsa-1")
	goodEC := ecJWK(t, elliptic.P256(), "P-256", "ec-1")

	// 构造带私钥参数的 RSA JWK（合法公钥 + d）
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privJWK := fmt.Sprintf(`{"kty":"RSA","kid":"priv","n":%q,"e":%q,"d":%q}`,
		b64u(privKey.N.Bytes()), b64u(big.NewInt(int64(privKey.E)).Bytes()), b64u(privKey.D.Bytes()))

	tooMany := make([]string, 0, MaxJWKSKeys+1)
	for i := 0; i <= MaxJWKSKeys; i++ {
		tooMany = append(tooMany, rsaJWK(t, 2048, fmt.Sprintf("k%d", i)))
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"短RSA", wrapKeys(rsaJWK(t, 1024, "short"))},
		{"错曲线P384", wrapKeys(ecJWK(t, elliptic.P384(), "P-384", "ec384"))},
		{"对称密钥", `{"keys":[{"kty":"oct","kid":"sym","k":"cGFzcw"}]}`},
		{"私钥参数d", wrapKeys(privJWK)},
		{"自带地址x5u", `{"keys":[` + strings.TrimSuffix(goodRSA, "}") + `,"x5u":"https://evil.example.com/x.pem"}]}`},
		{"自带地址jku", `{"keys":[` + strings.TrimSuffix(goodRSA, "}") + `,"jku":"https://evil.example.com/jwks"}]}`},
		{"重复kid", wrapKeys(goodRSA, rsaJWK(t, 2048, "rsa-1"))},
		{"空kid", `{"keys":[{"kty":"RSA","kid":"","n":"` + b64u([]byte{1, 2, 3}) + `","e":"AQAB"}]}`},
		{"use非sig", `{"keys":[` + strings.TrimSuffix(goodEC, "}") + `,"use":"enc"}]}`},
		{"重复JSON键", `{"keys":[` + goodRSA + `],"keys":[` + goodEC + `]}`},
		{"数量超限", wrapKeys(tooMany...)},
		{"空keys", `{"keys":[]}`},
		{"非JSON", `not-json`},
		{"非法kty", `{"keys":[{"kty":"OKP","kid":"okp","crv":"Ed25519","x":"eA"}]}`},
	}
	for _, tc := range cases {
		if _, err := ValidateJWKS(tc.raw, map[string]bool{AlgRS256: true, AlgES256: true}); err == nil {
			t.Errorf("%s: 应被拒绝", tc.name)
		}
	}
}

// TestValidateJWKSAlgMatrix 算法绑定矩阵：alg 越 issuer 白名单/HS 系列/none/kty 不匹配。
func TestValidateJWKSAlgMatrix(t *testing.T) {
	hsJWK := strings.Replace(rsaJWK(t, 2048, "k1"), `"alg":"RS256"`, `"alg":"HS256"`, 1)
	if _, err := ValidateJWKS(wrapKeys(hsJWK), map[string]bool{AlgRS256: true, AlgES256: true}); err == nil {
		t.Error("HS256 alg 应被拒绝（对称算法混淆）")
	}
	noneJWK := strings.Replace(rsaJWK(t, 2048, "k1"), `"alg":"RS256"`, `"alg":"none"`, 1)
	if _, err := ValidateJWKS(wrapKeys(noneJWK), nil); err == nil {
		t.Error("alg none 应被拒绝")
	}
	// alg 不在 issuer 白名单（issuer 仅允许 ES256，键声明 RS256）
	if _, err := ValidateJWKS(wrapKeys(rsaJWK(t, 2048, "k1")), map[string]bool{AlgES256: true}); err == nil {
		t.Error("alg 不在 issuer 白名单应被拒绝")
	}
	// kty 与 alg 不匹配（EC 密钥声明 RS256）
	badAlg := strings.Replace(ecJWK(t, elliptic.P256(), "P-256", "k2"), `"alg":"ES256"`, `"alg":"RS256"`, 1)
	if _, err := ValidateJWKS(wrapKeys(badAlg), map[string]bool{AlgRS256: true}); err == nil {
		t.Error("EC 密钥声明 RS256 应被拒绝")
	}
}

// TestKeysetVersion keyset_version 稳定且随密钥材料变化（含同 kid 换 key）。
func TestKeysetVersion(t *testing.T) {
	raw1 := wrapKeys(rsaJWK(t, 2048, "k1"))
	v1, err := KeysetVersion(raw1)
	if err != nil {
		t.Fatalf("KeysetVersion: %v", err)
	}
	if v1 == "" || len(v1) != 32 {
		t.Errorf("keyset version = %q, want 32 hex（与网关派生一致的截断指纹）", v1)
	}
	again, _ := KeysetVersion(raw1)
	if v1 != again {
		t.Error("keyset version must be deterministic")
	}
	v2, _ := KeysetVersion(wrapKeys(rsaJWK(t, 2048, "k2")))
	if v1 == v2 {
		t.Error("keyset version must change on rotation")
	}
	// 同 kid 更换整把密钥（材料变化）必须产生新版本——否则轮换溯源失效。
	v3, _ := KeysetVersion(wrapKeys(rsaJWK(t, 2048, "k1")))
	if v1 == v3 {
		t.Error("keyset version must change when key material rotates under the same kid")
	}
	// 仅空白差异的等价 JWKS 指纹不变（内容派生而非原文派生）。
	variant := strings.Replace(raw1, `,"kid"`, `, "kid"`, 1)
	v4, _ := KeysetVersion(variant)
	if v1 != v4 {
		t.Error("keyset version must be derived from canonical key material, not raw text")
	}
}

// jwksParityVector/jwksParityVersion 是跨模块共享测试向量：与网关
// jwtverify（gateway/dynamic_security/jwtverify/jwks_test.go
// TestKeysetVersionServerParity，同一 JWKS 同一期望值）逐字节一致，
// 保证管理面审计/下发契约指纹与网关运行期事件指纹可直接比对。
const jwksParityVector = `{"keys":[` +
	`{"kty":"RSA","kid":"vec-rsa","alg":"RS256","n":"2qdfkJaiGwLLMwTefJ0WiqpKieWuiU6y3heFT1BBLKdFnqSK8_mMJ6s3fmeGKsZr6q11F_ZfafCtvc9Q1mlg8fIKqr2IDiUBgiADHIYIKV6ym8zt8ybTIU_mtcSlo4oOSd8fCaJ_fFrhTZGEd8inHekOpcu60IF_AlZPuNSzhMNL4KfRwob1TfiwIX9AusLHYuu3wD_yAUH3e4LnAwqZLJ9qh_YX9kTRp28mr_wxZi60S1deGT6mqYOzDvfV7Y_DZuXQWalhu9eJMV2iG1ryeJkHUL8ACNO1B0T8JjTWRlUNck-Gmvw3KZEZbR4VjwgtyjhjZsn5Did0lt7jeS2qmQ","e":"AQAB"},` +
	`{"kty":"EC","kid":"vec-ec","alg":"ES256","crv":"P-256","x":"G4EBQn8WN4OdSoAS1Jl-Scbgbht8n34ucysL8GYQKq4","y":"LNhzHn7HH7TQ2M6FHnhw_RvO4VlJQZsmUITje1TecNM"}` +
	`]}`
const jwksParityVersion = "0ea50ea947969fcfee1bd6221cb36cf9"

// TestKeysetVersionGatewayParity 共享向量钉版（见常量注释）。
func TestKeysetVersionGatewayParity(t *testing.T) {
	v, err := KeysetVersion(jwksParityVector)
	if err != nil {
		t.Fatalf("KeysetVersion(parity vector): %v", err)
	}
	if v != jwksParityVersion {
		t.Errorf("keyset version = %q, want gateway-parity %q", v, jwksParityVersion)
	}
}
