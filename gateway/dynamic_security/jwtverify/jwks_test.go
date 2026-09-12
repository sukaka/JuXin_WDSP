package jwtverify

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// JWKS 解析校验：尺寸/数量/私钥/对称/短 RSA/错误曲线/重复 kid。
func TestParseJWKSValid(t *testing.T) {
	rsaKey := genRSA(t, 2048)
	ecKey := genEC(t, elliptic.P256())
	ks, err := ParseJWKS(jwksJSON(t, rsaJWK(rsaKey, "rsa-1"), ecJWK(ecKey, "ec-1")))
	if err != nil {
		t.Fatalf("合法 JWKS 解析失败: %v", err)
	}
	if ks.Version == "" || len(ks.Keys) != 2 {
		t.Fatalf("密钥集异常: %+v", ks)
	}
	if _, ok := ks.KeyFor("rsa-1"); !ok {
		t.Fatalf("kid 查找失败")
	}
}

func TestParseJWKSBounds(t *testing.T) {
	rsaKey := genRSA(t, 2048)

	t.Run("空数据", func(t *testing.T) {
		if _, err := ParseJWKS(nil); err == nil {
			t.Fatalf("空 JWKS 应拒绝")
		}
	})
	t.Run("超 256KiB", func(t *testing.T) {
		big := []byte(`{"keys":[` + strings.Repeat(" ", MaxJWKSBytes) + `]}`)
		if _, err := ParseJWKS(big); err == nil {
			t.Fatalf("超限 JWKS 应拒绝")
		}
	})
	t.Run("超 32 键", func(t *testing.T) {
		keys := make([]jose.JSONWebKey, 0, MaxJWKSKeys+1)
		for i := 0; i <= MaxJWKSKeys; i++ {
			keys = append(keys, rsaJWK(rsaKey, fmt.Sprintf("k%d", i)))
		}
		if _, err := ParseJWKS(jwksJSON(t, keys...)); err == nil {
			t.Fatalf("超 32 键应拒绝")
		}
	})
	t.Run("重复 kid", func(t *testing.T) {
		if _, err := ParseJWKS(jwksJSON(t, rsaJWK(rsaKey, "dup"), rsaJWK(rsaKey, "dup"))); err == nil {
			t.Fatalf("重复 kid 应拒绝")
		}
	})
	t.Run("空 kid", func(t *testing.T) {
		k := rsaJWK(rsaKey, "")
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("空 kid 应拒绝")
		}
	})
	t.Run("重复 JSON 键", func(t *testing.T) {
		raw := jwksJSON(t, rsaJWK(rsaKey, "a"))
		// 在 JWKS 顶层构造重复 "keys" 键。
		dup := []byte(`{"keys":[],` + string(raw[1:]))
		if _, err := ParseJWKS(dup); err == nil {
			t.Fatalf("重复 JSON 键应拒绝")
		}
	})
}

func TestParseJWKSKeyRestrictions(t *testing.T) {
	t.Run("拒绝私钥参数", func(t *testing.T) {
		priv := genRSA(t, 2048)
		k := jose.JSONWebKey{Key: priv, KeyID: "priv", Algorithm: "RS256"} // 含 d
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("私钥应被拒绝")
		}
	})
	t.Run("拒绝对称密钥", func(t *testing.T) {
		k := jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "oct", Algorithm: "HS256"}
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("对称密钥应被拒绝")
		}
	})
	t.Run("拒绝短 RSA", func(t *testing.T) {
		k := rsaJWK(genRSA(t, 1024), "short")
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("1024 位 RSA 应被拒绝")
		}
	})
	t.Run("拒绝 P-384", func(t *testing.T) {
		k := ecJWK(genEC(t, elliptic.P384()), "p384")
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("P-384 应被拒绝")
		}
	})
	t.Run("拒绝 use=enc", func(t *testing.T) {
		k := rsaJWK(genRSA(t, 2048), "enc-key")
		k.Use = "enc"
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("use=enc 应被拒绝")
		}
	})
	t.Run("拒绝 JWK alg 白名单外", func(t *testing.T) {
		k := rsaJWK(genRSA(t, 2048), "hs")
		k.Algorithm = "HS256"
		if _, err := ParseJWKS(jwksJSON(t, k)); err == nil {
			t.Fatalf("JWK alg=HS256 应被拒绝")
		}
	})
}

// 轮换改变 keyset 版本；删除 key 后版本变化（缓存替换语义见 cache_test.go）。
func TestKeysetVersionRotation(t *testing.T) {
	rsaKey := genRSA(t, 2048)
	v1, err := ParseJWKS(jwksJSON(t, rsaJWK(rsaKey, "a")))
	if err != nil {
		t.Fatal(err)
	}
	ecKey := genEC(t, elliptic.P256())
	v2, err := ParseJWKS(jwksJSON(t, rsaJWK(rsaKey, "a"), ecJWK(ecKey, "b")))
	if err != nil {
		t.Fatal(err)
	}
	v3, err := ParseJWKS(jwksJSON(t, ecJWK(ecKey, "b")))
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version == v2.Version || v2.Version == v3.Version || v1.Version == v3.Version {
		t.Fatalf("轮换后版本必须变化: %s %s %s", v1.Version, v2.Version, v3.Version)
	}
}

// JWKS 中携带 x5u 仅解析为字段，绝不发起获取（不触发网络由 fetcher 计数断言）。
func TestParseJWKSX5uNotDereferenced(t *testing.T) {
	rsaKey := genRSA(t, 2048)
	raw := jwksJSON(t, rsaJWK(rsaKey, "a"))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	key0 := m["keys"].([]any)[0].(map[string]any)
	key0["x5u"] = "https://attacker.example.com/cert.pem"
	withX5u, _ := json.Marshal(m)
	ks, err := ParseJWKS(withX5u)
	if err != nil {
		t.Fatalf("x5u 字段不应导致解析失败（仅忽略不解引用）: %v", err)
	}
	if _, ok := ks.KeyFor("a"); !ok {
		t.Fatalf("密钥应正常加载")
	}
}

// jwksParityVector/jwksParityVersion 是跨模块共享测试向量：与服务端
// jwttrust.KeysetVersion（server/internal/jwttrust/jwks_test.go
// TestKeysetVersionGatewayParity，同一 JWKS 同一期望值）逐字节一致，
// 保证网关运行期事件指纹与管理面审计/下发契约指纹可直接比对。
const jwksParityVector = `{"keys":[` +
	`{"kty":"RSA","kid":"vec-rsa","alg":"RS256","n":"2qdfkJaiGwLLMwTefJ0WiqpKieWuiU6y3heFT1BBLKdFnqSK8_mMJ6s3fmeGKsZr6q11F_ZfafCtvc9Q1mlg8fIKqr2IDiUBgiADHIYIKV6ym8zt8ybTIU_mtcSlo4oOSd8fCaJ_fFrhTZGEd8inHekOpcu60IF_AlZPuNSzhMNL4KfRwob1TfiwIX9AusLHYuu3wD_yAUH3e4LnAwqZLJ9qh_YX9kTRp28mr_wxZi60S1deGT6mqYOzDvfV7Y_DZuXQWalhu9eJMV2iG1ryeJkHUL8ACNO1B0T8JjTWRlUNck-Gmvw3KZEZbR4VjwgtyjhjZsn5Did0lt7jeS2qmQ","e":"AQAB"},` +
	`{"kty":"EC","kid":"vec-ec","alg":"ES256","crv":"P-256","x":"G4EBQn8WN4OdSoAS1Jl-Scbgbht8n34ucysL8GYQKq4","y":"LNhzHn7HH7TQ2M6FHnhw_RvO4VlJQZsmUITje1TecNM"}` +
	`]}`
const jwksParityVersion = "0ea50ea947969fcfee1bd6221cb36cf9"

// TestKeysetVersionServerParity 共享向量钉版（见常量注释）。
func TestKeysetVersionServerParity(t *testing.T) {
	ks, err := ParseJWKS([]byte(jwksParityVector))
	if err != nil {
		t.Fatalf("ParseJWKS(parity vector): %v", err)
	}
	if v := keysetVersion(ks.Keys); v != jwksParityVersion {
		t.Errorf("keyset version = %q, want server-parity %q", v, jwksParityVersion)
	}
}
