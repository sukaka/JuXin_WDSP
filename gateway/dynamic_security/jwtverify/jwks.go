package jwtverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sort"

	jose "github.com/go-jose/go-jose/v4"
)

// Keyset 一份已校验的不可变公钥集，kid 仅作内存键查找（绝不拼接路径/SQL/URL）。
type Keyset struct {
	Version string
	Keys    map[string]jose.JSONWebKey
}

// KeyFor 按 kid 查找公钥。
func (ks *Keyset) KeyFor(kid string) (jose.JSONWebKey, bool) {
	k, ok := ks.Keys[kid]
	return k, ok
}

// ParseJWKS 解析并校验 JWKS：尺寸/数量上限、kid 非空唯一、仅公钥（拒绝私钥
// 参数与对称密钥）、RSA ≥2048 位、EC 仅 P-256、use 仅允许缺省或 "sig"。
// x5u/x5c 仅按 go-jose 解析为字段，本包绝不按其发起任何网络获取。
func ParseJWKS(data []byte) (*Keyset, error) {
	if len(data) == 0 {
		return nil, errors.New("jwtverify: JWKS 为空")
	}
	if len(data) > MaxJWKSBytes {
		return nil, fmt.Errorf("jwtverify: JWKS 超过 %d 字节上限", MaxJWKSBytes)
	}
	// 重复 JSON 键同样拒绝（含 keys 数组元素内部）。
	if _, err := strictJSONObject(data); err != nil {
		return nil, fmt.Errorf("jwtverify: JWKS JSON 非法: %w", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwtverify: JWKS 反序列化失败: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwtverify: JWKS 不含任何密钥")
	}
	if len(set.Keys) > MaxJWKSKeys {
		return nil, fmt.Errorf("jwtverify: JWKS 公钥数超过 %d 上限", MaxJWKSKeys)
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		if err := validateJWK(&k); err != nil {
			return nil, err
		}
		if _, dup := keys[k.KeyID]; dup {
			return nil, fmt.Errorf("jwtverify: JWKS 存在重复 kid: %q", k.KeyID)
		}
		keys[k.KeyID] = k
	}
	return &Keyset{Version: keysetVersion(keys), Keys: keys}, nil
}

func validateJWK(k *jose.JSONWebKey) error {
	if k.KeyID == "" {
		return errors.New("jwtverify: JWK kid 不能为空")
	}
	if len(k.KeyID) > MaxKidBytes {
		return fmt.Errorf("jwtverify: JWK kid 超过 %d 字节上限", MaxKidBytes)
	}
	if !k.Valid() {
		return errors.New("jwtverify: JWK 密钥材料无效")
	}
	if !k.IsPublic() {
		return errors.New("jwtverify: 拒绝私钥参数或对称密钥，仅接受公钥")
	}
	if k.Use != "" && k.Use != "sig" {
		return fmt.Errorf("jwtverify: JWK use 仅允许 \"sig\": %q", k.Use)
	}
	if k.Algorithm != "" && k.Algorithm != string(AlgRS256) && k.Algorithm != string(AlgES256) {
		return fmt.Errorf("jwtverify: JWK alg 不在白名单: %q", k.Algorithm)
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("jwtverify: RSA 公钥不足 %d 位", minRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return errors.New("jwtverify: ES256 仅允许 P-256 曲线")
		}
	default:
		return fmt.Errorf("jwtverify: 不支持的 JWK 密钥类型 %T", k.Key)
	}
	return nil
}

// keysetVersion 由规范化密钥材料派生不可变版本标识（轮换即变化）。
func keysetVersion(keys map[string]jose.JSONWebKey) string {
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	h := sha256.New()
	for _, kid := range kids {
		k := keys[kid]
		writeHashField(h, kid)
		writeHashField(h, k.Algorithm)
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			writeHashField(h, "RSA")
			nb := pub.N.Bytes()
			var lb [8]byte
			binary.BigEndian.PutUint64(lb[:], uint64(len(nb)))
			_, _ = h.Write(lb[:])
			_, _ = h.Write(nb)
			eb := make([]byte, 8)
			binary.BigEndian.PutUint64(eb, uint64(pub.E))
			_, _ = h.Write(eb)
		case *ecdsa.PublicKey:
			writeHashField(h, "P-256")
			writeHashField(h, hex.EncodeToString(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)))
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func writeHashField(h hash.Hash, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write([]byte(s))
}
