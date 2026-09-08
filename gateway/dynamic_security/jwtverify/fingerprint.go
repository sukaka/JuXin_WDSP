package jwtverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
)

// principalHMACDomain 可信主体指纹的域分隔前缀（并入 HMAC 输入，区别于
// identitybehavior 的 identity_key 指纹域，两者密钥与语义互不混用）。
const principalHMACDomain = "jiuzhang/wdsp-jwt-principal/v1"

// ErrIdentitySecretRequired 身份指纹密钥缺失：可信身份功能禁用并显式报错。
var ErrIdentitySecretRequired = errors.New("jwtverify: 可信身份指纹密钥为空，功能禁用")

// sha256Hex16 返回 SHA-256 前 16 字节的 hex（32 字符），用于派生稳定标识。
func sha256Hex16(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// PrincipalID 计算应用隔离的可信主体指纹：HMAC-SHA256(key=secret) 截前 16
// 字节 hex。输入为域分隔前缀 + 带长度编码的 application_id、精确 issuer、
// sub、可选 tenant；长度前缀避免简单拼接歧义，tenant 带存在标志位区分
// “未配置/声明缺失”与“空值”。secret 为空时返回 ErrIdentitySecretRequired。
func PrincipalID(secret []byte, applicationID, issuer, subject, tenant string, tenantPresent bool) (string, error) {
	if len(secret) == 0 {
		return "", ErrIdentitySecretRequired
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(principalHMACDomain))
	writeLengthPrefixed(mac, applicationID)
	writeLengthPrefixed(mac, issuer)
	writeLengthPrefixed(mac, subject)
	if tenantPresent {
		_, _ = mac.Write([]byte{0x01})
		writeLengthPrefixed(mac, tenant)
	} else {
		_, _ = mac.Write([]byte{0x00})
	}
	return hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

func writeLengthPrefixed(h hash.Hash, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write([]byte(s))
}
