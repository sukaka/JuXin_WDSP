// mtls_bind.go OAuth 2.0 双向 TLS 证书绑定访问令牌校验（RFC 8705 §3.1，Phase 9A-1）。
//
// 安全纪律：
//   - 调用方必须仅在 TLS 握手客户端证书链已通过 CA 验证（len(r.TLS.VerifiedChains) > 0）后
//     传入 PeerCertDER，不得把未经验证的自签名叶证书传入本函数；
//   - 计算 base64url(SHA-256(cert.Raw)) 并以常量时间比对 Access Token 中 cnf["x5t#S256"]。
package jwtverify

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// verifyMTLSBinding 校验客户端证书 DER 与 cnf["x5t#S256"] 一致性。
func verifyMTLSBinding(peerCertDER []byte, wantX5TS256 string) (Status, ReasonCode) {
	if len(peerCertDER) == 0 {
		return StatusInvalid, ReasonMTLSNoCert
	}
	got := ComputeCertThumbprintSHA256(peerCertDER)
	if subtle.ConstantTimeCompare([]byte(got), []byte(wantX5TS256)) != 1 {
		return StatusInvalid, ReasonMTLSCertMismatch
	}
	return StatusVerified, ReasonValid
}

// ComputeCertThumbprintSHA256 按 RFC 8705 §3.1 计算 X.509 DER 证书的 x5t#S256 指纹。
func ComputeCertThumbprintSHA256(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
