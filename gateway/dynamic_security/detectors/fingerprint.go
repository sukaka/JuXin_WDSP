package detectors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// identityDomainPrefix 未配置 identity_salt 时的固定域分隔前缀（作为 HMAC key）。
// 指纹此时未加盐：仅保证与其他用途的域分隔，不具备抗彩虹表能力；
// 网关启动日志会对缺盐给出 Warn（见 jiuzhang_guard Provision）。
const identityDomainPrefix = "jiuzhang/wdsp-identity-fingerprint/v1"

// Fingerprint 统一身份/来源指纹：HMAC-SHA256(key=salt, value) 截断前 16 字节，hex 输出（32 字符）。
// salt 为空时以固定域分隔前缀代替（未加盐，跨部署可复现，仅作域分隔）。
// 不可逆、不落明文；凭据明文不得出调用函数作用域。
func Fingerprint(salt, v string) string {
	key := salt
	if key == "" {
		key = identityDomainPrefix
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(v))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
