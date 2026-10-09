// instancekey.go 强流程实例引用 HMAC 域（NG-FLOW-01 §1.2：实例键 = 应用 + 可信租户 +
// 可信主体 + 流程定义版本 + 实例引用；实例引用值经域隔离 HMAC——`sflow` 独立域，
// 与授权对象引用（objref 域）物理区分，跨域不可混用）。
// 本批只建域常量与 KDF 辅助（FLOW-02 消费实例键构造；与网关侧同算法同输入的
// 线契约在本文件冻结）。
package strongflow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// InstanceRefHMACDomain 实例引用 HMAC 域（版本化；独立于 objref 域
// 「jiuzhang-wdsp-authz-objref-v1\x00」——同输入在两域输出必不同）。
const InstanceRefHMACDomain = "jiuzhang-wdsp-strongflow-sfref-v1\x00"

// InstanceRefPrefix 实例引用脱敏形态前缀（objref: 同纪律，独立前缀 sfref:）。
const InstanceRefPrefix = "sfref:"

// InstanceRefHMAC 实例引用 HMAC-SHA256 全量 32 字节输出（与 objref 同算法同输出长度
// 纪律——服务端边界校验可按 64 位小写 hex 复用既有形态检查）。
// key 为定义级 HMAC 密钥（FLOW-02 发布链下发，同 api_authz.object_hmac_key 纪律）。
func InstanceRefHMAC(key []byte, raw string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(InstanceRefHMACDomain))
	_, _ = m.Write([]byte(raw))
	return InstanceRefPrefix + hex.EncodeToString(m.Sum(nil))
}
