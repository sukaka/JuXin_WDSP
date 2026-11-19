// registry.go 登记册查找、键状态机、证明时效与验签错误映射
// （NG-ID §1.4 步 2/3/4/5 与步 6~9 错误→词表映射的纯函数部分）。
package machineid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
)

// NewRegistry 装配登记册（keys 按身份逐行；仅 ENABLED 身份的键入索引——
// DISABLED 身份不可验（MID-KEY-UNKNOWN 语义的装配承载）；索引随装配只读）。
func NewRegistry(identities []Identity, registryVersion, watermark int64) *Registry {
	reg := &Registry{
		byIdentity:          make(map[string]*Identity, len(identities)),
		byKeyID:             make(map[string]registryHit),
		RegistryVersion:     registryVersion,
		RevocationWatermark: watermark,
	}
	for i := range identities {
		id := &identities[i]
		reg.byIdentity[id.Name] = id
		if id.Status != "ENABLED" {
			continue
		}
		for kid, k := range id.Keys {
			kk := k
			reg.byKeyID[kid] = registryHit{identity: id, key: &kk}
		}
	}
	return reg
}

// IdentityByName 按身份名取登记行（管理面/Bot 豁免联动消费；未登记 nil）。
func (r *Registry) IdentityByName(name string) *Identity {
	if r == nil {
		return nil
	}
	return r.byIdentity[name]
}

// lookupEnabled keyid 登记册精确查找（仅 ENABLED 身份的键——身份 DISABLED 即
// 不可见（MID-KEY-UNKNOWN 语义）；keyid 任何 URL/URI 形态不触发抓取（§1.3 红线——
// 纯 map 查找天然成立））。
func (r *Registry) lookupEnabled(kid string) (registryHit, bool) {
	if r == nil {
		return registryHit{}, false
	}
	h, ok := r.byKeyID[kid]
	return h, ok
}

// algAllowed 算法白名单（§1.2 词表——hmac-sha256 共享密钥形态排除、
// rsa-v1_5-sha256 排除（RFC 9421 标注不推荐））。
func algAllowed(alg string) bool {
	switch alg {
	case httpsig.AlgEd25519, httpsig.AlgECDSAP256SHA256, httpsig.AlgRSAPSSSHA512:
		return true
	default:
		return false
	}
}

// keyStateReason 键状态机（§1.4 步 4）：REVOKED 即拒；RETIRED 窗口内放行
// （retire_overlap_until 前）、窗口外拒；ACTIVE 生效域 not_before/not_after
// （nil=不约束）。返回空串=可验。
func keyStateReason(k *KeyRecord, now time.Time) string {
	switch k.Status {
	case "REVOKED":
		return ReasonKeyRevoked
	case "RETIRED":
		if k.RetireOverlapUntil == nil || now.After(*k.RetireOverlapUntil) {
			return ReasonKeyRetiredExpired
		}
		// 窗口内：生效域仍约束（重叠窗口不复活已失效键）
		if !withinValidity(k, now) {
			return ReasonKeyExpired
		}
		return ""
	case "ACTIVE":
		if !withinValidity(k, now) {
			return ReasonKeyExpired
		}
		return ""
	default:
		return ReasonKeyUnknown // 词表外状态按不可验（防御——装配期词表已锁定）
	}
}

// withinValidity 生效域判定（not_before/not_after 为 nil 时对应边界不约束）。
func withinValidity(k *KeyRecord, now time.Time) bool {
	if k.NotBefore != nil && now.Before(*k.NotBefore) {
		return false
	}
	if k.NotAfter != nil && now.After(*k.NotAfter) {
		return false
	}
	return true
}

// skewSeconds 时钟偏移窗口生效值（≤0 缺省 30；夹紧 ≤120——jwtverify 同纪律）。
func (c *Config) skewSeconds() int64 {
	if c.SkewSeconds <= 0 {
		return DefaultClockSkewSeconds
	}
	if c.SkewSeconds > MaxClockSkewSeconds {
		return MaxClockSkewSeconds
	}
	return c.SkewSeconds
}

// proofFreshnessReason 证明时效（§1.4 步 5）：created 不得未来偏移超窗口
// （MID-CLOCK-SKEW）；now 不得过 expires+skew（MID-PROOF-EXPIRED）；
// 证明寿命 expires-created 必须落在 (0, 120s]（MID-PROOF-EXPIRED——证明寿命
// 有界=重放窗口上界）；nonce 必填 8~64 字符（MID-NONCE-INVALID）。
// 语义登记（设计模糊点如实口径）：「created 在偏移窗口」按「created 不得显著
// 未来于 now」解读——created 显著早于 now 是合法在窗证明的常态（寿命窗口由
// expires-created ≤120s 独立承载），反向（未来日戳）才是时钟攻击面。
func proofFreshnessReason(p *httpsig.Params, now time.Time, skew int64) string {
	if p.Nonce != "" && (len(p.Nonce) < NonceMinLen || len(p.Nonce) > NonceMaxLen) {
		return ReasonNonceInvalid
	}
	nowSec := now.Unix()
	if p.Created-nowSec > skew {
		return ReasonClockSkew // 未来日戳超偏移窗口
	}
	if nowSec > p.Expires+skew {
		return ReasonProofExpired // 过期
	}
	if p.Expires-p.Created <= 0 || p.Expires-p.Created > MaxProofLifetimeSeconds {
		return ReasonProofExpired // 寿命窗口非法（重放窗口上界冻结）
	}
	return ""
}

// proofTTL 重放登记 TTL：覆盖完整可接受窗口 (now, expires+skew]，夹紧
// [1s, MaxProofLifetimeSeconds+2*skew]，消除 expires 之后至 expires+skew 之间的重放空窗。
func proofTTL(p *httpsig.Params, now time.Time, skew int64) time.Duration {
	if skew < 0 {
		skew = 0
	}
	deadline := time.Unix(p.Expires, 0).Add(time.Duration(skew) * time.Second)
	remain := deadline.Sub(now)
	if remain < time.Second {
		remain = time.Second // 防御归一最小存活期（过期证明已在步 5 拒绝——边界防御）
	}
	maxTTL := time.Duration(MaxProofLifetimeSeconds+2*skew) * time.Second
	if remain > maxTTL {
		remain = maxTTL
	}
	return remain
}

// coveredHas 覆盖成分存在判定（httpsig.Params 直读）。
func coveredHas(p *httpsig.Params, name string) bool {
	for _, c := range p.CoveredComponents {
		if c == name {
			return true
		}
	}
	return false
}

// mapVerifyError httpsig 验签错误 → 冻结 reason 词表映射（§1.4 步 6/7/8/9）：
// ErrBudget（体预算）由调用侧先行分流（UNKNOWN 不判无效）；
// ErrMalformed → MID-SIGNATURE-MALFORMED；ErrVerify 明细词表分流——
// coverage missing/privileged → MID-COVERAGE-INSUFFICIENT；
// digest → MID-DIGEST-MISMATCH；成分不可得（covered header/query-param 缺席）→
// MID-TARGET-MISMATCH（目标绑定的局部可证子集——签名目标含本请求不存在的成分；
// 密码学失败（含改签后目标不一致）并入 MID-SIGNATURE-INVALID（不可分割性见
// httpsig verify.go 登记——防探测不区分签名错/基线错））。
func mapVerifyError(err error) string {
	if errors.Is(err, httpsig.ErrMalformed) {
		return ReasonSignatureMalformed
	}
	if !errors.Is(err, httpsig.ErrVerify) {
		return ReasonSignatureInvalid // 未知类防御归一（不冒充细分）
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "coverage missing"):
		return ReasonCoverageInsufficient
	case strings.Contains(msg, "unsupported_component"):
		return ReasonCoverageInsufficient // @target-uri 等 G1 排除形态（§3 拒收口径）
	case strings.Contains(msg, "digest_mismatch"), strings.Contains(msg, "digest_no_supported_alg"):
		return ReasonDigestMismatch
	case strings.Contains(msg, "not present"), strings.Contains(msg, "unparseable"):
		return ReasonTargetMismatch
	default:
		return ReasonSignatureInvalid
	}
}

// identityFingerprint 身份指纹（identity_salt 加盐 HMAC-SHA256 截断 16 字节 hex——
// detectors.Fingerprint 同算法；域分隔 "machineid:identity:" 独立不混用）。
func identityFingerprint(salt, identityName string) string {
	if salt == "" {
		salt = "jiuzhang-wdsp-fp-default\x00"
	}
	m := hmac.New(sha256.New, []byte(salt))
	_, _ = m.Write([]byte("machineid:identity:"))
	_, _ = m.Write([]byte(identityName))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// principalFingerprint principal_binding 比对指纹（身份行绑定 JWT
// VerifiedPrincipalID 指纹值——域分隔 "jwt-principal:" 与 jwt_trust 租户指纹
// （jwt-tenant:）同族纪律；与 server B1 录入时计算口径同域（跨轨冻结对齐点））。
func principalFingerprint(salt, principalID string) string {
	if salt == "" {
		salt = "jiuzhang-wdsp-fp-default\x00"
	}
	m := hmac.New(sha256.New, []byte(salt))
	_, _ = m.Write([]byte("jwt-principal:"))
	_, _ = m.Write([]byte(principalID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
