// machineid.go 机器身份可信信号注入机制（NG-ID G1 批次 B2；WithVerifiedIdentity
// 同形机制——独立上下文键、独立信号类型；**不改 identity_key/identity_type
// 语义**（AGENTS.md 红线 + identity.go:63-70 先例：VerifiedMachineID 是验证链
// 注入的独立可信信号，不改写 Type、不合并、不参与 identity_key 计算））。
// 同请求可双 VERIFIED（JWT 主体+机器身份并存，授权层分别消费）。
package identitybehavior

import "context"

// VerifiedMachineIdentity 可信机器身份信号（仅十步验证链全步通过（VERIFIED）
// 时注入；指纹为 HMAC 值，不落身份名/签名原文/nonce 原文/公钥原文）。
type VerifiedMachineIdentity struct {
	MachineIDFP     string // 身份指纹（identity_salt 加盐 HMAC 截断）
	KeyID           string // 命中密钥引用名（登记册 kid，非密钥材料）
	RegistryVersion int64  // 登记册版本（溯源）
}

// verifiedMachineIdentityKey 请求上下文键（与 verifiedIdentityKey 物理分离——
// 机器身份是独立第二条信任链，不替代不改写 JWT 链信号）。
type verifiedMachineIdentityKey struct{}

// WithVerifiedMachineIdentity 把可信机器身份信号写入请求上下文（仅 VERIFIED
// 时调用——与 WithVerifiedIdentity 同形纪律）。
func WithVerifiedMachineIdentity(ctx context.Context, v *VerifiedMachineIdentity) context.Context {
	if v == nil {
		return ctx
	}
	return context.WithValue(ctx, verifiedMachineIdentityKey{}, v)
}

// VerifiedMachineIdentityFrom 取请求上下文中的可信机器身份信号（未注入为 nil）。
func VerifiedMachineIdentityFrom(ctx context.Context) *VerifiedMachineIdentity {
	v, _ := ctx.Value(verifiedMachineIdentityKey{}).(*VerifiedMachineIdentity)
	return v
}
