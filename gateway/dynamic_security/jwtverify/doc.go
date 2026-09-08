// Package jwtverify 实现 P0-03「业务 JWT 信任链」网关侧的纯本地验证器与 JWKS 缓存。
//
// 本包只做一次性的本地验证：解析并验证 Authorization Bearer JWT 的签名、
// 算法/密钥绑定、issuer、audience、exp/nbf 与 sub，产出不可变的
// VerificationResult（冻结契约见 docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md §5）。
// 本包不负责 HTTP 处置（401/503 由挂接层按模式决定）、不向源站注入任何身份头、
// 不信任 Token 自带的 jku/x5u/embedded jwk，也绝不回显原始 Token 或声明。
//
// 热路径零网络 IO：远程 JWKS 的获取只发生在后台刷新与未知 kid 触发的受限
// 异步刷新中；验证路径只读不可变密钥集快照（原子替换）。
package jwtverify
