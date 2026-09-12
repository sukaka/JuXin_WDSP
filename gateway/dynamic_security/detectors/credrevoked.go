package detectors

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 已吊销凭据使用检测（任务书 §35「API身份与凭据模型」第10项）：
// 发布通道下发 api_revoked_credentials（对应管理面 api_revoked_credentials 表当前生效
// 窗口内的行，迁移 000156 建立；server 契约 GuardRevokedCredential），载荷仅指纹级
// （credential_type + 32 位 hex 加盐 HMAC 指纹），无凭据明文。
//
// 比对口径：请求凭据键（CredentialKey：auth:/key:/sess: 前缀 + 指纹）与清单
// credential_type + ":" + fingerprint 全等匹配，集合查找 O(1)；expires_at 已过期的
// 条目不判定（发布间隙自行失效），expires_at 为空 = 永久吊销。
//
// 纪律与 credanomaly.go 同组：匿名流量（无凭据键）直接跳过；全部 OBSERVE 级只
// AddMatch，动作统一由决策引擎输出；证据只含指纹与类型，绝不含凭据明文。

// RevokedCredential 已吊销凭据清单条目（发布通道下发；json tag 为跨分片契约，
// 与 server GuardRevokedCredential 对齐，不得改动）。
type RevokedCredential struct {
	CredentialType string `json:"credential_type"`      // auth / key / sess（与凭据键前缀一致）
	Fingerprint    string `json:"fingerprint"`          // 加盐 HMAC-SHA256 截断 16 字节小写 hex（32 位，不含前缀）
	ExpiresAt      string `json:"expires_at,omitempty"` // RFC3339；空 = 永久吊销
}

// RevokedConfigError 吊销清单配置错误（指明条目下标与原因；装配期拒绝加载用）。
type RevokedConfigError struct {
	Index  int
	Reason string
}

func (e *RevokedConfigError) Error() string {
	return fmt.Sprintf("api_revoked_credentials[%d]: %s", e.Index, e.Reason)
}

// revokedCredentialTypes 凭据类型词表（与 CredentialKey 前缀一一对应）。
var revokedCredentialTypes = map[string]bool{"auth": true, "key": true, "sess": true}

// ValidateRevokedCredentials 装配期校验：类型词表、指纹格式（32 位小写 hex）、
// expires_at 可解析（RFC3339）。任一非法显式报错，不静默吞错——类型/指纹非法的
// 条目永远不可能命中（请求侧指纹恒为小写 hex），静默放过等于配置失效。
func ValidateRevokedCredentials(list []RevokedCredential) error {
	for i := range list {
		c := list[i]
		if !revokedCredentialTypes[c.CredentialType] {
			return &RevokedConfigError{Index: i, Reason: "credential_type 非法: " + c.CredentialType}
		}
		if len(c.Fingerprint) != 32 {
			return &RevokedConfigError{Index: i, Reason: "fingerprint 须为 32 位 hex"}
		}
		if _, err := hex.DecodeString(c.Fingerprint); err != nil {
			return &RevokedConfigError{Index: i, Reason: "fingerprint 非 hex 字符"}
		}
		if c.Fingerprint != strings.ToLower(c.Fingerprint) {
			return &RevokedConfigError{Index: i, Reason: "fingerprint 须为小写 hex"}
		}
		if c.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil {
				return &RevokedConfigError{Index: i, Reason: "expires_at 非 RFC3339: " + err.Error()}
			}
		}
	}
	return nil
}

// IndexRevokedCredentials 吊销清单编译为比对集合：键 = credential_type + ":" +
// fingerprint（与 CredentialKey 输出同形），值 = 过期时刻（零值 = 永久吊销）。
// 先校验后建索引，配置错误如实返回，不静默吞错。
func IndexRevokedCredentials(list []RevokedCredential) (map[string]time.Time, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if err := ValidateRevokedCredentials(list); err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(list))
	for _, c := range list {
		var exp time.Time
		if c.ExpiresAt != "" {
			// 上方校验已保证可解析，此处不会失败
			exp, _ = time.Parse(time.RFC3339, c.ExpiresAt)
		}
		out[c.CredentialType+":"+c.Fingerprint] = exp
	}
	return out, nil
}

// CheckCredentialRevoked 已吊销凭据使用：请求凭据键命中吊销集合且条目未过期 →
// auth.credential_revoked（OBSERVE/HIGH，只 AddMatch 不定案）。
// 匿名（credKey 空）与空清单直接跳过；expires_at 已过期条目不判定（发布间隙自行失效）。
// 证据只含凭据类型与指纹（指纹本身即加盐 HMAC，非凭据明文）。
func CheckCredentialRevoked(ctx *dsctx.RequestContext, credKey string, revoked map[string]time.Time, now time.Time) {
	if ctx == nil || credKey == "" || len(revoked) == 0 {
		return
	}
	exp, ok := revoked[credKey]
	if !ok {
		return
	}
	if !exp.IsZero() && !now.Before(exp) {
		return
	}
	credType, fp, _ := strings.Cut(credKey, ":")
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "authentication",
		RuleID:   "auth.credential_revoked",
		Category: "OBSERVE",
		Severity: "HIGH",
		Message:  "revoked credential in use",
		Evidence: map[string]string{
			"credential_type": credType,
			"fingerprint":     fp,
		},
		ScoreDelta: 30,
	})
}
