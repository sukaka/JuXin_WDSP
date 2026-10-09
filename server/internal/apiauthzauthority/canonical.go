// canonical.go 规范化签名输入与 Ed25519 验签（NG-AZ-01 §1/§2 第 1 步）。
//
// 规范化字节：事件字段（不含 source_signature 本身）→ map（键序字典序由
// encoding/json 保证）→ 紧凑 JSON。sequence 以 json.Number 承载——uint64 大值
// 不经 float64（防 1e+18 科学计数格式漂移破坏跨语言验签一致性）。
// 批次签名输入：{batch_id, mode, source_id, key_id, items:[各事件规范化 map（含其
// source_signature 字段）]} 的同法紧凑 JSON——批次与事件两级签名互不替代
// （事件级防单条替换，批次级防增删条目）。
package apiauthzauthority

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// canonicalEventMap 事件规范化 map（签名输入与验签重建共用同一构造函数——单一事实源）。
func canonicalEventMap(e ChangeEvent) map[string]any {
	m := map[string]any{
		"change_type":   e.ChangeType,
		"event_id":      e.EventID,
		"issued_at":     e.IssuedAt,
		"key_id":        e.KeyID,
		"object_ref":    e.ObjectRef,
		"object_type":   e.ObjectType,
		"principal_ref": e.PrincipalRef,
		"relation":      e.Relation,
		"sequence":      json.Number(strconv.FormatUint(e.Sequence, 10)),
		"source_id":     e.SourceID,
		"tenant_domain": e.TenantDomain,
		"valid_from":    e.ValidFrom,
	}
	if e.ValidUntil != "" {
		m["valid_until"] = e.ValidUntil
	}
	return m
}

// canonicalEventBytes 事件规范化字节（source_signature 的签名输入）。
func CanonicalEventBytes(e ChangeEvent) ([]byte, error) {
	return json.Marshal(canonicalEventMap(e))
}

// canonicalBatchBytes 批次规范化字节（batch_signature 的签名输入）。
func CanonicalBatchBytes(p ImportBatchPayload) ([]byte, error) {
	items := make([]any, 0, len(p.Items))
	for _, e := range p.Items {
		m := canonicalEventMap(e)
		m["source_signature"] = e.SourceSignature
		items = append(items, m)
	}
	return json.Marshal(map[string]any{
		"batch_id":  p.BatchID,
		"key_id":    p.KeyID,
		"mode":      p.Mode,
		"source_id": p.SourceID,
		"items":     items,
	})
}

// decodePublicKey Ed25519 公钥 hex 解码（32 字节强校验）。
func decodePublicKey(publicKeyHex string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("公钥 hex 解码失败: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("公钥长度 %d 字节，须 %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// verifyEventSignature 事件级验签（按事件 key_id 对应的公钥）。
func verifyEventSignature(pub ed25519.PublicKey, e ChangeEvent) bool {
	sig, err := hex.DecodeString(e.SourceSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := CanonicalEventBytes(e)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// verifyBatchSignature 批次级验签（按批次 key_id 对应的公钥）。
func verifyBatchSignature(pub ed25519.PublicKey, p ImportBatchPayload) bool {
	sig, err := hex.DecodeString(p.BatchSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := CanonicalBatchBytes(p)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// keyUsableAt 轮换窗口判定：ACTIVE 键恒可用；RETIRED 键仅验 issuedAt ≤ retired_at+maxAge
// 的事件（窗口长度=max_event_age_seconds，未配置取 24h 默认——设计 §4「窗口长度随
// 轮换事件登记」的本批实现口径）。
func keyUsableAt(k SourceKey, issuedAt time.Time, maxAge time.Duration) bool {
	if k.Status == KeyStatusActive {
		return true
	}
	if k.RetiredAt == nil {
		return false
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxEventAge
	}
	return !issuedAt.After(k.RetiredAt.Add(maxAge))
}
