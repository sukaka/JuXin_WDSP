// canonical_test.go 规范化签名与 Ed25519 验签测试（NG-AZ-01 §1/§2 第 1 步锚定）：
// 测试内生成密钥对并登记公钥——签名/验签与 canonicalEventBytes/canonicalBatchBytes
// 同一构造函数（单一事实源），键序字典序紧凑 JSON 跨实现一致性由本测试锚定。
package apiauthzauthority

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// testKey 测试密钥对（公钥 hex 登记用）。
type testKey struct {
	keyID string
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
}

func newTestKey(t *testing.T, keyID string) *testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testKey{keyID: keyID, pub: pub, priv: priv}
}

func (k *testKey) pubHex() string { return hex.EncodeToString(k.pub) }

// signEvent 事件签名（与验签同一规范化输入）。
func (k *testKey) signEvent(t *testing.T, e ChangeEvent) ChangeEvent {
	t.Helper()
	msg, err := CanonicalEventBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	e.SourceSignature = hex.EncodeToString(ed25519.Sign(k.priv, msg))
	return e
}

// signBatch 批次签名（items 先逐条签名后整体签名）。
func (k *testKey) signBatch(t *testing.T, p ImportBatchPayload) ImportBatchPayload {
	t.Helper()
	msg, err := CanonicalBatchBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	p.BatchSignature = hex.EncodeToString(ed25519.Sign(k.priv, msg))
	return p
}

func baseEvent(sourceID string, seq uint64) ChangeEvent {
	return ChangeEvent{
		SourceID:     sourceID,
		EventID:      "evt-1",
		KeyID:        "k1",
		Sequence:     seq,
		ObjectType:   "document",
		TenantDomain: "waf-s5.local",
		PrincipalRef: "subj:abc123",
		ObjectRef:    "objref:def456",
		Relation:     "OWNER",
		ChangeType:   "GRANT",
		ValidFrom:    "2026-10-04T00:00:00Z",
		IssuedAt:     "2026-10-04T00:00:00Z",
	}
}

// 规范化字节确定性：键序字典序、同输入恒同字节、sequence 大值无科学计数漂移。
func TestCanonicalEventBytesDeterministic(t *testing.T) {
	e := baseEvent("src", 1)
	e.Sequence = 1<<60 + 12345 // 超 float53 精确域
	b1, err := CanonicalEventBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := CanonicalEventBytes(e)
	if string(b1) != string(b2) {
		t.Fatal("同输入规范化字节必须恒定")
	}
	var m map[string]any
	if err := json.Unmarshal(b1, &m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b1), "e+") || strings.Contains(string(b1), "E+") {
		t.Fatalf("sequence 不得科学计数化: %s", b1)
	}
	if !strings.Contains(string(b1), "1152921504606859321") {
		t.Fatalf("sequence 精确保留: %s", b1)
	}
	// 键序字典序：首键 change_type
	if !strings.HasPrefix(string(b1), `{"change_type"`) {
		t.Fatalf("键序须字典序: %.60s", b1)
	}
	// valid_until 缺省不进签名输入；非空进入
	e2 := e
	e2.ValidUntil = "2026-10-05T00:00:00Z"
	b3, _ := CanonicalEventBytes(e2)
	if !strings.Contains(string(b3), "valid_until") {
		t.Fatal("valid_until 非空应进签名输入")
	}
}

// 签名/验签往返 + 篡改检测。
func TestEventSignatureRoundtrip(t *testing.T) {
	k := newTestKey(t, "k1")
	e := k.signEvent(t, baseEvent("src", 1))
	pub, err := decodePublicKey(k.pubHex())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyEventSignature(pub, e) {
		t.Fatal("合法签名必须验过")
	}
	// 篡改任一签名字段 → 验签失败
	tampered := e
	tampered.PrincipalRef = "subj:evil"
	if verifyEventSignature(pub, tampered) {
		t.Fatal("篡改 principal_ref 必须验签失败")
	}
	// 错公钥 → 失败
	k2 := newTestKey(t, "k2")
	pub2, _ := decodePublicKey(k2.pubHex())
	if verifyEventSignature(pub2, e) {
		t.Fatal("错公钥必须验签失败")
	}
	// 公钥形态校验
	if _, err := decodePublicKey("zz"); err == nil {
		t.Fatal("坏 hex 公钥应报错")
	}
	if _, err := decodePublicKey("abcd"); err == nil {
		t.Fatal("短公钥应报错")
	}
}

// 批次签名往返（批次级防增删条目）。
func TestBatchSignatureRoundtrip(t *testing.T) {
	k := newTestKey(t, "k1")
	src := "11111111-1111-1111-1111-111111111111"
	e := k.signEvent(t, baseEvent(src, 1))
	p := k.signBatch(t, ImportBatchPayload{
		BatchID: "b1", SourceID: src, Mode: ModeDelta, KeyID: "k1", Items: []ChangeEvent{e},
	})
	pub, _ := decodePublicKey(k.pubHex())
	if !verifyBatchSignature(pub, p) {
		t.Fatal("合法批次签名必须验过")
	}
	// 增一条目 → 批次验签失败
	e2 := k.signEvent(t, baseEvent(src, 2))
	p2 := p
	p2.Items = append(p2.Items, e2)
	if verifyBatchSignature(pub, p2) {
		t.Fatal("增删条目必须批次验签失败")
	}
}

// 轮换窗口：ACTIVE 恒可用；RETIRED 仅 issued_at ≤ retired_at+maxAge。
func TestKeyUsableAtRotationWindow(t *testing.T) {
	retired := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	k := SourceKey{KeyID: "k1", Status: KeyStatusRetired, RetiredAt: &retired}
	if !keyUsableAt(k, retired.Add(-time.Hour), 24*time.Hour) {
		t.Fatal("退役前事件应可用（窗口内）")
	}
	if !keyUsableAt(k, retired.Add(23*time.Hour), 24*time.Hour) {
		t.Fatal("窗口内事件应可用")
	}
	if keyUsableAt(k, retired.Add(25*time.Hour), 24*time.Hour) {
		t.Fatal("窗口外事件应不可用")
	}
	if !keyUsableAt(k, retired.Add(23*time.Hour), 0) {
		t.Fatal("maxAge≤0 走默认 24h——窗口内应可用")
	}
	if keyUsableAt(k, retired.Add(25*time.Hour), 0) {
		t.Fatal("maxAge≤0 走默认 24h——超窗不可用")
	}
	active := SourceKey{KeyID: "k2", Status: KeyStatusActive}
	if !keyUsableAt(active, time.Now(), 0) {
		t.Fatal("ACTIVE 恒可用")
	}
}
