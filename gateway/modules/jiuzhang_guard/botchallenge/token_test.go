package botchallenge

import (
	"strings"
	"testing"
	"time"
)

// 密钥环校验：非法 key_id（路径/URL 形态）、弱密钥、重复 ID 全部 fail-closed。
func TestKeyringValidation(t *testing.T) {
	sec := []byte(strings.Repeat("k", 32))
	for _, badID := range []string{"../secret", "/etc/keys/a", "https://x/k", "A-upper", "", " with-space", "-lead-dash"} {
		if _, err := NewKeyring(Key{ID: badID, Secret: sec}); err == nil {
			t.Errorf("key_id %q must be rejected (路径/URL 拼接禁止)", badID)
		}
	}
	if _, err := NewKeyring(Key{ID: "ok", Secret: []byte("short")}); err == nil {
		t.Error("short secret must be rejected (<32 bytes)")
	}
	if _, err := NewKeyring(Key{ID: "a", Secret: sec}, Key{ID: "a", Secret: sec}); err == nil {
		t.Error("duplicate key id must be rejected")
	}
	kr, err := NewKeyring(Key{ID: "bot-hmac-2026.09", Secret: sec}, Key{ID: "bot-hmac-2026.06", Secret: sec})
	if err != nil {
		t.Fatalf("valid keyring: %v", err)
	}
	if got := kr.KeyIDs(); len(got) != 2 || got[0] != "bot-hmac-2026.06" || got[1] != "bot-hmac-2026.09" {
		t.Fatalf("KeyIDs: %v", got)
	}
	if _, ok := kr.Lookup("../escape"); ok {
		t.Error("lookup must never resolve path-like id")
	}
}

// 会话/通行签名往返 + 篡改/跨用途/未知 key_id/过期拒绝。
func TestTokenSignVerify(t *testing.T) {
	kr := testKeyring(t, "k1")
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	val, err := signToken(mustLookup(t, kr, "k1"), purposeSession, sessionPayload{V: 1, Sid: strings.Repeat("ab", 32), Exp: now.Add(time.Minute).Unix(), Kid: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	var sp sessionPayload
	if err := verifyToken(kr, purposeSession, val, &sp, now); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	// 跨用途：会话 token 按通行用途验 → 拒绝（版本化用途标识参与签名）
	var cp clearancePayload
	if err := verifyToken(kr, purposeClearance, val, &cp, now); err == nil {
		t.Fatal("cross-purpose verify must fail")
	}
	// 篡改载荷一个字符
	tampered := val[:len(val)/2] + flipChar(string(val[len(val)/2])) + val[len(val)/2+1:]
	if err := verifyToken(kr, purposeSession, tampered, &sp, now); err == nil {
		t.Fatal("tampered payload must fail")
	}
	// 篡改签名
	parts := strings.Split(val, ".")
	badSig := parts[0] + "." + parts[1] + "." + strings.Repeat("0", tokenSigHexLen)
	if err := verifyToken(kr, purposeSession, badSig, &sp, now); err == nil {
		t.Fatal("bad signature must fail")
	}
	// 未知 key_id（允许列表之外 → 拒绝，不回退默认密钥）
	kr2 := testKeyring(t, "k2")
	if err := verifyToken(kr2, purposeSession, val, &sp, now); err == nil {
		t.Fatal("unknown key_id must fail")
	}
	// 过期
	if err := verifyToken(kr, purposeSession, val, &sp, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired token must fail")
	}
	// 超长 token
	if err := verifyToken(kr, purposeSession, val+strings.Repeat("A", 2048), &sp, now); err == nil {
		t.Fatal("oversized token must fail")
	}
	// 结构非法（段数/版本）
	if err := verifyToken(kr, purposeSession, "v2."+parts[1]+"."+parts[2], &sp, now); err == nil {
		t.Fatal("unknown version must fail")
	}
	if err := verifyToken(kr, purposeSession, parts[1], &sp, now); err == nil {
		t.Fatal("truncated token must fail")
	}
}

// 轮换窗口：旧密钥签发的通行在窗口内可验；当前密钥切换后新签用新 key_id；
// 旧 key 移出允许列表后立即不可验（紧急收缩）。
func TestTokenRotation(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	oldKr := testKeyring(t, "k-old")
	val, err := signToken(mustLookup(t, oldKr, "k-old"), purposeClearance, clearancePayload{
		V: 1, App: "app-1", Hh: "hh", Sd: "sd", Ep: 7, Fl: "f", Iat: now.Unix(), Exp: now.Add(15 * time.Minute).Unix(), Kid: "k-old",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 轮换：current=k-new，k-old 保留在验签窗口
	newKr := testKeyring(t, "k-new", "k-old")
	var cp clearancePayload
	if err := verifyToken(newKr, purposeClearance, val, &cp, now); err != nil {
		t.Fatalf("previous key must verify within window: %v", err)
	}
	// 窗口外过期：旧 key 仍在列表也拒（exp 强制）
	if err := verifyToken(newKr, purposeClearance, val, &cp, now.Add(16*time.Minute)); err == nil {
		t.Fatal("expired clearance must fail even with old key present")
	}
	// 旧 key 移出允许列表 → 立即不可验
	strictKr := testKeyring(t, "k-new")
	if err := verifyToken(strictKr, purposeClearance, val, &cp, now); err == nil {
		t.Fatal("removed key must not verify")
	}
}

func mustLookup(t *testing.T, kr *Keyring, id string) []byte {
	t.Helper()
	sec, ok := kr.Lookup(id)
	if !ok {
		t.Fatalf("key %q missing", id)
	}
	return sec
}

func flipChar(s string) string {
	if s == "a" {
		return "b"
	}
	return "a"
}
