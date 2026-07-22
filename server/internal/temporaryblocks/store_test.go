package temporaryblocks

import (
	"testing"
	"time"
)

// TestBlockFieldKeyStable 验证封禁 field 键算法的稳定性（已知向量，
// 与网关 counters.HashParts(ip, appID) 算法一致，改动会导致网关与管理面键不一致）。
func TestBlockFieldKeyStable(t *testing.T) {
	cases := []struct {
		ip, appID, want string
	}{
		{"192.168.1.10", "", "cb4420a9347d10bb29fcea66eec96a87"},
		{"192.168.1.10", "app-001", "8cdbb14939a0fec8b19b8280ef101253"},
		{"10.0.0.1", "550e8400-e29b-41d4-a716-446655440000", "b7e88d54fcb404df5b609d21d5634807"},
		{"::1", "", "2f12e64dd2ab99c6b9548ba99cc339ce"},
	}
	for _, c := range cases {
		if got := BlockFieldKey(c.ip, c.appID); got != c.want {
			t.Errorf("BlockFieldKey(%q, %q) = %q, want %q", c.ip, c.appID, got, c.want)
		}
		// 重复计算稳定
		if got := BlockFieldKey(c.ip, c.appID); got != c.want {
			t.Errorf("BlockFieldKey(%q, %q) not stable", c.ip, c.appID)
		}
	}
}

// TestBlockFieldKeyLengthPrefix 验证长度前缀编码避免拼接歧义：
// ("ab","c") 与 ("a","bc") 必须得到不同的键。
func TestBlockFieldKeyLengthPrefix(t *testing.T) {
	if BlockFieldKey("ab", "c") == BlockFieldKey("a", "bc") {
		t.Error("length-prefixed encoding should distinguish (ab,c) from (a,bc)")
	}
	// 全局（空 appID）与应用级键不同
	if BlockFieldKey("1.2.3.4", "") == BlockFieldKey("1.2.3.4", "any-app") {
		t.Error("global and app-scoped keys should differ")
	}
	if len(BlockFieldKey("1.2.3.4", "")) != 32 {
		t.Error("field key should be 32 hex chars")
	}
}

func TestValidateNewExpiry(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	if err := ValidateNewExpiry(now.Add(time.Hour), now); err != nil {
		t.Errorf("future expiry should pass: %v", err)
	}
	if err := ValidateNewExpiry(now, now); err == nil {
		t.Error("expiry equal to now should be rejected")
	}
	if err := ValidateNewExpiry(now.Add(-time.Hour), now); err == nil {
		t.Error("past expiry should be rejected")
	}
	if err := ValidateNewExpiry(time.Time{}, now); err == nil {
		t.Error("zero expiry should be rejected")
	}
}

func TestAppKey(t *testing.T) {
	b := &Block{}
	if b.appKey() != "" {
		t.Error("nil application_id should map to empty app key (global)")
	}
}
