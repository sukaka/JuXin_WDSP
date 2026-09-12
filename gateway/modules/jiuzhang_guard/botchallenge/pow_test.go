package botchallenge

import (
	"strings"
	"testing"
)

// PoW 往返：服务端出题 → 求解 → 权威校验通过；错误解答拒绝。
func TestPowSolveAndCheck(t *testing.T) {
	cid := strings.Repeat("ab", challengeIDBytes)
	nonce := strings.Repeat("cd", nonceBytes)
	sol, ok := Solve(cid, nonce, "app-1", "shop.example.com", MinDifficulty, 1<<20)
	if !ok {
		t.Fatal("solver must find solution within bound at difficulty 10")
	}
	pass, err := CheckSolution(cid, nonce, "app-1", "shop.example.com", sol, MinDifficulty)
	if err != nil || !pass {
		t.Fatalf("solution must pass: %v %v", pass, err)
	}
	// 更高难度拒绝同一解答（概率性极低误判；difficulty 18 vs 10 的解前导零位不足即拒）
	pass18, err := CheckSolution(cid, nonce, "app-1", "shop.example.com", sol, MaxDifficulty)
	if err != nil {
		t.Fatal(err)
	}
	if pass18 {
		d, _ := powDigest(cid, nonce, "app-1", "shop.example.com", sol)
		if leadingZeroBits(d) < MaxDifficulty {
			t.Fatal("pass18=true but leading zero bits < 18: impossible")
		}
		t.Skip("solution happens to satisfy 18 bits too (1/256 概率)")
	}
}

// 上下文绑定：跨应用/Host 同一解答不通过（PoW 输入绑定）。
func TestPowBinding(t *testing.T) {
	cid := strings.Repeat("ab", challengeIDBytes)
	nonce := strings.Repeat("cd", nonceBytes)
	sol, _ := Solve(cid, nonce, "app-1", "shop.example.com", MinDifficulty, 1<<20)
	if ok, _ := CheckSolution(cid, nonce, "app-2", "shop.example.com", sol, MinDifficulty); ok {
		t.Fatal("cross-app solution must not pass")
	}
	if ok, _ := CheckSolution(cid, nonce, "app-1", "other.example.com", sol, MinDifficulty); ok {
		t.Fatal("cross-host solution must not pass")
	}
	// Host 大小写不敏感（normalizeHost）
	if ok, err := CheckSolution(cid, nonce, "app-1", "SHOP.EXAMPLE.COM", sol, MinDifficulty); err != nil || !ok {
		t.Fatalf("host case-insensitive must pass: %v %v", ok, err)
	}
}

// solution 词形边界：空/超长/非数字/uint64 溢出拒绝；篡改难度（难度非请求字段）无从发生。
func TestPowSolutionBounds(t *testing.T) {
	cid := strings.Repeat("ab", challengeIDBytes)
	nonce := strings.Repeat("cd", nonceBytes)
	for _, bad := range []string{"", strings.Repeat("1", maxSolutionLen+1), "12a3", "-1", " 1", "18446744073709551616", "0x10"} {
		if validSolution(bad) {
			t.Errorf("solution %q must be rejected", bad)
		}
		if _, err := CheckSolution(cid, nonce, "app-1", "h", bad, MinDifficulty); err == nil {
			t.Errorf("CheckSolution(%q) must error", bad)
		}
	}
	if !validSolution("18446744073709551615") {
		t.Error("uint64 max must be accepted")
	}
}

// 非法 challenge_id / nonce 长度拒绝（固定编码）。
func TestPowInputValidation(t *testing.T) {
	nonce := strings.Repeat("cd", nonceBytes)
	if _, err := CheckSolution("zz", nonce, "app-1", "h", "1", MinDifficulty); err == nil {
		t.Fatal("bad challenge_id must error")
	}
	if _, err := CheckSolution(strings.Repeat("ab", challengeIDBytes), "00", "app-1", "h", "1", MinDifficulty); err == nil {
		t.Fatal("short nonce must error")
	}
}

// leadingZeroBits 边界。
func TestLeadingZeroBits(t *testing.T) {
	var zero [32]byte
	if n := leadingZeroBits(zero); n != 256 {
		t.Fatalf("all-zero: %d", n)
	}
	var one [32]byte
	one[0] = 0x80 // 首位 1
	if n := leadingZeroBits(one); n != 0 {
		t.Fatalf("msb set: %d", n)
	}
	var d [32]byte
	d[0] = 0x0F // 4 个前导零
	if n := leadingZeroBits(d); n != 4 {
		t.Fatalf("0x0F: %d", n)
	}
}

// flow_id：确定性、16 hex、与挑战 ID 不可逆区分（不含原始 ID 材料）。
func TestFlowID(t *testing.T) {
	cid := strings.Repeat("ef", challengeIDBytes)
	a, b := flowID(cid), flowID(cid)
	if a != b || len(a) != 16 {
		t.Fatalf("flow_id must be deterministic 16 hex: %q", a)
	}
	if strings.Contains(a, cid[:16]) {
		t.Fatal("flow_id must not embed raw challenge id")
	}
	if flowID(strings.Repeat("ee", challengeIDBytes)) == a {
		t.Fatal("distinct challenges must have distinct flow ids")
	}
}
