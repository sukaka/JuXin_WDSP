package ratelimitpolicies

import (
	"strings"
	"testing"
)

func simPolicy(algo string, limit, window, burst int) *Policy {
	return &Policy{
		Name:          "模拟策略",
		ScopeType:     ScopeGlobal,
		URIMatchType:  URIMatchAll,
		Dimension:     DimensionClientIP,
		Algorithm:     algo,
		RequestsLimit: limit,
		WindowSeconds: window,
		BurstCapacity: burst,
		Action:        ActionReject,
	}
}

func TestTokenBucketUnderThreshold(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 100, 60, 0)
	res := Simulate(p, SimInput{Requests: 50, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed != 50 || res.Rejected != 0 {
		t.Errorf("under threshold should allow all: %+v", res)
	}
	if res.FirstRejectAt != 0 || res.RetryAfterSeconds != 0 {
		t.Errorf("no rejection expected: %+v", res)
	}
}

func TestTokenBucketOverThreshold(t *testing.T) {
	// 窗口极大排除补充影响：容量=burst=20
	p := simPolicy(AlgorithmTokenBucket, 10, 86400, 20)
	res := Simulate(p, SimInput{Requests: 25, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed != 20 || res.Rejected != 5 {
		t.Errorf("expected 20 allowed 5 rejected: %+v", res)
	}
	if res.FirstRejectAt != 21 {
		t.Errorf("first reject should be request #21: %+v", res)
	}
	if res.RetryAfterSeconds < 1 {
		t.Errorf("retry_after should be >= 1 when rejected: %+v", res)
	}
}

func TestTokenBucketBurstZeroMeansLimit(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 10, 86400, 0)
	if p.EffectiveBurst() != 10 {
		t.Fatalf("burst 0 should mean limit: %d", p.EffectiveBurst())
	}
	res := Simulate(p, SimInput{Requests: 15, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed != 10 || res.FirstRejectAt != 11 {
		t.Errorf("capacity should equal limit: %+v", res)
	}
}

func TestTokenBucketRefillRecovery(t *testing.T) {
	// 速率 10/s，10ms 间隔：桶空后约每 100ms 恢复 1 个令牌
	p := simPolicy(AlgorithmTokenBucket, 10, 1, 0)
	res := Simulate(p, SimInput{Requests: 30, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed <= 10 {
		t.Errorf("refill should allow more than initial capacity: %+v", res)
	}
	if res.Rejected == 0 || res.Allowed+res.Rejected != 30 {
		t.Errorf("expected rejections too: %+v", res)
	}
	if res.FirstRejectAt < 11 || res.FirstRejectAt > 13 {
		t.Errorf("first reject should be around request #11: %+v", res)
	}
}

func TestSlidingWindowUnderThreshold(t *testing.T) {
	p := simPolicy(AlgorithmSlidingWindow, 100, 10, 0)
	res := Simulate(p, SimInput{Requests: 50, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed != 50 || res.Rejected != 0 {
		t.Errorf("under threshold should allow all: %+v", res)
	}
}

func TestSlidingWindowOverThreshold(t *testing.T) {
	p := simPolicy(AlgorithmSlidingWindow, 5, 10, 0)
	res := Simulate(p, SimInput{Requests: 8, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed != 5 || res.Rejected != 3 {
		t.Errorf("expected 5 allowed 3 rejected: %+v", res)
	}
	if res.FirstRejectAt != 6 {
		t.Errorf("first reject should be request #6: %+v", res)
	}
	// 首次拒绝在第 50ms，retry = 10s - 50ms = 9.95s → 向上取整 10s
	if res.RetryAfterSeconds != 10 {
		t.Errorf("retry_after should be 10s: %+v", res)
	}
}

func TestSlidingWindowRecovery(t *testing.T) {
	// 第 2 个窗口上一窗口权重随时间衰减，估算值下降后恢复放行
	p := simPolicy(AlgorithmSlidingWindow, 5, 1, 0)
	res := Simulate(p, SimInput{Requests: 150, ClientIPs: []string{"1.1.1.1"}})
	if res.Allowed <= 5 {
		t.Errorf("should recover in next window: %+v", res)
	}
	if res.Allowed >= 50 {
		t.Errorf("weighted window should still limit: %+v", res)
	}
	if res.FirstRejectAt != 6 {
		t.Errorf("first reject should be request #6: %+v", res)
	}
	if res.Allowed+res.Rejected != 150 {
		t.Errorf("count mismatch: %+v", res)
	}
}

func TestDimensionClientIPIsIndependent(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 5, 60, 0)
	p.Dimension = DimensionClientIP
	res := Simulate(p, SimInput{Requests: 12, ClientIPs: []string{"1.1.1.1", "2.2.2.2"}})
	// 每个 IP 各 6 个请求、各放行 5 个
	if res.Allowed != 10 || res.Rejected != 2 {
		t.Errorf("each IP should have independent quota: %+v", res)
	}
	if res.FirstRejectAt != 11 {
		t.Errorf("first reject should be request #11: %+v", res)
	}
	if !strings.Contains(res.DimensionNote, "CLIENT_IP") {
		t.Errorf("dimension note should explain CLIENT_IP: %+v", res)
	}
}

func TestDimensionApplicationShared(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 5, 60, 0)
	p.Dimension = DimensionApplication
	res := Simulate(p, SimInput{Requests: 12, ClientIPs: []string{"1.1.1.1", "2.2.2.2"}})
	// 全部请求共享一个计数器
	if res.Allowed != 5 || res.Rejected != 7 {
		t.Errorf("application dimension should share one counter: %+v", res)
	}
	if res.FirstRejectAt != 6 {
		t.Errorf("first reject should be request #6: %+v", res)
	}
	if !strings.Contains(res.DimensionNote, "APPLICATION") {
		t.Errorf("dimension note should explain APPLICATION: %+v", res)
	}
}

func TestSimulateDefaults(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 10, 60, 0)
	res := Simulate(p, SimInput{Requests: 5}) // 缺省 1 个模拟IP、URI "/"
	if res.Allowed != 5 {
		t.Errorf("default input should work: %+v", res)
	}
	if res.DimensionNote == "" {
		t.Error("dimension note should not be empty")
	}
}

func TestSimulateZeroRequests(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 10, 60, 0)
	res := Simulate(p, SimInput{Requests: 0})
	if res.Allowed != 0 || res.Rejected != 0 || res.FirstRejectAt != 0 {
		t.Errorf("zero requests should yield empty result: %+v", res)
	}
}

func TestSimulateInvalidPolicyRejected(t *testing.T) {
	// 防御：非法阈值（零窗口）不得静默放行
	p := simPolicy(AlgorithmTokenBucket, 10, 0, 0)
	res := Simulate(p, SimInput{Requests: 3})
	if res.Rejected != 3 || res.FirstRejectAt != 1 {
		t.Errorf("invalid policy should reject all: %+v", res)
	}
}

func TestEffectiveBurst(t *testing.T) {
	p := simPolicy(AlgorithmTokenBucket, 10, 60, 30)
	if p.EffectiveBurst() != 30 {
		t.Errorf("explicit burst should be used: %d", p.EffectiveBurst())
	}
}
