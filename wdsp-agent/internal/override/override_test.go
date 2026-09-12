// 定向采集规则集测试（Phase 4 契约 §2.2/§2.4）：匹配矩阵、过期忽略、
// 非法规则跳过、规则数钳制、热更。
package override

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

var testNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func newSet(t *testing.T, ovs ...config.Override) *Set {
	t.Helper()
	s := NewSet(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Replace(ovs)
	return s
}

func ov(match config.OverrideMatch, level string, expires time.Time) config.Override {
	return config.Override{
		ID: "r1", Match: match, CaptureLevel: level,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	}
}

func TestEvalFlowMatchMatrix(t *testing.T) {
	future := testNow.Add(time.Hour)
	cases := []struct {
		name    string
		match   config.OverrideMatch
		dstIP   string
		dstPort uint16
		want    bool
	}{
		{"单 IP 命中", config.OverrideMatch{DstIP: "10.10.20.30"}, "10.10.20.30", 80, true},
		{"单 IP 不命中", config.OverrideMatch{DstIP: "10.10.20.30"}, "10.10.20.31", 80, false},
		{"CIDR v4 命中", config.OverrideMatch{DstIP: "10.10.0.0/16"}, "10.10.20.30", 80, true},
		{"CIDR v4 不命中", config.OverrideMatch{DstIP: "10.10.0.0/16"}, "10.11.0.1", 80, false},
		{"CIDR v6 命中", config.OverrideMatch{DstIP: "2001:db8::/32"}, "2001:db8::1", 80, true},
		{"单 IP v6 命中", config.OverrideMatch{DstIP: "2001:db8::5"}, "2001:db8::5", 443, true},
		{"端口命中", config.OverrideMatch{DstPort: 8443}, "1.2.3.4", 8443, true},
		{"端口不命中", config.OverrideMatch{DstPort: 8443}, "1.2.3.4", 443, false},
		{"AND 全命中", config.OverrideMatch{DstIP: "10.0.0.0/8", DstPort: 8443}, "10.1.1.1", 8443, true},
		{"AND 缺一不命中", config.OverrideMatch{DstIP: "10.0.0.0/8", DstPort: 8443}, "10.1.1.1", 443, false},
		{"host 规则不在首包阶段求值", config.OverrideMatch{Host: "api.example.com"}, "10.1.1.1", 80, false},
		{"host+端口规则首包不求值", config.OverrideMatch{Host: "api.example.com", DstPort: 80}, "10.1.1.1", 80, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSet(t, ov(tc.match, config.LevelL2, future))
			got := s.EvalFlow(tc.dstIP, tc.dstPort, testNow)
			if tc.want && got != 2 {
				t.Fatalf("期望命中 L2，got %d", got)
			}
			if !tc.want && got != 0 {
				t.Fatalf("期望不命中，got %d", got)
			}
		})
	}
}

func TestEvalRequestHostAndURI(t *testing.T) {
	future := testNow.Add(time.Hour)
	s := newSet(t,
		ov(config.OverrideMatch{Host: "API.Example.COM"}, config.LevelL1, future),
		ov(config.OverrideMatch{URIPrefix: "/api/payment"}, config.LevelL2, future),
		ov(config.OverrideMatch{DstPort: 8443, Host: "api.example.com", URIPrefix: "/api"}, config.LevelL3, future),
	)
	// host 大小写不敏感精确匹配
	if got := s.EvalRequest("1.1.1.1", 80, "api.example.com", "/", testNow); got != 1 {
		t.Fatalf("host 大小写不敏感应命中 L1，got %d", got)
	}
	// uri_prefix 命中
	if got := s.EvalRequest("1.1.1.1", 80, "other.com", "/api/payment/order", testNow); got != 2 {
		t.Fatalf("uri_prefix 应命中 L2，got %d", got)
	}
	// 三字段 AND 全命中 → 多规则取最高 L3
	if got := s.EvalRequest("1.1.1.1", 8443, "api.example.com", "/api/x", testNow); got != 3 {
		t.Fatalf("AND 全命中应取最高 L3，got %d", got)
	}
	// AND 缺一（端口不对）
	if got := s.EvalRequest("1.1.1.1", 443, "api.example.com", "/api/x", testNow); got != 1 {
		t.Fatalf("AND 缺一不应命中 L3（仅 host 规则 L1），got %d", got)
	}
	// host 非精确（带后缀）不命中
	if got := s.EvalRequest("1.1.1.1", 80, "api.example.com.evil", "/", testNow); got != 0 {
		t.Fatalf("host 须精确匹配，got %d", got)
	}
	// uri 前缀边界：/api/paymentX 仍算前缀命中（契约语义为字符串前缀）
	if got := s.EvalRequest("1.1.1.1", 80, "x", "/api/paymentX", testNow); got != 2 {
		t.Fatalf("uri_prefix 为字符串前缀语义，got %d", got)
	}
}

func TestExpiredRulesIgnoredAndPruned(t *testing.T) {
	past := testNow.Add(-time.Minute)
	future := testNow.Add(time.Hour)
	s := newSet(t,
		ov(config.OverrideMatch{DstPort: 8080}, config.LevelL3, past),   // 已过期
		ov(config.OverrideMatch{DstPort: 8080}, config.LevelL1, future), // 有效
	)
	if got := s.EvalFlow("1.1.1.1", 8080, testNow); got != 1 {
		t.Fatalf("过期规则应即时忽略，got %d（期望仅有效规则 L1）", got)
	}
	if s.Len() != 2 {
		t.Fatalf("过期规则未清理前应仍在表内，len=%d", s.Len())
	}
	s.Prune(testNow)
	if s.Len() != 1 {
		t.Fatalf("Prune 后应仅剩 1 条，len=%d", s.Len())
	}
}

func TestInvalidRulesSkipped(t *testing.T) {
	future := testNow.Add(time.Hour)
	valid := ov(config.OverrideMatch{DstPort: 8080}, config.LevelL2, future)
	invalids := []config.Override{
		ov(config.OverrideMatch{}, config.LevelL1, future),                                          // 四字段全空
		ov(config.OverrideMatch{DstIP: "not-an-ip"}, config.LevelL1, future),                        // 非法 IP
		ov(config.OverrideMatch{DstIP: "10.0.0.0/33"}, config.LevelL1, future),                      // 非法 CIDR
		ov(config.OverrideMatch{DstPort: 70000}, config.LevelL1, future),                            // 端口越界（>65535 归零? 否：70000 非法）
		ov(config.OverrideMatch{URIPrefix: "api"}, config.LevelL1, future),                          // uri 不以 / 开头
		ov(config.OverrideMatch{URIPrefix: "/" + strings.Repeat("a", 512)}, config.LevelL1, future), // uri 超 512 字节
		{ID: "bad-level", Match: config.OverrideMatch{DstPort: 1}, CaptureLevel: "L9", ExpiresAt: future.Format(time.RFC3339)},
		{ID: "bad-time", Match: config.OverrideMatch{DstPort: 1}, CaptureLevel: "L1", ExpiresAt: "not-a-time"},
	}
	s := newSet(t, append(invalids, valid)...)
	if s.Len() != 1 {
		t.Fatalf("非法规则应全部跳过仅余 1 条，len=%d", s.Len())
	}
	if got := s.EvalFlow("1.1.1.1", 8080, testNow); got != 2 {
		t.Fatalf("有效规则不应受非法规则影响，got %d", got)
	}
}

func TestRulesClampedTo100(t *testing.T) {
	future := testNow.Add(time.Hour)
	ovs := make([]config.Override, 0, 105)
	for i := 0; i < 105; i++ {
		ovs = append(ovs, ov(config.OverrideMatch{DstPort: 10000 + i}, config.LevelL1, future))
	}
	s := newSet(t, ovs...)
	if s.Len() != MaxRules {
		t.Fatalf("规则数应钳到 %d，len=%d", MaxRules, s.Len())
	}
}

func TestReplaceHotUpdate(t *testing.T) {
	future := testNow.Add(time.Hour)
	s := newSet(t, ov(config.OverrideMatch{DstPort: 80}, config.LevelL1, future))
	if got := s.EvalFlow("1.1.1.1", 80, testNow); got != 1 {
		t.Fatalf("初始规则应命中，got %d", got)
	}
	// 热更整表替换（不重启抓包）
	s.Replace([]config.Override{ov(config.OverrideMatch{DstPort: 80}, config.LevelL3, future)})
	if got := s.EvalFlow("1.1.1.1", 80, testNow); got != 3 {
		t.Fatalf("热更后应按新规则命中 L3，got %d", got)
	}
	// 清空
	s.Replace(nil)
	if got := s.EvalFlow("1.1.1.1", 80, testNow); got != 0 {
		t.Fatalf("清空后不应命中，got %d", got)
	}
}

func TestEvalBadIPNoPanic(t *testing.T) {
	s := newSet(t, ov(config.OverrideMatch{DstPort: 80}, config.LevelL2, testNow.Add(time.Hour)))
	if got := s.EvalFlow("not-an-ip", 80, testNow); got != 0 {
		t.Fatalf("非法 dstIP 应按无命中处理，got %d", got)
	}
	if got := s.EvalRequest("not-an-ip", 80, "h", "/x", testNow); got != 0 {
		t.Fatalf("非法 dstIP 应按无命中处理，got %d", got)
	}
}

// 规约示例（契约 §2.2 逐字示例）求值冒烟。
func TestContractExample(t *testing.T) {
	s := newSet(t, ov(config.OverrideMatch{
		DstIP: "10.10.20.30", DstPort: 8443, Host: "api.example.com", URIPrefix: "/api/payment",
	}, config.LevelL2, testNow.Add(30*time.Minute)))
	if got := s.EvalRequest("10.10.20.30", 8443, "api.example.com", "/api/payment/callback", testNow); got != 2 {
		t.Fatalf("契约示例应全字段命中 L2，got %d", got)
	}
	if got := s.EvalRequest("10.10.20.30", 8443, "api.example.com", "/api/other", testNow); got != 0 {
		t.Fatalf("uri 不命中则整条不命中，got %d", got)
	}
}
