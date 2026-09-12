// identity_test.go 身份风险评估纯推导逻辑单测（GB/T 31509 修订稿矩阵法，不依赖数据库）。
// 规则见 identity.go 各函数注释：可能性（威胁频率分档 ± 密度/拦截消减）× 严重程度 → 5×5 矩阵定级。
package apisecurity

import (
	"testing"
	"time"
)

// TestIdentityQualityScore 质量分分档：基础40 + 认证15 + 请求量（对数刻度 4…30）+ 存活跨度（3…15），封顶 100。
func TestIdentityQualityScore(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	prof := func(auth string, count int64, span time.Duration) IdentityProfile {
		return IdentityProfile{AuthType: auth, RequestCount: count, FirstSeenAt: base, LastSeenAt: base.Add(span)}
	}
	cases := []struct {
		name string
		p    IdentityProfile
		want int
	}{
		{"零画像仅基础分", prof("", 0, 0), 40},
		{"有认证类型", prof("token", 0, 0), 55},
		{"请求量5", prof("token", 5, 0), 59},
		{"请求量10", prof("token", 10, 0), 63},
		{"请求量20", prof("token", 20, 0), 67},
		{"请求量50", prof("token", 50, 0), 72},
		{"请求量100", prof("token", 100, 0), 77},
		{"请求量500", prof("token", 500, 0), 81},
		{"请求量1000", prof("token", 1000, 0), 85},
		{"存活1小时", prof("token", 0, 2*time.Hour), 58},
		{"存活6小时", prof("token", 0, 7*time.Hour), 61},
		{"存活24小时", prof("token", 0, 25*time.Hour), 64},
		{"存活72小时", prof("token", 0, 73*time.Hour), 67},
		{"存活7天", prof("token", 0, 169*time.Hour), 70},
		{"全维度拉满封顶100", prof("token", 5000, 200*time.Hour), 100},
	}
	for _, tc := range cases {
		if got := identityQualityScore(tc.p); got != tc.want {
			t.Errorf("%s: quality = %d, want %d", tc.name, got, tc.want)
		}
	}
	// 单调性：请求量与存活跨度各自不降
	prev := -1
	for _, n := range []int64{0, 5, 10, 20, 50, 100, 500, 1000} {
		got := identityQualityScore(prof("token", n, 0))
		if got < prev {
			t.Errorf("请求量 %d 处分数回退: %d < %d", n, got, prev)
		}
		prev = got
	}
}

func TestIdentityLikelihood(t *testing.T) {
	cases := []struct {
		name string
		ind  IdentityRiskIndicators
		want int
	}{
		{"无高危事件", IdentityRiskIndicators{}, 1},
		{"1起高危", IdentityRiskIndicators{RiskyEventsTotal: 1}, 2},
		{"3起高危", IdentityRiskIndicators{RiskyEventsTotal: 3}, 3},
		{"10起高危", IdentityRiskIndicators{RiskyEventsTotal: 10}, 4},
		{"50起高危", IdentityRiskIndicators{RiskyEventsTotal: 50}, 5},
		{"24h密集上调一档", IdentityRiskIndicators{RiskyEventsTotal: 1, Events24h: 25}, 3},
		{"24h密集封顶5", IdentityRiskIndicators{RiskyEventsTotal: 50, Events24h: 25}, 5},
		{"全数拦截消减一档", IdentityRiskIndicators{RiskyEventsTotal: 3, BlockedEventsTotal: 3}, 2},
		{"部分拦截不消减", IdentityRiskIndicators{RiskyEventsTotal: 3, BlockedEventsTotal: 1}, 3},
		{"拦截消减不低于1", IdentityRiskIndicators{RiskyEventsTotal: 1, BlockedEventsTotal: 5}, 1},
	}
	for _, tc := range cases {
		if got := identityLikelihood(tc.ind); got != tc.want {
			t.Errorf("%s: likelihood = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestIdentitySeverity(t *testing.T) {
	cases := []struct {
		score int
		want  int
	}{
		{0, 1}, {19, 1}, {20, 2}, {39, 2}, {40, 3}, {59, 3}, {60, 4}, {79, 4}, {80, 5}, {100, 5},
	}
	for _, tc := range cases {
		if got := identitySeverity(tc.score); got != tc.want {
			t.Errorf("score %d: severity = %d, want %d", tc.score, got, tc.want)
		}
	}
}

func TestAssessIdentityRisk(t *testing.T) {
	// 矩阵边界：可能性1×严重1 → VERY_LOW；可能性5×严重5 → VERY_HIGH
	a := assessIdentityRisk(IdentityRiskIndicators{MaxRiskScore: 0})
	if a.Level != "VERY_LOW" || a.Likelihood != 1 || a.Severity != 1 {
		t.Errorf("min corner = %+v, want VERY_LOW 1×1", a)
	}
	a = assessIdentityRisk(IdentityRiskIndicators{RiskyEventsTotal: 60, MaxRiskScore: 95})
	if a.Level != "VERY_HIGH" || a.Likelihood != 5 || a.Severity != 5 {
		t.Errorf("max corner = %+v, want VERY_HIGH 5×5", a)
	}
	// 矩阵单调性：任一维度不降，级别不降
	for l := 1; l <= 5; l++ {
		for s := 1; s < 5; s++ {
			if identityRiskMatrix[l-1][s-1] > identityRiskMatrix[l-1][s] {
				t.Errorf("matrix not monotone on severity at l=%d s=%d", l, s)
			}
		}
	}
	// summary 透出关键计数
	a = assessIdentityRisk(IdentityRiskIndicators{RiskyEventsTotal: 3, BlockedEventsTotal: 3, Events24h: 8, MaxRiskScore: 50})
	if a.Summary == "" || a.Indicators.RiskyEventsTotal != 3 || a.Indicators.Events24h != 8 {
		t.Errorf("summary/indicators incomplete: %+v", a)
	}
	// 合法枚举
	valid := map[string]bool{"VERY_LOW": true, "LOW": true, "MEDIUM": true, "HIGH": true, "VERY_HIGH": true}
	for _, ind := range []IdentityRiskIndicators{
		{}, {RiskyEventsTotal: 7, MaxRiskScore: 42}, {RiskyEventsTotal: 20, Events24h: 30, MaxRiskScore: 88},
	} {
		if a := assessIdentityRisk(ind); !valid[a.Level] {
			t.Errorf("invalid level %q for %+v", a.Level, ind)
		}
	}
}
