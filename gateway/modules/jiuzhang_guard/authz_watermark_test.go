// authz_watermark_test.go NG-AZ-02 jiuzhang_guard 侧测试：注册表读写/合并口径、
// 水位回退拒绝（D4-1）、租约/漂移夹紧（D5/D8）、心跳 ACK 字段有无两态（D6）。
package jiuzhang_guard

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func wmOf(seq int64, sources map[string]int64) *authzWatermarkJSON {
	return &authzWatermarkJSON{ManualSeq: seq, Sources: sources}
}

func TestAuthzRegistryPutGetRemove(t *testing.T) {
	resetAuthzRegistryForTest()
	defer resetAuthzRegistryForTest()
	if _, ok := defaultAuthzRegistry.get("app-1"); ok {
		t.Fatal("空注册表不得命中")
	}
	defaultAuthzRegistry.put("app-1", authzAppliedEntry{watermark: wmOf(5, nil), leaseSeconds: 60, appliedAt: time.Now().UTC()})
	e, ok := defaultAuthzRegistry.get("app-1")
	if !ok || e.watermark.ManualSeq != 5 || e.leaseSeconds != 60 {
		t.Fatalf("读回不符: %+v", e)
	}
	defaultAuthzRegistry.remove("app-1")
	if _, ok := defaultAuthzRegistry.get("app-1"); ok {
		t.Fatal("删除后不得命中")
	}
}

// D6 合并口径：min(lease)、分量最小水位、最旧 appliedAt、最早过期时刻。
func TestAuthzRegistryMerged(t *testing.T) {
	resetAuthzRegistryForTest()
	defer resetAuthzRegistryForTest()
	if _, ok := defaultAuthzRegistry.merged(); ok {
		t.Fatal("空注册表 merged 应 false（心跳不携带字段）")
	}
	now := time.Now().UTC()
	exp1 := now.Add(time.Hour)
	exp2 := now.Add(2 * time.Hour)
	defaultAuthzRegistry.put("app-1", authzAppliedEntry{
		watermark: wmOf(5, map[string]int64{"s1": 7, "s2": 3}), leaseSeconds: 60,
		appliedAt: now.Add(-time.Minute), policyVersion: "authz-p1", expiresAt: &exp1,
	})
	defaultAuthzRegistry.put("app-2", authzAppliedEntry{
		watermark: wmOf(4, map[string]int64{"s1": 6, "s3": 9}), leaseSeconds: 30,
		appliedAt: now.Add(-2 * time.Minute), policyVersion: "authz-p2", expiresAt: &exp2,
	})
	st, ok := defaultAuthzRegistry.merged()
	if !ok {
		t.Fatal("merged 应命中")
	}
	if st.LeaseSeconds != 30 {
		t.Fatalf("min(lease)=30: %d", st.LeaseSeconds)
	}
	if st.Watermark.ManualSeq != 4 {
		t.Fatalf("分量最小 manual_seq=4: %d", st.Watermark.ManualSeq)
	}
	if st.Watermark.Sources["s1"] != 6 || st.Watermark.Sources["s2"] != 3 || st.Watermark.Sources["s3"] != 9 {
		t.Fatalf("sources 逐键最小: %+v", st.Watermark.Sources)
	}
	if !st.AppliedAt.Equal(now.Add(-2 * time.Minute)) {
		t.Fatalf("最旧 appliedAt: %v", st.AppliedAt)
	}
	if st.SnapshotExpiresAt == nil || !st.SnapshotExpiresAt.Equal(exp1) {
		t.Fatalf("最早过期时刻: %+v", st.SnapshotExpiresAt)
	}
}

// D4-1：v2 快照水位低于已应用 → 拒绝；≥ 放行；v1（无水位）跳过校验。
func TestCheckAuthzWatermarkRegression(t *testing.T) {
	resetAuthzRegistryForTest()
	defer resetAuthzRegistryForTest()
	g := &Guard{logger: zap.NewNop(), AppID: "app-r"}
	// 首次应用（注册表无记录）→ 放行
	g.APIAuthzRevocationWatermark = wmOf(5, map[string]int64{"s1": 3})
	if err := g.checkAuthzWatermarkRegression(); err != nil {
		t.Fatalf("首次应用应放行: %v", err)
	}
	defaultAuthzRegistry.put("app-r", authzAppliedEntry{watermark: wmOf(5, map[string]int64{"s1": 3})})
	// 水位回退（manual 与 source 均更低）→ 拒绝
	g.APIAuthzRevocationWatermark = wmOf(4, map[string]int64{"s1": 2})
	if err := g.checkAuthzWatermarkRegression(); err == nil {
		t.Fatal("水位回退应拒绝配置加载")
	}
	// manual 平但 source 回退 → 拒绝
	g.APIAuthzRevocationWatermark = wmOf(5, map[string]int64{"s1": 2})
	if err := g.checkAuthzWatermarkRegression(); err == nil {
		t.Fatal("source 分量回退应拒绝")
	}
	// 相等/更高 → 放行
	g.APIAuthzRevocationWatermark = wmOf(5, map[string]int64{"s1": 3})
	if err := g.checkAuthzWatermarkRegression(); err != nil {
		t.Fatalf("水位相等应放行: %v", err)
	}
	g.APIAuthzRevocationWatermark = wmOf(6, map[string]int64{"s1": 4})
	if err := g.checkAuthzWatermarkRegression(); err != nil {
		t.Fatalf("水位更高应放行: %v", err)
	}
	// v1（无水位字段）→ 跳过校验（D4-3 兼容）
	g.APIAuthzRevocationWatermark = nil
	if err := g.checkAuthzWatermarkRegression(); err != nil {
		t.Fatalf("v1 快照应跳过校验: %v", err)
	}
}

// D5/D8 夹紧：租约 15~300（≤0 未启用）、漂移 10~300（≤0 缺省 60）。
func TestAuthzClamps(t *testing.T) {
	for in, want := range map[int]int{0: 0, -1: 0, 1: 15, 15: 15, 60: 60, 300: 300, 301: 300, 1 << 20: 300} {
		if got := clampAuthzLeaseSeconds(in); got != want {
			t.Fatalf("lease clamp(%d)=%d want %d", in, got, want)
		}
	}
	for in, want := range map[int]int{0: 60, -1: 60, 1: 10, 10: 10, 60: 60, 300: 300, 999: 300} {
		if got := clampAuthzClockSkewMax(in); got != want {
			t.Fatalf("skew clamp(%d)=%d want %d", in, got, want)
		}
	}
}

// registerAuthzAppliedState：有水位 → 登记；无水位且无授权内容 → 清除注册项；
// v1 有授权内容 → 保留既有记忆。
func TestRegisterAuthzAppliedState(t *testing.T) {
	resetAuthzRegistryForTest()
	defer resetAuthzRegistryForTest()
	g := &Guard{logger: zap.NewNop(), AppID: "app-s"}
	// v2 登记
	g.APIAuthzRevocationWatermark = wmOf(7, nil)
	g.APIAuthzLeaseSeconds = 60
	g.registerAuthzAppliedState()
	e, ok := defaultAuthzRegistry.get("app-s")
	if !ok || e.watermark.ManualSeq != 7 || e.leaseSeconds != 60 || e.appliedAt.IsZero() {
		t.Fatalf("v2 登记不符: %+v", e)
	}
	// v1 且有 PreviousValid（有授权内容）→ 保留既有记忆
	g2 := &Guard{logger: zap.NewNop(), AppID: "app-s", APIAuthzRevocationWatermark: nil,
		APIAuthzPreviousValid: &authzSnapshotJSON{}}
	g2.registerAuthzAppliedState()
	if _, ok := defaultAuthzRegistry.get("app-s"); !ok {
		t.Fatal("v1 且有授权内容时应保留记忆")
	}
	// 无水位且无授权内容 → 清除
	g3 := &Guard{logger: zap.NewNop(), AppID: "app-s", APIAuthzRevocationWatermark: nil}
	g3.registerAuthzAppliedState()
	if _, ok := defaultAuthzRegistry.get("app-s"); ok {
		t.Fatal("无授权内容应清除注册项")
	}
}
