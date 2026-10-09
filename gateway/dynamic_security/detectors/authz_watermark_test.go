// authz_watermark_test.go NG-AZ-02 决策消费侧测试：分量比较、漂移/租约判定、
// strict/degraded 分流 reason、冲突集索引。
package detectors

import (
	"testing"
	"time"
)

func TestRevocationWatermarkAtLeast(t *testing.T) {
	mk := func(seq int64, sources map[string]int64) *RevocationWatermark {
		return &RevocationWatermark{ManualSeq: seq, Sources: sources}
	}
	// nil other 恒真；nil 主体按水位 0
	if !mk(0, nil).AtLeast(nil) {
		t.Fatal("any ≥ nil 恒真")
	}
	if mk(0, nil).AtLeast(mk(1, nil)) {
		t.Fatal("水位 0 < manual_seq 1")
	}
	// manual_seq 比较
	if !mk(5, nil).AtLeast(mk(5, nil)) || !mk(6, nil).AtLeast(mk(5, nil)) {
		t.Fatal("manual_seq 相等/更大应满足")
	}
	// sources 逐键：缺键为 0
	a := mk(5, map[string]int64{"s1": 3, "s2": 7})
	b := mk(5, map[string]int64{"s1": 3})
	if !a.AtLeast(b) {
		t.Fatal("超集键且相等值应满足")
	}
	if b.AtLeast(a) {
		t.Fatal("b 缺 s2 键按 0 计——不得 ≥ a（a 含 s2:7）")
	}
	c := mk(5, map[string]int64{"s1": 2})
	if c.AtLeast(mk(5, map[string]int64{"s1": 3})) {
		t.Fatal("sources 值更小不得满足")
	}
	if !mk(6, map[string]int64{"s1": 4}).AtLeast(c) {
		t.Fatal("manual 与 source 均不小于应满足")
	}
	// nil receiver 视为水位 0
	var nilWM *RevocationWatermark
	if nilWM.AtLeast(mk(1, nil)) {
		t.Fatal("nil 主体按水位 0，不得 ≥ manual_seq 1")
	}
	if !nilWM.AtLeast(mk(0, nil)) {
		t.Fatal("nil 主体 vs 全零应满足")
	}
}

func TestAuthzClockSkewExceeded(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	// 自然老化（produced_at 早于 now）不判漂移——由 D5 租约/陈旧口径处理
	old := now.Add(-5 * time.Minute)
	cfgOld := AuthorizationConfig{Schema: AuthzSnapshotSchemaV2, ProducedAt: &old}
	if authzClockSkewExceeded(cfgOld, now) {
		t.Fatal("快照自然老化不得误判漂移（24h 有效期与 60s 阈值共存前提）")
	}
	// 负向差值（produced_at 在未来 = 节点时钟落后管理面）超阈值 → 漂移
	future := now.Add(2 * time.Minute)
	cfg := AuthorizationConfig{Schema: AuthzSnapshotSchemaV2, ProducedAt: &future}
	if !authzClockSkewExceeded(cfg, now) {
		t.Fatal("produced_at 超前 2 分钟超默认 60s 上限应检出")
	}
	cfg.ClockSkewMaxSeconds = 300
	if authzClockSkewExceeded(cfg, now) {
		t.Fatal("上限 300s 时 2 分钟超前不应检出")
	}
	cfg.ClockSkewMaxSeconds = -5 // 负值回退默认 60
	if !authzClockSkewExceeded(cfg, now) {
		t.Fatal("负值应回退默认 60s")
	}
	// v1（无 schema / 无 produced_at）恒 false
	if authzClockSkewExceeded(AuthorizationConfig{}, now) {
		t.Fatal("v1 快照漂移判定恒 false")
	}
	nearFuture := now.Add(10 * time.Second)
	cfg2 := AuthorizationConfig{Schema: AuthzSnapshotSchemaV2, ProducedAt: &nearFuture}
	if authzClockSkewExceeded(cfg2, now) {
		t.Fatal("10s 超前在默认上限内")
	}
}

func TestAuthzLeaseExpired(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	applied := now.Add(-70 * time.Second)
	cfg := AuthorizationConfig{Schema: AuthzSnapshotSchemaV2, LeaseSeconds: 60, AppliedAt: applied}
	if !authzLeaseExpired(cfg, now) {
		t.Fatal("applied+60s < now 应过期")
	}
	cfg.LeaseSeconds = 300
	if authzLeaseExpired(cfg, now) {
		t.Fatal("租约 300s 未过期")
	}
	cfg.AppliedAt = time.Time{}
	if authzLeaseExpired(cfg, now) {
		t.Fatal("无应用时刻恒 false")
	}
	cfg.AppliedAt = applied
	cfg.Schema = ""
	if authzLeaseExpired(cfg, now) {
		t.Fatal("v1 快照租约判定恒 false")
	}
	cfg.Schema = AuthzSnapshotSchemaV2
	cfg.LeaseSeconds = 0
	if authzLeaseExpired(cfg, now) {
		t.Fatal("未配置租约恒 false")
	}
}

func TestAuthzTimedOutAndDegradedReason(t *testing.T) {
	strict := ObjectModel{}
	degraded := ObjectModel{OnLeaseExpired: "degraded"}
	if got := authzTimedOutReason(strict, true, true); got != "AUTHZ-CLOCK-001" {
		t.Fatalf("strict 漂移优先: %s", got)
	}
	if got := authzTimedOutReason(strict, false, true); got != "AUTHZ-LEASE-001" {
		t.Fatalf("strict 租约: %s", got)
	}
	if got := authzTimedOutReason(strict, false, false); got != "" {
		t.Fatalf("无时效问题应空串: %s", got)
	}
	if got := authzTimedOutReason(degraded, true, true); got != "" {
		t.Fatalf("degraded 不走 strict 拒绝: %s", got)
	}
	if got := authzDegradedMarkerReason(degraded, false, true); got != "AUTHZ-LEASE-002" {
		t.Fatalf("degraded 租约标记: %s", got)
	}
	if got := authzDegradedMarkerReason(degraded, true, true); got != "AUTHZ-LEASE-002" {
		t.Fatalf("并存时租约优先标记: %s", got)
	}
	if got := authzDegradedMarkerReason(degraded, true, false); got != "AUTHZ-CLOCK-001" {
		t.Fatalf("degraded 漂移标记: %s", got)
	}
	if got := authzDegradedMarkerReason(strict, true, true); got != "" {
		t.Fatalf("strict 无标记: %s", got)
	}
	if got := authzDegradedMarkerReason(degraded, false, false); got != "" {
		t.Fatalf("无时效问题无标记: %s", got)
	}
}

func TestConflictedObjectIndex(t *testing.T) {
	objs := []ConflictedObject{
		{ApplicationID: "app-1", ObjectType: "ORDER", TenantDomain: "t1", ObjectRef: "objref:x"},
	}
	idx := BuildConflictedObjectIndex(objs)
	if !Conflicted(idx, "app-1", "ORDER", "objref:x") {
		t.Fatal("命中应检出")
	}
	if Conflicted(idx, "app-1", "ORDER", "objref:y") {
		t.Fatal("不同 ref 不得命中")
	}
	if Conflicted(idx, "app-2", "ORDER", "objref:x") {
		t.Fatal("不同应用不得命中")
	}
	if Conflicted(idx, "app-1", "DOCUMENT", "objref:x") {
		t.Fatal("不同 object_type 不得命中")
	}
	if Conflicted(nil, "app-1", "ORDER", "objref:x") {
		t.Fatal("nil 索引恒 false（v1 零开销）")
	}
	if BuildConflictedObjectIndex(nil) != nil {
		t.Fatal("空集不建索引")
	}
}
