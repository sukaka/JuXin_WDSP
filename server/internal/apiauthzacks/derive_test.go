// derive_test.go ack_state 五态派生与视图组装单测（NG-AZ-02 D6 规则逐条正反用例）：
// NEVER_ACKED / CLOCK_SKEW（含边界与负漂移）/ STALE_EXPIRED（含 lease 边界、
// applied_at 缺失保守落）/ STALE_WITHIN_LEASE（含无租约形态）/ FRESH（含零水位），
// 优先级（漂移 > 过期 > 水位落后）、max_staleness 参与口径与空集 null。
package apiauthzacks

import (
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

var deriveNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func secondsAgo(s int64) *time.Time {
	t := deriveNow.Add(-time.Duration(s) * time.Second)
	return &t
}

func int64p(v int64) *int64 { return &v }

// 五态逐条 + 优先级 + 边界（skewMax=60 贯穿；mgmt 水位 {manual_seq:5, sources:{s1:10}}）。
func TestDeriveNodeAckStates(t *testing.T) {
	mgmt := apiruntime.VectorWatermark{ManualSeq: 5, Sources: map[string]int64{"s1": 10}}
	wmFresh := &apiruntime.VectorWatermark{ManualSeq: 5, Sources: map[string]int64{"s1": 10}}
	wmBehind := &apiruntime.VectorWatermark{ManualSeq: 4, Sources: map[string]int64{"s1": 10}}

	cases := []struct {
		name          string
		row           AckRow
		wantState     string
		wantStaleness *int64
	}{
		// NEVER_ACKED：无 ACK 行（v1 节点如实呈现；派生字段全空）
		{"never_acked", AckRow{NodeName: "n1", Status: "ACTIVE"}, StateNeverAcked, nil},
		// FRESH：水位 ≥ 管理面 且 staleness ≤ lease（含相等边界 staleness == lease）
		{"fresh", AckRow{NodeName: "n2", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60)}, StateFresh, int64p(30)},
		{"fresh_boundary_staleness_eq_lease", AckRow{NodeName: "n3", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(60), AuthzLeaseSeconds: int64p(60)}, StateFresh, int64p(60)},
		// STALE_EXPIRED：staleness > lease（正反边界各一）
		{"stale_expired", AckRow{NodeName: "n4", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(61), AuthzLeaseSeconds: int64p(60)}, StateStaleExpired, int64p(61)},
		{"stale_expired_even_when_watermark_fresh（优先级：过期先于水位）",
			AckRow{NodeName: "n5", HasAck: true,
				AuthzWatermark: &apiruntime.VectorWatermark{ManualSeq: 99, Sources: map[string]int64{"s1": 99}},
				AuthzAppliedAt: secondsAgo(300), AuthzLeaseSeconds: int64p(60)}, StateStaleExpired, int64p(300)},
		{"stale_expired_applied_at_missing（租约在却无法证明在租约内）",
			AckRow{NodeName: "n6", HasAck: true, AuthzWatermark: wmFresh,
				AuthzLeaseSeconds: int64p(60)}, StateStaleExpired, nil},
		// STALE_WITHIN_LEASE：staleness ≤ lease 但水位落后（manual_seq 臂 + 无租约臂）
		{"stale_within_lease", AckRow{NodeName: "n7", HasAck: true, AuthzWatermark: wmBehind,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60)}, StateStaleWithinLease, int64p(30)},
		{"stale_within_lease_no_lease_configured（无租约无过期一说，水位落后即此态）",
			AckRow{NodeName: "n8", HasAck: true, AuthzWatermark: wmBehind,
				AuthzAppliedAt: secondsAgo(9999)}, StateStaleWithinLease, int64p(9999)},
		{"stale_within_lease_source_lagging（来源分量缺键视为 0 → 落后）",
			AckRow{NodeName: "n9", HasAck: true,
				AuthzWatermark: &apiruntime.VectorWatermark{ManualSeq: 5},
				AuthzAppliedAt: secondsAgo(10), AuthzLeaseSeconds: int64p(60)}, StateStaleWithinLease, int64p(10)},
		// CLOCK_SKEW：|skew| > 60（正负两臂 + 边界 ==60 不误判 + 优先级最高）
		{"clock_skew_positive", AckRow{NodeName: "n10", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60),
			ClockSkewSeconds: int64p(61)}, StateClockSkew, int64p(30)},
		{"clock_skew_negative（节点时钟超前）", AckRow{NodeName: "n11", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60),
			ClockSkewSeconds: int64p(-61)}, StateClockSkew, int64p(30)},
		{"clock_skew_boundary_not_triggered", AckRow{NodeName: "n12", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60),
			ClockSkewSeconds: int64p(60)}, StateFresh, int64p(30)},
		{"clock_skew_beats_stale_expired（漂移优先于过期）", AckRow{NodeName: "n13", HasAck: true,
			AuthzWatermark: wmBehind, AuthzAppliedAt: secondsAgo(300), AuthzLeaseSeconds: int64p(60),
			ClockSkewSeconds: int64p(120)}, StateClockSkew, int64p(300)},
		{"clock_skew_nil_treated_zero", AckRow{NodeName: "n14", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(30), AuthzLeaseSeconds: int64p(60)}, StateFresh, int64p(30)},
		// 无租约 + 水位达标 → FRESH（v1 语义：不启用租约约束，无过期）
		{"fresh_no_lease", AckRow{NodeName: "n15", HasAck: true, AuthzWatermark: wmFresh,
			AuthzAppliedAt: secondsAgo(9999)}, StateFresh, int64p(9999)},
		// 水位缺失按零向量参与：管理面非零 → 落后；管理面也零 → FRESH
		{"watermark_missing_treated_zero", AckRow{NodeName: "n16", HasAck: true,
			AuthzAppliedAt: secondsAgo(10), AuthzLeaseSeconds: int64p(60)}, StateStaleWithinLease, int64p(10)},
	}
	for _, c := range cases {
		got := deriveNodeAck(c.row, mgmt, deriveNow, DefaultClockSkewMaxSeconds)
		if got.AckState != c.wantState {
			t.Fatalf("%s: ack_state = %s, want %s", c.name, got.AckState, c.wantState)
		}
		if c.wantStaleness == nil {
			if got.StalenessSeconds != nil {
				t.Fatalf("%s: staleness = %v, want nil", c.name, *got.StalenessSeconds)
			}
		} else if got.StalenessSeconds == nil || *got.StalenessSeconds != *c.wantStaleness {
			t.Fatalf("%s: staleness = %+v, want %d", c.name, got.StalenessSeconds, *c.wantStaleness)
		}
		if c.row.HasAck && got.AckState == StateNeverAcked {
			t.Fatalf("%s: has ack row but derived NEVER_ACKED", c.name)
		}
	}

	// 管理面零水位 + 节点零水位 → FRESH（零水位不小于零水位）
	zero := apiruntime.VectorWatermark{Sources: map[string]int64{}}
	got := deriveNodeAck(AckRow{NodeName: "z", HasAck: true, AuthzAppliedAt: secondsAgo(5),
		AuthzLeaseSeconds: int64p(60)}, zero, deriveNow, DefaultClockSkewMaxSeconds)
	if got.AckState != StateFresh {
		t.Fatalf("zero mgmt watermark: ack_state = %s, want FRESH", got.AckState)
	}
}

// 视图组装：max_staleness 取参与节点最大值（NEVER_ACKED/无 applied_at 不参与；
// CLOCK_SKEW 节点数值如实参与）；空集 null；management_watermark sources 非 nil。
func TestBuildViewMaxStaleness(t *testing.T) {
	mgmt := apiruntime.VectorWatermark{ManualSeq: 1, Sources: map[string]int64{"s1": 1}}
	wm := &apiruntime.VectorWatermark{ManualSeq: 1, Sources: map[string]int64{"s1": 1}}

	view := BuildView([]AckRow{
		{NodeName: "never", Status: "SILENT"}, // 不参与
		{NodeName: "fresh", HasAck: true, AuthzWatermark: wm, AuthzAppliedAt: secondsAgo(20), AuthzLeaseSeconds: int64p(60)},
		{NodeName: "skewed", HasAck: true, AuthzWatermark: wm, AuthzAppliedAt: secondsAgo(45),
			AuthzLeaseSeconds: int64p(60), ClockSkewSeconds: int64p(300)}, // 数值仍参与
		{NodeName: "no-applied", HasAck: true, AuthzWatermark: wm, AuthzLeaseSeconds: int64p(60)}, // 不参与
	}, mgmt, deriveNow, DefaultClockSkewMaxSeconds)

	if len(view.Items) != 4 {
		t.Fatalf("items = %d, want 4", len(view.Items))
	}
	if view.MaxStalenessSeconds == nil || *view.MaxStalenessSeconds != 45 {
		t.Fatalf("max_staleness = %+v, want 45", view.MaxStalenessSeconds)
	}
	if view.ManagementWatermark.Sources == nil {
		t.Fatal("management watermark sources must be non-nil")
	}
	if !view.GeneratedAt.Equal(deriveNow) {
		t.Fatalf("generated_at = %v, want %v", view.GeneratedAt, deriveNow)
	}

	// 空集/全不参与 → null（不伪造 0）
	empty := BuildView(nil, mgmt, deriveNow, DefaultClockSkewMaxSeconds)
	if empty.MaxStalenessSeconds != nil || len(empty.Items) != 0 {
		t.Fatalf("empty view = %+v", empty)
	}
	onlyNever := BuildView([]AckRow{{NodeName: "never"}}, mgmt, deriveNow, DefaultClockSkewMaxSeconds)
	if onlyNever.MaxStalenessSeconds != nil {
		t.Fatalf("no participant: max_staleness = %v, want null", *onlyNever.MaxStalenessSeconds)
	}
}

// 漂移上限夹紧（D8：10~300s；默认 60）。
func TestClampClockSkewMax(t *testing.T) {
	cases := map[int]int64{60: 60, 5: 10, 10: 10, 300: 300, 9999: 300, 0: 10, -3: 10}
	for in, want := range cases {
		if got := clampClockSkewMax(in); got != want {
			t.Fatalf("clamp(%d) = %d, want %d", in, got, want)
		}
	}
}
