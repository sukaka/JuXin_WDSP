// collector_heartbeat_authz_test.go 心跳授权 ACK 扩展（NG-AZ-02 §1.3）采集单测：
// 冻结 JSON 名透传（网关侧按此契约发射，改名即断链）、零值跳过（v1 节点不写
// ACK 表的前提——HasAuthzAck=false）、向量水位分量比较（§1.1）。
package apiruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// 冻结 JSON 名透传：原始 JSONL 字面量（含 §1.3 全部 ACK 键）经采集到达 recorder，
// 字段逐一完整；水位对象形状 {"manual_seq":N,"sources":{...}} 原样解析。
func TestCollectOnce_HeartbeatAuthzAckPassthrough(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	// 冻结 JSON 契约字面量（键名即网关发射侧契约，不得改名）
	line := `{"request_id":"hb-az-1","occurred_at":"2026-10-04T08:00:00Z","endpoint_key":"__heartbeat__","heartbeat":true,` +
		`"final_action":"ALLOW","risk_level":"NONE","gateway_node_id":"gw-az-1","policy_version":"v2026.10",` +
		`"authz_policy_version":"az-v42",` +
		`"authz_watermark":{"manual_seq":41,"sources":{"11111111-1111-1111-1111-111111111111":17,"22222222-2222-2222-2222-222222222222":9}},` +
		`"authz_snapshot_expires_at":"2026-10-05T08:00:00Z","authz_lease_seconds":60,"authz_applied_at":"2026-10-04T07:59:30Z"}`
	writeLines(t, logPath, []string{line})

	heartbeats := &fakeHeartbeatRecorder{}
	c := NewCollector(&fakeSaver{}, "test-hb-az", logPath, cpPath, "node-1")
	c.SetHeartbeatRecorder(heartbeats)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(heartbeats.calls) != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", len(heartbeats.calls))
	}
	got := heartbeats.calls[0]
	if got.NodeName != "gw-az-1" || got.PolicyVersion != "v2026.10" || got.AuthzPolicyVersion != "az-v42" {
		t.Fatalf("heartbeat identity fields = %+v", got)
	}
	if !got.HasAuthzAck() {
		t.Fatal("heartbeat with authz fields must report HasAuthzAck() = true")
	}
	if got.AuthzWatermark == nil || got.AuthzWatermark.ManualSeq != 41 ||
		got.AuthzWatermark.Sources["11111111-1111-1111-1111-111111111111"] != 17 ||
		got.AuthzWatermark.Sources["22222222-2222-2222-2222-222222222222"] != 9 {
		t.Fatalf("authz watermark = %+v", got.AuthzWatermark)
	}
	if got.AuthzLeaseSeconds == nil || *got.AuthzLeaseSeconds != 60 {
		t.Fatalf("authz lease = %+v", got.AuthzLeaseSeconds)
	}
	wantApplied := time.Date(2026, 10, 4, 7, 59, 30, 0, time.UTC)
	if got.AuthzAppliedAt == nil || !got.AuthzAppliedAt.Equal(wantApplied) {
		t.Fatalf("authz applied at = %+v, want %v", got.AuthzAppliedAt, wantApplied)
	}
	wantExpires := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	if got.AuthzSnapshotExpiresAt == nil || !got.AuthzSnapshotExpiresAt.Equal(wantExpires) {
		t.Fatalf("authz expires at = %+v, want %v", got.AuthzSnapshotExpiresAt, wantExpires)
	}
}

// 旧版网关心跳（无 ACK 键）：零值透传、HasAuthzAck=false（RecordHeartbeat 据此
// 跳过 ACK 表，ACK 视图如实 NEVER_ACKED）；活性/版本字段不受影响（NG-T-C01 零变化）。
func TestCollectOnce_HeartbeatV1NoAuthzFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	hb := Record{RequestID: "hb-v1", EndpointKey: "__heartbeat__", Heartbeat: true,
		FinalAction: "ALLOW", GatewayNode: "gw-v1", PolicyVersion: "v2026.3",
		OccurredAt: time.Now().UTC()}
	writeLines(t, logPath, []string{mustJSON(t, hb)})

	heartbeats := &fakeHeartbeatRecorder{}
	c := NewCollector(&fakeSaver{}, "test-hb-v1", logPath, cpPath, "node-1")
	c.SetHeartbeatRecorder(heartbeats)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(heartbeats.calls) != 1 {
		t.Fatalf("heartbeat calls = %d, want 1", len(heartbeats.calls))
	}
	got := heartbeats.calls[0]
	if got.HasAuthzAck() {
		t.Fatalf("v1 heartbeat must not report authz ack: %+v", got)
	}
	if got.AuthzPolicyVersion != "" || got.AuthzWatermark != nil || got.AuthzLeaseSeconds != nil ||
		got.AuthzAppliedAt != nil || got.AuthzSnapshotExpiresAt != nil {
		t.Fatalf("v1 heartbeat authz fields must be zero: %+v", got)
	}
	if got.NodeName != "gw-v1" || got.PolicyVersion != "v2026.3" {
		t.Fatalf("v1 heartbeat identity fields regressed: %+v", got)
	}
}

// HasAuthzAck 判定：全零 false；任一字段非零 true（单字段到达也如实落库）。
func TestHeartbeatHasAuthzAck(t *testing.T) {
	now := time.Now().UTC()
	lease := 60
	if (Heartbeat{}).HasAuthzAck() {
		t.Fatal("zero heartbeat must not report authz ack")
	}
	cases := map[string]Heartbeat{
		"policy_version": {AuthzPolicyVersion: "az-v1"},
		"watermark":      {AuthzWatermark: &VectorWatermark{}},
		"expires_at":     {AuthzSnapshotExpiresAt: &now},
		"lease":          {AuthzLeaseSeconds: &lease},
		"applied_at":     {AuthzAppliedAt: &now},
	}
	for name, hb := range cases {
		if !hb.HasAuthzAck() {
			t.Fatalf("%s: HasAuthzAck() = false, want true", name)
		}
	}
}

// 向量水位分量比较（§1.1：A≥B ⇔ manual_seq 不小于 且 sources 对 B 每键不小于，
// 缺键视为 0；任何分量更小即低于）正反用例。
func TestVectorWatermarkAtLeast(t *testing.T) {
	src1, src2 := "src-1", "src-2"
	cases := []struct {
		name string
		a, b VectorWatermark
		want bool
	}{
		{"双方零水位", VectorWatermark{}, VectorWatermark{}, true},
		{"完全相等", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}}, true},
		{"manual_seq 更高", VectorWatermark{ManualSeq: 4, Sources: map[string]int64{src1: 5}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}}, true},
		{"manual_seq 更低即低于（sources 更高不抵）", VectorWatermark{ManualSeq: 2, Sources: map[string]int64{src1: 99}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 1}}, false},
		{"来源分量更高", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 6}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}}, true},
		{"单一来源分量更低即低于", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5, src2: 1}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5, src2: 2}}, false},
		{"A 缺键视为 0（0 < B 分量 → 低于）", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5, src2: 1}}, false},
		{"A 缺键视为 0（B 分量为 0 → 不低于）", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5}},
			VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5, src2: 0}}, true},
		{"B 无 sources（A 多余键不影响）", VectorWatermark{ManualSeq: 3, Sources: map[string]int64{src1: 5, src2: 7}},
			VectorWatermark{ManualSeq: 3}, true},
		{"B 缺 manual 维度零值参与", VectorWatermark{ManualSeq: 0, Sources: map[string]int64{src1: 2}},
			VectorWatermark{Sources: map[string]int64{src1: 2}}, true},
	}
	for _, c := range cases {
		if got := c.a.AtLeast(c.b); got != c.want {
			t.Fatalf("%s: %+v.AtLeast(%+v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}
