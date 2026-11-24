// sweeper_test.go 节点版本校验单测：状态判定边界 / 一致性评估口径 /
// SweepOnce 聚合-告警链路（内存 fake 仓储与告警出口，不依赖 DB）。
package apinodes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// ---------- 状态判定 ----------

func TestStatusFor(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lastSeen time.Time
		want     string
	}{
		{"零值从未有事件", time.Time{}, StatusSilent},
		{"刚刚有事件", now, StatusActive},
		{"5min 边界内", now.Add(-4*time.Minute - 59*time.Second), StatusActive},
		{"恰好 5min 仍 ACTIVE", now.Add(-ActiveWindow), StatusActive},
		{"超过 5min 进入 STALE", now.Add(-5*time.Minute - time.Second), StatusStale},
		{"恰好 1h 仍 STALE", now.Add(-StaleWindow), StatusStale},
		{"超过 1h 进入 SILENT", now.Add(-time.Hour - time.Second), StatusSilent},
	}
	for _, c := range cases {
		if got := StatusFor(now, c.lastSeen); got != c.want {
			t.Errorf("%s: StatusFor = %s, want %s", c.name, got, c.want)
		}
	}
}

// ---------- 一致性评估 ----------

func nodeAt(name, version string, lastSeen time.Time) Node {
	return Node{NodeName: name, LastPolicyVersion: version, LastSeenAt: lastSeen, Status: StatusFor(fixedNow, lastSeen)}
}

var fixedNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func TestEvaluateConsistency(t *testing.T) {
	recent := fixedNow.Add(-time.Minute)     // ACTIVE
	stale := fixedNow.Add(-10 * time.Minute) // STALE
	silent := fixedNow.Add(-2 * time.Hour)   // SILENT

	t.Run("同版本一致", func(t *testing.T) {
		r := EvaluateConsistency([]Node{
			nodeAt("gw-1", "v2", recent), nodeAt("gw-2", "v2", stale),
		}, fixedNow)
		if !r.Consistent || r.EvaluatedNodes != 2 || r.DominantVersion != "v2" || len(r.Groups) != 1 {
			t.Fatalf("report = %+v", r)
		}
		if len(r.SilentNodes) != 0 {
			t.Fatalf("silent = %+v", r.SilentNodes)
		}
	})

	t.Run("活跃多版本不一致", func(t *testing.T) {
		r := EvaluateConsistency([]Node{
			nodeAt("gw-1", "v2", recent), nodeAt("gw-2", "v1", recent), nodeAt("gw-3", "v2", recent),
		}, fixedNow)
		if r.Consistent || r.EvaluatedNodes != 3 || r.DominantVersion != "v2" || len(r.Groups) != 2 {
			t.Fatalf("report = %+v", r)
		}
		// 多数派 v2 组 2 节点排前
		if r.Groups[0].PolicyVersion != "v2" || r.Groups[0].NodeCount != 2 {
			t.Fatalf("groups = %+v", r.Groups)
		}
	})

	t.Run("SILENT 不参与判定", func(t *testing.T) {
		r := EvaluateConsistency([]Node{
			nodeAt("gw-1", "v2", recent), nodeAt("gw-old", "v1", silent),
		}, fixedNow)
		if !r.Consistent || r.EvaluatedNodes != 1 || len(r.SilentNodes) != 1 || r.SilentNodes[0] != "gw-old" {
			t.Fatalf("report = %+v", r)
		}
	})

	t.Run("未上报不参与判定但单列", func(t *testing.T) {
		r := EvaluateConsistency([]Node{
			nodeAt("gw-1", "v2", recent), nodeAt("gw-legacy", "", recent),
		}, fixedNow)
		if !r.Consistent || r.EvaluatedNodes != 1 || len(r.Groups) != 2 {
			t.Fatalf("report = %+v", r)
		}
		var sawUnreported bool
		for _, g := range r.Groups {
			if g.PolicyVersion == "" && len(g.Nodes) == 1 && g.Nodes[0] == "gw-legacy" {
				sawUnreported = true
			}
		}
		if !sawUnreported {
			t.Fatalf("unreported group missing: %+v", r.Groups)
		}
	})

	t.Run("无节点与全未上报均不谎报不一致", func(t *testing.T) {
		if r := EvaluateConsistency(nil, fixedNow); !r.Consistent || r.EvaluatedNodes != 0 {
			t.Fatalf("empty report = %+v", r)
		}
		r := EvaluateConsistency([]Node{nodeAt("gw-legacy", "", recent)}, fixedNow)
		if !r.Consistent || r.EvaluatedNodes != 0 || r.DominantVersion != "" {
			t.Fatalf("unreported-only report = %+v", r)
		}
	})

	t.Run("逐项一致性标记", func(t *testing.T) {
		if f := versionConsistentFlag(nodeAt("gw-1", "v2", recent), "v2", fixedNow); f == nil || !*f {
			t.Fatalf("match flag = %v", f)
		}
		if f := versionConsistentFlag(nodeAt("gw-2", "v1", recent), "v2", fixedNow); f == nil || *f {
			t.Fatalf("mismatch flag = %v", f)
		}
		if f := versionConsistentFlag(nodeAt("gw-old", "v1", silent), "v2", fixedNow); f != nil {
			t.Fatalf("silent flag = %v, want nil", *f)
		}
		if f := versionConsistentFlag(nodeAt("gw-legacy", "", recent), "v2", fixedNow); f != nil {
			t.Fatalf("unreported flag = %v, want nil", *f)
		}
		if f := versionConsistentFlag(nodeAt("gw-1", "v2", recent), "", fixedNow); f != nil {
			t.Fatalf("no-dominant flag = %v, want nil", *f)
		}
	})
}

// ---------- SweepOnce（fake 仓储/告警出口） ----------

type upsertCall struct {
	agg    NodeAggregate
	status string
}

type fakeNodeStore struct {
	aggs          []NodeAggregate
	aggErr        error
	nodes         []Node
	secrets       map[uuid.UUID]string // stored encrypted ciphertexts (never exposed on Node)
	inHAGroup     map[uuid.UUID]bool
	listErr       error
	upserts       []upsertCall
	heartbeats    []apiruntime.Heartbeat
	statusUpd     map[string]string
	updateErr     error
	syncResults   []syncResultCall
}

func (f *fakeNodeStore) AggregateEvents(context.Context) ([]NodeAggregate, error) {
	return f.aggs, f.aggErr
}

// RecordHeartbeat 心跳写入（W17-HB 接口履约；本组用例不经此路径，记录参数备断言）。
func (f *fakeNodeStore) RecordHeartbeat(_ context.Context, hb apiruntime.Heartbeat) error {
	f.heartbeats = append(f.heartbeats, hb)
	return nil
}

func (f *fakeNodeStore) UpsertNode(_ context.Context, agg NodeAggregate, status string, _ time.Time) error {
	f.upserts = append(f.upserts, upsertCall{agg: agg, status: status})
	return nil
}

func (f *fakeNodeStore) ListNodes(context.Context) ([]Node, error) {
	return f.nodes, f.listErr
}

func (f *fakeNodeStore) UpdateNodeStatus(_ context.Context, nodeName, status string, _ time.Time) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if f.statusUpd == nil {
		f.statusUpd = map[string]string{}
	}
	f.statusUpd[nodeName] = status
	return nil
}

// ---------- W18-SYNC 同步登记接口履约（本组用例不经此路径，记录参数备断言） ----------

func (f *fakeNodeStore) GetNode(_ context.Context, id uuid.UUID) (*Node, error) {
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			n := f.nodes[i]
			return &n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (f *fakeNodeStore) GetNodeByName(_ context.Context, nodeName string) (*Node, error) {
	for i := range f.nodes {
		if f.nodes[i].NodeName == nodeName {
			n := f.nodes[i]
			return &n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (f *fakeNodeStore) CreateNode(_ context.Context, in CreateNodeInput) (*Node, error) {
	for i := range f.nodes {
		if f.nodes[i].NodeName == in.NodeName {
			return nil, ErrNodeNameExists
		}
	}
	now := time.Now().UTC()
	n := Node{
		ID:            uuid.New(),
		NodeName:      in.NodeName,
		FirstSeenAt:   now,
		LastSeenAt:    time.Unix(0, 0).UTC(),
		Status:        StatusSilent,
		AdminAddr:     in.AdminAddr,
		SyncAgentAddr: in.SyncAgentAddr,
		HasSyncSecret: in.SyncSecretCiphertext != "",
		SyncEnabled:   in.SyncEnabled,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if f.secrets == nil {
		f.secrets = map[uuid.UUID]string{}
	}
	if in.SyncSecretCiphertext != "" {
		f.secrets[n.ID] = in.SyncSecretCiphertext
	}
	f.nodes = append(f.nodes, n)
	cp := n
	return &cp, nil
}

func (f *fakeNodeStore) DeleteNode(_ context.Context, id uuid.UUID) error {
	if f.inHAGroup[id] {
		return ErrNodeInHAGroup
	}
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes = append(f.nodes[:i], f.nodes[i+1:]...)
			delete(f.secrets, id)
			return nil
		}
	}
	return ErrNodeNotFound
}

func (f *fakeNodeStore) UpdateSyncRegistration(_ context.Context, id uuid.UUID, adminAddr string, syncEnabled bool) error {
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes[i].AdminAddr = adminAddr
			f.nodes[i].SyncEnabled = syncEnabled
			return nil
		}
	}
	return ErrNodeNotFound
}

func (f *fakeNodeStore) UpdateNodeRegistration(_ context.Context, id uuid.UUID, upd SyncRegistrationUpdate) error {
	for i := range f.nodes {
		if f.nodes[i].ID == id {
			f.nodes[i].AdminAddr = upd.AdminAddr
			f.nodes[i].SyncAgentAddr = upd.SyncAgentAddr
			f.nodes[i].SyncEnabled = upd.SyncEnabled
			if upd.SyncSecretCiphertext != nil {
				if f.secrets == nil {
					f.secrets = map[uuid.UUID]string{}
				}
				if *upd.SyncSecretCiphertext == "" {
					delete(f.secrets, id)
					f.nodes[i].HasSyncSecret = false
				} else {
					f.secrets[id] = *upd.SyncSecretCiphertext
					f.nodes[i].HasSyncSecret = true
				}
			}
			return nil
		}
	}
	return ErrNodeNotFound
}

func (f *fakeNodeStore) ListSyncTargets(context.Context) ([]gatewayconfig.SyncTarget, error) {
	var out []gatewayconfig.SyncTarget
	for i := range f.nodes {
		if f.nodes[i].SyncEnabled && (f.nodes[i].AdminAddr != "" || f.nodes[i].SyncAgentAddr != "") {
			out = append(out, gatewayconfig.SyncTarget{
				NodeID:        f.nodes[i].ID,
				NodeName:      f.nodes[i].NodeName,
				AdminAddr:     f.nodes[i].AdminAddr,
				SyncAgentAddr: f.nodes[i].SyncAgentAddr,
			})
		}
	}
	return out, nil
}

type syncResultCall struct {
	nodeID    uuid.UUID
	result    string
	errMsg    string
	versionID uuid.UUID
}

func (f *fakeNodeStore) RecordSyncResult(_ context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error {
	f.syncResults = append(f.syncResults, syncResultCall{nodeID: nodeID, result: result, errMsg: errMsg, versionID: versionID})
	return nil
}

type raiseCall struct {
	alertType, component, title, message string
}

type fakeAlerter struct {
	raises   []raiseCall
	recovers []string
	raiseErr error
}

func (f *fakeAlerter) NotifyFailure(_ context.Context, alertType, component, title, message string) (*systemalerts.Alert, error) {
	if f.raiseErr != nil {
		return nil, f.raiseErr
	}
	f.raises = append(f.raises, raiseCall{alertType, component, title, message})
	return &systemalerts.Alert{AlertType: alertType, Component: component}, nil
}

func (f *fakeAlerter) AutoRecover(_ context.Context, component string, alertTypes ...string) (int, error) {
	f.recovers = append(f.recovers, component+"|"+strings.Join(alertTypes, ","))
	return 0, nil
}

func sweepClock() func() time.Time { return func() time.Time { return fixedNow } }

// TestSweepOnceInconsistentRaises 聚合 upsert + 状态刷新 + 不一致触发告警。
func TestSweepOnceInconsistentRaises(t *testing.T) {
	recent := fixedNow.Add(-time.Minute)
	store := &fakeNodeStore{
		aggs: []NodeAggregate{
			{NodeName: "gw-1", FirstSeenAt: recent, LastSeenAt: recent, LastPolicyVersion: "v2", EventCount: 3},
			{NodeName: "gw-2", FirstSeenAt: recent, LastSeenAt: recent, LastPolicyVersion: "v1", EventCount: 1},
		},
		// upsert 后的视图镜像（gw-2 库存状态滞后为 SILENT，验证状态刷新路径）
		nodes: []Node{
			nodeAt("gw-1", "v2", recent),
			{NodeName: "gw-2", LastPolicyVersion: "v1", LastSeenAt: recent, Status: StatusSilent},
		},
	}
	alerter := &fakeAlerter{}
	s := NewSweeper(store).SetAlerter(alerter).SetClock(sweepClock())

	stats, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Nodes != 2 || stats.Consistent || !stats.Inconsistent {
		t.Fatalf("stats = %+v", stats)
	}
	if len(store.upserts) != 2 || store.upserts[0].status != StatusActive {
		t.Fatalf("upserts = %+v", store.upserts)
	}
	if store.statusUpd["gw-2"] != StatusActive {
		t.Fatalf("status updates = %+v", store.statusUpd)
	}
	if stats.StatusChanges != 1 {
		t.Fatalf("status changes = %d, want 1", stats.StatusChanges)
	}
	if len(alerter.raises) != 1 {
		t.Fatalf("raises = %+v", alerter.raises)
	}
	raise := alerter.raises[0]
	if raise.alertType != systemalerts.TypeConfigHashMismatch || raise.component != AlertComponent {
		t.Fatalf("raise = %+v", raise)
	}
	if !strings.Contains(raise.message, "v2") || !strings.Contains(raise.message, "v1") ||
		!strings.Contains(raise.message, "gw-1") || !strings.Contains(raise.message, "gw-2") {
		t.Fatalf("message = %q", raise.message)
	}
	if len(alerter.recovers) != 0 {
		t.Fatalf("recovers = %+v", alerter.recovers)
	}
}

// TestSweepOnceConsistentRecovers 一致时自动恢复既有告警。
func TestSweepOnceConsistentRecovers(t *testing.T) {
	recent := fixedNow.Add(-time.Minute)
	store := &fakeNodeStore{
		nodes: []Node{nodeAt("gw-1", "v2", recent), nodeAt("gw-2", "v2", recent)},
	}
	alerter := &fakeAlerter{}
	s := NewSweeper(store).SetAlerter(alerter).SetClock(sweepClock())

	stats, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if !stats.Consistent || stats.Inconsistent {
		t.Fatalf("stats = %+v", stats)
	}
	if len(alerter.raises) != 0 {
		t.Fatalf("raises = %+v", alerter.raises)
	}
	if len(alerter.recovers) != 1 ||
		!strings.Contains(alerter.recovers[0], AlertComponent) ||
		!strings.Contains(alerter.recovers[0], systemalerts.TypeConfigHashMismatch) {
		t.Fatalf("recovers = %+v", alerter.recovers)
	}
}

// TestSweepOnceNilAlerter 告警出口未接线：不一致仅记录，SweepOnce 不报错不阻断。
func TestSweepOnceNilAlerter(t *testing.T) {
	recent := fixedNow.Add(-time.Minute)
	store := &fakeNodeStore{
		nodes: []Node{nodeAt("gw-1", "v2", recent), nodeAt("gw-2", "v1", recent)},
	}
	s := NewSweeper(store).SetClock(sweepClock())
	stats, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce with nil alerter: %v", err)
	}
	if stats.Consistent || !stats.Inconsistent {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestSweepOnceErrorPropagation 仓储/告警失败如实返回错误（不静默吞错）。
func TestSweepOnceErrorPropagation(t *testing.T) {
	boom := errors.New("db down")
	recent := fixedNow.Add(-time.Minute)

	if _, err := NewSweeper(&fakeNodeStore{aggErr: boom}).SetClock(sweepClock()).SweepOnce(context.Background()); err == nil {
		t.Fatalf("aggregate error swallowed")
	}
	if _, err := NewSweeper(&fakeNodeStore{listErr: boom}).SetClock(sweepClock()).SweepOnce(context.Background()); err == nil {
		t.Fatalf("list error swallowed")
	}
	store := &fakeNodeStore{
		nodes: []Node{nodeAt("gw-1", "v2", recent), nodeAt("gw-2", "v1", recent)},
	}
	if _, err := NewSweeper(store).SetAlerter(&fakeAlerter{raiseErr: boom}).SetClock(sweepClock()).SweepOnce(context.Background()); err == nil {
		t.Fatalf("raise error swallowed")
	}
}

// ---------- W17-HB 心跳活性与版本合并 ----------

// TestSweepOnceHeartbeatOnlyNodeStaysActive 有心跳无流量=ACTIVE：
// 纯心跳节点（不在事件聚合结果中）不被聚合 upsert 触碰、版本不被改写，
// 状态重算以来库 last_seen_at（心跳时间）判定为 ACTIVE。
func TestSweepOnceHeartbeatOnlyNodeStaysActive(t *testing.T) {
	hbSeen := fixedNow.Add(-time.Minute) // 心跳 1 分钟前（事件表无任何该节点行）
	store := &fakeNodeStore{
		aggs:  []NodeAggregate{},
		nodes: []Node{{NodeName: "gw-hb", LastPolicyVersion: "v2026.3", LastSeenAt: hbSeen, Status: StatusActive}},
	}
	s := NewSweeper(store).SetClock(sweepClock())

	stats, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Nodes != 0 {
		t.Fatalf("heartbeat-only node must not appear in event aggregates: %+v", stats)
	}
	if len(store.upserts) != 0 {
		t.Fatalf("heartbeat-only node must not be touched by aggregate upsert: %+v", store.upserts)
	}
	if len(store.statusUpd) != 0 || stats.StatusChanges != 0 {
		t.Fatalf("fresh heartbeat node must stay ACTIVE without rewrite: upd=%v changes=%d",
			store.statusUpd, stats.StatusChanges)
	}
	if !stats.Consistent || stats.Inconsistent {
		t.Fatalf("single heartbeat node must be consistent: %+v", stats)
	}
}

// TestSweepOnceHeartbeatLivenessMerged 心跳活性参与 upsert 状态判定：
// 业务聚合活性已入 STALE（30 分钟前最后事件），但现存视图被心跳推进到 1 分钟前——
// upsert 写入的状态须按合并后有效活性判定为 ACTIVE（不把心跳活性写回旧值）。
func TestSweepOnceHeartbeatLivenessMerged(t *testing.T) {
	bizSeen := fixedNow.Add(-30 * time.Minute) // 业务事件 30 分钟前（自身判 STALE）
	hbSeen := fixedNow.Add(-time.Minute)       // 心跳 1 分钟前
	store := &fakeNodeStore{
		aggs: []NodeAggregate{
			{NodeName: "gw-1", FirstSeenAt: bizSeen, LastSeenAt: bizSeen, LastPolicyVersion: "v2026.2", EventCount: 7},
		},
		// 现存行：心跳已推进活性与版本（v2026.3 为心跳上报的当前版本）
		nodes: []Node{{NodeName: "gw-1", LastPolicyVersion: "v2026.3", LastSeenAt: hbSeen, Status: StatusActive}},
	}
	s := NewSweeper(store).SetClock(sweepClock())

	stats, err := s.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %+v", store.upserts)
	}
	if got := store.upserts[0].status; got != StatusActive {
		t.Fatalf("upsert status = %s, want ACTIVE (heartbeat liveness merged over stale aggregate)", got)
	}
	// 合并后行仍为 ACTIVE：状态重算不产生额外变更
	if stats.StatusChanges != 0 {
		t.Fatalf("status changes = %d, want 0 (no oscillation between aggregate and heartbeat liveness)", stats.StatusChanges)
	}
}
