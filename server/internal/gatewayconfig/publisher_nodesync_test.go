// publisher_nodesync_test.go W18-SYNC 发布扇出单测（任务书 §200 配置面主动同步 v2）：
// 扇出成功逐节点记录 / 部分失败不阻断且不跳过其余节点 / 哈希不一致记录并告警 /
// 无仓储与无次要节点零变化 / 登记地址非法推送前拦截 / 结果回填失败不中断后续节点。
// 假 Caddy Admin 复用 caddyclient_nodesync_test.go 的 fakeCaddyAdmin（httptest 回环地址，
// 属内网校验放行范围）。
package gatewayconfig

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeNodeSyncStore 同步目标仓储 fake。
type fakeNodeSyncStore struct {
	targets   []SyncTarget
	listErr   error
	recordErr error
	records   []syncRecord
}

type syncRecord struct {
	nodeID    uuid.UUID
	result    string
	errMsg    string
	versionID uuid.UUID
}

func (f *fakeNodeSyncStore) ListSyncTargets(context.Context) ([]SyncTarget, error) {
	return f.targets, f.listErr
}

func (f *fakeNodeSyncStore) RecordSyncResult(_ context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error {
	f.records = append(f.records, syncRecord{nodeID: nodeID, result: result, errMsg: errMsg, versionID: versionID})
	return f.recordErr
}

// fakeSyncAlerter 告警出口 fake。
type fakeSyncAlerter struct {
	calls []syncAlertCall
}

type syncAlertCall struct {
	alertType, component, title, message string
}

func (f *fakeSyncAlerter) NotifyFailure(_ context.Context, alertType, component, title, message string) error {
	f.calls = append(f.calls, syncAlertCall{alertType: alertType, component: component, title: title, message: message})
	return nil
}

const fanoutTestConfig = `{"admin":{"listen":"unix//run/caddy.sock"},"apps":{"http":{"servers":{"s0":{}}}}}`

// TestFanoutNilStoreNoop 未注入仓储：发布不扇出（与单网关行为一致）。
func TestFanoutNilStoreNoop(t *testing.T) {
	p := &Publisher{}
	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New()) // 不 panic 即通过
}

// TestFanoutNoTargetsZeroEffect 无登记次要节点：零记录零告警。
func TestFanoutNoTargetsZeroEffect(t *testing.T) {
	store := &fakeNodeSyncStore{}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)
	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New())
	if len(store.records) != 0 || len(alerter.calls) != 0 {
		t.Fatalf("records=%v alerts=%v, want zero effect", store.records, alerter.calls)
	}
}

// TestFanoutListErrorNoop 目标查询失败：如实记日志，不产生记录/告警（不阻断发布）。
func TestFanoutListErrorNoop(t *testing.T) {
	store := &fakeNodeSyncStore{listErr: errors.New("db down")}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)
	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New())
	if len(store.records) != 0 || len(alerter.calls) != 0 {
		t.Fatalf("records=%v alerts=%v, want zero effect", store.records, alerter.calls)
	}
}

// TestFanoutSuccess 全部节点扇出成功：原文推送 + 逐节点 SUCCESS 记录（带版本），无告警。
func TestFanoutSuccess(t *testing.T) {
	fakeA := &fakeCaddyAdmin{}
	srvA := httptest.NewServer(fakeA.handler())
	defer srvA.Close()
	fakeB := &fakeCaddyAdmin{}
	srvB := httptest.NewServer(fakeB.handler())
	defer srvB.Close()

	nodeA, nodeB := uuid.New(), uuid.New()
	versionID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeA, NodeName: "gw-a", AdminAddr: srvA.URL},
		{NodeID: nodeB, NodeName: "gw-b", AdminAddr: srvB.URL},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, versionID)

	// 两节点收到与发布内容一致的原文（不重新构建）
	if got := fakeA.loadCalls(); len(got) != 1 || got[0] != fanoutTestConfig {
		t.Fatalf("gw-a load bodies = %v", got)
	}
	if got := fakeB.loadCalls(); len(got) != 1 || got[0] != fanoutTestConfig {
		t.Fatalf("gw-b load bodies = %v", got)
	}
	// 逐节点 SUCCESS 记录
	if len(store.records) != 2 {
		t.Fatalf("records = %+v", store.records)
	}
	for i, nodeID := range []uuid.UUID{nodeA, nodeB} {
		r := store.records[i]
		if r.nodeID != nodeID || r.result != NodeSyncSuccess || r.errMsg != "" || r.versionID != versionID {
			t.Fatalf("record[%d] = %+v", i, r)
		}
	}
	if len(alerter.calls) != 0 {
		t.Fatalf("alerts = %+v, want none", alerter.calls)
	}
}

// TestFanoutPartialFailureNotBlocking 部分失败不阻断：失败节点 FAILED + 告警，
// 其余节点照常成功；主发布语义不受影响的体现是每节点独立记录。
func TestFanoutPartialFailureNotBlocking(t *testing.T) {
	fakeA := &fakeCaddyAdmin{loadCode: 500}
	srvA := httptest.NewServer(fakeA.handler())
	defer srvA.Close()
	fakeB := &fakeCaddyAdmin{}
	srvB := httptest.NewServer(fakeB.handler())
	defer srvB.Close()

	nodeA, nodeB := uuid.New(), uuid.New()
	versionID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeA, NodeName: "gw-a", AdminAddr: srvA.URL},
		{NodeID: nodeB, NodeName: "gw-b", AdminAddr: srvB.URL},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, versionID)

	if len(store.records) != 2 {
		t.Fatalf("records = %+v, want both nodes recorded", store.records)
	}
	if store.records[0].result != NodeSyncFailed || store.records[0].errMsg == "" {
		t.Fatalf("gw-a record = %+v, want FAILED with error", store.records[0])
	}
	if store.records[1].result != NodeSyncSuccess {
		t.Fatalf("gw-b record = %+v, want SUCCESS (failure must not skip remaining nodes)", store.records[1])
	}
	if len(alerter.calls) != 1 {
		t.Fatalf("alerts = %+v, want exactly one", alerter.calls)
	}
	call := alerter.calls[0]
	if call.alertType != syncAlertTypePublishFailed || call.component != SyncAlertComponent {
		t.Fatalf("alert = %+v", call)
	}
	if !strings.Contains(call.title, "gw-a") || !strings.Contains(call.message, versionID.String()) {
		t.Fatalf("alert content = %+v", call)
	}
}

// TestFanoutHashMismatch 推送成功但节点实际加载内容不一致：HASH_MISMATCH 记录 + 对应告警类型。
func TestFanoutHashMismatch(t *testing.T) {
	// /load 存原文但 /config/ 返回另一份配置（模拟节点侧改写/并发加载）
	fake := &fakeCaddyAdmin{config: `{"apps":{"http":{"servers":{"other":{}}}}}`}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	nodeID := uuid.New()
	versionID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeID, NodeName: "gw-drift", AdminAddr: srv.URL},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, versionID)

	if len(store.records) != 1 || store.records[0].result != NodeSyncHashMismatch {
		t.Fatalf("records = %+v, want HASH_MISMATCH", store.records)
	}
	if !strings.Contains(store.records[0].errMsg, "不一致") {
		t.Fatalf("mismatch errMsg = %q", store.records[0].errMsg)
	}
	if len(alerter.calls) != 1 || alerter.calls[0].alertType != syncAlertTypeHashMismatch {
		t.Fatalf("alerts = %+v, want CONFIG_HASH_MISMATCH", alerter.calls)
	}
}

// TestFanoutInvalidAddrBlocked 登记地址非法（如 DB 直改绕过登记校验）：推送前拦截，
// FAILED 记录含地址原因，不产生对该地址的 HTTP 请求。
func TestFanoutInvalidAddrBlocked(t *testing.T) {
	nodeID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeID, NodeName: "gw-evil", AdminAddr: "http://8.8.8.8:2019"},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New())

	if len(store.records) != 1 || store.records[0].result != NodeSyncFailed {
		t.Fatalf("records = %+v, want FAILED", store.records)
	}
	if !strings.Contains(store.records[0].errMsg, "管理通道地址非法") {
		t.Fatalf("errMsg = %q, want address rejection reason", store.records[0].errMsg)
	}
	if len(alerter.calls) != 1 {
		t.Fatalf("alerts = %+v, want one", alerter.calls)
	}
}

// TestFanoutRecordErrorDoesNotStopRemaining 单节点结果回填失败不中断后续节点处理。
func TestFanoutRecordErrorDoesNotStopRemaining(t *testing.T) {
	fakeA := &fakeCaddyAdmin{}
	srvA := httptest.NewServer(fakeA.handler())
	defer srvA.Close()

	nodeA, nodeB := uuid.New(), uuid.New()
	store := &fakeNodeSyncStore{
		recordErr: errors.New("db write down"),
		targets: []SyncTarget{
			{NodeID: nodeA, NodeName: "gw-a", AdminAddr: "http://8.8.8.8:2019"}, // 失败节点：告警仍应产生
			{NodeID: nodeB, NodeName: "gw-b", AdminAddr: srvA.URL},              // 后续节点仍应推送成功
		},
	}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New())

	if len(alerter.calls) != 1 {
		t.Fatalf("alerts = %+v, want one for failed node", alerter.calls)
	}
	if got := fakeA.loadCalls(); len(got) != 1 {
		t.Fatalf("gw-b load calls = %v, want processed after record error", got)
	}
	if len(store.records) != 2 {
		t.Fatalf("records attempted = %+v, want both", store.records)
	}
}

// TestFanoutNilAlerterStillRecords 告警未接线：失败如实落库（不静默），不 panic。
func TestFanoutNilAlerterStillRecords(t *testing.T) {
	nodeID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeID, NodeName: "gw-x", AdminAddr: "http://8.8.8.8:2019"},
	}}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SyncConfigToNodes(context.Background(), fanoutTestConfig, uuid.New())
	if len(store.records) != 1 || store.records[0].result != NodeSyncFailed {
		t.Fatalf("records = %+v, want FAILED recorded without alerter", store.records)
	}
}
