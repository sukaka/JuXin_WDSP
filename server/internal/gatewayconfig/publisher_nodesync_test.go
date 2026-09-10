// publisher_nodesync_test.go W18-SYNC 发布扇出单测（任务书 §200 配置面主动同步 v2）：
// 扇出成功逐节点记录 / 部分失败不阻断且不跳过其余节点 / 哈希不一致记录并告警 /
// 无仓储与无次要节点零变化 / 登记地址非法推送前拦截 / 结果回填失败不中断后续节点。
// 假 Caddy Admin 复用 caddyclient_nodesync_test.go 的 fakeCaddyAdmin（httptest 回环地址，
// 属内网校验放行范围）。
package gatewayconfig

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// failedTargetNodeSyncStore 模拟持久化仓储的定向恢复查询扩展。
type failedTargetNodeSyncStore struct {
	*fakeNodeSyncStore
	failedTargets []SyncTarget
	failedErr     error
}

func (f *failedTargetNodeSyncStore) ListFailedSyncTargets(context.Context, uuid.UUID) ([]SyncTarget, error) {
	return f.failedTargets, f.failedErr
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

const rollbackFanoutAuthzConfig = `{"admin":{"listen":"unix//run/caddy.sock"},"apps":{"http":{"servers":{"s0":{}}}},"api_authz_models":[{"application_id":"app-1","endpoint_key":"GET /objects/{id}","object_type":"order","identifiers":[{"location":"PATH","name":"id","primary":true}],"required_relation":"OWNER","owner_exclusive":true,"publishable":true,"unique_endpoint_template":true}],"api_authz_object_hmac_key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","api_authz_previous_valid":{"policy_version":"v-old","stale":true,"object_hmac_key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`

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

// TestRollbackFanoutPreservesRestoredConfig 回退扇出必须逐字发送主节点已验证的
// 恢复配置，包含授权模型与上一有效快照，避免次节点重新构建或丢失回退语义。
func TestRollbackFanoutPreservesRestoredConfig(t *testing.T) {
	fake := &fakeCaddyAdmin{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	nodeID, versionID := uuid.New(), uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{{
		NodeID: nodeID, NodeName: "gw-rollback", AdminAddr: srv.URL,
	}}}
	p := &Publisher{}
	p.SetNodeSyncStore(store)

	// 这是 Rollback 在 setCurrentVersion 成功后使用的同一扇出契约。
	p.SyncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)

	if got := fake.loadCalls(); len(got) != 1 || got[0] != rollbackFanoutAuthzConfig {
		t.Fatalf("rollback config load bodies = %v, want exact restored config", got)
	}
	if len(store.records) != 1 || store.records[0].result != NodeSyncSuccess ||
		store.records[0].versionID != versionID {
		t.Fatalf("rollback sync records = %+v, want SUCCESS for target version", store.records)
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

// TestRollbackFanoutPartialFailureIsPersistedAsIncomplete 验证显式回滚的主节点
// 已恢复后，部分次节点失败不能再被当作回滚成功；失败码必须能驱动任务持久化。
func TestRollbackFanoutPartialFailureIsPersistedAsIncomplete(t *testing.T) {
	fakeA := &fakeCaddyAdmin{loadCode: 500}
	srvA := httptest.NewServer(fakeA.handler())
	defer srvA.Close()
	fakeB := &fakeCaddyAdmin{}
	srvB := httptest.NewServer(fakeB.handler())
	defer srvB.Close()

	versionID := uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: uuid.New(), NodeName: "gw-failed", AdminAddr: srvA.URL},
		{NodeID: uuid.New(), NodeName: "gw-restored", AdminAddr: srvB.URL},
	}}
	p := &Publisher{}
	p.SetNodeSyncStore(store)

	outcome := p.syncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)
	if outcome.failed != 1 || outcome.succeeded != 1 || outcome.attempted != 2 {
		t.Fatalf("rollback fanout outcome = %+v, want one failed and one successful target", outcome)
	}
	code, message, incomplete := outcome.rollbackFailure(versionID)
	if !incomplete || code != "ROLLBACK_NODE_SYNC_FAILED" {
		t.Fatalf("rollback failure = (%q, %q, %v), want durable node-sync failure", code, message, incomplete)
	}
	if !strings.Contains(message, "主节点已回滚") || !strings.Contains(message, versionID.String()) {
		t.Fatalf("rollback failure message = %q, want main recovery and version context", message)
	}
}

// TestRollbackFanoutRecordFailureIsPersistedAsIncomplete 结果水位无法落库时，回滚
// 不能声称全节点完成；这条边界避免恢复任务丢失持久化契约。
func TestRollbackFanoutRecordFailureIsPersistedAsIncomplete(t *testing.T) {
	fake := &fakeCaddyAdmin{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	versionID := uuid.New()
	store := &fakeNodeSyncStore{
		recordErr: errors.New("node sync state store unavailable"),
		targets:   []SyncTarget{{NodeID: uuid.New(), NodeName: "gw-state", AdminAddr: srv.URL}},
	}
	p := &Publisher{}
	p.SetNodeSyncStore(store)

	outcome := p.syncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)
	if outcome.succeeded != 1 || outcome.recordFailures != 1 {
		t.Fatalf("rollback fanout outcome = %+v, want success with one state persistence failure", outcome)
	}
	code, _, incomplete := outcome.rollbackFailure(versionID)
	if !incomplete || code != "ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED" {
		t.Fatalf("rollback failure = (%q, %v), want state persistence failure", code, incomplete)
	}
}

// TestFanoutTransientFailureCanRetryExactAuthzSnapshot 验证节点短暂故障时，
// 失败节点不会污染其他节点；后续以相同版本再次调用同步即可重试，并且重试
// 仍逐字发送包含当前授权快照与 PreviousValid 的配置。故障注入发生在真实 HTTP
// /load 与 /config/ 链路上，覆盖 AZ-13 的部分节点失败/恢复契约。
func TestFanoutTransientFailureCanRetryExactAuthzSnapshot(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	var loadBodies []string
	// SyncConfigToNodes first reads the current node config before POST /load.
	// Seed a valid previous snapshot so the test reaches the interrupted load
	// response path it is intended to exercise.
	loaded := rollbackFanoutAuthzConfig
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			attempts++
			attempt := attempts
			loadBodies = append(loadBodies, string(body))
			if attempt > 1 {
				loaded = string(body)
			}
			mu.Unlock()
			if attempt == 1 {
				http.Error(w, `{"error":"temporary node outage"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			mu.Lock()
			body := loaded
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	nodeID, versionID := uuid.New(), uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{{
		NodeID: nodeID, NodeName: "gw-retry", AdminAddr: srv.URL,
	}}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	// 一次发布内自动重试瞬时故障，且两次请求必须使用同一份已验证快照。
	p.SyncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)

	mu.Lock()
	gotAttempts := attempts
	gotBodies := append([]string(nil), loadBodies...)
	gotLoaded := loaded
	mu.Unlock()
	if gotAttempts != 2 || len(gotBodies) != 2 {
		t.Fatalf("load attempts=%d bodies=%d, want two attempts", gotAttempts, len(gotBodies))
	}
	if gotBodies[0] != rollbackFanoutAuthzConfig || gotBodies[1] != rollbackFanoutAuthzConfig || gotLoaded != rollbackFanoutAuthzConfig {
		t.Fatalf("retry payloads=%q loaded=%q, want exact authz rollback config", gotBodies, gotLoaded)
	}
	if len(store.records) != 1 {
		t.Fatalf("records = %+v, want one final SUCCESS record", store.records)
	}
	if store.records[0].result != NodeSyncSuccess || store.records[0].versionID != versionID || store.records[0].errMsg != "" {
		t.Fatalf("final record = %+v, want SUCCESS with no error", store.records[0])
	}
	if len(alerter.calls) != 0 {
		t.Fatalf("alerts = %+v, want no alert after recovered retry", alerter.calls)
	}
}

// TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart 验证节点进程停止后，
// 发布器记录连接失败；节点以同一管理地址重新启动后，新的 Publisher 进程仍能
// 从版本快照与持久化失败节点清单恢复，而不依赖旧进程内存状态。
func TestRetryNodeSyncVersionRecoversAfterNodeProcessRestart(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen node admin: %v", err)
	}
	adminAddr := "http://" + listener.Addr().String()

	// 先启动并停止一个节点进程，确保下面的连接拒绝来自真实监听端口已关闭。
	first := &http.Server{Handler: (&fakeCaddyAdmin{}).handler()}
	go func() { _ = first.Serve(listener) }()
	if err := first.Close(); err != nil {
		t.Fatalf("stop first node process: %v", err)
	}

	nodeID, versionID := uuid.New(), uuid.New()
	target := SyncTarget{NodeID: nodeID, NodeName: "gw-process-restart", AdminAddr: adminAddr}
	baseStore := &fakeNodeSyncStore{targets: []SyncTarget{target}}
	store := &failedTargetNodeSyncStore{fakeNodeSyncStore: baseStore}
	publishProcess := &Publisher{}
	publishProcess.SetNodeSyncStore(store)

	// 发布进程看到节点断连，必须将失败结果写入现有同步状态存储。
	publishProcess.SyncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)
	if len(baseStore.records) != 1 || baseStore.records[0].result != NodeSyncFailed ||
		baseStore.records[0].versionID != versionID || baseStore.records[0].errMsg == "" {
		t.Fatalf("disconnected node record = %+v, want persisted FAILED with version and error", baseStore.records)
	}
	if !strings.Contains(baseStore.records[0].errMsg, "connection refused") {
		t.Fatalf("disconnected node error = %q, want classified connection refusal", baseStore.records[0].errMsg)
	}
	store.failedTargets = []SyncTarget{target}

	// 节点进程重启，复用原管理地址；恢复进程使用新的 Publisher 实例。
	restartedListener, err := net.Listen("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("rebind restarted node admin: %v", err)
	}
	defer restartedListener.Close()
	restartedFake := &fakeCaddyAdmin{}
	restarted := &http.Server{Handler: restartedFake.handler()}
	go func() { _ = restarted.Serve(restartedListener) }()
	defer restarted.Close()

	recoveryProcess := &Publisher{}
	recoveryProcess.SetNodeSyncStore(store)
	if err := recoveryProcess.retryNodeSyncVersion(context.Background(), &ConfigVersion{
		ID: versionID, ConfigurationJSON: rollbackFanoutAuthzConfig, PublishResult: TaskSuccess,
	}); err != nil {
		t.Fatalf("retry after node process restart: %v", err)
	}

	if got := restartedFake.loadCalls(); len(got) != 1 || got[0] != rollbackFanoutAuthzConfig {
		t.Fatalf("restarted node payloads = %q, want one exact persisted snapshot", got)
	}
	if len(baseStore.records) != 2 || baseStore.records[1].nodeID != nodeID ||
		baseStore.records[1].result != NodeSyncSuccess || baseStore.records[1].versionID != versionID {
		t.Fatalf("recovery records = %+v, want same node SUCCESS for same version", baseStore.records)
	}
}

// TestFanoutMultiNodeRetryKeepsAuthzRollbackSnapshot 验证多节点扇出中单节点失败时，
// 其他节点仍完成发布；随后只重试失败节点，并继续发送同一份授权回滚快照。
func TestFanoutMultiNodeRetryKeepsAuthzRollbackSnapshot(t *testing.T) {
	var mu sync.Mutex
	failedLoads := 0
	var nodeABodies []string
	var loadedA string
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			nodeABodies = append(nodeABodies, string(body))
			fail := failedLoads < 2
			if fail {
				failedLoads++
			}
			if !fail {
				loadedA = string(body)
			}
			mu.Unlock()
			if fail {
				http.Error(w, `{"error":"temporary node outage"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			mu.Lock()
			body := loadedA
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srvA.Close()

	fakeB := &fakeCaddyAdmin{}
	srvB := httptest.NewServer(fakeB.handler())
	defer srvB.Close()

	nodeAID, nodeBID, versionID := uuid.New(), uuid.New(), uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: nodeAID, NodeName: "gw-a", AdminAddr: srvA.URL},
		{NodeID: nodeBID, NodeName: "gw-b", AdminAddr: srvB.URL},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	p.SyncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)
	if len(store.records) != 2 || store.records[0].result != NodeSyncFailed ||
		store.records[1].result != NodeSyncSuccess {
		t.Fatalf("initial records = %+v, want gw-a FAILED and gw-b SUCCESS", store.records)
	}
	if got := fakeB.loadCalls(); len(got) != 1 || got[0] != rollbackFanoutAuthzConfig {
		t.Fatalf("gw-b payloads = %v, want exact rollback authz snapshot", got)
	}

	// 模拟发布方筛选失败节点后的重试，避免将已成功节点重复计为恢复证据。
	store.targets = []SyncTarget{{NodeID: nodeAID, NodeName: "gw-a", AdminAddr: srvA.URL}}
	p.SyncConfigToNodes(context.Background(), rollbackFanoutAuthzConfig, versionID)

	mu.Lock()
	gotBodies := append([]string(nil), nodeABodies...)
	gotLoaded := loadedA
	mu.Unlock()
	if len(gotBodies) != 3 || gotBodies[0] != rollbackFanoutAuthzConfig ||
		gotBodies[1] != rollbackFanoutAuthzConfig || gotBodies[2] != rollbackFanoutAuthzConfig || gotLoaded != rollbackFanoutAuthzConfig {
		t.Fatalf("gw-a retry payloads = %q, loaded = %q, want exact snapshot across bounded auto retry and recovery", gotBodies, gotLoaded)
	}
	if len(store.records) != 3 || store.records[2].nodeID != nodeAID ||
		store.records[2].result != NodeSyncSuccess || store.records[2].versionID != versionID {
		t.Fatalf("retry records = %+v, want gw-a SUCCESS for same version", store.records)
	}
	if len(alerter.calls) != 1 {
		t.Fatalf("alerts = %+v, want one alert for initial failed node", alerter.calls)
	}
}

// TestFanoutLegacyNodeRejectsUnknownAuthzShardsKeepsExactSnapshot 验证旧版本节点
// 尚不认识授权分片字段时，发布器不重建、不裁剪配置：失败水位和告警包含可解释
// 原因，后续节点仍继续处理；节点恢复后以同一版本再次同步，授权快照逐字保留。
// 这里用真实 HTTP Admin /load 响应 400 模拟旧二进制的未知字段拒绝，不声称覆盖
// 真实旧二进制的解析细节或跨主机网络故障。
func TestFanoutLegacyNodeRejectsUnknownAuthzShardsKeepsExactSnapshot(t *testing.T) {
	const legacyRejectedConfig = `{"admin":{"listen":"unix//run/caddy.sock"},"apps":{"http":{"servers":{"s0":{}}}},"api_authz_models":[{"application_id":"app-1","endpoint_key":"GET /objects/{id}","object_type":"order"}],"api_authz_previous_valid":{"policy_version":"v-old","models":[{"application_id":"app-1","endpoint_key":"GET /objects/{id}","object_type":"order"}],"unknown_authz_shard":{"future_field":true}}}`

	var mu sync.Mutex
	legacyAttempts := 0
	var legacyBodies []string
	legacyLoaded := ""
	legacySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			mu.Lock()
			legacyAttempts++
			attempt := legacyAttempts
			legacyBodies = append(legacyBodies, string(body))
			if attempt > 1 {
				legacyLoaded = string(body)
			}
			mu.Unlock()
			if attempt == 1 {
				// 旧节点拒绝 api_authz_models/api_authz_previous_valid 内的未知分片。
				http.Error(w, `{"error":"unknown api_authz shard: api_authz_previous_valid.unknown_authz_shard"}`, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			mu.Lock()
			body := legacyLoaded
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	defer legacySrv.Close()

	current := &fakeCaddyAdmin{}
	currentSrv := httptest.NewServer(current.handler())
	defer currentSrv.Close()

	legacyID, currentID, versionID := uuid.New(), uuid.New(), uuid.New()
	store := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: legacyID, NodeName: "legacy-gw", AdminAddr: legacySrv.URL},
		{NodeID: currentID, NodeName: "current-gw", AdminAddr: currentSrv.URL},
	}}
	alerter := &fakeSyncAlerter{}
	p := &Publisher{}
	p.SetNodeSyncStore(store)
	p.SetSyncAlerter(alerter)

	// 首次扇出：旧节点拒绝，但不能跳过当前节点，也不能修改发送原文。
	p.SyncConfigToNodes(context.Background(), legacyRejectedConfig, versionID)
	if len(store.records) != 2 || store.records[0].nodeID != legacyID ||
		store.records[0].result != NodeSyncFailed ||
		!strings.Contains(store.records[0].errMsg, "caddy load failed (status 400)") ||
		!strings.Contains(store.records[0].errMsg, "unknown api_authz shard") ||
		store.records[1].nodeID != currentID || store.records[1].result != NodeSyncSuccess {
		t.Fatalf("initial records = %+v, want explainable legacy failure and current success", store.records)
	}
	if got := current.loadCalls(); len(got) != 1 || got[0] != legacyRejectedConfig {
		t.Fatalf("current node payload = %q, want exact authz snapshot", got)
	}
	if len(alerter.calls) != 1 || !strings.Contains(alerter.calls[0].title, "legacy-gw") ||
		!strings.Contains(alerter.calls[0].message, versionID.String()) {
		t.Fatalf("legacy alert = %+v, want node and version context", alerter.calls)
	}

	// 模拟旧节点升级/兼容后，仅重试失败节点；同一版本和授权快照逐字不变。
	store.targets = []SyncTarget{{NodeID: legacyID, NodeName: "legacy-gw", AdminAddr: legacySrv.URL}}
	p.SyncConfigToNodes(context.Background(), legacyRejectedConfig, versionID)
	mu.Lock()
	gotAttempts := legacyAttempts
	gotBodies := append([]string(nil), legacyBodies...)
	gotLoaded := legacyLoaded
	mu.Unlock()
	if gotAttempts != 2 || len(gotBodies) != 2 || gotBodies[0] != legacyRejectedConfig ||
		gotBodies[1] != legacyRejectedConfig || gotLoaded != legacyRejectedConfig {
		t.Fatalf("legacy retry attempts=%d bodies=%q loaded=%q, want exact snapshot twice", gotAttempts, gotBodies, gotLoaded)
	}
	if len(store.records) != 3 || store.records[2].nodeID != legacyID ||
		store.records[2].result != NodeSyncSuccess || store.records[2].versionID != versionID {
		t.Fatalf("retry records = %+v, want legacy SUCCESS for same version", store.records)
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

// TestRetryNodeSyncVersionRehydratesPersistedSnapshot 验证进程重启后的版本级恢复：
// 从版本表取出的脱敏配置必须先重注入当前密钥，再沿用同一份最终配置扇出到节点。
// 该测试直接调用恢复契约，避免把恢复行为退化成调用方重新构建当前配置。
func TestRetryNodeSyncVersionRehydratesPersistedSnapshot(t *testing.T) {
	fake := &fakeCaddyAdmin{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	versionID := uuid.New()
	baseStore := &fakeNodeSyncStore{targets: []SyncTarget{{
		NodeID: uuid.New(), NodeName: "gw-recovery", AdminAddr: srv.URL,
	}}}
	store := &failedTargetNodeSyncStore{fakeNodeSyncStore: baseStore, failedTargets: baseStore.targets}
	guard := &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}
	p := &Publisher{guard: guard}
	p.SetNodeSyncStore(store)

	version := &ConfigVersion{
		ID:                versionID,
		ConfigurationJSON: stored,
		PublishResult:     TaskSuccess,
	}
	if err := p.retryNodeSyncVersion(context.Background(), version); err != nil {
		t.Fatalf("retryNodeSyncVersion: %v", err)
	}

	loads := fake.loadCalls()
	if len(loads) != 1 {
		t.Fatalf("load calls = %d, want one", len(loads))
	}
	if strings.Contains(loads[0], "old-") || strings.Contains(loads[0], `"***"`) {
		t.Fatalf("recovery payload contains stale or redacted secrets: %s", loads[0])
	}
	for _, want := range secretValues("new") {
		if !strings.Contains(loads[0], want) {
			t.Errorf("recovery payload missing current secret %q", want)
		}
	}
	if len(baseStore.records) != 1 || baseStore.records[0].result != NodeSyncSuccess ||
		baseStore.records[0].versionID != versionID {
		t.Fatalf("sync records = %+v, want SUCCESS for persisted version", baseStore.records)
	}
}

// TestRetryNodeSyncVersionUsesFailedTargetQuery 验证持久化恢复只重试本版本失败节点，
// 不会因为恢复入口被调用而再次覆盖已经成功的节点。
func TestRetryNodeSyncVersionUsesFailedTargetQuery(t *testing.T) {
	fakeFailed, fakeSuccess := &fakeCaddyAdmin{}, &fakeCaddyAdmin{}
	srvFailed := httptest.NewServer(fakeFailed.handler())
	defer srvFailed.Close()
	srvSuccess := httptest.NewServer(fakeSuccess.handler())
	defer srvSuccess.Close()

	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	failedID, successID, versionID := uuid.New(), uuid.New(), uuid.New()
	baseStore := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: failedID, NodeName: "gw-failed", AdminAddr: srvFailed.URL},
		{NodeID: successID, NodeName: "gw-success", AdminAddr: srvSuccess.URL},
	}}
	store := &failedTargetNodeSyncStore{
		fakeNodeSyncStore: baseStore,
		failedTargets:     []SyncTarget{{NodeID: failedID, NodeName: "gw-failed", AdminAddr: srvFailed.URL}},
	}
	p := &Publisher{guard: &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}}
	p.SetNodeSyncStore(store)
	if err := p.retryNodeSyncVersion(context.Background(), &ConfigVersion{
		ID: versionID, ConfigurationJSON: stored, PublishResult: TaskSuccess,
	}); err != nil {
		t.Fatalf("retryNodeSyncVersion: %v", err)
	}
	if got := fakeFailed.loadCalls(); len(got) != 1 {
		t.Fatalf("failed node load calls = %d, want 1", len(got))
	}
	if got := fakeSuccess.loadCalls(); len(got) != 0 {
		t.Fatalf("successful node load calls = %d, want 0", len(got))
	}
	if len(baseStore.records) != 1 || baseStore.records[0].nodeID != failedID || baseStore.records[0].versionID != versionID {
		t.Fatalf("sync records = %+v, want failed node only", baseStore.records)
	}
}

// TestRetryNodeSyncVersionPropagatesFailedTargetQueryError 防止恢复查询失败时静默
// 当作“无失败节点”返回成功，调用方应能感知持久化恢复链路不可用。
func TestRetryNodeSyncVersionPropagatesFailedTargetQueryError(t *testing.T) {
	baseStore := &fakeNodeSyncStore{}
	store := &failedTargetNodeSyncStore{fakeNodeSyncStore: baseStore, failedErr: errors.New("db unavailable")}
	p := &Publisher{nodeSync: store}
	err := p.retryNodeSyncVersion(context.Background(), &ConfigVersion{
		ID: uuid.New(), ConfigurationJSON: `{"apps":{}}`, PublishResult: TaskSuccess,
	})
	if err == nil || !strings.Contains(err.Error(), "list failed gateway nodes") {
		t.Fatalf("retry error = %v, want failed-target query error", err)
	}
}

// TestRetryNodeSyncVersionReturnsContextCancellation 验证恢复上下文已取消时，
// 恢复入口必须返回可判定的 context.Canceled，而不是把“没有尝试节点”当作成功。
func TestRetryNodeSyncVersionReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &failedTargetNodeSyncStore{
		fakeNodeSyncStore: &fakeNodeSyncStore{},
		failedTargets: []SyncTarget{{
			NodeID: uuid.New(), NodeName: "gw-canceled", AdminAddr: "http://127.0.0.1:1",
		}},
	}
	p := &Publisher{nodeSync: store}
	err := p.retryNodeSyncVersion(ctx, &ConfigVersion{
		ID: uuid.New(), ConfigurationJSON: `{"apps":{}}`, PublishResult: TaskSuccess,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retry error = %v, want context.Canceled", err)
	}
	if len(store.records) != 0 {
		t.Fatalf("records = %+v, want no node attempt after cancellation", store.records)
	}
}

// TestRetryNodeSyncVersionStopsAfterContextCancellation 验证跨节点恢复过程中，
// 首个节点触发取消后仍保留已完成节点的同步事实，但不会继续访问后续节点。
func TestRetryNodeSyncVersionStopsAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			cancel()
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unexpected request", http.StatusNotFound)
	}))
	defer first.Close()
	secondFake := &fakeCaddyAdmin{}
	second := httptest.NewServer(secondFake.handler())
	defer second.Close()

	firstID, secondID, versionID := uuid.New(), uuid.New(), uuid.New()
	baseStore := &fakeNodeSyncStore{}
	store := &failedTargetNodeSyncStore{
		fakeNodeSyncStore: baseStore,
		failedTargets: []SyncTarget{
			{NodeID: firstID, NodeName: "gw-cancel-first", AdminAddr: first.URL},
			{NodeID: secondID, NodeName: "gw-after-cancel", AdminAddr: second.URL},
		},
	}
	p := &Publisher{nodeSync: store}
	err := p.retryNodeSyncVersion(ctx, &ConfigVersion{
		ID: versionID, ConfigurationJSON: `{"apps":{}}`, PublishResult: TaskSuccess,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retry error = %v, want context.Canceled", err)
	}
	if len(baseStore.records) != 1 || baseStore.records[0].nodeID != firstID ||
		baseStore.records[0].result != NodeSyncFailed || baseStore.records[0].versionID != versionID {
		t.Fatalf("records = %+v, want only first canceled node persisted as FAILED", baseStore.records)
	}
	if got := secondFake.loadCalls(); len(got) != 0 {
		t.Fatalf("second node load calls = %d, want zero after cancellation", len(got))
	}
}

// TestRetryNodeSyncVersionRejectsUnpublishedVersion 防止把未激活的候选配置
// 当作可恢复版本扇出到次要节点。
func TestRetryNodeSyncVersionRejectsUnpublishedVersion(t *testing.T) {
	p := &Publisher{nodeSync: &fakeNodeSyncStore{}}
	err := p.retryNodeSyncVersion(context.Background(), &ConfigVersion{
		ID:            uuid.New(),
		PublishResult: TaskFailed,
	})
	if err == nil || !strings.Contains(err.Error(), "was not published successfully") {
		t.Fatalf("retry unpublished version error = %v, want explicit refusal", err)
	}
}
