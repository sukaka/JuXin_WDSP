package app

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/nodesync"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

type fakeRPNodeLister struct {
	nodes []apinodes.Node
	err   error
}

func (f fakeRPNodeLister) ListNodes(_ context.Context) ([]apinodes.Node, error) {
	return f.nodes, f.err
}

type fakeRPSplitBrainStore struct {
	alerts []systemalerts.Alert
	err    error
	got    []string
}

func (f *fakeRPSplitBrainStore) ListOpenByTypes(_ context.Context, types []string) ([]systemalerts.Alert, error) {
	f.got = append([]string(nil), types...)
	return f.alerts, f.err
}

type fakeRPNodeSyncClient struct {
	statusResp   *nodesync.NodeRulePackStatus
	statusErr    error
	staged       []string
	activated    []string
	pruned       []string
	stageErr     error
	activateErr  error
	pruneErr     error
}

func (f *fakeRPNodeSyncClient) CheckNodeHealth(_ context.Context, _ uuid.UUID) (*nodesync.HealthResponse, error) {
	return &nodesync.HealthResponse{RulePackReady: true}, nil
}

func (f *fakeRPNodeSyncClient) CheckNodeRulePackStatus(_ context.Context, _ uuid.UUID) (*nodesync.NodeRulePackStatus, error) {
	return f.statusResp, f.statusErr
}

func (f *fakeRPNodeSyncClient) StageRulePack(_ context.Context, nodeID uuid.UUID, version, archivePath, expectedSHA256 string) (*nodesync.RulePackStageResponse, error) {
	f.staged = append(f.staged, nodeID.String()+":"+version+":"+archivePath+":"+expectedSHA256)
	if f.stageErr != nil {
		return nil, f.stageErr
	}
	return &nodesync.RulePackStageResponse{OK: true, Version: version, FileSHA256: expectedSHA256}, nil
}

func (f *fakeRPNodeSyncClient) ActivateRulePack(_ context.Context, nodeID uuid.UUID, version, manifestSHA256 string) (*nodesync.RulePackActivateResponse, error) {
	f.activated = append(f.activated, nodeID.String()+":"+version+":"+manifestSHA256)
	if f.activateErr != nil {
		return nil, f.activateErr
	}
	return &nodesync.RulePackActivateResponse{OK: true, Version: version}, nil
}

func (f *fakeRPNodeSyncClient) DeleteRulePackRelease(_ context.Context, nodeID uuid.UUID, version string) (*nodesync.RulePackDeleteResponse, error) {
	f.pruned = append(f.pruned, nodeID.String()+":"+version)
	if f.pruneErr != nil {
		return nil, f.pruneErr
	}
	return &nodesync.RulePackDeleteResponse{OK: true, Version: version, Deleted: true}, nil
}

type fakeRPConfigRetryPub struct {
	curVer          *gatewayconfig.ConfigVersion
	curVerErr       error
	retryRes        *gatewayconfig.NodeSyncRetryResult
	retryErr        error
	calledVersionID uuid.UUID
	calledNodeID    *uuid.UUID
	sidecarsRefreshed int
}

func (f *fakeRPConfigRetryPub) GetCurrentVersion(_ context.Context) (*gatewayconfig.ConfigVersion, error) {
	return f.curVer, f.curVerErr
}

func (f *fakeRPConfigRetryPub) RetryNodeSyncForVersionTargeted(_ context.Context, versionID uuid.UUID, nodeID *uuid.UUID) (*gatewayconfig.NodeSyncRetryResult, error) {
	f.calledVersionID = versionID
	if nodeID != nil {
		id := *nodeID
		f.calledNodeID = &id
	}
	return f.retryRes, f.retryErr
}

func (f *fakeRPConfigRetryPub) RefreshSidecarConfigs(_ context.Context) error {
	f.sidecarsRefreshed++
	return nil
}

func TestRulePackClusterSyncAdapter(t *testing.T) {
	ctx := context.Background()
	idA := uuid.New()
	idB := uuid.New()
	idC := uuid.New()
	idDisabled := uuid.New()
	idNoAgent := uuid.New()

	alerts := &fakeRPSplitBrainStore{}
	mgr := &fakeRPNodeSyncClient{
		statusResp: &nodesync.NodeRulePackStatus{
			Reachable:        true,
			RulePackReady:    true,
			RulesDirWritable: true,
			ActiveSymlink:    "releases/20261201.1",
			ActiveVersion:    "", // verify fallback stripping "releases/"
			StagedVersions:   map[string]string{"20261201.1": "abc"},
			DiskFreeBytes:    1024,
		},
	}
	verID := uuid.New()
	pub := &fakeRPConfigRetryPub{
		curVer:   &gatewayconfig.ConfigVersion{ID: verID, PublishResult: gatewayconfig.TaskSuccess},
		retryRes: &gatewayconfig.NodeSyncRetryResult{VersionID: verID, Attempted: 1, Succeeded: 1, Failed: 0},
	}

	adapter := rulePackClusterSyncAdapter{
		nodeStore: fakeRPNodeLister{nodes: []apinodes.Node{
			{ID: idA, NodeName: "gw-a", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.1:18443"},
			{ID: idC, NodeName: "gw-c", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.3:18443"},
			{ID: idB, NodeName: "gw-b", SyncEnabled: true, SyncAgentAddr: "https://10.0.0.2:18443"},
			{ID: idDisabled, NodeName: "gw-off", SyncEnabled: false, SyncAgentAddr: "https://10.0.0.4:18443"},
			{ID: idNoAgent, NodeName: "gw-legacy", SyncEnabled: true, SyncAgentAddr: ""},
		}},
		alertStore:    alerts,
		mgr:           mgr,
		pub:           pub,
		localNodeName: "GW-A",
	}

	// 1. ListStandbyNodes skips local node (case-insensitive), disabled nodes, and empty sync_agent_addr, sorted by name.
	standbys, err := adapter.ListStandbyNodes(ctx)
	if err != nil {
		t.Fatalf("ListStandbyNodes: %v", err)
	}
	if len(standbys) != 2 || standbys[0].NodeName != "gw-b" || standbys[1].NodeName != "gw-c" {
		t.Fatalf("unexpected standbys: %+v", standbys)
	}

	// 2. HasOpenSplitBrain queries TypeHASplitBrain
	sb, err := adapter.HasOpenSplitBrain(ctx)
	if err != nil || sb || len(alerts.got) != 1 || alerts.got[0] != systemalerts.TypeHASplitBrain {
		t.Fatalf("HasOpenSplitBrain(clean) = (%v, %v, queried=%v)", sb, err, alerts.got)
	}
	alerts.alerts = []systemalerts.Alert{{AlertType: systemalerts.TypeHASplitBrain}}
	sb, err = adapter.HasOpenSplitBrain(ctx)
	if err != nil || !sb {
		t.Fatalf("HasOpenSplitBrain(open) = (%v, %v)", sb, err)
	}

	// 3. CheckNodeRulePackStatus strips releases/ prefix so service.go aligns against ActiveVersion cleanly
	st, err := adapter.CheckNodeRulePackStatus(ctx, idB)
	if err != nil {
		t.Fatalf("CheckNodeRulePackStatus: %v", err)
	}
	if !st.Reachable || !st.RulePackReady || st.ActiveSymlink != "20261201.1" || st.StagedVersions["20261201.1"] != "abc" {
		t.Fatalf("unexpected RemoteRulePackStatus: %+v", st)
	}

	// 4. Stage / Activate / Prune forward cleanly
	if err := adapter.StageRulePack(ctx, idB, "20261201.1", "/tmp/rp.tar.gz", "deadbeef"); err != nil {
		t.Fatalf("StageRulePack: %v", err)
	}
	if err := adapter.ActivateRulePack(ctx, idB, "20261201.1", "cafebabe"); err != nil {
		t.Fatalf("ActivateRulePack: %v", err)
	}
	if err := adapter.PruneRulePack(ctx, idB, "20261101.1"); err != nil {
		t.Fatalf("PruneRulePack: %v", err)
	}
	if len(mgr.staged) != 1 || len(mgr.activated) != 1 || len(mgr.pruned) != 1 {
		t.Fatalf("expected 1 call each, got staged=%v activated=%v pruned=%v", mgr.staged, mgr.activated, mgr.pruned)
	}

	// 5. RetryNodeConfigSync triggers targeted retry for current version and refreshes sidecars
	if err := adapter.RetryNodeConfigSync(ctx, idB); err != nil {
		t.Fatalf("RetryNodeConfigSync: %v", err)
	}
	if pub.calledVersionID != verID || pub.calledNodeID == nil || *pub.calledNodeID != idB || pub.sidecarsRefreshed != 1 {
		t.Fatalf("unexpected retry invocation: ver=%s node=%v sidecars=%d", pub.calledVersionID, pub.calledNodeID, pub.sidecarsRefreshed)
	}

	// 6. RetryNodeConfigSync fails closed when targeted node sync records Failed > 0
	pub.retryRes = &gatewayconfig.NodeSyncRetryResult{VersionID: verID, Attempted: 1, Succeeded: 0, Failed: 1}
	if err := adapter.RetryNodeConfigSync(ctx, idB); err == nil {
		t.Fatal("expected error when targeted retry reports Failed=1")
	}

	// 7. RetryNodeConfigSync handles zero-app (curVer == nil) gracefully
	pub.curVer = nil
	pub.retryRes = nil
	if err := adapter.RetryNodeConfigSync(ctx, idB); err != nil {
		t.Fatalf("expected zero-app RetryNodeConfigSync to succeed gracefully, got %v", err)
	}

	// 8. RetryNodeConfigSync propagates GetCurrentVersion error
	pub.curVerErr = errors.New("db down")
	if err := adapter.RetryNodeConfigSync(ctx, idB); err == nil {
		t.Fatal("expected GetCurrentVersion error to propagate")
	}
}
