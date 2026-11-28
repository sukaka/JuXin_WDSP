package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/nodesync"
	"github.com/jiuzhang-waf/server/internal/rulepacks"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// RulePackService 返回离线 WAF 规则包服务实例（供 cmd/api 启动同步复用当前生效规则源）。
func (a *App) RulePackService() *rulepacks.Service {
	if a == nil {
		return nil
	}
	return a.rulePackSvc
}

type wafrulesMetaSyncerAdapter struct {
	db      *pgxpool.Pool
	handler *wafrules.Handler
}

func (w wafrulesMetaSyncerAdapter) SyncActiveRulePack(ctx context.Context, crsDir, crsVersion, rulePackVersion string) (*wafrules.SyncReport, error) {
	syncSvc := wafrules.NewSyncService(w.db)
	rep, err := syncSvc.SyncFromSourcesWithPack(ctx, crsVersion, rulePackVersion, wafrules.BuildSyncSources(crsDir))
	if err != nil {
		return nil, err
	}
	if w.handler != nil {
		w.handler.InvalidateRawCache()
	}
	return rep, nil
}

type gatewayRulePackPublisherAdapter struct {
	pub *gatewayconfig.Publisher
}

func (g gatewayRulePackPublisherAdapter) PublishWithRulePack(ctx context.Context, rulePackVersion, gatewayRulesBasePath string, requestedBy uuid.UUID, requestID string) (*rulepacks.PublishResult, error) {
	taskID, zeroApps, summary, err := g.pub.PublishForRulePack(ctx, rulePackVersion, gatewayRulesBasePath, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	return &rulepacks.PublishResult{
		PublishTaskID: taskID,
		ZeroApps:      zeroApps,
		Summary:       summary,
	}, nil
}

func (g gatewayRulePackPublisherAdapter) RefreshSidecars(ctx context.Context) error {
	return g.pub.RefreshSidecarConfigs(ctx)
}

type rulePackNodeLister interface {
	ListNodes(ctx context.Context) ([]apinodes.Node, error)
}

type rulePackSplitBrainStore interface {
	ListOpenByTypes(ctx context.Context, alertTypes []string) ([]systemalerts.Alert, error)
}

type rulePackConfigRetryPublisher interface {
	GetCurrentVersion(ctx context.Context) (*gatewayconfig.ConfigVersion, error)
	RetryNodeSyncForVersionTargeted(ctx context.Context, versionID uuid.UUID, nodeID *uuid.UUID) (*gatewayconfig.NodeSyncRetryResult, error)
	RefreshSidecarConfigs(ctx context.Context) error
}

// rulePackClusterSyncAdapter 桥接 apinodes.Store、systemalerts(HA_SPLIT_BRAIN)、
// nodesync.Manager 与 gatewayconfig.Publisher，实现阶段 R2 的 rulepacks.ClusterRulePackSyncer。
type rulePackClusterSyncAdapter struct {
	nodeStore     rulePackNodeLister
	alertStore    rulePackSplitBrainStore
	mgr           nodesync.RulePackSyncClient
	pub           rulePackConfigRetryPublisher
	localNodeName string
}

var _ rulepacks.ClusterRulePackSyncer = rulePackClusterSyncAdapter{}

func (a rulePackClusterSyncAdapter) ListStandbyNodes(ctx context.Context) ([]rulepacks.ClusterNode, error) {
	if a.nodeStore == nil {
		return nil, nil
	}
	nodes, err := a.nodeStore.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	local := strings.TrimSpace(a.localNodeName)
	out := make([]rulepacks.ClusterNode, 0, len(nodes))
	for _, n := range nodes {
		name := strings.TrimSpace(n.NodeName)
		if local != "" && strings.EqualFold(name, local) {
			continue
		}
		addr := strings.TrimSpace(n.SyncAgentAddr)
		if !n.SyncEnabled || addr == "" {
			continue
		}
		out = append(out, rulepacks.ClusterNode{
			NodeID:        n.ID,
			NodeName:      name,
			SyncAgentAddr: addr,
			SyncEnabled:   n.SyncEnabled,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeName != out[j].NodeName {
			return out[i].NodeName < out[j].NodeName
		}
		return out[i].NodeID.String() < out[j].NodeID.String()
	})
	return out, nil
}

func (a rulePackClusterSyncAdapter) HasOpenSplitBrain(ctx context.Context) (bool, error) {
	if a.alertStore == nil {
		return false, nil
	}
	open, err := a.alertStore.ListOpenByTypes(ctx, []string{systemalerts.TypeHASplitBrain})
	if err != nil {
		return false, err
	}
	return len(open) > 0, nil
}

func (a rulePackClusterSyncAdapter) CheckNodeRulePackStatus(ctx context.Context, nodeID uuid.UUID) (*rulepacks.RemoteRulePackStatus, error) {
	if a.mgr == nil {
		return nil, rulepacks.ErrClusterUnsupported
	}
	st, err := a.mgr.CheckNodeRulePackStatus(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	activeVer := strings.TrimSpace(st.ActiveVersion)
	if activeVer == "" {
		activeVer = strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(st.ActiveSymlink)), "releases/")
	}
	staged := st.StagedVersions
	if staged == nil {
		staged = map[string]string{}
	}
	return &rulepacks.RemoteRulePackStatus{
		Reachable:      st.Reachable,
		RulePackReady:  st.RulePackReady,
		ActiveSymlink:  activeVer,
		StagedVersions: staged,
		DiskFreeBytes:  st.DiskFreeBytes,
		Error:          st.Error,
	}, nil
}

func (a rulePackClusterSyncAdapter) StageRulePack(ctx context.Context, nodeID uuid.UUID, version, archivePath, fileSHA256 string) error {
	if a.mgr == nil {
		return rulepacks.ErrClusterUnsupported
	}
	_, err := a.mgr.StageRulePack(ctx, nodeID, version, archivePath, fileSHA256)
	return err
}

func (a rulePackClusterSyncAdapter) ActivateRulePack(ctx context.Context, nodeID uuid.UUID, version, manifestSHA256 string) error {
	if a.mgr == nil {
		return rulepacks.ErrClusterUnsupported
	}
	_, err := a.mgr.ActivateRulePack(ctx, nodeID, version, manifestSHA256)
	return err
}

func (a rulePackClusterSyncAdapter) PruneRulePack(ctx context.Context, nodeID uuid.UUID, version string) error {
	if a.mgr == nil {
		return rulepacks.ErrClusterUnsupported
	}
	_, err := a.mgr.DeleteRulePackRelease(ctx, nodeID, version)
	return err
}

func (a rulePackClusterSyncAdapter) RetryNodeConfigSync(ctx context.Context, nodeID uuid.UUID) error {
	if a.pub == nil {
		return errors.New("gateway publisher is not configured")
	}
	ver, err := a.pub.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("查询当前已发布网关配置版本失败: %w", err)
	}
	if ver == nil {
		// 尚未发布过任何业务应用配置（零应用边界）：仅尽力刷新边车配置，不阻断备机规则激活。
		if rerr := a.pub.RefreshSidecarConfigs(ctx); rerr != nil {
			slog.Warn("refresh sidecar configs during zero-app node retry failed", "node_id", nodeID, "error", rerr)
		}
		return nil
	}
	targetID := nodeID
	res, err := a.pub.RetryNodeSyncForVersionTargeted(ctx, ver.ID, &targetID)
	if err != nil {
		return err
	}
	if res == nil || res.Attempted == 0 || res.Failed > 0 || res.Succeeded == 0 {
		attempted, succeeded, failed := 0, 0, 0
		if res != nil {
			attempted, succeeded, failed = res.Attempted, res.Succeeded, res.Failed
		}
		return fmt.Errorf("向备节点 %s 定向重同步网关配置失败 (attempted=%d succeeded=%d failed=%d)", nodeID, attempted, succeeded, failed)
	}
	if rerr := a.pub.RefreshSidecarConfigs(ctx); rerr != nil {
		slog.Warn("refresh sidecar configs after targeted node config sync failed", "node_id", nodeID, "error", rerr)
	}
	return nil
}
