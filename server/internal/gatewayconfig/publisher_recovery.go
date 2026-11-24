package gatewayconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 版本级重试同步的业务哨兵错误（供 HTTP Handler 精确映射状态码）。
var (
	ErrVersionNotFound       = errors.New("gateway config version not found")
	ErrVersionNotPublished   = errors.New("gateway config version was not published successfully")
	ErrNodeSyncNotConfigured = errors.New("gateway node sync store is not configured")
	ErrSyncTargetNotFound    = errors.New("gateway sync target not found")
	ErrLocalPrimaryTarget    = errors.New("target is local primary gateway node")
)

// NodeSyncRetryResult 是版本级次要节点重试同步的结果摘要。
type NodeSyncRetryResult struct {
	VersionID      uuid.UUID `json:"version_id"`
	NodeID         string    `json:"node_id,omitempty"`
	Attempted      int       `json:"attempted"`
	Succeeded      int       `json:"succeeded"`
	Failed         int       `json:"failed"`
	RecordFailures int       `json:"record_failures"`
}

func (p *Publisher) loadVersion(ctx context.Context, versionID uuid.UUID) (*ConfigVersion, error) {
	if p.loadVersionFn != nil {
		return p.loadVersionFn(ctx, versionID)
	}
	if p.db == nil {
		return nil, fmt.Errorf("gateway config database is not configured")
	}
	version, err := p.getVersion(ctx, versionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: %v", ErrVersionNotFound, err)
		}
		return nil, fmt.Errorf("load gateway config version %s: %w", versionID, err)
	}
	return version, nil
}

// RetryNodeSyncForVersion resumes the secondary-node fan-out for a persisted
// successfully published version. The version JSON is the redacted snapshot
// stored in gateway_config_versions, so current secrets are re-injected before
// the existing SyncConfigToNodes path is reused.
//
// 持久化 NodeSyncStore 若实现失败目标查询，则只重试该版本最近一次 FAILED 或
// HASH_MISMATCH 的节点；旧实现仍回退到全部启用节点。加载同一版本是幂等的，节点结果
// 继续由既有扇出路径记录并告警。本方法只对不可恢复的快照或目标查询错误返回错误，
// 单节点下发失败仍作为节点事实持久化。
func (p *Publisher) RetryNodeSyncForVersion(ctx context.Context, versionID uuid.UUID) error {
	_, err := p.RetryNodeSyncForVersionTargeted(ctx, versionID, nil)
	return err
}

// RetryNodeSyncForVersionTargeted 支持整版本失败节点重试（nodeID == nil）或单节点定向重试
// （nodeID 非空），返回本次同步尝试/成功/失败计数，供 HTTP 接口与运维审计使用。
func (p *Publisher) RetryNodeSyncForVersionTargeted(ctx context.Context, versionID uuid.UUID, nodeID *uuid.UUID) (*NodeSyncRetryResult, error) {
	version, err := p.loadVersion(ctx, versionID)
	if err != nil {
		return nil, err
	}
	return p.retryNodeSyncVersionTargeted(ctx, version, nodeID)
}

func (p *Publisher) retryNodeSyncVersion(ctx context.Context, version *ConfigVersion) error {
	_, err := p.retryNodeSyncVersionTargeted(ctx, version, nil)
	return err
}

func (p *Publisher) retryNodeSyncVersionTargeted(ctx context.Context, version *ConfigVersion, nodeID *uuid.UUID) (*NodeSyncRetryResult, error) {
	if version == nil {
		return nil, fmt.Errorf("gateway config version is nil")
	}
	if version.ID == uuid.Nil {
		return nil, fmt.Errorf("gateway config version id is empty")
	}
	if version.PublishResult != TaskSuccess {
		return nil, fmt.Errorf("%w: %s", ErrVersionNotPublished, version.ID)
	}
	if p.nodeSync == nil {
		return nil, ErrNodeSyncNotConfigured
	}

	configJSON, err := p.reinjectConfigSecrets(ctx, version.ConfigurationJSON)
	if err != nil {
		return nil, fmt.Errorf("recover gateway config version %s: %w", version.ID, err)
	}

	var targets []SyncTarget
	res := &NodeSyncRetryResult{VersionID: version.ID}

	if nodeID != nil && *nodeID != uuid.Nil {
		res.NodeID = nodeID.String()
		allTargets, err := p.nodeSync.ListSyncTargets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list gateway nodes for version %s: %w", version.ID, err)
		}
		var matched *SyncTarget
		for i := range allTargets {
			if allTargets[i].NodeID == *nodeID {
				matched = &allTargets[i]
				break
			}
		}
		if matched == nil {
			return nil, fmt.Errorf("%w: %s", ErrSyncTargetNotFound, *nodeID)
		}
		if p.isLocalPrimaryTarget(*matched) {
			return nil, fmt.Errorf("%w: %s", ErrLocalPrimaryTarget, matched.NodeName)
		}
		targets = []SyncTarget{*matched}
	} else if failedStore, ok := p.nodeSync.(failedNodeSyncStore); ok {
		targets, err = failedStore.ListFailedSyncTargets(ctx, version.ID)
		if err != nil {
			return nil, fmt.Errorf("list failed gateway nodes for version %s: %w", version.ID, err)
		}
	} else {
		targets, err = p.nodeSync.ListSyncTargets(ctx)
		if err != nil {
			return nil, fmt.Errorf("list gateway nodes for version %s: %w", version.ID, err)
		}
	}

	if ports, ok := extractPublicTCPPortsFromConfig(configJSON); ok && len(ports) > 0 {
		p.syncRemoteFirewallPortsToTargets(ctx, targets, ports, uuid.Nil, "")
	}

	outcome := p.syncConfigToTargets(ctx, configJSON, version.ID, targets)
	res.Attempted = outcome.attempted
	res.Succeeded = outcome.succeeded
	res.Failed = outcome.failed
	res.RecordFailures = outcome.recordFailures

	if outcome.contextErr != nil {
		return res, fmt.Errorf("recover gateway config version %s: %w", version.ID, outcome.contextErr)
	}
	if outcome.hashErr != nil {
		return res, fmt.Errorf("recover gateway config version %s: %w", version.ID, outcome.hashErr)
	}
	return res, nil
}
