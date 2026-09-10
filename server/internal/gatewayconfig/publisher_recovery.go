package gatewayconfig

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

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
	if p.db == nil {
		return fmt.Errorf("gateway config database is not configured")
	}
	version, err := p.getVersion(ctx, versionID)
	if err != nil {
		return fmt.Errorf("load gateway config version %s: %w", versionID, err)
	}
	return p.retryNodeSyncVersion(ctx, version)
}

func (p *Publisher) retryNodeSyncVersion(ctx context.Context, version *ConfigVersion) error {
	if version == nil {
		return fmt.Errorf("gateway config version is nil")
	}
	if version.ID == uuid.Nil {
		return fmt.Errorf("gateway config version id is empty")
	}
	if version.PublishResult != TaskSuccess {
		return fmt.Errorf("gateway config version %s was not published successfully", version.ID)
	}
	if p.nodeSync == nil {
		return fmt.Errorf("gateway node sync store is not configured")
	}

	configJSON, err := p.reinjectConfigSecrets(ctx, version.ConfigurationJSON)
	if err != nil {
		return fmt.Errorf("recover gateway config version %s: %w", version.ID, err)
	}

	// 持久化仓储若支持失败筛选，只重试该版本最近一次失败或哈希不一致的节点；
	// 旧实现回退到全量启用节点，保持 NodeSyncStore 的兼容性与幂等语义。
	if failedStore, ok := p.nodeSync.(failedNodeSyncStore); ok {
		targets, err := failedStore.ListFailedSyncTargets(ctx, version.ID)
		if err != nil {
			return fmt.Errorf("list failed gateway nodes for version %s: %w", version.ID, err)
		}
		outcome := p.syncConfigToTargets(ctx, configJSON, version.ID, targets)
		if outcome.contextErr != nil {
			return fmt.Errorf("recover gateway config version %s: %w", version.ID, outcome.contextErr)
		}
		return nil
	}
	outcome := p.syncConfigToNodes(ctx, configJSON, version.ID)
	if outcome.contextErr != nil {
		return fmt.Errorf("recover gateway config version %s: %w", version.ID, outcome.contextErr)
	}
	return nil
}
