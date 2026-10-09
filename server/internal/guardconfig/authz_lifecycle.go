package guardconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// latestSuccessfulVersionID is a defensive boundary around the store query:
// even if a caller or test supplies a malformed result, only SUCCESS may be
// linked as the previous effective version.
func latestSuccessfulVersionID(latest *accesscontrolversions.Version, err error) (*uuid.UUID, error) {
	if err != nil {
		if errors.Is(err, accesscontrolversions.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load previous successful access control version: %w", err)
	}
	if latest == nil || latest.PublishResult != accesscontrolversions.PublishSuccess {
		return nil, nil
	}
	id := latest.ID
	return &id, nil
}

// loadLatestSuccessfulAuthzSnapshot loads only the authorization payload from
// the last successful GuardConfig version. Runtime secrets are deliberately
// omitted; gatewayconfig reinjects the current object-reference HMAC key when
// rendering the previous snapshot.
func (p *Provider) loadLatestSuccessfulAuthzSnapshot(ctx context.Context) (*gatewayconfig.GuardAuthzSnapshot, error) {
	if p.versions == nil {
		return nil, nil
	}
	v, err := p.versions.GetLatestSuccessful(ctx)
	if err != nil {
		return nil, fmt.Errorf("load latest successful authorization snapshot: %w", err)
	}
	if v == nil || len(v.Config) == 0 {
		return nil, nil
	}

	cfg, err := decodeGuardConfigSnapshot(v.Config)
	if err != nil {
		return nil, fmt.Errorf("decode latest successful authorization snapshot: %w", err)
	}
	if len(cfg.APIAuthzModels) == 0 && len(cfg.APIAuthzRelations) == 0 && len(cfg.APIAuthzRoleBaselines) == 0 {
		return nil, nil
	}
	snapshot := cloneAuthzSnapshot(&cfg)

	// NG-AZ-02 D3 PreviousValid 水位资格过滤：候选旧快照的水位必须 ≥ 发布时刻管理面
	// 水位（分量比较，含 manual_seq 与逐来源）且自身未过期——无合格候选置空（不降级
	// 选旧，防把已撤销许可重新下发；DB/解码错误仍中止发布 fail-hard）。
	// 缺水位字段的旧版本快照按水位 0 参与比较（仅当管理面从未撤销时才可能合格）。
	eligible, err := p.authzPreviousValidEligible(ctx, &cfg, snapshot)
	if err != nil {
		return nil, err
	}
	if !eligible {
		return nil, nil
	}
	return snapshot, nil
}

// authzPreviousValidEligible D3 资格判定：候选快照水位分量比较 ≥ 当前管理面水位
// 且快照有效期未过（expires_at 为空视为随模型行判定——沿用既有网关侧逐行口径，
// 此处对快照级 expires_at 做发布侧过滤）。
func (p *Provider) authzPreviousValidEligible(ctx context.Context, cfg *gatewayconfig.GuardConfig, snapshot *gatewayconfig.GuardAuthzSnapshot) (bool, error) {
	if snapshot.SnapshotExpiresAt != nil && !time.Now().UTC().Before(*snapshot.SnapshotExpiresAt) {
		return false, nil
	}
	current, err := p.loadManagementWatermark(ctx)
	if err != nil {
		return false, err
	}
	candidate := cfg.APIAuthzRevocationWatermark // 缺省（旧版本快照）= 水位 0 参与比较
	return gatewayconfig.RevocationWatermarkAtLeast(candidate, current), nil
}

// loadManagementWatermark 读当前管理面向量水位（复用 AuthzSnapshotV2Lister；
// 未装配/未实现（测试与纯 WAF 形态）时按全零水位处理——此时任何候选水位 ≥ 0 恒合格，
// 与「无权威/无撤销事实环境」语义一致，不伪造资格）。
func (p *Provider) loadManagementWatermark(ctx context.Context) (*gatewayconfig.RevocationWatermark, error) {
	l, ok := p.authzSnapshot.(AuthzSnapshotV2Lister)
	if !ok || l == nil {
		return &gatewayconfig.RevocationWatermark{}, nil
	}
	return l.LoadManagementRevocationWatermark(ctx)
}

// decodeGuardConfigSnapshot is the compatibility boundary for persisted Guard
// snapshots. Persisted versions may predate newer optional fields, and a
// newer producer may add fields that this Provider does not yet consume. Keep
// the default JSON decoder here so both recovery paths apply the same
// forward/backward-compatible schema rules.
func decodeGuardConfigSnapshot(data []byte) (gatewayconfig.GuardConfig, error) {
	var cfg gatewayconfig.GuardConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return gatewayconfig.GuardConfig{}, err
	}
	return cfg, nil
}

// cloneAuthzSnapshot creates the explicit PreviousValid payload. The saved
// version's expiry is retained so selecting a historical snapshot cannot
// extend the authorization facts beyond their compiled maximum lifetime.
func cloneAuthzSnapshot(cfg *gatewayconfig.GuardConfig) *gatewayconfig.GuardAuthzSnapshot {
	if cfg == nil {
		return nil
	}

	models := append([]gatewayconfig.GuardAuthzObjectModel(nil), cfg.APIAuthzModels...)
	for i := range models {
		models[i].Identifiers = append([]gatewayconfig.GuardAuthzObjectIdentifier(nil), models[i].Identifiers...)
		if models[i].SnapshotExpiresAt != nil {
			expiresAt := models[i].SnapshotExpiresAt.UTC()
			models[i].SnapshotExpiresAt = &expiresAt
		}
	}
	relations := append([]gatewayconfig.GuardAuthzObjectRelation(nil), cfg.APIAuthzRelations...)
	for i := range relations {
		if relations[i].ValidFrom != nil {
			validFrom := relations[i].ValidFrom.UTC()
			relations[i].ValidFrom = &validFrom
		}
		if relations[i].ValidUntil != nil {
			validUntil := relations[i].ValidUntil.UTC()
			relations[i].ValidUntil = &validUntil
		}
	}
	roles := append([]gatewayconfig.GuardAuthzRoleBaseline(nil), cfg.APIAuthzRoleBaselines...)

	var expiresAt *time.Time
	if cfg.APIAuthzSnapshotExpiresAt != nil {
		expires := cfg.APIAuthzSnapshotExpiresAt.UTC()
		expiresAt = &expires
	}
	return &gatewayconfig.GuardAuthzSnapshot{
		Models:            models,
		Relations:         relations,
		RoleBaselines:     roles,
		PolicyVersion:     cfg.APIPolicyVersion,
		Stale:             false,
		SnapshotExpiresAt: expiresAt,
		// NG-AZ-02 v2 元数据随克隆保留（D2：PreviousValid 同样携带各自水位/租约/排除集/
		// 编译时刻——旧版本快照缺省即零值，D3 按水位 0 判定）
		Schema:              cfg.APIAuthzSchema,
		RevocationWatermark: cfg.APIAuthzRevocationWatermark,
		LeaseSeconds:        minPositiveInt(cfg.APIAuthzLeaseSeconds),
		ConflictedObjects:   append([]gatewayconfig.GuardAuthzConflictedObject(nil), cfg.APIAuthzConflictedObjects...),
		ProducedAt:          cfg.APIAuthzProducedAt,
	}
}

// minPositiveInt 取 map 正数最小值（D6 合并口径：快照级租约取 per-app 最小者；
// 全空/全零返回 0=未启用）。
func minPositiveInt(m map[string]int) int {
	min := 0
	for _, v := range m {
		if v <= 0 {
			continue
		}
		if min == 0 || v < min {
			min = v
		}
	}
	return min
}
