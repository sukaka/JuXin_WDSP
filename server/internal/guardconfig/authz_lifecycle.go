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
	return cloneAuthzSnapshot(&cfg), nil
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
	}
}
