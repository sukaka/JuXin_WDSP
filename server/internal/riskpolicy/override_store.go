package riskpolicy

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

var ErrApplicationRequired = errors.New("应用不能为空")

const applicationOverrideColumns = `id, application_id, enabled, mode, version,
	block_threshold, rate_limit_threshold, challenge_threshold, rate_limit_rps, signal_window_seconds,
	shared_device_account_limit, scores, risk_levels, updated_by, created_at, updated_at`

type applicationOverrideScanner interface{ Scan(...any) error }

func scanApplicationOverride(row applicationOverrideScanner) (*Policy, error) {
	var p Policy
	var applicationID uuid.UUID
	var scores, riskLevels []byte
	var updatedBy *string
	if err := row.Scan(&p.ID, &applicationID, &p.Enabled, &p.Mode, &p.Version,
		&p.BlockThreshold, &p.RateLimitThreshold, &p.ChallengeThreshold, &p.RateLimitRPS, &p.SignalWindowSeconds,
		&p.SharedDeviceAccountLimit, &scores, &riskLevels, &updatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Scope = ScopeApplication
	p.ApplicationID = &applicationID
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	if err := json.Unmarshal(scores, &p.Scores); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(riskLevels, &p.RiskLevels); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) GetApplicationOverride(ctx context.Context, applicationID uuid.UUID) (*Policy, error) {
	p, err := scanApplicationOverride(s.db.QueryRow(ctx, `SELECT `+applicationOverrideColumns+` FROM security_risk_policy_overrides WHERE application_id=$1`, applicationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func (s *Store) PutApplicationOverride(ctx context.Context, p *Policy, expectedVersion int, updatedBy string) (*Policy, error) {
	if p.ApplicationID == nil || *p.ApplicationID == uuid.Nil {
		return nil, ErrApplicationRequired
	}
	if errs := Validate(p); len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	scores, err := json.Marshal(nonNilScores(p.Scores))
	if err != nil {
		return nil, err
	}
	riskLevels, err := json.Marshal(nonNilScores(p.RiskLevels))
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(ctx, `INSERT INTO security_risk_policy_overrides
		(id, application_id, enabled, mode, block_threshold, rate_limit_threshold, challenge_threshold,
		 rate_limit_rps, signal_window_seconds, shared_device_account_limit, scores, risk_levels, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (application_id) DO UPDATE SET
		 enabled=EXCLUDED.enabled, mode=EXCLUDED.mode, block_threshold=EXCLUDED.block_threshold,
		 rate_limit_threshold=EXCLUDED.rate_limit_threshold, challenge_threshold=EXCLUDED.challenge_threshold,
		 rate_limit_rps=EXCLUDED.rate_limit_rps, signal_window_seconds=EXCLUDED.signal_window_seconds,
		 shared_device_account_limit=EXCLUDED.shared_device_account_limit, scores=EXCLUDED.scores,
		 risk_levels=EXCLUDED.risk_levels, updated_by=EXCLUDED.updated_by, updated_at=now(),
		 version=security_risk_policy_overrides.version+1
		WHERE security_risk_policy_overrides.version=$14
		RETURNING `+applicationOverrideColumns,
		p.ID, *p.ApplicationID, p.Enabled, p.Mode, p.BlockThreshold, p.RateLimitThreshold, p.ChallengeThreshold,
		p.RateLimitRPS, p.SignalWindowSeconds, p.SharedDeviceAccountLimit, scores, riskLevels, updatedBy, expectedVersion)
	updated, err := scanApplicationOverride(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return nil, ErrNotFound
	}
	return updated, err
}

func (s *Store) DeleteApplicationOverride(ctx context.Context, applicationID uuid.UUID, version int) error {
	result, err := s.db.Exec(ctx, `DELETE FROM security_risk_policy_overrides WHERE application_id=$1 AND version=$2`, applicationID, version)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListGuardRiskPolicyOverrides(ctx context.Context) ([]gatewayconfig.GuardRiskPolicyOverride, error) {
	rows, err := s.db.Query(ctx, `SELECT `+applicationOverrideColumns+` FROM security_risk_policy_overrides ORDER BY application_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardRiskPolicyOverride{}
	for rows.Next() {
		p, err := scanApplicationOverride(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, gatewayconfig.GuardRiskPolicyOverride{
			ApplicationID: p.ApplicationID.String(), Policy: guardRiskPolicy(p),
			SharedDeviceAccountLimit: p.SharedDeviceAccountLimit,
		})
	}
	return out, rows.Err()
}

func guardRiskPolicy(p *Policy) gatewayconfig.GuardRiskPolicy {
	return gatewayconfig.GuardRiskPolicy{
		Enabled: p.Enabled, Mode: p.Mode, Version: p.Version,
		BlockThreshold: p.BlockThreshold, RateLimitThreshold: p.RateLimitThreshold,
		ChallengeThreshold: p.ChallengeThreshold,
		RateLimitRPS:       p.RateLimitRPS, SignalWindowSeconds: p.SignalWindowSeconds,
		Scores: nonNilScores(p.Scores), RiskLevels: nonNilScores(p.RiskLevels),
	}
}
