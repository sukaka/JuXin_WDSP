package apillm

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type SecurityPolicyRepository interface {
	ListSecurityPolicies(context.Context) ([]SecurityPolicy, error)
	GetSecurityPolicy(context.Context, uuid.UUID) (*SecurityPolicy, error)
	CreateSecurityPolicy(context.Context, *SecurityPolicy) error
	UpdateSecurityPolicy(context.Context, *SecurityPolicy) error
	DeleteSecurityPolicy(context.Context, uuid.UUID) error
	ListSecurityPolicyVersions(context.Context, uuid.UUID) ([]SecurityPolicyVersion, error)
	ListEnabledSecurityPolicies(context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error)
}

var _ SecurityPolicyRepository = (*Store)(nil)

const securityPolicyColumns = `id, application_id, name, mode, prompt_injection_enabled,
	input_content_enabled, pii_detection_enabled, output_content_enabled, output_pii_enabled,
	blocked_topics, max_prompt_bytes, max_output_tokens, enabled, version,
	created_by, updated_by, created_at, updated_at`

type securityPolicyScanner interface{ Scan(...any) error }

func scanSecurityPolicy(row securityPolicyScanner) (*SecurityPolicy, error) {
	var p SecurityPolicy
	var topics json.RawMessage
	if err := row.Scan(&p.ID, &p.ApplicationID, &p.Name, &p.Mode, &p.PromptInjectionEnabled,
		&p.InputContentEnabled, &p.PIIDetectionEnabled, &p.OutputContentEnabled, &p.OutputPIIEnabled,
		&topics, &p.MaxPromptBytes, &p.MaxOutputTokens, &p.Enabled, &p.Version,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.BlockedTopics = []string{}
	if len(topics) > 0 {
		if err := json.Unmarshal(topics, &p.BlockedTopics); err != nil {
			return nil, err
		}
	}
	return &p, nil
}

func (s *Store) ListSecurityPolicies(ctx context.Context) ([]SecurityPolicy, error) {
	rows, err := s.db.Query(ctx, `SELECT `+securityPolicyColumns+` FROM api_llm_security_policies ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityPolicy{}
	for rows.Next() {
		p, err := scanSecurityPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) GetSecurityPolicy(ctx context.Context, id uuid.UUID) (*SecurityPolicy, error) {
	p, err := scanSecurityPolicy(s.db.QueryRow(ctx, `SELECT `+securityPolicyColumns+` FROM api_llm_security_policies WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecurityPolicyNotFound
	}
	return p, err
}

func insertSecurityPolicyVersion(ctx context.Context, tx pgx.Tx, p *SecurityPolicy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO api_llm_security_policy_versions
		(policy_id, version, policy_snapshot, created_by) VALUES ($1,$2,$3,$4)`,
		p.ID, p.Version, raw, p.UpdatedBy)
	return err
}

func (s *Store) CreateSecurityPolicy(ctx context.Context, p *SecurityPolicy) error {
	topics, err := json.Marshal(p.BlockedTopics)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = tx.QueryRow(ctx, `INSERT INTO api_llm_security_policies
		(application_id, name, mode, prompt_injection_enabled, input_content_enabled, pii_detection_enabled,
		 output_content_enabled, output_pii_enabled,
		 blocked_topics, max_prompt_bytes, max_output_tokens, enabled, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)
		RETURNING id, version, created_at, updated_at`, p.ApplicationID, p.Name, p.Mode,
		p.PromptInjectionEnabled, p.InputContentEnabled, p.PIIDetectionEnabled, p.OutputContentEnabled, p.OutputPIIEnabled,
		topics, p.MaxPromptBytes, p.MaxOutputTokens, p.Enabled, p.CreatedBy, p.UpdatedBy).Scan(&p.ID, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if isSecurityPolicyUniqueViolation(err) {
		return ErrSecurityPolicyConflict
	}
	if err != nil {
		return err
	}
	if err := insertSecurityPolicyVersion(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateSecurityPolicy(ctx context.Context, p *SecurityPolicy) error {
	topics, err := json.Marshal(p.BlockedTopics)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = tx.QueryRow(ctx, `UPDATE api_llm_security_policies SET
		name=$2, mode=$3, prompt_injection_enabled=$4, input_content_enabled=$5, pii_detection_enabled=$6,
		output_content_enabled=$7, output_pii_enabled=$8,
		blocked_topics=$9, max_prompt_bytes=$10, max_output_tokens=$11, enabled=$12, version=version+1,
		updated_by=$13, updated_at=now() WHERE id=$1
		RETURNING version, updated_at`, p.ID, p.Name, p.Mode, p.PromptInjectionEnabled, p.InputContentEnabled,
		p.PIIDetectionEnabled, p.OutputContentEnabled, p.OutputPIIEnabled,
		topics, p.MaxPromptBytes, p.MaxOutputTokens, p.Enabled, p.UpdatedBy).
		Scan(&p.Version, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSecurityPolicyNotFound
	}
	if err != nil {
		return err
	}
	if err := insertSecurityPolicyVersion(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteSecurityPolicy(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_llm_security_policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSecurityPolicyNotFound
	}
	return nil
}

func (s *Store) ListSecurityPolicyVersions(ctx context.Context, id uuid.UUID) ([]SecurityPolicyVersion, error) {
	rows, err := s.db.Query(ctx, `SELECT id, policy_id, version, policy_snapshot, created_by, created_at
		FROM api_llm_security_policy_versions WHERE policy_id=$1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityPolicyVersion{}
	for rows.Next() {
		var v SecurityPolicyVersion
		if err := rows.Scan(&v.ID, &v.PolicyID, &v.Version, &v.PolicySnapshot, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabledSecurityPolicies(ctx context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error) {
	rows, err := s.db.Query(ctx, `SELECT `+securityPolicyColumns+` FROM api_llm_security_policies WHERE enabled ORDER BY application_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardLLMSecurityPolicy{}
	for rows.Next() {
		p, err := scanSecurityPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p.GuardConfig())
	}
	return out, rows.Err()
}

func isSecurityPolicyUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func cloneSecurityPolicy(p SecurityPolicy) SecurityPolicy {
	p.BlockedTopics = append([]string(nil), p.BlockedTopics...)
	return p
}
