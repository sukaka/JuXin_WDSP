package securityidentities

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func scanIdentity(row pgx.Row) (*Identity, error) {
	var it Identity
	err := row.Scan(&it.ID, &it.IdentityKey, &it.IdentityType, &it.FirstSeenAt, &it.LastSeenAt, &it.PrimaryIP,
		&it.IdentityConfidence, &it.ConfidenceSource, &it.ASN, &it.TLSFingerprint, &it.BrowserFingerprint, &it.AccountID, &it.JWTSubject, &it.APIKeyHash,
		&it.OAuthClientID, &it.DeviceType, &it.RiskScore, &it.RiskLevel, &it.Status, &it.RequestCount,
		&it.BlockedReason, &it.BlockedBy, &it.BlockedAt, &it.UnblockedBy, &it.UnblockedAt, &it.CreatedAt, &it.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	it.IdentityType = normalizeIdentityType(it.IdentityType)
	return &it, nil
}

func (s *Store) Block(ctx context.Context, id uuid.UUID, reason string, operatorID uuid.UUID) (*Identity, bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanIdentity(tx.QueryRow(ctx, `SELECT `+identityColumns+` FROM client_identity WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, false, err
	}
	if current.Status == "BLOCKED" {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}
	if current.Status != "NORMAL" {
		return nil, false, fmt.Errorf("identity status %s does not allow manual block", current.Status)
	}
	updated, err := scanIdentity(tx.QueryRow(ctx, `
UPDATE client_identity
SET status='BLOCKED', blocked_reason=$2, blocked_by=$3, blocked_at=now(),
    unblocked_by=NULL, unblocked_at=NULL, updated_at=now()
WHERE id=$1 AND status='NORMAL'
RETURNING `+identityColumns, id, reason, operatorID))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return updated, true, nil
}

func (s *Store) Unblock(ctx context.Context, id uuid.UUID, operatorID uuid.UUID) (*Identity, bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanIdentity(tx.QueryRow(ctx, `SELECT `+identityColumns+` FROM client_identity WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, false, err
	}
	if current.Status == "NORMAL" {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return current, false, nil
	}
	if current.Status != "BLOCKED" {
		return nil, false, fmt.Errorf("identity status %s does not allow manual unblock", current.Status)
	}
	updated, err := scanIdentity(tx.QueryRow(ctx, `
UPDATE client_identity
SET status='NORMAL', unblocked_by=$2, unblocked_at=now(), updated_at=now()
WHERE id=$1 AND status='BLOCKED'
RETURNING `+identityColumns, id, operatorID))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return updated, true, nil
}

func (s *Store) ListBlockedIdentities(ctx context.Context) ([]gatewayconfig.GuardIdentityBlock, error) {
	rows, err := s.db.Query(ctx, `SELECT id, identity_key FROM client_identity WHERE status='BLOCKED' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardIdentityBlock{}
	for rows.Next() {
		var id uuid.UUID
		var key string
		if err := rows.Scan(&id, &key); err != nil {
			return nil, err
		}
		out = append(out, gatewayconfig.GuardIdentityBlock{ID: id.String(), IdentityKey: key})
	}
	return out, rows.Err()
}
