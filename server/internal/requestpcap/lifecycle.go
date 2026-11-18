package requestpcap

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ArtifactLifecycleStore 同时支持本地Store和未来受控远程节点适配器。
type ArtifactLifecycleStore interface {
	GetArtifact(context.Context, uuid.UUID) (Artifact, error)
	BeginMigration(context.Context, uuid.UUID) error
	CompleteMigration(context.Context, uuid.UUID, string) error
	BeginExpiry(context.Context, uuid.UUID) error
	CompleteExpiry(context.Context, uuid.UUID) error
	MarkUnavailable(context.Context, uuid.UUID) error
	ListHotArtifacts(context.Context, string, time.Time, int) ([]Artifact, error)
	ListExpiredArtifacts(context.Context, string, time.Time, int) ([]Artifact, error)
}

func (s *Store) ListHotArtifacts(ctx context.Context, nodeID string, before time.Time, limit int) ([]Artifact, error) {
	return s.listArtifactLifecycle(ctx, nodeID, "state='HOT' AND capture_ended_at <= $1", before, limit)
}

func (s *Store) ListExpiredArtifacts(ctx context.Context, nodeID string, at time.Time, limit int) ([]Artifact, error) {
	return s.listArtifactLifecycle(ctx, nodeID, "state='WARM' AND expires_at <= $1", at, limit)
}

func (s *Store) listArtifactLifecycle(ctx context.Context, nodeID, condition string, at time.Time, limit int) ([]Artifact, error) {
	if nodeID == "" || at.IsZero() {
		return nil, fmt.Errorf("lifecycle query node and time are required")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx, `SELECT `+artifactColumns+` FROM request_pcap_artifacts
		WHERE `+condition+` AND gateway_node_id=$2 ORDER BY capture_ended_at,id LIMIT $3`, at, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Artifact, 0)
	for rows.Next() {
		artifact, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, artifact)
	}
	return out, rows.Err()
}

func scanArtifact(row pgx.Row) (Artifact, error) {
	var artifact Artifact
	var policyVersion, verificationErrorCode *string
	err := row.Scan(
		&artifact.ID, &artifact.NodeID, &artifact.CapturePoint, &artifact.State, &artifact.StorageTier,
		&artifact.CaptureStartedAt, &artifact.CaptureEndedAt, &artifact.PacketCount, &artifact.DroppedCount,
		&artifact.Truncated, &artifact.PlaintextSizeBytes, &artifact.CiphertextSizeBytes,
		&artifact.PlaintextSHA256, &artifact.CiphertextSHA256, &artifact.ChunkSizeBytes, &artifact.ChunkCount,
		&artifact.WrappedDEK, &artifact.KeyID, &policyVersion, &artifact.Manifest, &artifact.ExpiresAt,
		&artifact.CreatedAt, &artifact.UpdatedAt, &artifact.IntegrityStatus, &artifact.LastVerifiedAt, &verificationErrorCode)
	if err != nil {
		return Artifact{}, err
	}
	artifact.PolicyVersion = stringValue(policyVersion)
	artifact.VerificationErrorCode = stringValue(verificationErrorCode)
	return artifact, nil
}
