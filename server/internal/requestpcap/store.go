package requestpcap

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrArtifactNotFound  = errors.New("request PCAP artifact not found")
	ErrInvalidTransition = errors.New("invalid request PCAP state transition")
)

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func (s *Store) CreateArtifact(ctx context.Context, artifact Artifact) error {
	if err := ValidateArtifact(artifact); err != nil {
		return err
	}
	result, err := s.db.Exec(ctx, `
INSERT INTO request_pcap_artifacts (
 id,gateway_node_id,capture_point,state,storage_tier,capture_started_at,capture_ended_at,
 packet_count,dropped_count,truncated,plaintext_size_bytes,ciphertext_size_bytes,
 plaintext_sha256,ciphertext_sha256,encryption_algorithm,chunk_size_bytes,chunk_count,
 wrapped_dek,key_id,policy_version,manifest_json,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'AES-256-GCM',$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT (id) DO NOTHING`,
		artifact.ID, artifact.NodeID, artifact.CapturePoint, artifact.State, artifact.StorageTier,
		artifact.CaptureStartedAt, artifact.CaptureEndedAt, artifact.PacketCount, artifact.DroppedCount,
		artifact.Truncated, artifact.PlaintextSizeBytes, artifact.CiphertextSizeBytes,
		artifact.PlaintextSHA256, artifact.CiphertextSHA256, artifact.ChunkSizeBytes, artifact.ChunkCount,
		artifact.WrappedDEK, artifact.KeyID, nullString(artifact.PolicyVersion), artifact.Manifest, artifact.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert request PCAP artifact: %w", err)
	}
	if result.RowsAffected() != 0 {
		return nil
	}
	existing, err := s.GetArtifact(ctx, artifact.ID)
	if err != nil {
		return err
	}
	if existing.NodeID != artifact.NodeID || existing.CapturePoint != artifact.CapturePoint ||
		!existing.CaptureStartedAt.Equal(artifact.CaptureStartedAt) || !existing.CaptureEndedAt.Equal(artifact.CaptureEndedAt) ||
		existing.PacketCount != artifact.PacketCount || existing.DroppedCount != artifact.DroppedCount ||
		existing.Truncated != artifact.Truncated || existing.PlaintextSizeBytes != artifact.PlaintextSizeBytes ||
		existing.CiphertextSizeBytes != artifact.CiphertextSizeBytes || existing.PlaintextSHA256 != artifact.PlaintextSHA256 ||
		existing.CiphertextSHA256 != artifact.CiphertextSHA256 || existing.ChunkSizeBytes != artifact.ChunkSizeBytes ||
		existing.ChunkCount != artifact.ChunkCount || !bytes.Equal(existing.WrappedDEK, artifact.WrappedDEK) ||
		existing.KeyID != artifact.KeyID || existing.PolicyVersion != artifact.PolicyVersion || !existing.ExpiresAt.Equal(artifact.ExpiresAt) {
		return fmt.Errorf("request PCAP artifact id conflicts with different evidence")
	}
	return nil
}

const artifactColumns = `id,gateway_node_id,capture_point,state,storage_tier,capture_started_at,capture_ended_at,
 packet_count,dropped_count,truncated,plaintext_size_bytes,ciphertext_size_bytes,
 plaintext_sha256,ciphertext_sha256,chunk_size_bytes,chunk_count,wrapped_dek,key_id,policy_version,
 manifest_json,expires_at,created_at,updated_at,integrity_status,last_verified_at,verification_error_code`

func (s *Store) GetArtifact(ctx context.Context, id uuid.UUID) (Artifact, error) {
	if id == uuid.Nil {
		return Artifact{}, ErrArtifactNotFound
	}
	var artifact Artifact
	var policyVersion, verificationErrorCode *string
	err := s.db.QueryRow(ctx, `SELECT `+artifactColumns+` FROM request_pcap_artifacts WHERE id=$1`, id).Scan(
		&artifact.ID, &artifact.NodeID, &artifact.CapturePoint, &artifact.State, &artifact.StorageTier,
		&artifact.CaptureStartedAt, &artifact.CaptureEndedAt, &artifact.PacketCount, &artifact.DroppedCount,
		&artifact.Truncated, &artifact.PlaintextSizeBytes, &artifact.CiphertextSizeBytes,
		&artifact.PlaintextSHA256, &artifact.CiphertextSHA256, &artifact.ChunkSizeBytes, &artifact.ChunkCount,
		&artifact.WrappedDEK, &artifact.KeyID, &policyVersion, &artifact.Manifest, &artifact.ExpiresAt,
		&artifact.CreatedAt, &artifact.UpdatedAt, &artifact.IntegrityStatus, &artifact.LastVerifiedAt, &verificationErrorCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrArtifactNotFound
	}
	if err != nil {
		return Artifact{}, err
	}
	artifact.PolicyVersion = stringValue(policyVersion)
	artifact.VerificationErrorCode = stringValue(verificationErrorCode)
	return artifact, nil
}

// BeginMigration 只允许热分片进入迁移中；调用方必须先完成SAS持久化再调用CompleteMigration。
func (s *Store) BeginMigration(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, "HOT", "MIGRATING", "HOT", "")
}

func (s *Store) CompleteMigration(ctx context.Context, id uuid.UUID, ciphertextSHA256 string) error {
	return s.transition(ctx, id, "MIGRATING", "WARM", "WARM", ciphertextSHA256)
}

func (s *Store) BeginExpiry(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, "WARM", "EXPIRING", "WARM", "")
}

// CompleteExpiry 只允许在文件删除已成功、墓碑需要落库时调用。
func (s *Store) CompleteExpiry(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, "EXPIRING", "EXPIRED", "WARM", "")
}

func (s *Store) MarkUnavailable(ctx context.Context, id uuid.UUID) error {
	result, err := s.db.Exec(ctx, `UPDATE request_pcap_artifacts SET state='UNAVAILABLE',updated_at=now()
		WHERE id=$1 AND state<>'EXPIRED'`, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *Store) transition(ctx context.Context, id uuid.UUID, from, to, tier, expectedHash string) error {
	query := `UPDATE request_pcap_artifacts SET state=$2,storage_tier=$3,updated_at=now() WHERE id=$1 AND state=$4`
	args := []interface{}{id, to, tier, from}
	if expectedHash != "" {
		if !lowerHex64.MatchString(expectedHash) {
			return fmt.Errorf("invalid expected evidence hash")
		}
		query += ` AND ciphertext_sha256=$5`
		args = append(args, expectedHash)
	}
	result, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	return nil
}

func (s *Store) LinkRequest(ctx context.Context, link RequestLink) error {
	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}
	if err := ValidateRequestLink(link); err != nil {
		return err
	}
	result, err := s.db.Exec(ctx, `
INSERT INTO request_pcap_links (
 id,artifact_id,request_id,trace_id,application_id,match_status,match_basis,coverage,
 candidate_count,first_packet_no,last_packet_no,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (artifact_id,request_id,coverage) DO NOTHING`,
		link.ID, link.ArtifactID, link.RequestID, nullString(link.TraceID), link.ApplicationID,
		link.MatchStatus, link.MatchBasis, link.Coverage, link.CandidateCount,
		link.FirstPacketNo, link.LastPacketNo, link.ExpiresAt)
	if err != nil {
		return fmt.Errorf("link request PCAP evidence: %w", err)
	}
	if result.RowsAffected() != 0 {
		return nil
	}
	existing, err := s.GetRequestLink(ctx, link.RequestID, link.ArtifactID)
	if err != nil {
		return err
	}
	if existing.TraceID != link.TraceID || !equalOptionalUUID(existing.ApplicationID, link.ApplicationID) ||
		existing.MatchStatus != link.MatchStatus || existing.MatchBasis != link.MatchBasis || existing.Coverage != link.Coverage ||
		existing.CandidateCount != link.CandidateCount || !equalOptionalInt64(existing.FirstPacketNo, link.FirstPacketNo) ||
		!equalOptionalInt64(existing.LastPacketNo, link.LastPacketNo) || !existing.ExpiresAt.Equal(link.ExpiresAt) {
		return fmt.Errorf("request PCAP link conflicts with different evidence facts")
	}
	return nil
}

const requestLinkColumns = `id,artifact_id,request_id,trace_id,application_id,match_status,match_basis,coverage,
 candidate_count,first_packet_no,last_packet_no,created_at,expires_at`

func scanRequestLink(row pgx.Row) (RequestLink, error) {
	var link RequestLink
	var traceID *string
	if err := row.Scan(&link.ID, &link.ArtifactID, &link.RequestID, &traceID, &link.ApplicationID,
		&link.MatchStatus, &link.MatchBasis, &link.Coverage, &link.CandidateCount,
		&link.FirstPacketNo, &link.LastPacketNo, &link.CreatedAt, &link.ExpiresAt); err != nil {
		return RequestLink{}, err
	}
	link.TraceID = stringValue(traceID)
	return link, nil
}

func (s *Store) GetRequestLink(ctx context.Context, requestID string, artifactID uuid.UUID) (RequestLink, error) {
	rows, err := s.db.Query(ctx, `SELECT `+requestLinkColumns+` FROM request_pcap_links WHERE request_id=$1 AND artifact_id=$2`, requestID, artifactID)
	if err != nil {
		return RequestLink{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return RequestLink{}, err
		}
		return RequestLink{}, ErrArtifactNotFound
	}
	link, err := scanRequestLink(rows)
	if err != nil {
		return RequestLink{}, err
	}
	if rows.Next() {
		return RequestLink{}, fmt.Errorf("request PCAP artifact has ambiguous coverage records")
	}
	return link, rows.Err()
}

func (s *Store) ListRequestLinks(ctx context.Context, requestID string) ([]RequestLink, error) {
	if requestID == "" || len(requestID) > 64 {
		return nil, fmt.Errorf("invalid request id")
	}
	rows, err := s.db.Query(ctx, `SELECT `+requestLinkColumns+`
FROM request_pcap_links WHERE request_id=$1 ORDER BY created_at DESC,id LIMIT 101`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RequestLink, 0)
	for rows.Next() {
		link, err := scanRequestLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func nullString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
