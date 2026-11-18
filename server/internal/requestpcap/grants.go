package requestpcap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrGrantNotAvailable = errors.New("request PCAP download grant is expired, consumed or unavailable")

type DownloadGrant struct {
	ID         uuid.UUID
	ArtifactID uuid.UUID
	RequestID  string
	UserID     uuid.UUID
	SessionID  string
	Reason     string
	SourceIP   string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

func (s *Store) SetVerification(ctx context.Context, artifactID uuid.UUID, status, errorCode string, at time.Time) error {
	switch status {
	case "PASS", "FAILED", "KEY_UNAVAILABLE", "UNVERIFIED":
	default:
		return fmt.Errorf("invalid evidence verification status")
	}
	if len(errorCode) > 64 || (status == "PASS" && errorCode != "") || (status != "PASS" && status != "UNVERIFIED" && errorCode == "") {
		return fmt.Errorf("invalid evidence verification error code")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	result, err := s.db.Exec(ctx, `UPDATE request_pcap_artifacts
		SET integrity_status=$2,last_verified_at=$3,verification_error_code=$4,updated_at=now()
		WHERE id=$1 AND state IN ('HOT','WARM','MIGRATING','UNAVAILABLE')`, artifactID, status, at, nullString(errorCode))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrArtifactNotFound
	}
	return nil
}

func (s *Store) CreateDownloadGrant(ctx context.Context, grant DownloadGrant) error {
	grant.Reason = strings.TrimSpace(grant.Reason)
	if grant.ID == uuid.Nil || grant.ArtifactID == uuid.Nil || grant.UserID == uuid.Nil ||
		grant.RequestID == "" || len(grant.RequestID) > 64 || grant.SessionID == "" || len(grant.SessionID) > 128 ||
		grant.Reason == "" || len(grant.Reason) > 500 {
		return fmt.Errorf("invalid download grant identity or reason")
	}
	if !grant.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("download grant must expire in the future")
	}
	var sourceIP interface{}
	if grant.SourceIP != "" {
		address, err := netip.ParseAddr(grant.SourceIP)
		if err != nil {
			return fmt.Errorf("invalid download grant source IP")
		}
		sourceIP = address.String()
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO request_pcap_download_grants
 (id,artifact_id,request_id,user_id,session_id,reason,source_ip,expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		grant.ID, grant.ArtifactID, grant.RequestID, grant.UserID, grant.SessionID,
		grant.Reason, sourceIP, grant.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create request PCAP download grant: %w", err)
	}
	return nil
}

// ConsumeDownloadGrant 原子消费短时单次授权；不区分不存在、过期、已消费或跨用户细节。
func (s *Store) ConsumeDownloadGrant(ctx context.Context, id uuid.UUID, userID uuid.UUID, sessionID string, now time.Time) (DownloadGrant, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var grant DownloadGrant
	err := s.db.QueryRow(ctx, `UPDATE request_pcap_download_grants SET consumed_at=$1
		WHERE id=$2 AND user_id=$3 AND session_id=$4 AND consumed_at IS NULL AND expires_at>$1
		RETURNING id,artifact_id,request_id,user_id,session_id,expires_at,created_at`, now, id, userID, sessionID).
		Scan(&grant.ID, &grant.ArtifactID, &grant.RequestID, &grant.UserID, &grant.SessionID, &grant.ExpiresAt, &grant.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DownloadGrant{}, ErrGrantNotAvailable
	}
	if err != nil {
		return DownloadGrant{}, err
	}
	return grant, nil
}
