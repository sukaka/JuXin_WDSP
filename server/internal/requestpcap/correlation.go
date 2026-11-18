package requestpcap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrRequestAuditNotFound = errors.New("no matching access log for captured request")

// CapturedRequest 是抓包侧请求证据的受控镜像，不包含正文或任意Header集合。
type CapturedRequest struct {
	RequestID     string    `json:"request_id"`
	TraceID       string    `json:"trace_id,omitempty"`
	ConnectionID  string    `json:"connection_id"`
	ObservedAt    time.Time `json:"observed_at"`
	CapturePoint  string    `json:"capture_point"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Host          string    `json:"host"`
	BodyTruncated bool      `json:"body_truncated"`
	FirstPacketNo uint64    `json:"first_packet_no,omitempty"`
	LastPacketNo  uint64    `json:"last_packet_no,omitempty"`
}

func (s *Store) RecordCapturedRequest(ctx context.Context, artifactID uuid.UUID, evidence CapturedRequest) error {
	artifact, err := s.GetArtifact(ctx, artifactID)
	if err != nil {
		return err
	}
	if artifact.State == "EXPIRED" || artifact.State == "UNAVAILABLE" {
		return fmt.Errorf("cannot link evidence in state %s", artifact.State)
	}
	if evidence.CapturePoint != "GATEWAY_EGRESS" || evidence.ObservedAt.IsZero() || !lowerHex64.MatchString(evidence.ConnectionID) {
		return fmt.Errorf("captured request lacks trusted connection evidence")
	}
	var applicationID *uuid.UUID
	var traceID, method, requestPath *string
	err = s.db.QueryRow(ctx, `
SELECT application_id,trace_id,request_method,request_path FROM access_logs WHERE request_id=$1`, evidence.RequestID).
		Scan(&applicationID, &traceID, &method, &requestPath)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRequestAuditNotFound
	}
	if err != nil {
		return err
	}
	if method == nil || requestPath == nil || strings.ToUpper(*method) != strings.ToUpper(evidence.Method) || *requestPath != evidence.Path {
		return fmt.Errorf("captured request method or path does not match access log")
	}
	if traceID != nil && *traceID != "" && evidence.TraceID != "" && *traceID != evidence.TraceID {
		return fmt.Errorf("captured request trace does not match access log")
	}
	actualTrace := evidence.TraceID
	if actualTrace == "" {
		actualTrace = stringValue(traceID)
	}
	if evidence.FirstPacketNo == 0 || evidence.LastPacketNo < evidence.FirstPacketNo || evidence.LastPacketNo > uint64(1<<63-1) {
		return fmt.Errorf("captured request has no valid packet range")
	}
	firstPacket := int64(evidence.FirstPacketNo)
	lastPacket := int64(evidence.LastPacketNo)
	return s.LinkRequest(ctx, RequestLink{
		ArtifactID: artifactID, RequestID: evidence.RequestID, TraceID: actualTrace,
		ApplicationID: applicationID, MatchStatus: "MATCHED", MatchBasis: "HTTP1_REQUEST_ID",
		Coverage: "CONNECTION", CandidateCount: 1, FirstPacketNo: &firstPacket, LastPacketNo: &lastPacket,
		ExpiresAt: artifact.ExpiresAt,
	})
}
