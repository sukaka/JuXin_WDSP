// Package requestpcap 保存请求PCAP的元数据与关联状态，不保存报文正文或明文密钥。
package requestpcap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Artifact struct {
	ID                    uuid.UUID
	NodeID                string
	CapturePoint          string
	State                 string
	StorageTier           string
	CaptureStartedAt      time.Time
	CaptureEndedAt        time.Time
	PacketCount           int64
	DroppedCount          int64
	Truncated             bool
	PlaintextSizeBytes    int64
	CiphertextSizeBytes   int64
	PlaintextSHA256       string
	CiphertextSHA256      string
	ChunkSizeBytes        int
	ChunkCount            int64
	WrappedDEK            []byte `json:"-"`
	KeyID                 string
	PolicyVersion         string
	Manifest              json.RawMessage
	ExpiresAt             time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
	IntegrityStatus       string     `json:"integrity_status"`
	LastVerifiedAt        *time.Time `json:"last_verified_at,omitempty"`
	VerificationErrorCode string     `json:"verification_error_code,omitempty"`
}

type manifestProjection struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"format_version"`
	Segment       struct {
		ArtifactID    string    `json:"artifact_id"`
		NodeID        string    `json:"node_id"`
		CapturePoint  string    `json:"capture_point"`
		StartedAt     time.Time `json:"started_at"`
		PacketCount   int64     `json:"packet_count"`
		DroppedCount  int64     `json:"dropped_count"`
		Truncated     bool      `json:"truncated"`
		PolicyVersion string    `json:"policy_version,omitempty"`
	} `json:"segment"`
	EndedAt         time.Time `json:"ended_at"`
	SizePlain       int64     `json:"size_plain"`
	SizeEncrypted   int64     `json:"size_encrypted"`
	SHA256Plain     string    `json:"sha256_plain"`
	SHA256Encrypted string    `json:"sha256_encrypted"`
	Encryption      struct {
		Algorithm  string `json:"algorithm"`
		ChunkSize  int    `json:"chunk_size"`
		ChunkCount int64  `json:"chunk_count"`
	} `json:"encryption"`
}

func ValidateArtifact(artifact Artifact) error {
	if artifact.ID == uuid.Nil || artifact.NodeID == "" || len(artifact.NodeID) > 64 || artifact.CapturePoint == "" || len(artifact.CapturePoint) > 32 {
		return fmt.Errorf("invalid evidence identity or capture point")
	}
	// 注册入口只接收已在抓包侧封口的HOT分片；迁移和到期走显式状态转换。
	if artifact.State != "HOT" || artifact.StorageTier != "HOT" {
		return fmt.Errorf("new evidence must be sealed in the HOT tier")
	}
	if artifact.CaptureStartedAt.IsZero() || artifact.CaptureEndedAt.Before(artifact.CaptureStartedAt) || !artifact.ExpiresAt.After(artifact.CaptureEndedAt) {
		return fmt.Errorf("invalid evidence capture or expiry time")
	}
	if artifact.PacketCount < 0 || artifact.DroppedCount < 0 || artifact.PlaintextSizeBytes < 0 || artifact.CiphertextSizeBytes <= 28 {
		return fmt.Errorf("invalid evidence counters or size")
	}
	if !lowerHex64.MatchString(artifact.PlaintextSHA256) || !lowerHex64.MatchString(artifact.CiphertextSHA256) {
		return fmt.Errorf("invalid evidence SHA-256")
	}
	if artifact.ChunkSizeBytes <= 0 || artifact.ChunkSizeBytes > 16<<20 {
		return fmt.Errorf("invalid evidence chunk size")
	}
	wantChunks := int64(0)
	if artifact.PlaintextSizeBytes > 0 {
		wantChunks = (artifact.PlaintextSizeBytes + int64(artifact.ChunkSizeBytes) - 1) / int64(artifact.ChunkSizeBytes)
	}
	if artifact.ChunkCount != wantChunks {
		return fmt.Errorf("evidence chunk count does not match plaintext size")
	}
	if len(artifact.WrappedDEK) == 0 || len(artifact.WrappedDEK) > 4096 || artifact.KeyID == "" || len(artifact.KeyID) > 128 {
		return fmt.Errorf("invalid wrapped evidence key metadata")
	}
	if len(artifact.PolicyVersion) > 128 || len(artifact.Manifest) == 0 || len(artifact.Manifest) > 256<<10 {
		return fmt.Errorf("invalid evidence manifest size or policy version")
	}
	projection, err := decodeManifest(artifact.Manifest)
	if err != nil {
		return err
	}
	manifestID, err := uuid.Parse(projection.Segment.ArtifactID)
	if err != nil || manifestID != artifact.ID {
		return fmt.Errorf("manifest artifact id does not match record")
	}
	if projection.Format != "wdsp-encrypted-pcap" || projection.FormatVersion != 1 || projection.Encryption.Algorithm != "AES-256-GCM" {
		return fmt.Errorf("unsupported manifest format or encryption")
	}
	if projection.Segment.NodeID != artifact.NodeID || projection.Segment.CapturePoint != artifact.CapturePoint ||
		!projection.Segment.StartedAt.Equal(artifact.CaptureStartedAt) || !projection.EndedAt.Equal(artifact.CaptureEndedAt) ||
		projection.Segment.PacketCount != artifact.PacketCount || projection.Segment.DroppedCount != artifact.DroppedCount ||
		projection.Segment.Truncated != artifact.Truncated || projection.Segment.PolicyVersion != artifact.PolicyVersion ||
		projection.SizePlain != artifact.PlaintextSizeBytes || projection.SizeEncrypted != artifact.CiphertextSizeBytes ||
		projection.SHA256Plain != artifact.PlaintextSHA256 || projection.SHA256Encrypted != artifact.CiphertextSHA256 ||
		projection.Encryption.ChunkSize != artifact.ChunkSizeBytes || projection.Encryption.ChunkCount != artifact.ChunkCount {
		return fmt.Errorf("manifest fields do not match evidence record")
	}
	return nil
}

func decodeManifest(raw json.RawMessage) (manifestProjection, error) {
	var projection manifestProjection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return projection, fmt.Errorf("invalid evidence manifest: %w", err)
	}
	if decoder.More() {
		return projection, fmt.Errorf("evidence manifest contains trailing content")
	}
	return projection, nil
}

type RequestLink struct {
	ID             uuid.UUID
	ArtifactID     uuid.UUID
	RequestID      string
	TraceID        string
	ApplicationID  *uuid.UUID
	MatchStatus    string
	MatchBasis     string
	Coverage       string
	CandidateCount int
	FirstPacketNo  *int64
	LastPacketNo   *int64
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

func ValidateRequestLink(link RequestLink) error {
	if link.ArtifactID == uuid.Nil || link.RequestID == "" || len(link.RequestID) > 64 {
		return fmt.Errorf("invalid request evidence identity")
	}
	if link.TraceID != "" && !validTraceID(link.TraceID) {
		return fmt.Errorf("invalid request evidence trace")
	}
	switch link.MatchStatus {
	case "PENDING", "UNMATCHED", "FAILED", "AMBIGUOUS", "MATCHED":
	default:
		return fmt.Errorf("invalid request evidence match status")
	}
	if link.MatchBasis == "" || len(link.MatchBasis) > 64 || link.CandidateCount < 0 || link.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid request evidence basis or candidates")
	}
	if link.Coverage != "REQUEST" && link.Coverage != "CONNECTION" && link.Coverage != "UNKNOWN" {
		return fmt.Errorf("invalid request evidence coverage")
	}
	if (link.FirstPacketNo == nil) != (link.LastPacketNo == nil) ||
		(link.FirstPacketNo != nil && (*link.FirstPacketNo <= 0 || *link.LastPacketNo < *link.FirstPacketNo)) {
		return fmt.Errorf("invalid request packet range")
	}
	if link.MatchStatus == "MATCHED" {
		if link.CandidateCount != 1 || (link.Coverage != "REQUEST" && link.Coverage != "CONNECTION") {
			return fmt.Errorf("matched evidence must be unique and have explicit coverage")
		}
		if (link.Coverage == "REQUEST" || link.Coverage == "CONNECTION") && link.FirstPacketNo == nil {
			return fmt.Errorf("request/connection-scoped evidence requires an exact packet range")
		}
		switch link.MatchBasis {
		case "SOCKET_COOKIE", "CONNECTION_EPOCH", "HTTP1_SEQUENCE", "H2_STREAM", "AGENT_FLOW_ID", "HTTP1_REQUEST_ID":
		default:
			return fmt.Errorf("matched evidence requires a direct connection or stream correlation basis")
		}
	}
	if link.MatchStatus == "AMBIGUOUS" && link.CandidateCount < 2 {
		return fmt.Errorf("ambiguous evidence requires at least two candidates")
	}
	return nil
}

func validTraceID(value string) bool {
	if len(value) != 32 || value == "00000000000000000000000000000000" {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
