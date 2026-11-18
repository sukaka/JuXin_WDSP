package requestpcap

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ArtifactFromManifest 将抓包侧已封口清单转换为HOT证据记录；密钥明文和PCAP路径不在输入中。
func ArtifactFromManifest(raw json.RawMessage, wrappedDEK []byte, keyID string, expiresAt time.Time) (Artifact, error) {
	projection, err := decodeManifest(raw)
	if err != nil {
		return Artifact{}, err
	}
	artifactID, err := uuid.Parse(projection.Segment.ArtifactID)
	if err != nil {
		return Artifact{}, fmt.Errorf("invalid manifest artifact id: %w", err)
	}
	artifact := Artifact{
		ID: artifactID, NodeID: projection.Segment.NodeID, CapturePoint: projection.Segment.CapturePoint,
		State: "HOT", StorageTier: "HOT", CaptureStartedAt: projection.Segment.StartedAt,
		CaptureEndedAt: projection.EndedAt, PacketCount: projection.Segment.PacketCount,
		DroppedCount: projection.Segment.DroppedCount, Truncated: projection.Segment.Truncated,
		PlaintextSizeBytes: projection.SizePlain, CiphertextSizeBytes: projection.SizeEncrypted,
		PlaintextSHA256: projection.SHA256Plain, CiphertextSHA256: projection.SHA256Encrypted,
		ChunkSizeBytes: projection.Encryption.ChunkSize, ChunkCount: projection.Encryption.ChunkCount,
		WrappedDEK: append([]byte(nil), wrappedDEK...), KeyID: keyID, PolicyVersion: projection.Segment.PolicyVersion,
		Manifest: append(json.RawMessage(nil), raw...), ExpiresAt: expiresAt,
	}
	if err := ValidateArtifact(artifact); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}
