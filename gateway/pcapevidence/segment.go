// Package pcapevidence 提供请求审计PCAP的流式加密分片、受控Linux抓包与真实请求关联，不包含重放能力。
package pcapevidence

import (
	"encoding/hex"
	"fmt"
	"time"
)

const (
	FormatName          = "wdsp-encrypted-pcap"
	FormatVersion       = 1
	EncryptionAlgorithm = "AES-256-GCM"
	DefaultChunkSize    = 1 << 20
	MaxChunkSize        = 16 << 20
	fileMagic           = "WPCAP01\n"
	fileHeaderSize      = 28
	frameHeaderSize     = 28
)

// Segment 是抓包侧事实。密钥、原始报文和内部路径不得进入该结构。
type Segment struct {
	ArtifactID    ArtifactID `json:"artifact_id"`
	NodeID        string     `json:"node_id"`
	CapturePoint  string     `json:"capture_point"`
	StartedAt     time.Time  `json:"started_at"`
	PacketCount   uint64     `json:"packet_count"`
	DroppedCount  uint64     `json:"dropped_count"`
	Truncated     bool       `json:"truncated"`
	PolicyVersion string     `json:"policy_version,omitempty"`
}

type EncryptionMeta struct {
	Algorithm  string `json:"algorithm"`
	ChunkSize  int    `json:"chunk_size"`
	ChunkCount uint64 `json:"chunk_count"`
}

type Manifest struct {
	Format          string         `json:"format"`
	FormatVersion   int            `json:"format_version"`
	Segment         Segment        `json:"segment"`
	EndedAt         time.Time      `json:"ended_at"`
	SizePlain       int64          `json:"size_plain"`
	SizeEncrypted   int64          `json:"size_encrypted"`
	SHA256Plain     string         `json:"sha256_plain"`
	SHA256Encrypted string         `json:"sha256_encrypted"`
	Encryption      EncryptionMeta `json:"encryption"`
}

func (m Manifest) Validate() error {
	if m.Format != FormatName || m.FormatVersion != FormatVersion {
		return fmt.Errorf("unsupported evidence format")
	}
	if m.Segment.ArtifactID.IsZero() || m.Segment.StartedAt.IsZero() || m.EndedAt.Before(m.Segment.StartedAt) {
		return fmt.Errorf("invalid evidence identity or time range")
	}
	if m.SizePlain < 0 || m.SizeEncrypted < fileHeaderSize || m.EndedAt.IsZero() {
		return fmt.Errorf("invalid evidence size or seal time")
	}
	if m.Encryption.Algorithm != EncryptionAlgorithm || m.Encryption.ChunkSize <= 0 || m.Encryption.ChunkSize > MaxChunkSize {
		return fmt.Errorf("unsupported evidence encryption parameters")
	}
	if m.SizePlain == 0 && m.Encryption.ChunkCount != 0 {
		return fmt.Errorf("empty evidence cannot contain encrypted chunks")
	}
	if m.SizePlain > 0 {
		want := (uint64(m.SizePlain) + uint64(m.Encryption.ChunkSize) - 1) / uint64(m.Encryption.ChunkSize)
		if want != m.Encryption.ChunkCount {
			return fmt.Errorf("evidence chunk count does not match plaintext size")
		}
	}
	if err := validateHash(m.SHA256Plain); err != nil {
		return err
	}
	return validateHash(m.SHA256Encrypted)
}

func validateHash(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("invalid SHA-256 digest")
	}
	return nil
}
