// manifest.go 备份清单：元数据、表统计与哈希，随备份文件尾部存储。
package backups

import (
	"fmt"
	"time"
)

// 备份文件格式标识
const (
	// FormatName 自定义备份格式名
	FormatName = "jzbk"
	// FormatVersion 格式版本（结构不兼容时递增）
	FormatVersion = 1
)

// 加密参数
const (
	// EncryptionAlgorithm 数据段加密算法（与 encryption.Service 一致）
	EncryptionAlgorithm = "AES-256-GCM"
	// ChunkSize 分块加密块大小（4MB，控制内存占用）
	ChunkSize = 4 << 20
)

// EncryptionMeta 清单中的加密信息（nonce 由每块独立随机生成并随密文存储）。
type EncryptionMeta struct {
	Algorithm  string `json:"algorithm"`
	ChunkSize  int    `json:"chunk_size"`
	ChunkCount int64  `json:"chunk_count"`
}

// DataMeta 清单中的数据段统计与哈希。
type DataMeta struct {
	// SHA256Encrypted 加密数据段（全部密文块）的 SHA-256
	SHA256Encrypted string `json:"sha256_encrypted"`
	// SizeEncrypted 加密数据段字节数
	SizeEncrypted int64 `json:"size_encrypted"`
	// SHA256Plain 明文（gzip 压缩 tar 流）的 SHA-256
	SHA256Plain string `json:"sha256_plain"`
	// SizePlain 明文字节数
	SizePlain int64 `json:"size_plain"`
}

// TableManifest 单表统计（列名用于恢复时显式列清单）。
type TableManifest struct {
	Name      string   `json:"name"`
	Group     string   `json:"group"`
	Columns   []string `json:"columns"`
	RowCount  int64    `json:"row_count"`
	ByteCount int64    `json:"byte_count"`
	SHA256    string   `json:"sha256"` // 明文 JSONL 段哈希
	// Archive=true 表示归档段（审计表），仅导出查阅，不参与恢复
	Archive bool `json:"archive,omitempty"`
	// Truncated=true 表示导出被 RecentLimit 截断
	Truncated bool `json:"truncated,omitempty"`
}

// Manifest 备份清单（文件尾部的 manifest.json 内容）。
type Manifest struct {
	Format        string          `json:"format"`
	FormatVersion int             `json:"format_version"`
	BackupID      string          `json:"backup_id"`
	BackupType    string          `json:"backup_type"`
	CreatedAt     time.Time       `json:"created_at"`
	CreatedBy     string          `json:"created_by"`
	SchemaVersion int             `json:"schema_version"` // 备份时 schema_migrations 最大版本
	AppComponent  string          `json:"app_component"`
	Compression   string          `json:"compression"`    // gzip
	ArchiveFormat string          `json:"archive_format"` // tar
	Encryption    EncryptionMeta  `json:"encryption"`
	Data          DataMeta        `json:"data"`
	Tables        []TableManifest `json:"tables"`
	TotalRows     int64           `json:"total_rows"`
}

// Validate 校验清单完整性与自洽性（不含数据哈希比对）。
func (m *Manifest) Validate() error {
	if m.Format != FormatName {
		return fmt.Errorf("%w: unknown format %q", ErrManifestInvalid, m.Format)
	}
	if m.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: unsupported format version %d", ErrManifestInvalid, m.FormatVersion)
	}
	if m.BackupID == "" || !ValidType(m.BackupType) {
		return fmt.Errorf("%w: missing backup id or bad type", ErrManifestInvalid)
	}
	if m.Encryption.Algorithm != EncryptionAlgorithm || m.Encryption.ChunkSize != ChunkSize {
		return fmt.Errorf("%w: unsupported encryption parameters", ErrManifestInvalid)
	}
	if m.Compression != "gzip" || m.ArchiveFormat != "tar" {
		return fmt.Errorf("%w: unsupported compression/archive", ErrManifestInvalid)
	}
	if m.Data.SHA256Encrypted == "" || m.Data.SHA256Plain == "" {
		return fmt.Errorf("%w: missing data hashes", ErrManifestInvalid)
	}
	if len(m.Tables) == 0 {
		return fmt.Errorf("%w: no tables", ErrManifestInvalid)
	}
	var total int64
	for _, t := range m.Tables {
		if !IsBackupTable(t.Name) {
			return fmt.Errorf("%w: unknown table %q", ErrManifestInvalid, t.Name)
		}
		if len(t.Columns) == 0 {
			return fmt.Errorf("%w: table %s has no columns", ErrManifestInvalid, t.Name)
		}
		if t.RowCount < 0 || t.ByteCount < 0 {
			return fmt.Errorf("%w: table %s negative counters", ErrManifestInvalid, t.Name)
		}
		if t.RowCount > 0 && t.SHA256 == "" {
			return fmt.Errorf("%w: table %s missing segment hash", ErrManifestInvalid, t.Name)
		}
		total += t.RowCount
	}
	if total != m.TotalRows {
		return fmt.Errorf("%w: total_rows %d != sum %d", ErrManifestInvalid, m.TotalRows, total)
	}
	return nil
}

// Table 按名取表清单。
func (m *Manifest) Table(name string) *TableManifest {
	for i := range m.Tables {
		if m.Tables[i].Name == name {
			return &m.Tables[i]
		}
	}
	return nil
}

// CheckSchemaCompat 版本兼容性：备份的 schema 版本高于当前库时拒绝恢复。
func CheckSchemaCompat(backupVersion, currentVersion int) error {
	if backupVersion > currentVersion {
		return fmt.Errorf("%w: backup schema v%d > current v%d", ErrIncompatible, backupVersion, currentVersion)
	}
	return nil
}
