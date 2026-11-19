// format.go 九章备份文件格式（.jzbk）读写。
//
// 文件布局：
//
//	[8B magic "JZBK0001"]
//	[加密数据段：[4B 大端长度][密文块]...]   —— 明文为带 chunk 索引与备份绑定 ID 帧头的 gzip/tar 流，按 4MB 分块独立随机 nonce 加密
//	[manifest.json]                        —— 含主密钥绑定的 HMAC-SHA256 认证标签
//	[4B 大端 manifest 长度]
//
// 清单置于尾部，导出可单遍流式写入（无需预知数据段统计）。
package backups

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// 格式常量
const (
	// Magic 文件头标识（8字节）
	Magic = "JZBK0001"
	// chunkFrameMagic 加密块明文帧头（绑定 chunk 序号与备份标识，经 AES-256-GCM 联合认证）
	chunkFrameMagic = "JZCH0001"
	// manifestKeyDomain 清单认证密钥封装域分离前缀
	manifestKeyDomain = "JZMK0001:"
	// manifestMACDomain 清单 HMAC-SHA256 域分离前缀
	manifestMACDomain = "JZMF0001\x00"
	// MaxBackupFileSize 单文件上限 2GB
	MaxBackupFileSize = int64(2) << 30
	// 密文块长度上界（4MB 明文 + 帧头 + GCM nonce/tag 开销）
	maxChunkCipherLen = ChunkSize + 1024
	// manifest 长度上界（防御畸形文件）
	maxManifestLen = 4 << 20
)

// ErrBadFile 备份文件结构非法或已损坏。
var ErrBadFile = errors.New("invalid or corrupt backup file")

// ErrTooLarge 备份超过单文件大小上限。
var ErrTooLarge = errors.New("backup file exceeds 2GB limit")

// Writer 备份文件写入器（流式、加密、统计）。
type Writer struct {
	f                *os.File
	enc              *encryption.Service
	explicitBackupID string
	bindingID        string
	fileHash         hash.Hash // 全文件哈希（magic 起）
	segHash          hash.Hash // 加密数据段哈希
	plainHash        hash.Hash // 明文哈希
	plainSize        int64
	segSize          int64
	chunks           int64
	buf              []byte
	finished         bool
}

// CreateWriter 创建备份文件写入器并写入 magic（自动生成唯一块绑定 ID）。
func CreateWriter(path string, enc *encryption.Service) (*Writer, error) {
	return CreateWriterWithID(path, enc, "")
}

// CreateWriterWithID 创建绑定到指定 backupID 的备份文件写入器并写入 magic。
func CreateWriterWithID(path string, enc *encryption.Service, backupID string) (*Writer, error) {
	if enc == nil {
		return nil, ErrNoEncryption
	}
	bindingID := strings.TrimSpace(backupID)
	if bindingID == "" {
		bindingID = uuid.NewString()
	}
	if len(bindingID) > 256 {
		return nil, fmt.Errorf("backup binding id too long")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		f:                f,
		enc:              enc,
		explicitBackupID: strings.TrimSpace(backupID),
		bindingID:        bindingID,
		fileHash:         sha256.New(),
		segHash:          sha256.New(),
		plainHash:        sha256.New(),
		buf:              make([]byte, 0, ChunkSize),
	}
	if _, err := f.Write([]byte(Magic)); err != nil {
		_ = f.Close()
		return nil, err
	}
	w.fileHash.Write([]byte(Magic))
	return w, nil
}

// Write 写入明文数据（调用方写入 gzip 压缩 tar 流），内部按块加密。
func (w *Writer) Write(p []byte) (int, error) {
	if w.finished {
		return 0, fmt.Errorf("writer already finished")
	}
	w.plainHash.Write(p)
	w.plainSize += int64(len(p))
	total := 0
	for len(p) > 0 {
		n := ChunkSize - len(w.buf)
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		total += n
		if len(w.buf) == ChunkSize {
			if err := w.flushChunk(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// frameChunk 为密文块构造经 AES-256-GCM 联合认证的帧头：magic || chunkIdx || len(bindingID) || bindingID || payload。
func frameChunk(bindingID string, index int64, payload []byte) []byte {
	idBytes := []byte(bindingID)
	out := make([]byte, 8+8+2+len(idBytes)+len(payload))
	copy(out[:8], chunkFrameMagic)
	binary.BigEndian.PutUint64(out[8:16], uint64(index))
	binary.BigEndian.PutUint16(out[16:18], uint16(len(idBytes)))
	copy(out[18:18+len(idBytes)], idBytes)
	copy(out[18+len(idBytes):], payload)
	return out
}

func unframeChunk(framed []byte, expectedBindingID string, expectedIndex int64) ([]byte, error) {
	if len(framed) < 18 || !bytes.Equal(framed[:8], []byte(chunkFrameMagic)) {
		return nil, fmt.Errorf("%w: missing or invalid chunk auth frame", ErrBadFile)
	}
	gotIndex := binary.BigEndian.Uint64(framed[8:16])
	if gotIndex != uint64(expectedIndex) {
		return nil, fmt.Errorf("%w: chunk index mismatch (got %d, want %d)", ErrBadFile, gotIndex, expectedIndex)
	}
	idLen := int(binary.BigEndian.Uint16(framed[16:18]))
	if idLen == 0 || 18+idLen > len(framed) {
		return nil, fmt.Errorf("%w: malformed chunk binding id", ErrBadFile)
	}
	gotBindingID := string(framed[18 : 18+idLen])
	if gotBindingID != expectedBindingID {
		return nil, fmt.Errorf("%w: chunk backup binding mismatch", ErrBadFile)
	}
	return framed[18+idLen:], nil
}

// flushChunk 加密并写出一个数据块（将 chunk 索引和备份绑定 ID 纳入 GCM 认证）。
func (w *Writer) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	framed := frameChunk(w.bindingID, w.chunks, w.buf)
	encB64, err := w.enc.Encrypt(string(framed))
	if err != nil {
		return fmt.Errorf("encrypt chunk: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return fmt.Errorf("encode chunk: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
	out := io.MultiWriter(w.f, w.segHash, w.fileHash)
	if _, err := out.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := out.Write(raw); err != nil {
		return err
	}
	w.segSize += 4 + int64(len(raw))
	w.chunks++
	w.buf = w.buf[:0]
	if w.segSize > MaxBackupFileSize {
		return ErrTooLarge
	}
	return nil
}

func canonicalManifestPayload(m *Manifest) ([]byte, error) {
	cp := *m
	cp.CreatedAt = cp.CreatedAt.UTC()
	cp.AuthKey = ""
	cp.AuthMAC = ""
	return json.Marshal(&cp)
}

func signManifest(m *Manifest, enc *encryption.Service) error {
	if enc == nil {
		return ErrNoEncryption
	}
	if m.BackupID == "" {
		return fmt.Errorf("%w: missing backup id", ErrManifestInvalid)
	}
	m.CreatedAt = m.CreatedAt.UTC()
	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		return fmt.Errorf("generate manifest mac key: %w", err)
	}
	authKey, err := enc.Encrypt(manifestKeyDomain + m.BackupID + ":" + hex.EncodeToString(macKey))
	if err != nil {
		return fmt.Errorf("wrap manifest mac key: %w", err)
	}
	payload, err := canonicalManifestPayload(m)
	if err != nil {
		return fmt.Errorf("marshal canonical manifest: %w", err)
	}
	h := hmac.New(sha256.New, macKey)
	_, _ = h.Write([]byte(manifestMACDomain))
	_, _ = h.Write(payload)
	m.AuthKey = authKey
	m.AuthMAC = hex.EncodeToString(h.Sum(nil))
	return nil
}

func verifyManifestAuth(m *Manifest, enc *encryption.Service) error {
	if enc == nil {
		return ErrNoEncryption
	}
	if m.AuthKey == "" || m.AuthMAC == "" || m.Encryption.ChunkBindingID == "" {
		return fmt.Errorf("%w: manifest missing authentication tag", ErrManifestInvalid)
	}
	unwrapped, err := enc.Decrypt(m.AuthKey)
	if err != nil {
		return fmt.Errorf("%w: manifest auth key verification failed: %v", ErrManifestInvalid, err)
	}
	expectedPrefix := manifestKeyDomain + m.BackupID + ":"
	if !strings.HasPrefix(unwrapped, expectedPrefix) {
		return fmt.Errorf("%w: manifest auth key backup binding mismatch", ErrManifestInvalid)
	}
	macKey, err := hex.DecodeString(strings.TrimPrefix(unwrapped, expectedPrefix))
	if err != nil || len(macKey) != 32 {
		return fmt.Errorf("%w: malformed manifest mac key", ErrManifestInvalid)
	}
	gotMAC, err := hex.DecodeString(m.AuthMAC)
	if err != nil || len(gotMAC) != sha256.Size {
		return fmt.Errorf("%w: malformed manifest mac", ErrManifestInvalid)
	}
	payload, err := canonicalManifestPayload(m)
	if err != nil {
		return fmt.Errorf("%w: canonical manifest marshal: %v", ErrManifestInvalid, err)
	}
	h := hmac.New(sha256.New, macKey)
	_, _ = h.Write([]byte(manifestMACDomain))
	_, _ = h.Write(payload)
	if !hmac.Equal(gotMAC, h.Sum(nil)) {
		return fmt.Errorf("%w: manifest HMAC mismatch", ErrHashMismatch)
	}
	return nil
}

// Finish 收尾：刷新最后一块，补全清单统计并做 HMAC-SHA256 认证后写入尾部清单，返回全文件哈希与大小。
func (w *Writer) Finish(m *Manifest) (string, int64, error) {
	if w.finished {
		return "", 0, fmt.Errorf("writer already finished")
	}
	w.finished = true
	defer func() { _ = w.f.Close() }()
	if w.explicitBackupID != "" && m.BackupID != w.explicitBackupID {
		return "", 0, fmt.Errorf("%w: manifest backup_id %q does not match writer binding %q", ErrManifestInvalid, m.BackupID, w.explicitBackupID)
	}
	if err := w.flushChunk(); err != nil {
		return "", 0, err
	}
	m.Encryption = EncryptionMeta{
		Algorithm:      EncryptionAlgorithm,
		ChunkSize:      ChunkSize,
		ChunkCount:     w.chunks,
		ChunkBindingID: w.bindingID,
	}
	m.Data = DataMeta{
		SHA256Encrypted: hex.EncodeToString(w.segHash.Sum(nil)),
		SizeEncrypted:   w.segSize,
		SHA256Plain:     hex.EncodeToString(w.plainHash.Sum(nil)),
		SizePlain:       w.plainSize,
	}
	if err := signManifest(m, w.enc); err != nil {
		return "", 0, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return "", 0, err
	}
	if len(body) > maxManifestLen {
		return "", 0, fmt.Errorf("manifest too large")
	}
	out := io.MultiWriter(w.f, w.fileHash)
	if _, err := out.Write(body); err != nil {
		return "", 0, err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := out.Write(lenBuf[:]); err != nil {
		return "", 0, err
	}
	if err := w.f.Sync(); err != nil {
		return "", 0, err
	}
	st, err := w.f.Stat()
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(w.fileHash.Sum(nil)), st.Size(), nil
}

// Abort 放弃写入并关闭（不删除文件，由调用方清理）。
func (w *Writer) Abort() {
	w.finished = true
	_ = w.f.Close()
}

// Reader 备份文件读取器（解密明文字节流并校验加密段完整性与块序/绑定）。
type Reader struct {
	f           *os.File
	enc         *encryption.Service
	Manifest    *Manifest
	dataEnd     int64 // 加密数据段结束偏移（manifest 起始）
	off         int64
	buf         []byte
	segHash     hash.Hash
	chunksRead  int64
	eofVerified bool
}

// OpenReader 打开备份文件：校验 magic，读取、验证结构并认证尾部清单（含 HMAC-SHA256 与加密段长度）。
func OpenReader(path string, enc *encryption.Service) (*Reader, error) {
	if enc == nil {
		return nil, ErrNoEncryption
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	size := st.Size()
	if size < int64(len(Magic))+4 {
		_ = f.Close()
		return nil, ErrBadFile
	}
	magic := make([]byte, len(Magic))
	if _, err := f.ReadAt(magic, 0); err != nil || string(magic) != Magic {
		_ = f.Close()
		return nil, ErrBadFile
	}
	// 尾部 4 字节 = manifest 长度
	var lenBuf [4]byte
	if _, err := f.ReadAt(lenBuf[:], size-4); err != nil {
		_ = f.Close()
		return nil, ErrBadFile
	}
	mLen := int64(binary.BigEndian.Uint32(lenBuf[:]))
	if mLen <= 0 || mLen > maxManifestLen || size-4-mLen < int64(len(Magic)) {
		_ = f.Close()
		return nil, ErrBadFile
	}
	body := make([]byte, mLen)
	if _, err := f.ReadAt(body, size-4-mLen); err != nil {
		_ = f.Close()
		return nil, ErrBadFile
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: manifest parse: %v", ErrBadFile, err)
	}
	if err := m.Validate(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := verifyManifestAuth(&m, enc); err != nil {
		_ = f.Close()
		return nil, err
	}
	dataEnd := size - 4 - mLen
	actualSegSize := dataEnd - int64(len(Magic))
	if actualSegSize != m.Data.SizeEncrypted {
		_ = f.Close()
		return nil, fmt.Errorf("%w: encrypted segment size %d != manifest %d", ErrBadFile, actualSegSize, m.Data.SizeEncrypted)
	}
	if _, err := f.Seek(int64(len(Magic)), io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Reader{
		f:        f,
		enc:      enc,
		Manifest: &m,
		dataEnd:  dataEnd,
		off:      int64(len(Magic)),
		segHash:  sha256.New(),
	}, nil
}

// Read 解密数据段，校验每块索引与备份绑定并在到达段尾时验证 ChunkCount 与 SHA256Encrypted。
func (r *Reader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		if r.off >= r.dataEnd {
			if !r.eofVerified {
				if r.chunksRead != r.Manifest.Encryption.ChunkCount {
					return 0, fmt.Errorf("%w: chunk count %d != manifest %d", ErrBadFile, r.chunksRead, r.Manifest.Encryption.ChunkCount)
				}
				if got := hex.EncodeToString(r.segHash.Sum(nil)); got != r.Manifest.Data.SHA256Encrypted {
					return 0, fmt.Errorf("%w: encrypted segment sha256 mismatch", ErrHashMismatch)
				}
				r.eofVerified = true
			}
			return 0, io.EOF
		}
		var lenBuf [4]byte
		if _, err := io.ReadFull(r.f, lenBuf[:]); err != nil {
			return 0, fmt.Errorf("%w: chunk header: %v", ErrBadFile, err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > maxChunkCipherLen || r.off+4+int64(n) > r.dataEnd {
			return 0, fmt.Errorf("%w: bad chunk length", ErrBadFile)
		}
		raw := make([]byte, n)
		if _, err := io.ReadFull(r.f, raw); err != nil {
			return 0, fmt.Errorf("%w: chunk body: %v", ErrBadFile, err)
		}
		r.segHash.Write(lenBuf[:])
		r.segHash.Write(raw)
		r.off += 4 + int64(n)
		plain, err := r.enc.Decrypt(base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			return 0, fmt.Errorf("decrypt chunk: %w", err)
		}
		payload, err := unframeChunk([]byte(plain), r.Manifest.Encryption.ChunkBindingID, r.chunksRead)
		if err != nil {
			return 0, err
		}
		r.chunksRead++
		r.buf = payload
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Close 关闭读取器。
func (r *Reader) Close() error {
	return r.f.Close()
}

// FileSHA256 计算文件全量 SHA-256（流式）。
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// segmentNameRe 数据段条目名白名单（防 zip-slip）。
var segmentNameRe = regexp.MustCompile(`^tables/([a-z0-9_]+)\.jsonl$`)

// SegmentTableName 从 tar 条目名解析表名，非法条目返回空串。
func SegmentTableName(entryName string) string {
	m := segmentNameRe.FindStringSubmatch(entryName)
	if m == nil {
		return ""
	}
	return m[1]
}

// SegmentEntryName 生成表对应的 tar 条目名。
func SegmentEntryName(table string) string {
	return "tables/" + table + ".jsonl"
}
