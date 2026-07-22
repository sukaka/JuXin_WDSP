// format.go 九章备份文件格式（.jzbk）读写。
//
// 文件布局：
//
//	[8B magic "JZBK0001"]
//	[加密数据段：[4B 大端长度][密文块]...]   —— 明文为 gzip 压缩的 tar 流，按 4MB 分块独立随机 nonce 加密
//	[manifest.json]
//	[4B 大端 manifest 长度]
//
// 清单置于尾部，导出可单遍流式写入（无需预知数据段统计）。
package backups

import (
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

	"github.com/jiuzhang-waf/server/internal/encryption"
)

// 格式常量
const (
	// Magic 文件头标识（8字节）
	Magic = "JZBK0001"
	// MaxBackupFileSize 单文件上限 2GB
	MaxBackupFileSize = int64(2) << 30
	// 密文块长度上界（4MB 明文 + GCM nonce/tag 开销）
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
	f         *os.File
	enc       *encryption.Service
	fileHash  hash.Hash // 全文件哈希（magic 起）
	segHash   hash.Hash // 加密数据段哈希
	plainHash hash.Hash // 明文哈希
	plainSize int64
	segSize   int64
	chunks    int64
	buf       []byte
	finished  bool
}

// CreateWriter 创建备份文件写入器并写入 magic。
func CreateWriter(path string, enc *encryption.Service) (*Writer, error) {
	if enc == nil {
		return nil, ErrNoEncryption
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		f:         f,
		enc:       enc,
		fileHash:  sha256.New(),
		segHash:   sha256.New(),
		plainHash: sha256.New(),
		buf:       make([]byte, 0, ChunkSize),
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

// flushChunk 加密并写出一个数据块。
func (w *Writer) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	encB64, err := w.enc.Encrypt(string(w.buf))
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

// Finish 收尾：刷新最后一块，补全清单统计并写入尾部清单，返回全文件哈希与大小。
func (w *Writer) Finish(m *Manifest) (string, int64, error) {
	if w.finished {
		return "", 0, fmt.Errorf("writer already finished")
	}
	w.finished = true
	defer func() { _ = w.f.Close() }()
	if err := w.flushChunk(); err != nil {
		return "", 0, err
	}
	m.Encryption = EncryptionMeta{
		Algorithm:  EncryptionAlgorithm,
		ChunkSize:  ChunkSize,
		ChunkCount: w.chunks,
	}
	m.Data = DataMeta{
		SHA256Encrypted: hex.EncodeToString(w.segHash.Sum(nil)),
		SizeEncrypted:   w.segSize,
		SHA256Plain:     hex.EncodeToString(w.plainHash.Sum(nil)),
		SizePlain:       w.plainSize,
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

// Reader 备份文件读取器（解密明文字节流）。
type Reader struct {
	f        *os.File
	enc      *encryption.Service
	Manifest *Manifest
	dataEnd  int64 // 加密数据段结束偏移（manifest 起始）
	off      int64
	buf      []byte
}

// OpenReader 打开备份文件：校验 magic，读取并校验尾部清单（不解密数据段）。
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
	if _, err := f.Seek(int64(len(Magic)), io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Reader{
		f: f, enc: enc, Manifest: &m,
		dataEnd: size - 4 - mLen,
		off:     int64(len(Magic)),
	}, nil
}

// Read 解密数据段，产出明文（gzip 压缩 tar 流）。
func (r *Reader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		if r.off >= r.dataEnd {
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
		r.off += 4 + int64(n)
		plain, err := r.enc.Decrypt(base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			return 0, fmt.Errorf("decrypt chunk: %w", err)
		}
		r.buf = []byte(plain)
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
