package backups

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

func testEnc(t *testing.T) *encryption.Service {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	svc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// TestFormatRoundtrip 加密写入 → 读回解密，明文一致，清单一致，文件哈希一致。
func TestFormatRoundtrip(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jzbk")

	// 9MB+ 数据 → 多块
	data := make([]byte, 9<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	w, err := CreateWriter(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Format:        FormatName,
		FormatVersion: FormatVersion,
		BackupID:      uuid.NewString(),
		BackupType:    TypeFull,
		CreatedAt:     time.Now().UTC(),
		SchemaVersion: 11,
		AppComponent:  "test",
		Compression:   "gzip",
		ArchiveFormat: "tar",
		Tables:        []TableManifest{{Name: "users", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 0}},
		TotalRows:     0,
	}
	fileHash, _, err := w.Finish(m)
	if err != nil {
		t.Fatal(err)
	}
	// 9MB / 4MB = 3 块
	if m.Encryption.ChunkCount != 3 {
		t.Errorf("chunk count = %d, want 3", m.Encryption.ChunkCount)
	}
	// 全文件哈希一致
	recomputed, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != fileHash {
		t.Error("file hash mismatch")
	}
	// 读回解密
	rd, err := OpenReader(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	got, err := io.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("plaintext roundtrip mismatch")
	}
	if rd.Manifest.BackupID != m.BackupID || rd.Manifest.SchemaVersion != 11 {
		t.Error("manifest roundtrip mismatch")
	}
	// 明文哈希一致
	sum := sha256.Sum256(data)
	if rd.Manifest.Data.SHA256Plain != hex.EncodeToString(sum[:]) {
		t.Error("plain hash mismatch")
	}
}

// TestWrongKeyFails 错误主密钥解密必须失败。
func TestWrongKeyFails(t *testing.T) {
	enc1 := testEnc(t)
	enc2 := testEnc(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jzbk")
	w, err := CreateWriter(path, enc1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("secret data")); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeConfigOnly, CreatedAt: time.Now().UTC(), Compression: "gzip", ArchiveFormat: "tar",
		Tables: []TableManifest{{Name: "users", Group: GroupDatabase, Columns: []string{"id"}}},
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	rd, err := OpenReader(path, enc2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	if _, err := io.ReadAll(rd); err == nil {
		t.Error("decrypt with wrong key must fail")
	}
}

// TestOpenReaderRejectsBadFile 畸形文件拒绝。
func TestOpenReaderRejectsBadFile(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	// 坏 magic
	p1 := filepath.Join(dir, "bad.jzbk")
	if err := os.WriteFile(p1, []byte("XXXXXXXX...."), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReader(p1, enc); err == nil {
		t.Error("bad magic should be rejected")
	}
	// 截断
	p2 := filepath.Join(dir, "short.jzbk")
	if err := os.WriteFile(p2, []byte("JZ"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReader(p2, enc); err == nil {
		t.Error("truncated file should be rejected")
	}
}

// buildTestBackup 不依赖 DB 构造一个真实备份文件（模拟导出产物）。
// tables: 表名 → JSONL 行。返回文件路径与清单。
func buildTestBackup(t *testing.T, enc *encryption.Service, dir string, tables map[string][]string) (string, *Manifest) {
	t.Helper()
	path := filepath.Join(dir, "backup-"+uuid.NewString()+".jzbk")
	w, err := CreateWriter(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	m := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeFull, CreatedAt: time.Now().UTC(), SchemaVersion: 11,
		AppComponent: "test", Compression: "gzip", ArchiveFormat: "tar",
	}
	// 固定顺序保证可重复
	names := []string{"roles", "users"}
	for _, name := range names {
		lines, ok := tables[name]
		if !ok {
			continue
		}
		var buf bytes.Buffer
		h := sha256.New()
		var rowCount int64
		for _, ln := range lines {
			buf.WriteString(ln)
			buf.WriteByte('\n')
			h.Write([]byte(ln))
			h.Write([]byte{'\n'})
			rowCount++
		}
		body := buf.Bytes()
		if err := tw.WriteHeader(&tar.Header{Name: SegmentEntryName(name), Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
		tm := TableManifest{
			Name: name, Group: GroupDatabase, Columns: []string{"id"},
			RowCount: rowCount, ByteCount: int64(len(body)),
		}
		if rowCount > 0 {
			tm.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		m.Tables = append(m.Tables, tm)
		m.TotalRows += rowCount
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	return path, m
}

// TestWalkSegmentsAndExtract 解密 → 解压 → 逐段校验 → 解包。
func TestWalkSegmentsAndExtract(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	ex := &Exporter{enc: enc, dataDir: dir}
	path, m := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"r1"}`, `{"id":"r2"}`},
		"users": {`{"id":"u1"}`},
	})

	seen := map[string]int64{}
	err := ex.WalkSegments(path, func(mm *Manifest) error {
		if mm.BackupID != m.BackupID {
			t.Error("manifest id mismatch")
		}
		return nil
	}, func(table string, r io.Reader) error {
		rows, _, _, err := statSegment(r)
		seen[table] = rows
		return err
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if seen["roles"] != 2 || seen["users"] != 1 {
		t.Errorf("row counts = %v", seen)
	}

	// 解包
	dest := t.TempDir()
	em, err := ex.Extract(path, dest)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if em.TotalRows != 3 {
		t.Errorf("total rows = %d", em.TotalRows)
	}
	body, err := os.ReadFile(filepath.Join(dest, "roles.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(body), "\n") != 2 {
		t.Error("extracted roles content mismatch")
	}
}

// TestWalkDetectsTamperedCiphertext 密文被篡改 → 解密失败。
func TestWalkDetectsTamperedCiphertext(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	ex := &Exporter{enc: enc, dataDir: dir}
	path, _ := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"r1"}`},
		"users": {`{"id":"u1"}`},
	})
	// 篡改数据段中部一字节
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(Magic)+8] ^= 0xFF
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	err = ex.WalkSegments(path, func(*Manifest) error { return nil }, func(_ string, r io.Reader) error {
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err == nil {
		t.Error("tampered ciphertext must be detected")
	}
}

// TestWalkDetectsManifestTamper 清单行数被改 → 重算比对失败。
func TestWalkDetectsManifestTamper(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	ex := &Exporter{enc: enc, dataDir: dir}
	path, _ := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"r1"}`},
		"users": {`{"id":"u1"}`},
	})
	// 读取并篡改尾部清单（roles 行数 1 → 99，同步改 total）
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mLen := int64(binary.BigEndian.Uint32(raw[len(raw)-4:]))
	var m Manifest
	if err := json.Unmarshal(raw[len(raw)-4-int(mLen):len(raw)-4], &m); err != nil {
		t.Fatal(err)
	}
	m.Tables[0].RowCount = 99
	m.TotalRows = 100
	body, _ := json.Marshal(&m)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	out := append(raw[:len(raw)-4-int(mLen)], body...)
	out = append(out, lenBuf[:]...)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
	err = ex.WalkSegments(path, func(*Manifest) error { return nil }, func(table string, r io.Reader) error {
		rows, _, _, err := statSegment(r)
		if err != nil {
			return err
		}
		// 模拟 Verify 的重算比对
		tm := m.Table(table)
		if tm != nil && rows != tm.RowCount {
			return os.ErrInvalid
		}
		return nil
	})
	if err == nil {
		t.Error("tampered manifest row count must be detected")
	}
}

// TestWalkRejectsIllegalEntry 非表白名单条目（zip-slip）拒绝。
func TestWalkRejectsIllegalEntry(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "evil.jzbk")
	w, err := CreateWriter(path, enc)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	body := []byte("x\n")
	if err := tw.WriteHeader(&tar.Header{Name: "../evil.jsonl", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeFull, CreatedAt: time.Now().UTC(), Compression: "gzip", ArchiveFormat: "tar",
		Tables: []TableManifest{{Name: "users", Group: GroupDatabase, Columns: []string{"id"}}},
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	ex := &Exporter{enc: enc, dataDir: dir}
	err = ex.WalkSegments(path, func(*Manifest) error { return nil }, func(_ string, r io.Reader) error {
		_, _ = io.Copy(io.Discard, r)
		return nil
	})
	if err == nil {
		t.Error("illegal tar entry must be rejected")
	}
}

// TestStatSegment 行/字节/哈希统计（含末行无换行）。
func TestStatSegment(t *testing.T) {
	rows, bytesN, sum, err := statSegment(strings.NewReader("a\nb\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 || bytesN != 4 || sum == "" {
		t.Errorf("stat = %d/%d/%q", rows, bytesN, sum)
	}
	rows, _, _, err = statSegment(strings.NewReader("a\nb"))
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("trailing-no-newline rows = %d, want 2", rows)
	}
	rows, _, sum, err = statSegment(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 || sum != "" {
		t.Errorf("empty rows = %d sum = %q", rows, sum)
	}
}

// TestSegmentNameSafety 条目名白名单。
func TestSegmentNameSafety(t *testing.T) {
	if SegmentTableName("tables/users.jsonl") != "users" {
		t.Error("valid entry rejected")
	}
	for _, bad := range []string{"../x", "tables/../x.jsonl", "tables/a/b.jsonl", "x.jsonl", "tables/users.jsonl/x", "tables/Users.jsonl"} {
		if SegmentTableName(bad) != "" {
			t.Errorf("illegal entry accepted: %s", bad)
		}
	}
}
