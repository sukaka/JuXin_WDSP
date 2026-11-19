package backups

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if err == nil {
		defer func() { _ = rd.Close() }()
		if _, rerr := io.ReadAll(rd); rerr == nil {
			t.Error("decrypt with wrong key must fail")
		}
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

// TestWorkerAlertFnAssignedAndFiresOnFailure 回归（H-06）：NewWorker 必须绑定 alertFn 并在任务失败时触发告警。
func TestWorkerAlertFnAssignedAndFiresOnFailure(t *testing.T) {
	var fired []string
	alertFn := func(alertType, component, title, message string) {
		fired = append(fired, alertType+"|"+component+"|"+title)
	}
	w := NewWorker(nil, NewExporter(nil, nil, t.TempDir()), alertFn)
	if w.alertFn == nil {
		t.Fatal("NewWorker did not assign alertFn")
	}
	w.process(context.Background(), &Job{ID: uuid.New(), BackupType: TypeFull})
	if len(fired) != 1 || !strings.HasPrefix(fired[0], "BACKUP_FAILED|backup|") {
		t.Fatalf("expected BACKUP_FAILED alert, got %v", fired)
	}
}

// TestManifestHMACRejectsTamperAndStrip 回归（H-06）：未授权修改清单任意字段或剥离认证标签均在 OpenReader 即拒绝。
func TestManifestHMACRejectsTamperAndStrip(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	path, _ := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"r1"}`},
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mLen := int(binary.BigEndian.Uint32(raw[len(raw)-4:]))
	var m Manifest
	if err := json.Unmarshal(raw[len(raw)-4-mLen:len(raw)-4], &m); err != nil {
		t.Fatal(err)
	}

	writeModified := func(mod Manifest, name string) string {
		body, err := json.Marshal(&mod)
		if err != nil {
			t.Fatal(err)
		}
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(body)))
		out := append(append([]byte(nil), raw[:len(raw)-4-mLen]...), body...)
		out = append(out, lb[:]...)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 1. 篡改 SchemaVersion
	tampered := m
	tampered.SchemaVersion = 999
	if _, err := OpenReader(writeModified(tampered, "tamper-schema.jzbk"), enc); err == nil {
		t.Fatal("tampered manifest schema_version was accepted")
	}

	// 2. 剥离认证标签（降级攻击）
	stripped := m
	stripped.AuthKey = ""
	stripped.AuthMAC = ""
	if _, err := OpenReader(writeModified(stripped, "strip-auth.jzbk"), enc); err == nil {
		t.Fatal("stripped manifest auth was accepted")
	}
}

// TestChunkReorderingAndTransplantRejected 回归（H-06）：块乱序与跨备份块移植必须被 GCM 认证帧拦截。
func TestChunkReorderingAndTransplantRejected(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()

	writeTwoChunks := func(name string, backupID string, fill byte) (string, *Manifest) {
		p := filepath.Join(dir, name)
		w, err := CreateWriterWithID(p, enc, backupID)
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{fill}, ChunkSize+1024)
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
		m := &Manifest{
			Format: FormatName, FormatVersion: FormatVersion, BackupID: backupID,
			BackupType: TypeFull, CreatedAt: time.Now().UTC(), SchemaVersion: 11,
			AppComponent: "test", Compression: "gzip", ArchiveFormat: "tar",
			Tables: []TableManifest{{Name: "users", Group: GroupDatabase, Columns: []string{"id"}}},
		}
		if _, _, err := w.Finish(m); err != nil {
			t.Fatal(err)
		}
		return p, m
	}

	readChunks := func(path string) [][]byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		mLen := int(binary.BigEndian.Uint32(raw[len(raw)-4:]))
		seg := raw[len(Magic) : len(raw)-4-mLen]
		var chunks [][]byte
		for len(seg) > 0 {
			n := binary.BigEndian.Uint32(seg[:4])
			chunks = append(chunks, append([]byte(nil), seg[:4+n]...))
			seg = seg[4+n:]
		}
		return chunks
	}

	writeWithRebuiltManifest := func(outName string, m Manifest, chunks [][]byte) string {
		var seg bytes.Buffer
		for _, c := range chunks {
			seg.Write(c)
		}
		segBytes := seg.Bytes()
		segSum := sha256.Sum256(segBytes)
		m.Data.SHA256Encrypted = hex.EncodeToString(segSum[:])
		m.Data.SizeEncrypted = int64(len(segBytes))
		m.Encryption.ChunkCount = int64(len(chunks))
		// 即使攻击者拥有同密钥或绕过外层清单校验，内层 chunk 帧仍应拦截乱序与移植
		if err := signManifest(&m, enc); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(&m)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(body)))
		var fileBuf bytes.Buffer
		fileBuf.WriteString(Magic)
		fileBuf.Write(segBytes)
		fileBuf.Write(body)
		fileBuf.Write(lb[:])
		outPath := filepath.Join(dir, outName)
		if err := os.WriteFile(outPath, fileBuf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return outPath
	}

	pA, mA := writeTwoChunks("a.jzbk", uuid.NewString(), 'A')
	pB, _ := writeTwoChunks("b.jzbk", uuid.NewString(), 'B')
	chunksA := readChunks(pA)
	chunksB := readChunks(pB)
	if len(chunksA) != 2 || len(chunksB) != 2 {
		t.Fatalf("expected 2 chunks each, got %d/%d", len(chunksA), len(chunksB))
	}

	// 1. 交换 chunk 0 与 chunk 1（重排攻击）
	reorderedPath := writeWithRebuiltManifest("reordered.jzbk", *mA, [][]byte{chunksA[1], chunksA[0]})
	rd, err := OpenReader(reorderedPath, enc)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := io.ReadAll(rd)
	_ = rd.Close()
	if rerr == nil {
		t.Fatal("reordered chunks must be rejected")
	}

	// 2. 将备份 B 的 chunk 0 移植到备份 A（跨备份移植攻击）
	transplantedPath := writeWithRebuiltManifest("transplanted.jzbk", *mA, [][]byte{chunksB[0], chunksA[1]})
	rd2, err := OpenReader(transplantedPath, enc)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr2 := io.ReadAll(rd2)
	_ = rd2.Close()
	if rerr2 == nil {
		t.Fatal("transplanted chunk from another backup must be rejected")
	}
}

// TestWalkSegmentsRejectsDuplicateTableAndEnforcesDecompressedCap 回归（H-06）：
// 拒绝重复表条目并强制执行解压后字节硬上限（防 gzip 炸弹）。
func TestWalkSegmentsRejectsDuplicateTableAndEnforcesDecompressedCap(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()

	// 1. 重复表条目
	dupPath := filepath.Join(dir, "dup.jzbk")
	w, err := CreateWriter(dupPath, enc)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	row := []byte(`{"id":"1"}` + "\n")
	for i := 0; i < 2; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: SegmentEntryName("roles"), Mode: 0o600, Size: int64(len(row))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(row); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gzw.Close()
	sum := sha256.Sum256(row)
	m := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeFull, CreatedAt: time.Now().UTC(), SchemaVersion: 11,
		AppComponent: "test", Compression: "gzip", ArchiveFormat: "tar",
		Tables:    []TableManifest{{Name: "roles", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: int64(len(row)), SHA256: hex.EncodeToString(sum[:])}},
		TotalRows: 1,
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	ex := &Exporter{enc: enc, dataDir: dir}
	err = ex.WalkSegments(dupPath, func(*Manifest) error { return nil }, func(_ string, r io.Reader) error {
		_, err := io.Copy(io.Discard, r)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate table") {
		t.Fatalf("duplicate table entry should be rejected, got %v", err)
	}

	// 2. 解压字节硬上限（模拟高压缩比 gzip 炸弹）
	bombPath, _ := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"` + strings.Repeat("A", 4096) + `"}`},
	})
	cappedEx := &Exporter{enc: enc, dataDir: dir, maxDecompressedBytes: 1024}
	err = cappedEx.WalkSegments(bombPath, func(*Manifest) error { return nil }, func(_ string, r io.Reader) error {
		_, err := io.Copy(io.Discard, r)
		return err
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge on decompressed cap, got %v", err)
	}
}
