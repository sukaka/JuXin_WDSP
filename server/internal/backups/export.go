// export.go 逻辑导出与备份验证：SELECT → JSONL → tar/gzip → 分块加密 → 清单。
package backups

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/rulepacks"
)

// MaxDecompressedBytes 备份解压后总字节硬上限（8GiB，防 gzip 炸弹耗尽磁盘/CPU）。
const MaxDecompressedBytes = int64(8) << 30

// queryRunner 抽象数据库查询能力，供 Export 在 RepeatableRead 只读事务内执行。
type queryRunner interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Exporter 备份导出器/验证器。
type Exporter struct {
	db                   *pgxpool.Pool
	enc                  *encryption.Service
	dataDir              string
	maxDecompressedBytes int64
}

func (e *Exporter) decompressedLimit() int64 {
	if e != nil && e.maxDecompressedBytes > 0 {
		return e.maxDecompressedBytes
	}
	return MaxDecompressedBytes
}

// NewExporter 创建导出器。
func NewExporter(db *pgxpool.Pool, enc *encryption.Service, dataDir string) *Exporter {
	return &Exporter{db: db, enc: enc, dataDir: dataDir}
}

// BackupDir 备份目录。
func (e *Exporter) BackupDir() string {
	return filepath.Join(e.dataDir, DirName)
}

// SchemaVersion 当前库最大迁移版本（schema_migrations 由 database 包维护）。
func SchemaVersion(ctx context.Context, db *pgxpool.Pool) (int, error) {
	return schemaVersionFrom(ctx, db)
}

func schemaVersionFrom(ctx context.Context, q queryRunner) (int, error) {
	var v int
	err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return v, nil
}

// Export 执行逻辑导出并写入加密备份文件，返回清单、全文件哈希与大小。
// 全过程在 REPEATABLE READ 只读事务内执行，确保跨表快照一致。
// outPath 由调用方决定（临时路径，成功后原子改名）。
func (e *Exporter) Export(ctx context.Context, jobID uuid.UUID, backupType, createdBy, outPath string) (*Manifest, string, int64, error) {
	if e.enc == nil {
		return nil, "", 0, ErrNoEncryption
	}
	tx, err := e.db.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, "", 0, fmt.Errorf("begin repeatable read backup tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	schemaVer, err := schemaVersionFrom(ctx, tx)
	if err != nil {
		return nil, "", 0, err
	}
	w, err := CreateWriterWithID(outPath, e.enc, jobID.String())
	if err != nil {
		return nil, "", 0, err
	}
	cleanup := func(err error) (*Manifest, string, int64, error) {
		w.Abort()
		_ = os.Remove(outPath)
		return nil, "", 0, err
	}

	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	m := &Manifest{
		Format:        FormatName,
		FormatVersion: FormatVersion,
		BackupID:      jobID.String(),
		BackupType:    backupType,
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     createdBy,
		SchemaVersion: schemaVer,
		AppComponent:  "jiuzhang-waf-server",
		Compression:   "gzip",
		ArchiveFormat: "tar",
	}
	for _, t := range TablesForBackup(backupType) {
		tm, err := e.exportTable(ctx, tx, tw, t)
		if err != nil {
			return cleanup(fmt.Errorf("export table %s: %w", t.Name, err))
		}
		m.Tables = append(m.Tables, *tm)
		m.TotalRows += tm.RowCount
	}
	if backupType == TypeFull {
		rpMeta, err := e.exportActiveRulePackArchive(ctx, tx, tw)
		if err != nil {
			return cleanup(fmt.Errorf("export active rulepack archive: %w", err))
		}
		m.ActiveRulePack = rpMeta
	}
	if err := tx.Commit(ctx); err != nil {
		return cleanup(fmt.Errorf("commit backup read tx: %w", err))
	}
	if err := tw.Close(); err != nil {
		return cleanup(err)
	}
	if err := gzw.Close(); err != nil {
		return cleanup(err)
	}
	fileHash, fileSize, err := w.Finish(m)
	if err != nil {
		return cleanup(err)
	}
	return m, fileHash, fileSize, nil
}

// exportTable 导出单表为一个 tar 条目（JSON Lines，每行一个 JSON 对象）。
// 大表经临时卷文件中转，避免整表驻留内存。
func (e *Exporter) exportTable(ctx context.Context, q queryRunner, tw *tar.Writer, t TableDef) (*TableManifest, error) {
	cols, err := e.tableColumns(ctx, q, t.Name)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s not found", t.Name)
	}
	query := fmt.Sprintf(`SELECT to_jsonb(t)::text FROM (SELECT * FROM %s) t`, pgx.Identifier{t.Name}.Sanitize())
	if t.RecentLimit > 0 {
		query = fmt.Sprintf(`SELECT to_jsonb(t)::text FROM (SELECT * FROM %s ORDER BY %s DESC LIMIT %d) t`,
			pgx.Identifier{t.Name}.Sanitize(), pgx.Identifier{t.OrderBy}.Sanitize(), t.RecentLimit)
	}
	rows, err := q.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 临时卷文件：边写边统计哈希/行数/字节
	spool, err := os.CreateTemp(e.dataDir, ".spool-*.jsonl")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}()

	h := sha256.New()
	out := io.MultiWriter(spool, h)
	tm := &TableManifest{
		Name:    t.Name,
		Group:   t.Group,
		Columns: cols,
		Archive: t.Group == GroupAudit,
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		if _, err := out.Write([]byte(line)); err != nil {
			return nil, err
		}
		if _, err := out.Write([]byte{'\n'}); err != nil {
			return nil, err
		}
		tm.RowCount++
		tm.ByteCount += int64(len(line)) + 1
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if tm.RowCount > 0 {
		tm.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	tm.Truncated = t.RecentLimit > 0 && tm.RowCount >= int64(t.RecentLimit)

	// 写入 tar 条目
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:    SegmentEntryName(t.Name),
		Mode:    0600,
		Size:    tm.ByteCount,
		ModTime: time.Now(),
	}); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tw, spool); err != nil {
		return nil, err
	}
	return tm, nil
}

// ResolveRulePackArchivePath 在 <dataDir>/rulepack-archives/ 安全边界内定位规则包签名归档文件。
// 拒绝符号链接与目录穿越；文件不存在时返回 ("", os.ErrNotExist)。
func ResolveRulePackArchivePath(dataDir string, packID uuid.UUID, storedPath string) (string, error) {
	baseDir := filepath.Join(strings.TrimSpace(dataDir), RulePackArchivesDirName)
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(baseAbs, packID.String()+".tar.gz"),
	}
	if trimmed := strings.TrimSpace(storedPath); trimmed != "" {
		if abs, absErr := filepath.Abs(trimmed); absErr == nil {
			if strings.HasPrefix(abs, baseAbs+string(os.PathSeparator)) && abs != candidates[0] {
				candidates = append(candidates, abs)
			}
		}
	}
	for _, cand := range candidates {
		st, err := os.Lstat(cand)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return "", fmt.Errorf("%w: rulepack archive %s is not a regular file", ErrBadFile, filepath.Base(cand))
		}
		return cand, nil
	}
	return "", os.ErrNotExist
}

// WriteRulePackArchiveEntry 校验磁盘签名规则包归档并将其写入备份 tar 的固定条目 rulepacks/active.tar.gz。
func WriteRulePackArchiveEntry(tw *tar.Writer, meta RulePackArchiveMeta, archivePath string) (*RulePackArchiveMeta, error) {
	if _, err := uuid.Parse(strings.TrimSpace(meta.PackID)); err != nil {
		return nil, fmt.Errorf("%w: invalid rulepack pack_id", ErrManifestInvalid)
	}
	if err := rulepacks.ValidateRulePackVersion(meta.RulePackVersion); err != nil {
		return nil, fmt.Errorf("%w: invalid rulepack version: %v", ErrManifestInvalid, err)
	}
	st, err := os.Lstat(archivePath)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: rulepack archive must be a regular non-symlink file", ErrBadFile)
	}
	if st.Size() <= 0 || st.Size() > rulepacks.MaxArchiveBytes {
		return nil, fmt.Errorf("%w: rulepack archive size %d out of bounds", ErrBadFile, st.Size())
	}
	actualSHA, err := FileSHA256(archivePath)
	if err != nil {
		return nil, err
	}
	if want := strings.TrimSpace(meta.FileSHA256); want != "" && !strings.EqualFold(actualSHA, want) {
		return nil, fmt.Errorf("%w: active rulepack archive sha256 mismatch on disk", ErrHashMismatch)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if err := tw.WriteHeader(&tar.Header{
		Name:    RulePackArchiveEntryName,
		Mode:    0600,
		Size:    st.Size(),
		ModTime: time.Now(),
	}); err != nil {
		return nil, err
	}
	h := sha256.New()
	written, err := io.CopyN(io.MultiWriter(tw, h), f, st.Size())
	if err != nil {
		return nil, err
	}
	if written != st.Size() {
		return nil, fmt.Errorf("%w: short write for rulepack archive", ErrBadFile)
	}
	streamSHA := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(streamSHA, actualSHA) {
		return nil, fmt.Errorf("%w: active rulepack archive changed during export", ErrHashMismatch)
	}
	out := meta
	out.EntryName = RulePackArchiveEntryName
	out.FileSize = st.Size()
	out.FileSHA256 = streamSHA
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// exportActiveRulePackArchive 在 FULL 备份事务中查询当前生效的非内置离线规则包，
// 若磁盘上存在其签名原始归档（<dataDir>/rulepack-archives/<id>.tar.gz），则同步打入备份流。
func (e *Exporter) exportActiveRulePackArchive(ctx context.Context, q queryRunner, tw *tar.Writer) (*RulePackArchiveMeta, error) {
	var (
		packID         uuid.UUID
		version        string
		crsVersion     string
		fileName       string
		fileSHA256     string
		manifestSHA256 string
		archivePath    string
	)
	err := q.QueryRow(ctx, `
SELECT id, rulepack_version, crs_version, file_name, file_sha256, manifest_sha256, archive_path
FROM waf_rule_packs
WHERE status = 'APPLIED' AND is_builtin = FALSE
LIMIT 1`).Scan(&packID, &version, &crsVersion, &fileName, &fileSHA256, &manifestSHA256, &archivePath)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	resolved, err := ResolveRulePackArchivePath(e.dataDir, packID, archivePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("active non-builtin rulepack archive missing on disk; backup will continue without bundled archive",
				"pack_id", packID, "version", version)
			return nil, nil
		}
		return nil, err
	}
	return WriteRulePackArchiveEntry(tw, RulePackArchiveMeta{
		PackID:          packID.String(),
		RulePackVersion: version,
		CRSVersion:      crsVersion,
		FileName:        fileName,
		EntryName:       RulePackArchiveEntryName,
		FileSHA256:      fileSHA256,
		ManifestSHA256:  manifestSHA256,
	}, resolved)
}

// tableColumns 当前库表列名（按定义顺序）。
func (e *Exporter) tableColumns(ctx context.Context, q queryRunner, table string) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT column_name FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = $1
ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// VerifyResult 验证结果摘要。
type VerifyResult struct {
	Manifest   *Manifest `json:"manifest"`
	CheckedAt  time.Time `json:"checked_at"`
	TablesOK   int       `json:"tables_ok"`
	TotalRows  int64     `json:"total_rows"`
	FileIntact bool      `json:"file_intact"`
}

// Verify 验证备份文件：
// 全文件哈希（对 DB 记录）→ 清单校验 → schema 兼容 → 解密 → 解压 → 逐表重算行数/字节/哈希比对。
// 任一步失败返回错误，绝不部分通过。
func (e *Exporter) Verify(ctx context.Context, path, expectedFileHash string) (*VerifyResult, error) {
	if e.enc == nil {
		return nil, ErrNoEncryption
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, ErrFileMissing
	}
	if st.Size() > MaxBackupFileSize {
		return nil, ErrTooLarge
	}
	if expectedFileHash != "" {
		sum, err := FileSHA256(path)
		if err != nil {
			return nil, err
		}
		if sum != expectedFileHash {
			return nil, fmt.Errorf("%w: file sha256 mismatch", ErrHashMismatch)
		}
	}
	// 逐表校验
	res := &VerifyResult{CheckedAt: time.Now().UTC(), FileIntact: true}
	err = e.WalkSegments(path, func(m *Manifest) error {
		res.Manifest = m
		cur, err := SchemaVersion(ctx, e.db)
		if err != nil {
			return err
		}
		return CheckSchemaCompat(m.SchemaVersion, cur)
	}, func(table string, r io.Reader) error {
		tm := res.Manifest.Table(table)
		if tm == nil {
			return fmt.Errorf("%w: unexpected segment %q", ErrManifestInvalid, table)
		}
		rowsN, bytesN, sum, err := statSegment(r)
		if err != nil {
			return err
		}
		if rowsN != tm.RowCount || bytesN != tm.ByteCount || sum != tm.SHA256 {
			return fmt.Errorf("%w: table %s segment mismatch (rows %d/%d bytes %d/%d)",
				ErrManifestInvalid, table, rowsN, tm.RowCount, bytesN, tm.ByteCount)
		}
		res.TablesOK++
		res.TotalRows += rowsN
		return nil
	})
	if err != nil {
		return nil, err
	}
	if res.TablesOK != len(res.Manifest.Tables) {
		return nil, fmt.Errorf("%w: segments %d != manifest tables %d", ErrManifestInvalid, res.TablesOK, len(res.Manifest.Tables))
	}
	return res, nil
}

// cappedReader 对解压后流实施硬字节上限，防止 gzip 炸弹耗尽 CPU/磁盘。
type cappedReader struct {
	r    io.Reader
	read int64
	max  int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.read += int64(n)
		if c.read > c.max {
			return n, fmt.Errorf("%w: decompressed backup exceeds %d bytes limit", ErrTooLarge, c.max)
		}
	}
	return n, err
}

// byteCounter 统计经过 TeeReader 的明文字节数。
type byteCounter struct {
	n int64
}

func (b *byteCounter) Write(p []byte) (int, error) {
	b.n += int64(len(p))
	return len(p), nil
}

// WalkSegments 遍历备份文件数据段：先回调清单（onManifest），再逐表回调明文 JSONL 流。
// 若备份携带激活规则包归档条目（rulepacks/active.tar.gz），同时执行大小与 SHA-256 完整性核验。
// 条目名经白名单校验，拒绝非白名单条目与重复条目，并强制执行解压字节上限与密文/明文摘要核验。
func (e *Exporter) WalkSegments(path string, onManifest func(*Manifest) error, fn func(table string, r io.Reader) error) error {
	return e.WalkEntries(path, onManifest, fn, nil)
}

// WalkEntries 遍历备份文件全部白名单条目：表 JSONL 段（tables/*.jsonl）及可选的激活规则包签名归档（rulepacks/active.tar.gz）。
func (e *Exporter) WalkEntries(
	path string,
	onManifest func(*Manifest) error,
	onTable func(table string, r io.Reader) error,
	onRulePack func(meta *RulePackArchiveMeta, r io.Reader) error,
) error {
	rd, err := OpenReader(path, e.enc)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }()
	if onManifest != nil {
		if err := onManifest(rd.Manifest); err != nil {
			return err
		}
	}
	// 明文整体哈希与长度在解压前统计（gzip 可能预读，结束后排空 tee 并核验密文段与明文段摘要）
	ph := sha256.New()
	plainCount := &byteCounter{}
	tee := io.TeeReader(rd, io.MultiWriter(ph, plainCount))
	gz, err := gzip.NewReader(tee)
	if err != nil {
		return fmt.Errorf("%w: gzip: %v", ErrBadFile, err)
	}
	defer func() { _ = gz.Close() }()

	maxDecomp := e.decompressedLimit()
	limitedGZ := &cappedReader{r: gz, max: maxDecomp}
	tr := tar.NewReader(limitedGZ)
	seenTables := make(map[string]bool)
	seenRulePack := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return err
			}
			return fmt.Errorf("%w: tar: %v", ErrBadFile, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: non-regular entry %q", ErrBadFile, hdr.Name)
		}
		if hdr.Size < 0 || hdr.Size > maxDecomp {
			return fmt.Errorf("%w: entry %q exceeds decompressed limit", ErrTooLarge, hdr.Name)
		}
		if hdr.Name == RulePackArchiveEntryName {
			meta := rd.Manifest.ActiveRulePack
			if meta == nil {
				return fmt.Errorf("%w: unexpected rulepack archive entry not declared in manifest", ErrBadFile)
			}
			if seenRulePack {
				return fmt.Errorf("%w: duplicate rulepack archive entry", ErrBadFile)
			}
			if hdr.Size != meta.FileSize || hdr.Size > rulepacks.MaxArchiveBytes {
				return fmt.Errorf("%w: rulepack archive size %d != manifest %d", ErrManifestInvalid, hdr.Size, meta.FileSize)
			}
			seenRulePack = true
			rph := sha256.New()
			rpBytes := &byteCounter{}
			rpReader := io.TeeReader(tr, io.MultiWriter(rph, rpBytes))
			if onRulePack != nil {
				if err := onRulePack(meta, rpReader); err != nil {
					return err
				}
			}
			if _, err := io.Copy(io.Discard, rpReader); err != nil {
				return err
			}
			if rpBytes.n != meta.FileSize {
				return fmt.Errorf("%w: rulepack archive byte count %d != manifest %d", ErrManifestInvalid, rpBytes.n, meta.FileSize)
			}
			if got := hex.EncodeToString(rph.Sum(nil)); !strings.EqualFold(got, meta.FileSHA256) {
				return fmt.Errorf("%w: rulepack archive sha256 mismatch", ErrHashMismatch)
			}
			continue
		}
		table := SegmentTableName(hdr.Name)
		if table == "" || !IsBackupTable(table) {
			return fmt.Errorf("%w: illegal entry %q", ErrBadFile, hdr.Name)
		}
		if seenTables[table] {
			return fmt.Errorf("%w: duplicate table entry %q", ErrBadFile, table)
		}
		seenTables[table] = true
		if onTable != nil {
			if err := onTable(table, tr); err != nil {
				return err
			}
		} else {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return err
			}
		}
	}
	if rd.Manifest.ActiveRulePack != nil && !seenRulePack {
		return fmt.Errorf("%w: manifest declares active_rulepack but archive entry is missing", ErrManifestInvalid)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("%w: gzip close: %v", ErrBadFile, err)
	}
	// 排空残余字节并触发 Reader 的 ChunkCount / SHA256Encrypted 校验，不吞任何错误
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return err
	}
	if plainCount.n != rd.Manifest.Data.SizePlain {
		return fmt.Errorf("%w: plaintext stream size %d != manifest %d", ErrHashMismatch, plainCount.n, rd.Manifest.Data.SizePlain)
	}
	if got := hex.EncodeToString(ph.Sum(nil)); got != rd.Manifest.Data.SHA256Plain {
		return fmt.Errorf("%w: plaintext stream sha256 mismatch", ErrHashMismatch)
	}
	return nil
}

// Extract 解密并解包备份文件到目标目录（每表一个 {table}.jsonl，若携带激活规则包归档则同时解出 active-rulepack.tar.gz），返回清单。
// 目标目录必须已存在且为空；调用方负责清理。
func (e *Exporter) Extract(path, destDir string) (*Manifest, error) {
	var m *Manifest
	err := e.WalkEntries(path, func(mm *Manifest) error {
		m = mm
		return nil
	}, func(table string, r io.Reader) error {
		name, err := SafeJoin(destDir, table+".jsonl")
		if err != nil {
			return err
		}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}, func(_ *RulePackArchiveMeta, r io.Reader) error {
		name, err := SafeJoin(destDir, ExtractedRulePackFileName)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, r)
		closeErr := f.Close()
		if copyErr != nil {
			_ = os.Remove(name)
			return copyErr
		}
		if closeErr != nil {
			_ = os.Remove(name)
			return closeErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// statSegment 统计 JSONL 段：行数、字节数、SHA-256。
func statSegment(r io.Reader) (rows, bytes int64, sum string, err error) {
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var pending int64 // 不以换行结尾的残余字节（正常导出不会发生）
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			h.Write(chunk)
			bytes += int64(n)
			for _, b := range chunk {
				if b == '\n' {
					rows++
					pending = 0
				} else {
					pending++
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return 0, 0, "", rerr
		}
	}
	if pending > 0 {
		rows++ // 最后一行无换行符也计一行
	}
	if rows > 0 {
		sum = hex.EncodeToString(h.Sum(nil))
	}
	return rows, bytes, sum, nil
}
