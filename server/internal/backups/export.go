// export.go 逻辑导出与备份验证：SELECT → JSONL → tar/gzip → 分块加密 → 清单。
package backups

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// Exporter 备份导出器/验证器。
type Exporter struct {
	db      *pgxpool.Pool
	enc     *encryption.Service
	dataDir string
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
	var v int
	err := db.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return v, nil
}

// Export 执行逻辑导出并写入加密备份文件，返回清单、全文件哈希与大小。
// outPath 由调用方决定（临时路径，成功后原子改名）。
func (e *Exporter) Export(ctx context.Context, jobID uuid.UUID, backupType, createdBy, outPath string) (*Manifest, string, int64, error) {
	if e.enc == nil {
		return nil, "", 0, ErrNoEncryption
	}
	schemaVer, err := SchemaVersion(ctx, e.db)
	if err != nil {
		return nil, "", 0, err
	}
	w, err := CreateWriter(outPath, e.enc)
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
		tm, err := e.exportTable(ctx, tw, t)
		if err != nil {
			return cleanup(fmt.Errorf("export table %s: %w", t.Name, err))
		}
		m.Tables = append(m.Tables, *tm)
		m.TotalRows += tm.RowCount
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
func (e *Exporter) exportTable(ctx context.Context, tw *tar.Writer, t TableDef) (*TableManifest, error) {
	cols, err := e.tableColumns(ctx, t.Name)
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
	rows, err := e.db.Query(ctx, query)
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

// tableColumns 当前库表列名（按定义顺序）。
func (e *Exporter) tableColumns(ctx context.Context, table string) ([]string, error) {
	rows, err := e.db.Query(ctx, `
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

// WalkSegments 遍历备份文件数据段：先回调清单（onManifest），再逐表回调明文 JSONL 流。
// 条目名经白名单校验，拒绝非表数据条目。fn 必须消费完流。
func (e *Exporter) WalkSegments(path string, onManifest func(*Manifest) error, fn func(table string, r io.Reader) error) error {
	rd, err := OpenReader(path, e.enc)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }()
	if err := onManifest(rd.Manifest); err != nil {
		return err
	}
	// 明文整体哈希在解压前校验（gzip 可能预读，结束后需排空 tee 保证全量计数）
	ph := sha256.New()
	tee := io.TeeReader(rd, ph)
	gz, err := gzip.NewReader(tee)
	if err != nil {
		return fmt.Errorf("%w: gzip: %v", ErrBadFile, err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: tar: %v", ErrBadFile, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: non-regular entry %q", ErrBadFile, hdr.Name)
		}
		table := SegmentTableName(hdr.Name)
		if table == "" || !IsBackupTable(table) {
			return fmt.Errorf("%w: illegal entry %q", ErrBadFile, hdr.Name)
		}
		if err := fn(table, tr); err != nil {
			return err
		}
	}
	// 排空残余字节后比对明文整体哈希
	_, _ = io.Copy(io.Discard, tee)
	if got := hex.EncodeToString(ph.Sum(nil)); got != rd.Manifest.Data.SHA256Plain {
		return fmt.Errorf("%w: plaintext stream sha256 mismatch", ErrHashMismatch)
	}
	return nil
}

// Extract 解密并解包备份文件到目标目录（每表一个 {table}.jsonl），返回清单。
// 目标目录必须已存在且为空；调用方负责清理。
func (e *Exporter) Extract(path, destDir string) (*Manifest, error) {
	var m *Manifest
	err := e.WalkSegments(path, func(mm *Manifest) error {
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
