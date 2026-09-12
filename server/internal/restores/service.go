// service.go 恢复流程：校验 → 隔离恢复 → 预览 → 确认 → 正式恢复。
package restores

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/backups"
)

// MaintenanceFlag 维护模式标志存储（*cache.Client 满足）。
type MaintenanceFlag interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// Service 恢复服务。
type Service struct {
	db       *pgxpool.Pool
	store    *Store
	backups  *backups.Store
	exporter *backups.Exporter
	dataDir  string
	maint    MaintenanceFlag
	alertFn  backups.AlertFunc
}

// NewService 创建恢复服务。
func NewService(db *pgxpool.Pool, store *Store, backupStore *backups.Store, exporter *backups.Exporter,
	dataDir string, maint MaintenanceFlag, alertFn backups.AlertFunc) *Service {
	return &Service{
		db: db, store: store, backups: backupStore, exporter: exporter,
		dataDir: dataDir, maint: maint, alertFn: alertFn,
	}
}

// StagingImportPath 返回导入上传的暂存路径（数据目录内，供 ImportBackup 校验）。
func (s *Service) StagingImportPath(name string) (string, error) {
	base := filepath.Join(s.dataDir, RestoreTmpDirName)
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	return filepath.Join(base, name), nil
}

// tmpDir 恢复临时目录（解包用，完成即清理）。
func (s *Service) tmpDir(id string) (string, error) {
	base := filepath.Join(s.dataDir, RestoreTmpDirName)
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	// id 为 UUID 或 "validate-"+UUID，仅含安全字符，仍经 SafeJoin 防御
	name, err := backups.SafeJoin(base, id)
	if err != nil {
		return "", err
	}
	return name, os.MkdirAll(name, 0700)
}

// loadVerifiedBackup 加载备份任务并确认可用于恢复（成功且已验证）。
func (s *Service) loadVerifiedBackup(ctx context.Context, backupID uuid.UUID) (*backups.Job, string, error) {
	job, err := s.backups.GetByID(ctx, backupID)
	if err != nil {
		return nil, "", err
	}
	if job.Status != backups.StatusSuccess || !job.Verified {
		return nil, "", fmt.Errorf("%w: backup %s status=%s verified=%v",
			ErrBackupNotReady, backupID, job.Status, job.Verified)
	}
	path, err := backups.BackupPath(s.dataDir, backupID)
	if err != nil {
		return nil, "", err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, "", backups.ErrFileMissing
	}
	return job, path, nil
}

// buildPreview 从清单与当前库版本构建预览。
func (s *Service) buildPreview(ctx context.Context, job *backups.Job, m *backups.Manifest, scope string, restored map[string]int64) (*Preview, error) {
	cur, err := backups.SchemaVersion(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if err := backups.CheckSchemaCompat(m.SchemaVersion, cur); err != nil {
		return nil, err
	}
	available := map[string]bool{}
	for _, t := range m.Tables {
		available[t.Name] = true
	}
	inScope := map[string]bool{}
	if scope != "" {
		names, err := ScopeTables(scope, available)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			inScope[n] = true
		}
	}
	p := &Preview{
		BackupID:             job.ID,
		BackupType:           job.BackupType,
		Scope:                scope,
		BackupTime:           m.CreatedAt,
		SchemaVersion:        m.SchemaVersion,
		CurrentSchemaVersion: cur,
		Compatible:           true,
	}
	for _, t := range m.Tables {
		tp := TablePreview{
			Name:       t.Name,
			Group:      t.Group,
			BackupRows: t.RowCount,
			Match:      true,
		}
		if scope != "" {
			tp.InScope = inScope[t.Name]
		} else {
			tp.InScope = t.Group != backups.GroupAudit
		}
		if restored != nil {
			if n, ok := restored[t.Name]; ok {
				tp.RestoredRows = n
				tp.Match = n == t.RowCount
			}
		}
		p.Tables = append(p.Tables, tp)
		p.TotalRows += t.RowCount
	}
	for _, t := range m.Tables {
		if t.Group == backups.GroupAudit {
			p.Note = "审计归档段仅用于查阅，不会写回生产库"
			break
		}
	}
	return p, nil
}

// ValidateBackup 校验备份并输出预览（不创建任务，不解包残留）。
func (s *Service) ValidateBackup(ctx context.Context, backupID uuid.UUID) (*Preview, error) {
	job, path, err := s.loadVerifiedBackup(ctx, backupID)
	if err != nil {
		return nil, err
	}
	// 哈希 + 清单 + 解密 + 逐段行数校验
	if _, err := s.exporter.Verify(ctx, path, job.FileHash); err != nil {
		return nil, fmt.Errorf("%w: %v", backups.ErrManifestInvalid, err)
	}
	// 解密到临时目录（完成后清理）
	dir, err := s.tmpDir("validate-" + uuid.NewString())
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	m, err := s.exporter.Extract(path, dir)
	if err != nil {
		return nil, err
	}
	return s.buildPreview(ctx, job, m, "", nil)
}

// Create 创建恢复任务并启动异步隔离恢复（绝不触碰正式表）。
func (s *Service) Create(ctx context.Context, backupID uuid.UUID, scope string, requestedBy *uuid.UUID, requestID string) (*Job, error) {
	if !ValidScope(scope) {
		return nil, ErrInvalidScope
	}
	active, err := s.store.HasActive(ctx)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrActiveRestore
	}
	job, _, err := s.loadVerifiedBackup(ctx, backupID)
	if err != nil {
		return nil, err
	}
	// 范围内必须有实际表（如 CERTIFICATE 对 CONFIG_ONLY 备份为空）
	var m backups.Manifest
	if err := json.Unmarshal(job.Manifest, &m); err != nil {
		return nil, fmt.Errorf("parse backup manifest: %w", err)
	}
	available := map[string]bool{}
	for _, t := range m.Tables {
		available[t.Name] = true
	}
	tables, err := ScopeTables(scope, available)
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, ErrEmptyScope
	}
	rj, err := s.store.Create(ctx, backupID, scope, requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	go s.runIsolated(rj.ID)
	return rj, nil
}

// runIsolated 异步隔离恢复：解包 → 临时 schema 克隆建表 → 插入 → 行数核对 → 等待确认。
func (s *Service) runIsolated(id uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), IsolatedTimeout)
	defer cancel()
	schema := StagingSchema(id)
	extractDir := ""
	fail := func(code string, err error) {
		slog.Error("restore isolated stage failed", "id", id, "code", code, "error", err)
		if dbErr := s.store.MarkFailed(ctx, id, code, err); dbErr != nil {
			slog.Error("mark restore failed status error", "id", id, "error", dbErr)
		}
		backups.NotifyAlert(s.alertFn, "RESTORE_FAILED", "restore", "恢复任务失败",
			"恢复任务 "+id.String()+" 失败（"+code+"）："+failMsg(err))
		s.cleanupSchema(schema)
		if extractDir != "" {
			_ = os.RemoveAll(extractDir)
		}
	}

	job, err := s.store.GetByID(ctx, id)
	if err != nil {
		slog.Error("load restore job failed", "id", id, "error", err)
		return
	}
	// ---- VALIDATING ----
	if err := s.store.SetStatus(ctx, id, StatusValidating); err != nil {
		fail(FailValidate, err)
		return
	}
	bj, path, err := s.loadVerifiedBackup(ctx, *job.BackupJobID)
	if err != nil {
		fail(FailBackupNotReady, err)
		return
	}
	if _, err := s.exporter.Verify(ctx, path, bj.FileHash); err != nil {
		fail(FailValidate, err)
		return
	}
	extractDir, err = s.tmpDir(id.String())
	if err != nil {
		fail(FailValidate, err)
		return
	}
	m, err := s.exporter.Extract(path, extractDir)
	if err != nil {
		fail(FailValidate, err)
		return
	}
	cur, err := backups.SchemaVersion(ctx, s.db)
	if err != nil {
		fail(FailValidate, err)
		return
	}
	if err := backups.CheckSchemaCompat(m.SchemaVersion, cur); err != nil {
		fail(FailValidate, err)
		return
	}

	// ---- ISOLATED_RESTORE ----
	if err := s.store.SetStatus(ctx, id, StatusIsolatedRestore); err != nil {
		fail(FailIsolatedRestore, err)
		return
	}
	available := map[string]bool{}
	for _, t := range m.Tables {
		available[t.Name] = true
	}
	tables, err := ScopeTables(job.RestoreScope, available)
	if err != nil || len(tables) == 0 {
		fail(FailEmptyScope, fmt.Errorf("%w", ErrEmptyScope))
		return
	}
	if err := s.createStagingSchema(ctx, schema); err != nil {
		fail(FailIsolatedRestore, err)
		return
	}
	restored := map[string]int64{}
	for _, table := range tables {
		tm := m.Table(table)
		cols, err := s.currentColumns(ctx, table)
		if err != nil {
			fail(FailIsolatedRestore, fmt.Errorf("table %s: %w", table, err))
			return
		}
		insertCols := intersectColumns(tm.Columns, cols)
		if len(insertCols) == 0 {
			fail(FailIsolatedRestore, fmt.Errorf("table %s: no common columns", table))
			return
		}
		if err := s.cloneTable(ctx, schema, table); err != nil {
			fail(FailIsolatedRestore, fmt.Errorf("clone table %s: %w", table, err))
			return
		}
		n, err := s.insertFromFile(ctx, schema, table, insertCols, filepath.Join(extractDir, table+".jsonl"))
		if err != nil {
			fail(FailIsolatedRestore, fmt.Errorf("insert table %s: %w", table, err))
			return
		}
		restored[table] = n
	}

	// ---- VERIFYING（行数核对） ----
	if err := s.store.SetStatus(ctx, id, StatusVerifying); err != nil {
		fail(FailVerify, err)
		return
	}
	for _, table := range tables {
		tm := m.Table(table)
		var cnt int64
		if err := s.db.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{schema, table}.Sanitize())).Scan(&cnt); err != nil {
			fail(FailVerify, fmt.Errorf("count table %s: %w", table, err))
			return
		}
		if cnt != tm.RowCount || cnt != restored[table] {
			fail(FailVerify, fmt.Errorf("table %s row mismatch: staging=%d manifest=%d inserted=%d",
				table, cnt, tm.RowCount, restored[table]))
			return
		}
	}

	// ---- 预览 → 等待确认 ----
	preview, err := s.buildPreview(ctx, bj, m, job.RestoreScope, restored)
	if err != nil {
		fail(FailVerify, err)
		return
	}
	if err := s.store.MarkAwaitingConfirm(ctx, id, preview); err != nil {
		fail(FailVerify, err)
		return
	}
	_ = os.RemoveAll(extractDir) // 解包明文立即清理；隔离 schema 保留至确认/取消
	slog.Info("restore awaiting confirm", "id", id, "scope", job.RestoreScope, "tables", len(tables))
}

// Confirm 管理员二次确认后正式恢复：维护模式 → 事务内替换 → 验证 → 成功。
// 关键段使用独立超时上下文，避免客户端断开中断恢复。
func (s *Service) Confirm(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (*Job, map[string]int64, error) {
	job, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if job.Status != StatusAwaitingConfirm {
		return nil, nil, fmt.Errorf("%w: status=%s", ErrInvalidStatus, job.Status)
	}
	if s.maint == nil {
		return nil, nil, ErrMaintenanceUnavail
	}
	if err := s.store.MarkRestoring(ctx, id, confirmedBy); err != nil {
		return nil, nil, err
	}
	fail := func(code string, err error) (*Job, map[string]int64, error) {
		slog.Error("restore confirm failed", "id", id, "code", code, "error", err)
		if dbErr := s.store.MarkFailed(context.Background(), id, code, err); dbErr != nil {
			slog.Error("mark restore failed status error", "id", id, "error", dbErr)
		}
		backups.NotifyAlert(s.alertFn, "RESTORE_FAILED", "restore", "正式恢复失败",
			"恢复任务 "+id.String()+" 失败（"+code+"）："+failMsg(err))
		s.cleanupSchema(StagingSchema(id))
		return nil, nil, err
	}

	// ---- 维护模式（Valkey 标志；本阶段实现标志设置） ----
	mctx, mcancel := context.WithTimeout(context.Background(), 10*time.Second)
	mErr := s.maint.Set(mctx, MaintenanceKey, "1", MaintenanceTTL)
	mcancel()
	if mErr != nil {
		return fail(FailMaintenance, fmt.Errorf("set maintenance flag: %w", mErr))
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		if err := s.maint.Del(dctx, MaintenanceKey); err != nil {
			slog.Error("clear maintenance flag failed", "id", id, "error", err)
		}
	}()

	ctxT, cancel := context.WithTimeout(context.Background(), ConfirmTimeout)
	defer cancel()

	// 范围内表（与隔离恢复同一推导）
	bj, err := s.backups.GetByID(ctxT, *job.BackupJobID)
	if err != nil {
		return fail(FailRestore, err)
	}
	var m backups.Manifest
	if err := json.Unmarshal(bj.Manifest, &m); err != nil {
		return fail(FailRestore, err)
	}
	available := map[string]bool{}
	for _, t := range m.Tables {
		available[t.Name] = true
	}
	tables, err := ScopeTables(job.RestoreScope, available)
	if err != nil || len(tables) == 0 {
		return fail(FailEmptyScope, ErrEmptyScope)
	}
	// 删除集合按当前 schema 推导，插入集合仍按备份实际包含的表推导。
	// 这样旧格式备份缺少新增 WDSP 表时不会把恢复前的数据遗留在库中。
	deleteTables, err := ScopeTablesForRestore(job.RestoreScope)
	if err != nil || len(deleteTables) == 0 {
		return fail(FailEmptyScope, ErrEmptyScope)
	}
	schema := StagingSchema(id)

	tx, err := s.db.Begin(ctxT)
	if err != nil {
		return fail(FailRestore, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	// 关闭 FK/触发器检查（外键由触发器实现；恢复为整组替换，备份集自洽）。
	// 需要超级用户或等效权限，失败则明确报错，绝不降级继续。
	if _, err := tx.Exec(ctxT, `SET LOCAL session_replication_role = 'replica'`); err != nil {
		return fail(FailPrivilege, fmt.Errorf("disable triggers (superuser required): %w", err))
	}
	// 先删（child → parent）
	for i := len(deleteTables) - 1; i >= 0; i-- {
		if _, err := tx.Exec(ctxT,
			fmt.Sprintf(`DELETE FROM %s`, pgx.Identifier{"public", deleteTables[i]}.Sanitize())); err != nil {
			return fail(FailRestore, fmt.Errorf("truncate table %s: %w", deleteTables[i], err))
		}
	}
	// 再插（parent → child），保留原主键，关联关系不失
	for _, table := range tables {
		tm := m.Table(table)
		cols, err := s.currentColumns(ctxT, table)
		if err != nil {
			return fail(FailRestore, err)
		}
		insertCols := intersectColumns(tm.Columns, cols)
		var stagingCount int64
		if err := tx.QueryRow(ctxT,
			fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{schema, table}.Sanitize())).Scan(&stagingCount); err != nil {
			return fail(FailRestore, fmt.Errorf("count staging %s: %w", table, err))
		}
		colList := quotedColumnList(insertCols)
		res, err := tx.Exec(ctxT, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`,
			pgx.Identifier{"public", table}.Sanitize(), colList, colList,
			pgx.Identifier{schema, table}.Sanitize()))
		if err != nil {
			return fail(FailRestore, fmt.Errorf("restore table %s: %w", table, err))
		}
		if res.RowsAffected() != stagingCount {
			return fail(FailRestore, fmt.Errorf("table %s: inserted %d != staging %d", table, res.RowsAffected(), stagingCount))
		}
	}
	// 隔离 schema 随事务一并删除
	if _, err := tx.Exec(ctxT, fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, pgx.Identifier{schema}.Sanitize())); err != nil {
		return fail(FailRestore, err)
	}
	if err := tx.Commit(ctxT); err != nil {
		return fail(FailRestore, err)
	}
	committed = true

	// ---- 恢复后验证（核心表可读） ----
	summary, err := s.postVerify(ctxT, job.RestoreScope)
	if err != nil {
		return fail(FailVerify, err)
	}
	if err := s.store.MarkSuccess(context.Background(), id); err != nil {
		return fail(FailRestore, err)
	}
	slog.Info("restore success", "id", id, "scope", job.RestoreScope, "summary", summary)
	final, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, summary, err
	}
	return final, summary, nil
}

// Cancel 取消等待确认的任务（删除隔离 schema）。
func (s *Service) Cancel(ctx context.Context, id uuid.UUID) error {
	if err := s.store.MarkCancelled(ctx, id); err != nil {
		return err
	}
	s.cleanupSchema(StagingSchema(id))
	return nil
}

// createStagingSchema 创建隔离 schema（重复执行安全）。
func (s *Service) createStagingSchema(ctx context.Context, schema string) error {
	if !ValidStagingSchema(schema) {
		return ErrStagingSchema
	}
	if _, err := s.db.Exec(ctx,
		fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, pgx.Identifier{schema}.Sanitize())); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, pgx.Identifier{schema}.Sanitize()))
	return err
}

// cleanupSchema 尽力删除隔离 schema（失败仅记录日志并告警，不掩盖主错误）。
func (s *Service) cleanupSchema(schema string) {
	if !ValidStagingSchema(schema) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.db.Exec(ctx,
		fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, pgx.Identifier{schema}.Sanitize())); err != nil {
		slog.Error("cleanup staging schema failed", "schema", schema, "error", err)
		backups.NotifyAlert(s.alertFn, "RESTORE_CLEANUP_FAILED", "restore", "隔离环境清理失败",
			"隔离 schema "+schema+" 清理失败："+failMsg(err))
	}
}

// cloneTable 按当前库信息模式克隆表结构到隔离 schema（仅列与类型，不带默认值/约束/索引）。
func (s *Service) cloneTable(ctx context.Context, schema, table string) error {
	_, err := s.db.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`,
		pgx.Identifier{schema, table}.Sanitize(), pgx.Identifier{"public", table}.Sanitize()))
	return err
}

// currentColumns 当前库表列名集合。
func (s *Service) currentColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.Query(ctx, `
SELECT column_name FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = $1`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols[c] = true
	}
	return cols, rows.Err()
}

// insertFromFile 从 JSONL 文件批量插入隔离 schema 表，返回插入行数。
func (s *Service) insertFromFile(ctx context.Context, schema, table string, cols []string, path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	colList := quotedColumnList(cols)
	stmt := fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM jsonb_populate_recordset(NULL::%s, $1::jsonb)`,
		pgx.Identifier{schema, table}.Sanitize(), colList, colList,
		pgx.Identifier{schema, table}.Sanitize())

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // 单行最大 16MB
	var total int64
	batch := make([]string, 0, insertBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		arr := "[" + strings.Join(batch, ",") + "]"
		res, err := s.db.Exec(ctx, stmt, arr)
		if err != nil {
			return err
		}
		total += res.RowsAffected()
		batch = batch[:0]
		return nil
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		batch = append(batch, line)
		if len(batch) >= insertBatchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return total, err
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

// postVerify 恢复后验证：核心表可读且计数合理。
func (s *Service) postVerify(ctx context.Context, scope string) (map[string]int64, error) {
	checks, err := ScopeTablesForRestore(scope)
	if err != nil {
		return nil, err
	}
	summary := map[string]int64{}
	for _, t := range checks {
		var cnt int64
		if err := s.db.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{t}.Sanitize())).Scan(&cnt); err != nil {
			return nil, fmt.Errorf("post-restore verify %s: %w", t, err)
		}
		summary[t] = cnt
	}
	return summary, nil
}

// intersectColumns 备份列 ∩ 当前列（保持备份列序）。
func intersectColumns(backupCols []string, current map[string]bool) []string {
	var out []string
	for _, c := range backupCols {
		if current[c] {
			out = append(out, c)
		}
	}
	return out
}

// quotedColumnList 安全引用列名清单。
func quotedColumnList(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = pgx.Identifier{c}.Sanitize()
	}
	return strings.Join(parts, ", ")
}
