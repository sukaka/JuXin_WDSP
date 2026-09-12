// worker.go 备份异步执行器：认领 → 导出 → 验证 → 成功/失败，含保留清理。
package backups

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// 保留策略（可调常量）
const (
	// RetainRecentSuccess 保留最近成功备份数
	RetainRecentSuccess = 10
	// RetainMaxAge 保留最长时间（30天）
	RetainMaxAge = 30 * 24 * time.Hour
	// JobTimeout 单任务超时
	JobTimeout = 30 * time.Minute
	// PollInterval 轮询间隔
	PollInterval = 5 * time.Second
	// cleanupInterval 保留清理间隔
	cleanupInterval = time.Hour
)

// Worker 备份执行器。
type Worker struct {
	store    *Store
	exporter *Exporter
	alertFn  AlertFunc
}

// NewWorker 创建执行器。
func NewWorker(store *Store, exporter *Exporter, alertFn AlertFunc) *Worker {
	return &Worker{store: store, exporter: exporter}
}

// SetAlertFunc 注入告警回调。
func (w *Worker) SetAlertFunc(fn AlertFunc) {
	w.alertFn = fn
}

// Run 周期调度：认领执行任务 + 定时保留清理。
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(PollInterval)
	cleanupT := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	defer cleanupT.Stop()
	slog.Info("backup worker started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				claimed, err := w.ProcessOnce(ctx)
				if err != nil {
					slog.Error("backup job process failed", "error", err)
					break
				}
				if !claimed {
					break
				}
			}
		case <-cleanupT.C:
			if n, err := w.CleanupRetention(ctx); err != nil {
				slog.Error("backup retention cleanup failed", "error", err)
			} else if n > 0 {
				slog.Info("backup retention cleanup", "deleted", n)
			}
		}
	}
}

// ProcessOnce 认领并执行一个待处理任务，返回是否认领成功。
func (w *Worker) ProcessOnce(ctx context.Context) (bool, error) {
	job, err := w.store.Claim(ctx)
	if err != nil {
		return false, err
	}
	if job == nil {
		return false, nil
	}
	jobCtx, cancel := context.WithTimeout(ctx, JobTimeout)
	defer cancel()
	w.process(jobCtx, job)
	return true, nil
}

// process 执行单个任务：导出 → 验证 → 落库。任何失败标记 FAILED 并告警。
func (w *Worker) process(ctx context.Context, job *Job) {
	fail := func(code string, err error) {
		slog.Error("backup job failed", "id", job.ID, "code", code, "error", err)
		if dbErr := w.store.MarkFailed(ctx, job.ID, code, err); dbErr != nil {
			slog.Error("mark backup failed status error", "id", job.ID, "error", dbErr)
		}
		NotifyAlert(w.alertFn, "BACKUP_FAILED", "backup", "备份任务失败",
			"备份任务 "+job.ID.String()+" 失败（"+code+"）："+failMsg(err))
	}

	if w.exporter.enc == nil {
		fail(FailEncryption, ErrNoEncryption)
		return
	}
	dir := w.exporter.BackupDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		fail(FailExportFailed, err)
		return
	}
	tmpPath, err := SafeJoin(dir, TempFileName(job.ID))
	if err != nil {
		fail(FailExportFailed, err)
		return
	}

	// ---- 导出 ----
	var requestedBy string
	if job.RequestedBy != nil {
		requestedBy = job.RequestedBy.String()
	}
	m, fileHash, fileSize, err := w.exporter.Export(ctx, job.ID, job.BackupType, requestedBy, tmpPath)
	if err != nil {
		code := FailExportFailed
		if err == ErrTooLarge {
			code = FailSizeLimit
		}
		fail(code, err)
		return
	}

	// ---- 验证（未验证不得成功） ----
	if err := w.store.SetStatus(ctx, job.ID, StatusVerifying); err != nil {
		_ = os.Remove(tmpPath)
		fail(FailExportFailed, err)
		return
	}
	if _, err := w.exporter.Verify(ctx, tmpPath, ""); err != nil {
		_ = os.Remove(tmpPath)
		fail(FailVerifyFailed, err)
		return
	}

	// ---- 落库 + 原子改名 ----
	finalPath, err := SafeJoin(dir, BackupFileName(job.ID))
	if err != nil {
		_ = os.Remove(tmpPath)
		fail(FailExportFailed, err)
		return
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		fail(FailExportFailed, err)
		return
	}
	if err := w.store.MarkSuccess(ctx, job.ID, m, BackupFileName(job.ID), fileSize, fileHash); err != nil {
		_ = os.Remove(finalPath)
		fail(FailExportFailed, err)
		return
	}
	slog.Info("backup job success", "id", job.ID, "type", job.BackupType,
		"size", fileSize, "tables", len(m.Tables), "rows", m.TotalRows)
}

// VerifyBackup 手动验证：重算文件哈希并对照 DB 记录，通过后更新 verified。
// 验证失败的任务被标记 FAILED（不得保持"成功"外观）并产生告警。
func (w *Worker) VerifyBackup(ctx context.Context, id uuid.UUID) (*VerifyResult, error) {
	job, err := w.store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if job.Status != StatusSuccess && job.Status != StatusFailed {
		return nil, ErrInvalidStatus
	}
	if w.exporter.enc == nil {
		return nil, ErrNoEncryption
	}
	path, err := BackupPath(w.exporter.dataDir, id)
	if err != nil {
		return nil, err
	}
	res, err := w.exporter.Verify(ctx, path, job.FileHash)
	if err != nil {
		if dbErr := w.store.MarkVerified(ctx, id, false, err); dbErr != nil {
			slog.Error("mark verify result failed", "id", id, "error", dbErr)
		}
		NotifyAlert(w.alertFn, "BACKUP_VERIFY_FAILED", "backup", "备份验证失败",
			"备份 "+id.String()+" 验证失败："+failMsg(err))
		return nil, err
	}
	if err := w.store.MarkVerified(ctx, id, true, nil); err != nil {
		return nil, err
	}
	return res, nil
}

// CleanupRetention 执行保留清理：删除过期/超额任务的文件与记录。
func (w *Worker) CleanupRetention(ctx context.Context) (int, error) {
	candidates, err := w.store.RetentionCandidates(ctx, RetainRecentSuccess, time.Now().Add(-RetainMaxAge))
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, j := range candidates {
		path, err := BackupPath(w.exporter.dataDir, j.ID)
		if err == nil {
			if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
				slog.Error("remove backup file failed", "path", filepath.Base(path), "error", rmErr)
				continue // 文件删除失败则保留记录，下轮再试，不静默
			}
		}
		if err := w.store.Delete(ctx, j.ID); err != nil {
			slog.Error("delete backup job failed", "id", j.ID, "error", err)
			continue
		}
		deleted++
	}
	return deleted, nil
}
