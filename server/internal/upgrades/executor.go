package upgrades

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/backups"
)

const defaultExecutorWait = 30 * time.Minute

// ExecutorRequest 是 API 与宿主机升级执行器之间的最小文件协议。
type ExecutorRequest struct {
	JobID         string    `json:"job_id"`
	PackageFile   string    `json:"package_file"`
	PackageSHA256 string    `json:"package_sha256"`
	VersionFrom   string    `json:"version_from"`
	VersionTo     string    `json:"version_to"`
	RequestedAt   time.Time `json:"requested_at"`
}

// ExecutorResult 是宿主机执行器回写的终态结果。
type ExecutorResult struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"`
	Stage      string    `json:"stage"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Message    string    `json:"message,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

// SetExecutorDirs 配置容器内共享的升级包目录与执行器任务目录。
func (s *Service) SetExecutorDirs(packagesDir, executorDir string) {
	s.packagesDir = filepath.Clean(packagesDir)
	s.executorDir = filepath.Clean(executorDir)
}

func (s *Service) submitExecutorJob(ctx context.Context, job *Job) error {
	if s.executorDir == "" || s.packagesDir == "" || job.PackageID == nil {
		return errors.New("宿主机升级执行器目录未配置")
	}
	pkg, err := s.store.GetPackage(ctx, *job.PackageID)
	if err != nil {
		return err
	}
	name := filepath.Base(pkg.FileName)
	if name != pkg.FileName || name == "." || name == "" {
		return errors.New("升级包文件名无效")
	}
	if len(pkg.FileHash) != 64 {
		return errors.New("升级包 SHA-256 无效")
	}
	packagePath := filepath.Join(s.packagesDir, name)
	if _, err := os.Stat(packagePath); err != nil {
		return fmt.Errorf("升级包文件不可用: %w", err)
	}
	// 执行器任务落盘前再次复核固定信任根、包内 manifest 与文件清单。
	// 预检通过不等于执行时仍然安全：共享目录中的包可能在两次检查之间被替换。
	if s.prechecker != nil {
		if err := s.prechecker.VerifyArtifact(packagePath, pkg); err != nil {
			return fmt.Errorf("升级包固定信任根验证失败: %w", err)
		}
	} else if err := verifyPackageArtifact(packagePath, pkg); err != nil {
		return fmt.Errorf("升级包固定信任根验证失败: %w", err)
	}
	req := ExecutorRequest{
		JobID: job.ID.String(), PackageFile: name, PackageSHA256: strings.ToLower(pkg.FileHash),
		VersionFrom: pkg.VersionFrom, VersionTo: pkg.VersionTo, RequestedAt: time.Now().UTC(),
	}
	return writeJSONAtomic(filepath.Join(s.executorDir, "jobs", req.JobID+".json"), req, 0o640)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func readExecutorResult(path string) (*ExecutorResult, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var result ExecutorResult
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(result.JobID); err != nil {
		return nil, errors.New("执行器结果中的任务 ID 无效")
	}
	if result.Status != "SUCCESS" && result.Status != "FAILED" {
		return nil, errors.New("执行器结果状态无效")
	}
	return &result, nil
}

func (s *Service) waitExecutorResult(ctx context.Context, id uuid.UUID) (*ExecutorResult, error) {
	deadline := time.NewTimer(s.executorWait)
	defer deadline.Stop()
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	path := filepath.Join(s.executorDir, "results", id.String()+".json")
	for {
		result, err := readExecutorResult(path)
		if err == nil {
			if result.JobID != id.String() {
				return nil, errors.New("宿主机执行器返回了错误的任务 ID")
			}
			return result, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("读取宿主机执行结果: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("等待宿主机升级执行器超时")
		case <-ticker.C:
		}
	}
}

func (s *Service) processExecutorResult(ctx context.Context, result *ExecutorResult) error {
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	id, err := uuid.Parse(result.JobID)
	if err != nil {
		return err
	}
	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if job.Status == StatusSuccess || job.Status == StatusFailed || job.Status == StatusRolledBack {
		return nil
	}
	if result.Status == "FAILED" {
		code := result.ErrorCode
		if code == "" {
			code = FailApply
		}
		stepErr := fmt.Errorf("宿主机升级失败（%s）：%s", code, result.Message)
		if err := s.rollback(ctx, id, job.RequestedBy); err != nil {
			combined := fmt.Errorf("%v；自动回滚失败：%w", stepErr, err)
			_ = s.store.MarkFailed(context.Background(), id, FailRollback, combined)
			backups.NotifyAlert(s.alertFn, "UPGRADE_ROLLBACK_FAILED", "UPGRADE", "升级失败且自动回滚失败",
				"升级任务 "+id.String()+" 的宿主机执行失败，自动恢复数据库失败："+failMsg(err))
			return combined
		}
		if err := s.store.MarkFinished(context.Background(), id, StatusRolledBack); err != nil {
			return err
		}
		backups.NotifyAlert(s.alertFn, "UPGRADE_ROLLED_BACK", "UPGRADE", "升级失败已自动回滚",
			"升级任务 "+id.String()+" 的宿主机执行失败，容器镜像和数据库均已尝试恢复："+failMsg(stepErr))
		return nil
	}
	if job.Status == StatusApplying {
		if err := s.store.Transition(ctx, id, StatusApplying, StatusMigrating); err != nil {
			return err
		}
		job.Status = StatusMigrating
	}
	if job.Status == StatusMigrating {
		if err := s.store.Transition(ctx, id, StatusMigrating, StatusVerifying); err != nil {
			return err
		}
	}
	if err := s.verify(ctx); err != nil {
		return err
	}
	return s.store.MarkFinished(ctx, id, StatusSuccess)
}

// RunResultReconciler 在 API 因升级重启后补偿处理宿主机已写入的结果。
func (s *Service) RunResultReconciler(ctx context.Context) {
	if s.executorDir == "" {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		s.reconcileResults(ctx)
		s.reconcileExpiredApplying(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) reconcileResults(ctx context.Context) {
	entries, err := os.ReadDir(filepath.Join(s.executorDir, "results"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		result, err := readExecutorResult(filepath.Join(s.executorDir, "results", entry.Name()))
		if err != nil {
			continue
		}
		_ = s.processExecutorResult(ctx, result)
	}
}

// reconcileExpiredApplying 兜底终结滞留 APPLYING 任务（NG-REL-02 批次 C 实证 F7）：
// 执行器被中断（无结果文件）且 API 重启后，进程内等待定时器已丢失；以持久化
// executor_deadline 为准，超期任务标记 FAILED/EXECUTOR_TIMEOUT 并留审计与告警。
// 不自动重跑、不假装成功：执行器镜像/数据侧状态由人工核查，任务可经既有
// FAILED → ROLLING_BACK 手动回滚入口处置。
func (s *Service) reconcileExpiredApplying(ctx context.Context) {
	if s.stranded == nil {
		return
	}
	jobs, err := s.stranded.ListExpiredApplyingJobs(ctx, time.Now(), s.executorWait)
	if err != nil {
		slog.Error("list expired applying upgrade jobs failed", "error", err)
		return
	}
	for i := range jobs {
		job := &jobs[i]
		// 结果文件已落盘的任务交给 reconcileResults 正常处理，不按超时终结。
		if _, err := os.Stat(filepath.Join(s.executorDir, "results", job.ID.String()+".json")); err == nil {
			continue
		}
		closeErr := fmt.Errorf("宿主机升级执行器超期（%s）未返回终态结果，任务按中断终结；不自动重跑，请人工核查执行器与镜像/数据状态后可手动回滚", s.executorWait)
		if err := s.stranded.MarkFailedIfStatus(ctx, job.ID, StatusApplying, FailExecutorTimeout, closeErr); err != nil {
			if !errors.Is(err, ErrInvalidStatus) {
				slog.Error("close stranded applying upgrade job failed", "id", job.ID, "error", err)
			}
			continue
		}
		slog.Warn("stranded applying upgrade job closed", "id", job.ID, "code", FailExecutorTimeout)
		s.recordStrandedAudit(ctx, job)
		backups.NotifyAlert(s.alertFn, "UPGRADE_FAILED", "UPGRADE", "升级执行器超时，滞留任务已终结",
			"升级任务 "+job.ID.String()+" 等待宿主机执行器结果超期（含 API 重启前等待），已按中断标记失败（EXECUTOR_TIMEOUT）；不自动重跑，请人工核查后处置")
	}
}

// recordStrandedAudit 滞留任务终结审计（系统动作，操作人取任务创建人；高危）。
func (s *Service) recordStrandedAudit(ctx context.Context, job *Job) {
	if s.auditFn == nil {
		return
	}
	in := audits.RecordInput{
		UserID:       job.RequestedBy,
		Module:       "upgrades",
		Action:       "executor_timeout_close",
		ObjectType:   "upgrade",
		ObjectID:     job.ID.String(),
		AfterSummary: "宿主机升级执行器超期未返回终态结果，滞留 APPLYING 任务已按中断终结（不自动重跑，可手动回滚）",
		Result:       audits.ResultSuccess,
		RiskLevel:    audits.RiskHigh,
		RequestID:    job.RequestID,
	}
	if err := s.auditFn(ctx, in); err != nil {
		slog.Error("record stranded upgrade audit failed", "job_id", job.ID, "error", err)
	}
}
