// service.go 升级执行编排：PRECHECK → BACKUP → APPLYING → MIGRATING → VERIFYING，
// 失败自动 ROLLING_BACK（恢复升级前备份）→ ROLLED_BACK。
package upgrades

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/restores"
)

// 默认等待参数
const (
	defaultBackupWait  = 30 * time.Minute
	defaultRestoreWait = 60 * time.Minute
	defaultPoll        = 5 * time.Second
	// defaultScheduleTick 定时任务到点检查周期（与 RunResultReconciler 同周期）
	defaultScheduleTick = 3 * time.Second
)

// scheduleStore 定时升级所需的持久化能力（*Store 实现；测试可注入内存实现，
// 同 Handler 的 packageRegistrar/upgradeExecutor 测试替换模式）。
type scheduleStore interface {
	GetPackage(ctx context.Context, id uuid.UUID) (*Package, error)
	GetJob(ctx context.Context, id uuid.UUID) (*Job, error)
	CreateScheduledJobIfNoActive(ctx context.Context, packageID uuid.UUID, requestedBy *uuid.UUID, requestID string, scheduledAt time.Time) (*Job, error)
	ListDueScheduledJobs(ctx context.Context, now time.Time) ([]Job, error)
	PromoteScheduledToPending(ctx context.Context, id uuid.UUID, now time.Time) error
	CancelScheduled(ctx context.Context, id uuid.UUID) error
}

// strandedStore 滞留 APPLYING 任务兜底清扫所需的持久化能力
// （*Store 实现；测试可注入内存实现，同 scheduleStore 模式）。
type strandedStore interface {
	ListExpiredApplyingJobs(ctx context.Context, cutoff time.Time, wait time.Duration) ([]Job, error)
	MarkFailedIfStatus(ctx context.Context, id uuid.UUID, from, code string, err error) error
}

// Service 升级服务。
type Service struct {
	db            *pgxpool.Pool
	store         *Store
	backupStore   *backups.Store
	restores      *restores.Service
	prechecker    *Prechecker
	migrationsDir string
	alertFn       backups.AlertFunc
	packagesDir   string
	executorDir   string
	resultMu      sync.Mutex

	backupWait  time.Duration
	restoreWait time.Duration
	poll        time.Duration
	// executorWait 等待宿主机执行器终态结果的上限（进程内定时器随 API 退出丢失；
	// 进入 APPLYING 时持久化 executor_deadline = 当前时刻 + executorWait 供重启后兜底清扫）。
	executorWait time.Duration

	// 定时升级（测试可替换的协作点，生产由 NewService 绑定默认实现）
	schedStore   scheduleStore
	stranded     strandedStore
	nowFn        func() time.Time
	startRun     func(id uuid.UUID)
	auditFn      func(ctx context.Context, in audits.RecordInput) error
	scheduleTick time.Duration
}

// NewService 创建升级服务。
func NewService(db *pgxpool.Pool, store *Store, backupStore *backups.Store, restoreSvc *restores.Service,
	prechecker *Prechecker, migrationsDir string, alertFn backups.AlertFunc) *Service {
	s := &Service{
		db: db, store: store, backupStore: backupStore, restores: restoreSvc,
		prechecker: prechecker, migrationsDir: migrationsDir, alertFn: alertFn,
		backupWait: defaultBackupWait, restoreWait: defaultRestoreWait, poll: defaultPoll,
		executorWait: defaultExecutorWait,
		schedStore: store, stranded: store, nowFn: time.Now, scheduleTick: defaultScheduleTick,
	}
	s.startRun = func(id uuid.UUID) { go s.run(id) }
	return s
}

// SetTimeouts 覆盖等待参数（测试用）。
func (s *Service) SetTimeouts(backupWait, restoreWait, poll time.Duration) {
	if backupWait > 0 {
		s.backupWait = backupWait
	}
	if restoreWait > 0 {
		s.restoreWait = restoreWait
	}
	if poll > 0 {
		s.poll = poll
	}
}

// SetScheduleStore 为隔离测试注入内存版定时任务存储；生产装配使用 store。
func (s *Service) SetScheduleStore(ss scheduleStore) *Service {
	s.schedStore = ss
	return s
}

// SetStrandedStore 为隔离测试注入内存版滞留任务存储；生产装配使用 store。
func (s *Service) SetStrandedStore(ss strandedStore) *Service {
	s.stranded = ss
	return s
}

// SetNowFunc 为隔离测试注入时钟；生产默认 time.Now。
func (s *Service) SetNowFunc(fn func() time.Time) *Service {
	s.nowFn = fn
	return s
}

// SetStartRunFunc 为隔离测试替换 promote 后的执行启动入口（默认异步进入正常执行流程）。
func (s *Service) SetStartRunFunc(fn func(id uuid.UUID)) *Service {
	s.startRun = fn
	return s
}

// SetAuditFunc 注入定时执行 promote 的审计记录入口（装配层绑定 audits.Service.Record）。
func (s *Service) SetAuditFunc(fn func(ctx context.Context, in audits.RecordInput) error) *Service {
	s.auditFn = fn
	return s
}

// SetScheduleTick 覆盖定时任务到点检查周期（测试用）。
func (s *Service) SetScheduleTick(d time.Duration) *Service {
	if d > 0 {
		s.scheduleTick = d
	}
	return s
}

// RunPrecheck 对升级包执行预检（不落任务，供单独预检接口）。
func (s *Service) RunPrecheck(ctx context.Context, packageID uuid.UUID) ([]CheckItem, error) {
	pkg, err := s.store.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	facts := s.prechecker.Gather(ctx, pkg)
	return Evaluate(facts), nil
}

// Execute 创建升级任务并异步执行。
func (s *Service) Execute(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string) (*Job, error) {
	pkg, err := s.store.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	if pkg.Status != PackageVerified {
		return nil, ErrPackageNotVerified
	}
	job, err := s.store.CreateJobIfNoActive(ctx, packageID, &requestedBy, requestID)
	if err != nil {
		return nil, err
	}
	go s.run(job.ID)
	return job, nil
}

// Schedule 创建定时升级任务（SCHEDULED），不立即启动；
// 到点由 RunScheduler promote 为 PENDING 后进入与 Execute 相同的执行流程。
// VERIFIED 校验与活动任务互斥语义同 Execute；scheduledAt 的合法性由上传入口
// ParseScheduledAt 保证，此处仅落库（统一 UTC）。
func (s *Service) Schedule(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string, scheduledAt time.Time) (*Job, error) {
	pkg, err := s.schedStore.GetPackage(ctx, packageID)
	if err != nil {
		return nil, err
	}
	if pkg.Status != PackageVerified {
		return nil, ErrPackageNotVerified
	}
	return s.schedStore.CreateScheduledJobIfNoActive(ctx, packageID, &requestedBy, requestID, scheduledAt.UTC())
}

// Cancel 取消定时升级任务：仅 SCHEDULED 状态可取消（转为终态 CANCELLED）；
// 已进入 PENDING 及以后的任务返回 ErrInvalidStatus（任务已开始，无法取消）。
func (s *Service) Cancel(ctx context.Context, jobID, requestedBy uuid.UUID) (*Job, error) {
	job, err := s.schedStore.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.Status != StatusScheduled {
		return nil, fmt.Errorf("%w: 任务已开始，无法取消（当前状态 %s）", ErrInvalidStatus, job.Status)
	}
	if err := s.schedStore.CancelScheduled(ctx, jobID); err != nil {
		return nil, err
	}
	return s.schedStore.GetJob(ctx, jobID)
}

// RunScheduler 周期检查到点的定时升级任务并 promote 进入正常执行流程。
func (s *Service) RunScheduler(ctx context.Context) {
	ticker := time.NewTicker(s.scheduleTick)
	defer ticker.Stop()
	for {
		s.promoteDueScheduled(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// promoteDueScheduled 将到点（SCHEDULED && scheduled_at <= now）的任务 promote 为
// PENDING 并启动执行。promote 与取消互为乐观竞争，失败方如实记审计，不静默。
func (s *Service) promoteDueScheduled(ctx context.Context) {
	now := s.nowFn()
	jobs, err := s.schedStore.ListDueScheduledJobs(ctx, now)
	if err != nil {
		slog.Error("list due scheduled upgrade jobs failed", "error", err)
		return
	}
	for i := range jobs {
		job := &jobs[i]
		if err := s.schedStore.PromoteScheduledToPending(ctx, job.ID, now); err != nil {
			slog.Error("promote scheduled upgrade job failed", "id", job.ID, "error", err)
			s.recordScheduleAudit(ctx, job, audits.ResultFailure, err.Error())
			continue
		}
		slog.Info("scheduled upgrade job promoted", "id", job.ID, "scheduled_at", job.ScheduledAt)
		s.recordScheduleAudit(ctx, job, audits.ResultSuccess, "")
		s.startRun(job.ID)
	}
}

// recordScheduleAudit 定时执行 promote 审计（系统动作，操作人取任务创建人；高危）。
func (s *Service) recordScheduleAudit(ctx context.Context, job *Job, result, failReason string) {
	if s.auditFn == nil {
		return
	}
	in := audits.RecordInput{
		UserID:        job.RequestedBy,
		Module:        "upgrades",
		Action:        "scheduled_execute",
		ObjectType:    "upgrade",
		ObjectID:      job.ID.String(),
		AfterSummary:  "到点自动开始定时升级（scheduled_at=" + scheduledAtText(job.ScheduledAt) + "）",
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskHigh,
		RequestID:     job.RequestID,
	}
	if err := s.auditFn(ctx, in); err != nil {
		slog.Error("record scheduled upgrade audit failed", "job_id", job.ID, "error", err)
	}
}

func scheduledAtText(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// run 升级主流程（异步）。任何失败落库并告警，绝不静默。
func (s *Service) run(id uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), s.backupWait+s.restoreWait+30*time.Minute)
	defer cancel()
	fail := func(code string, err error) {
		slog.Error("upgrade job failed", "id", id, "code", code, "error", err)
		if dbErr := s.store.MarkFailed(context.Background(), id, code, err); dbErr != nil {
			slog.Error("mark upgrade failed status error", "id", id, "error", dbErr)
		}
		backups.NotifyAlert(s.alertFn, "UPGRADE_FAILED", "UPGRADE", "升级任务失败",
			"升级任务 "+id.String()+" 失败（"+code+"）："+failMsg(err))
	}

	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		slog.Error("load upgrade job failed", "id", id, "error", err)
		return
	}

	// ---- PRECHECK ----
	if err := s.store.Transition(ctx, id, StatusPending, StatusPrecheck); err != nil {
		fail(FailPrecheck, err)
		return
	}
	items, err := s.RunPrecheck(ctx, *job.PackageID)
	if err != nil {
		fail(FailPrecheck, err)
		return
	}
	if err := s.store.SetPrecheck(ctx, id, items); err != nil {
		fail(FailPrecheck, err)
		return
	}
	if HasFail(items) {
		fail(FailPrecheck, fmt.Errorf("升级前检查未通过：%s", firstFailMessage(items)))
		return
	}

	// ---- BACKUP（升级前必须备份） ----
	if err := s.store.Transition(ctx, id, StatusPrecheck, StatusBackup); err != nil {
		fail(FailBackup, err)
		return
	}
	backupJob, err := s.backupStore.Create(ctx, backups.TypeFull, job.RequestedBy, "upgrade-"+id.String())
	if err != nil {
		fail(FailBackup, err)
		return
	}
	if err := s.store.SetBackupJob(ctx, id, backupJob.ID); err != nil {
		fail(FailBackup, err)
		return
	}
	if err := s.waitBackup(ctx, backupJob.ID); err != nil {
		fail(FailBackup, err)
		return
	}

	// 备份成功之后的失败均需自动回滚
	rollbackOnFail := func(stage, code string, stepErr error) {
		slog.Error("upgrade stage failed, rolling back", "id", id, "stage", stage, "error", stepErr)
		if rbErr := s.rollback(context.Background(), id, job.RequestedBy); rbErr != nil {
			combined := fmt.Errorf("%v；自动回滚失败：%w", stepErr, rbErr)
			slog.Error("upgrade auto rollback failed", "id", id, "error", rbErr)
			if dbErr := s.store.MarkFailed(context.Background(), id, FailRollback, combined); dbErr != nil {
				slog.Error("mark upgrade rollback-failed status error", "id", id, "error", dbErr)
			}
			backups.NotifyAlert(s.alertFn, "UPGRADE_ROLLBACK_FAILED", "UPGRADE", "升级失败且自动回滚失败",
				"升级任务 "+id.String()+" 阶段 "+stage+" 失败，自动回滚失败："+failMsg(rbErr))
			return
		}
		if dbErr := s.store.MarkFinished(context.Background(), id, StatusRolledBack); dbErr != nil {
			slog.Error("mark upgrade rolled-back status error", "id", id, "error", dbErr)
		}
		backups.NotifyAlert(s.alertFn, "UPGRADE_ROLLED_BACK", "UPGRADE", "升级失败已自动回滚",
			"升级任务 "+id.String()+" 阶段 "+stage+" 失败（"+code+"），已恢复升级前备份："+failMsg(stepErr))
	}

	// ---- APPLYING（提交宿主机执行器；执行器负责镜像、迁移、健康检查与容器回滚） ----
	if err := s.store.Transition(ctx, id, StatusBackup, StatusApplying); err != nil {
		rollbackOnFail(StatusApplying, FailApply, err)
		return
	}
	// 持久化执行器等待截止：进程内等待定时器随 API 重启丢失，
	// 重启后的兜底清扫以此 deadline 终结滞留任务（F7）。
	if err := s.store.SetExecutorDeadline(ctx, id, time.Now().UTC().Add(s.executorWait)); err != nil {
		rollbackOnFail(StatusApplying, FailApply, err)
		return
	}
	if err := s.applyDryRun(*job.PackageID); err != nil {
		rollbackOnFail(StatusApplying, FailApply, err)
		return
	}
	if err := s.submitExecutorJob(ctx, job); err != nil {
		rollbackOnFail(StatusApplying, FailApply, err)
		return
	}
	result, err := s.waitExecutorResult(ctx, id)
	if err != nil {
		rollbackOnFail(StatusApplying, FailApply, err)
		return
	}
	if err := s.processExecutorResult(context.Background(), result); err != nil {
		rollbackOnFail(result.Stage, result.ErrorCode, err)
	}
}

// applyDryRun 迁移 dry-run 校验：迁移文件成对（up/down）且版本序列可读；
// 记录组件目标版本（镜像切换由宿主机升级执行器完成）。
func (s *Service) applyDryRun(packageID uuid.UUID) error {
	pkg, err := s.store.GetPackage(context.Background(), packageID)
	if err != nil {
		return err
	}
	if err := checkMigrationFiles(s.migrationsDir); err != nil {
		return err
	}
	slog.Info("upgrade apply dry-run ok",
		"package", pkg.FileName, "version_to", pkg.VersionTo,
		"note", "即将提交宿主机升级执行器")
	return nil
}

// checkMigrationFiles 校验迁移目录：每个 NNNNNN_name.up.sql 必须有对应 .down.sql。
func checkMigrationFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	ups := map[string]string{}
	downs := map[string]bool{}
	for _, e := range entries {
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m != nil {
			ups[m[1]] = e.Name()
			continue
		}
		if downRe.MatchString(e.Name()) {
			downs[e.Name()] = true
		}
	}
	if len(ups) == 0 {
		return fmt.Errorf("no migration files found in %s", dir)
	}
	for v, up := range ups {
		down := up[:len(up)-len(".up.sql")] + ".down.sql"
		if !downs[down] {
			return fmt.Errorf("migration %s (version %s) missing down file %s（迁移必须具备回滚能力）", up, v, down)
		}
	}
	return nil
}

// downRe 迁移回滚文件名。
var downRe = regexp.MustCompile(`^\d{6}_[a-z0-9_]+\.down\.sql$`)

// verify 升级后验证：db ping、迁移版本核对（当前版本应为本地最大版本）。
func (s *Service) verify(ctx context.Context) error {
	if err := s.db.Ping(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}
	if s.prechecker.pingValkey != nil {
		if err := s.prechecker.pingValkey(ctx); err != nil {
			return fmt.Errorf("valkey ping: %w", err)
		}
	}
	cur, err := backups.SchemaVersion(ctx, s.db)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	maxLocal := MaxMigrationVersion(s.migrationsDir)
	if cur != maxLocal {
		return fmt.Errorf("迁移版本核对失败：当前 %d，本地文件最大 %d", cur, maxLocal)
	}
	return nil
}

// waitBackup 等待备份任务到达终态（SUCCESS 为准；FAILED/CANCELLED/超时均为失败）。
func (s *Service) waitBackup(ctx context.Context, id uuid.UUID) error {
	deadline := time.Now().Add(s.backupWait)
	for {
		job, err := s.backupStore.GetByID(ctx, id)
		if err != nil {
			return err
		}
		switch job.Status {
		case backups.StatusSuccess:
			if !job.Verified {
				return fmt.Errorf("备份任务 %s 成功但未通过验证", id)
			}
			return nil
		case backups.StatusFailed, backups.StatusCancelled:
			return fmt.Errorf("备份任务 %s 未成功（%s）：%s", id, job.Status, job.FailureMessage)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待备份任务 %s 完成超时", id)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.poll):
		}
	}
}

// rollback 使用升级前备份执行恢复（validate → create → 等待 AWAITING_CONFIRM → confirm）。
// 状态先迁移到 ROLLING_BACK，由调用方在成功后 MarkFinished(ROLLED_BACK)。
func (s *Service) rollback(ctx context.Context, id uuid.UUID, requestedBy *uuid.UUID) error {
	job, err := s.store.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if job.BackupJobID == nil {
		return ErrNoBackup
	}
	if err := s.store.Transition(ctx, id, job.Status, StatusRollingBack); err != nil {
		return err
	}
	return s.restoreFromBackup(ctx, *job.BackupJobID, requestedBy)
}

// restoreFromBackup 驱动 restores.Service 完成正式恢复。
func (s *Service) restoreFromBackup(ctx context.Context, backupID uuid.UUID, requestedBy *uuid.UUID) error {
	if s.restores == nil {
		return fmt.Errorf("恢复服务未配置")
	}
	if _, err := s.restores.ValidateBackup(ctx, backupID); err != nil {
		return fmt.Errorf("备份校验失败：%w", err)
	}
	rj, err := s.restores.Create(ctx, backupID, restores.ScopeFull, requestedBy, "upgrade-rollback")
	if err != nil {
		return fmt.Errorf("创建恢复任务失败：%w", err)
	}
	confirmedBy := uuid.Nil
	if requestedBy != nil {
		confirmedBy = *requestedBy
	}
	deadline := time.Now().Add(s.restoreWait)
	for {
		cur, err := s.restoresStoreGet(ctx, rj.ID)
		if err != nil {
			return err
		}
		switch cur {
		case restores.StatusAwaitingConfirm:
			if _, _, err := s.restores.Confirm(ctx, rj.ID, confirmedBy); err != nil {
				return fmt.Errorf("正式恢复失败：%w", err)
			}
			return nil
		case restores.StatusFailed, restores.StatusCancelled:
			return fmt.Errorf("恢复任务 %s 未就绪（%s）", rj.ID, cur)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待恢复任务 %s 就绪超时", rj.ID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.poll):
		}
	}
}

// restoresStoreGet 查询恢复任务状态（通过 restores.Store 所在库）。
func (s *Service) restoresStoreGet(ctx context.Context, id uuid.UUID) (string, error) {
	var status string
	err := s.db.QueryRow(ctx, `SELECT status FROM restore_jobs WHERE id = $1`, id).Scan(&status)
	return status, err
}

// Rollback 显式回滚已完成/失败的升级任务（异步执行恢复）。
func (s *Service) Rollback(ctx context.Context, jobID, requestedBy uuid.UUID) (*Job, error) {
	job, err := s.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.Status != StatusSuccess && job.Status != StatusFailed {
		return nil, fmt.Errorf("%w: 仅 SUCCESS/FAILED 状态可显式回滚（当前 %s）", ErrInvalidStatus, job.Status)
	}
	if job.BackupJobID == nil {
		return nil, ErrNoBackup
	}
	if err := s.store.Transition(ctx, jobID, job.Status, StatusRollingBack); err != nil {
		return nil, err
	}
	go func() {
		rctx, cancel := context.WithTimeout(context.Background(), s.restoreWait+10*time.Minute)
		defer cancel()
		if err := s.restoreFromBackup(rctx, *job.BackupJobID, &requestedBy); err != nil {
			slog.Error("upgrade manual rollback failed", "id", jobID, "error", err)
			if dbErr := s.store.MarkFailed(context.Background(), jobID, FailRollback, err); dbErr != nil {
				slog.Error("mark rollback failed status error", "id", jobID, "error", dbErr)
			}
			backups.NotifyAlert(s.alertFn, "UPGRADE_ROLLBACK_FAILED", "UPGRADE", "升级回滚失败",
				"升级任务 "+jobID.String()+" 回滚失败："+failMsg(err))
			return
		}
		if err := s.store.MarkFinished(context.Background(), jobID, StatusRolledBack); err != nil {
			slog.Error("mark rolled-back status error", "id", jobID, "error", err)
		}
		slog.Info("upgrade manual rollback success", "id", jobID)
	}()
	return s.store.GetJob(ctx, jobID)
}

// firstFailMessage 取首个 FAIL 预检项描述。
func firstFailMessage(items []CheckItem) string {
	for _, it := range items {
		if it.Result == CheckFail {
			return it.Name + ": " + it.Message
		}
	}
	return ""
}
