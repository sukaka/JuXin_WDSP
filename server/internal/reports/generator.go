package reports

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
)

// Generator 报告生成器：加载任务 → 采集 → 结论 → 渲染 → 写文件 → 记录产物。
type Generator struct {
	store     *Store
	collector *Collector
	dataDir   string
	fontPath  string
	timeout   time.Duration
}

// NewGenerator 创建报告生成器。
// fontPath 为内嵌中文字体路径（NotoSansCJKsc-VF.ttf），为空或文件缺失时
// PDF 降级为 ASCII 摘要页。
func NewGenerator(store *Store, db *pgxpool.Pool, agg *aggregations.Store, dataDir, fontPath string) *Generator {
	return &Generator{
		store:     store,
		collector: NewCollector(db, agg),
		dataDir:   dataDir,
		fontPath:  fontPath,
		timeout:   GenerateTimeout,
	}
}

// Generate 执行一次完整生成流程。任何失败都会标记任务 FAILED 并返回错误。
func (g *Generator) Generate(ctx context.Context, jobID uuid.UUID) error {
	job, err := g.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	switch job.Status {
	case StatusPending:
		if err := g.store.UpdateProgress(ctx, jobID, StatusCollecting, 10); err != nil {
			return g.fail(ctx, jobID, FailInvalidState, err)
		}
	case StatusCollecting:
		// 已被 worker 认领，继续
	default:
		return fmt.Errorf("%w: 任务状态 %s 不可生成", ErrInvalidState, job.Status)
	}

	// 1. 采集（COLLECTING → 40%）
	data, err := g.collector.Collect(ctx, CollectInput{
		ReportType:     job.ReportType,
		Start:          job.Start,
		End:            job.End,
		ApplicationIDs: job.ApplicationIDs,
	})
	if err != nil {
		return g.fail(ctx, jobID, FailCollect, err)
	}
	if err := ctx.Err(); err != nil {
		return g.fail(ctx, jobID, FailTimeout, err)
	}
	if err := g.store.UpdateProgress(ctx, jobID, StatusAggregating, 40); err != nil {
		return g.fail(ctx, jobID, FailInvalidState, err)
	}

	// 2. 模板与报告编号（AGGREGATING → 70%）
	tpl, err := g.jobTemplate(ctx, job)
	if err != nil {
		return g.fail(ctx, jobID, FailTemplate, err)
	}
	seq, err := g.store.NextMonthlySeq(ctx, job.RequestedAt)
	if err != nil {
		return g.fail(ctx, jobID, FailRender, fmt.Errorf("report no seq: %w", err))
	}
	reportNo := FormatReportNo(tpl.ReportNoFormat, job.RequestedAt, seq)
	if err := g.store.UpdateProgress(ctx, jobID, StatusRendering, 70); err != nil {
		return g.fail(ctx, jobID, FailInvalidState, err)
	}

	// 3. 渲染（RENDERING）
	html, err := RenderHTML(tpl, data, reportNo)
	if err != nil {
		return g.fail(ctx, jobID, FailRender, err)
	}
	content := html
	if job.FileFormat == FormatPDF {
		content, err = RenderPDF(tpl, data, reportNo, g.fontPath)
		if err != nil {
			code := FailRender
			if errors.Is(err, errPDFFont) {
				code = FailFont
			}
			return g.fail(ctx, jobID, code, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return g.fail(ctx, jobID, FailTimeout, err)
	}

	// 4. 写文件（权限0600 + sha256 + 大小限制）
	name := ReportFileName(job.ID, job.FileFormat)
	hash, size, err := writeReportFile(g.dataDir, name, content)
	if err != nil {
		code := FailWrite
		if len(content) > MaxReportFileSize {
			code = FailFileTooLarge
		}
		return g.fail(ctx, jobID, code, err)
	}

	// 5. 完成
	if err := g.store.CompleteJob(ctx, jobID, name, hash, job.FileFormat, size, reportNo); err != nil {
		return g.fail(ctx, jobID, FailWrite, fmt.Errorf("complete job: %w", err))
	}
	return nil
}

// jobTemplate 加载任务模板（未指定则用默认模板）。
func (g *Generator) jobTemplate(ctx context.Context, job *Job) (*Template, error) {
	if job.TemplateID != nil {
		return g.store.GetTemplate(ctx, *job.TemplateID)
	}
	if err := g.store.EnsureBuiltinTemplate(ctx); err != nil {
		return nil, err
	}
	return g.store.DefaultTemplate(ctx)
}

// fail 标记任务失败并返回错误。标记失败本身的错误只记录日志（不覆盖原始错误）。
func (g *Generator) fail(ctx context.Context, jobID uuid.UUID, code string, cause error) error {
	if ctx.Err() != nil {
		code = FailTimeout
	}
	if err := g.store.FailJob(context.Background(), jobID, code, cause.Error()); err != nil {
		slog.Error("mark report job failed failed", "job_id", jobID, "error", err)
	}
	return fmt.Errorf("generate report %s: %w", jobID, cause)
}

// errPDFFont 字体解析失败标记错误。
var errPDFFont = errors.New("pdf font unavailable")

// Run Worker 轮询 PENDING 任务（FOR UPDATE SKIP LOCKED 认领），带超时与失败标记。
// 供 main.go 以后台 goroutine 启动。
func (g *Generator) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	// 启动时确保内置模板存在（失败仅记录，后续任务加载模板时会重试）
	if err := g.store.EnsureBuiltinTemplate(ctx); err != nil {
		slog.Error("ensure builtin report template failed", "error", err)
	}
	// 启动时回收僵尸任务
	if n, err := g.store.ReclaimStaleJobs(ctx, GenerateTimeout); err != nil {
		slog.Error("reclaim stale report jobs failed", "error", err)
	} else if n > 0 {
		slog.Warn("reclaimed stale report jobs", "count", n)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	reclaimEvery := 0
	slog.Info("report generator worker started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reclaimEvery++
			if reclaimEvery%30 == 0 { // 约每 60s（interval=2s）
				if n, err := g.store.ReclaimStaleJobs(ctx, GenerateTimeout); err != nil {
					slog.Error("reclaim stale report jobs failed", "error", err)
				} else if n > 0 {
					slog.Warn("reclaimed stale report jobs", "count", n)
				}
			}
			g.processOne(ctx)
		}
	}
}

// processOne 认领并处理一个待生成任务。
func (g *Generator) processOne(ctx context.Context) {
	job, err := g.store.ClaimPending(ctx)
	if err != nil {
		slog.Error("claim report job failed", "error", err)
		return
	}
	if job == nil {
		return
	}
	jobCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	start := time.Now()
	if err := g.Generate(jobCtx, job.ID); err != nil {
		slog.Error("report generate failed",
			"job_id", job.ID, "report_type", job.ReportType, "error", err)
		return
	}
	slog.Info("report generated",
		"job_id", job.ID, "report_type", job.ReportType, "elapsed", time.Since(start))
}
