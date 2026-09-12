package accesslogs

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// retentionBatchSize 单批删除行数上限（分批防长事务/锁表）。
const retentionBatchSize = 10000

// retentionBatchSleep 批间暂停（给业务查询让行）。
const retentionBatchSleep = time.Second

// RetentionCleaner 访问日志留存清理（按 logging.retention_days 定期批量删除）。
type RetentionCleaner struct {
	db       *pgxpool.Pool
	settings *settings.Service
}

// NewRetentionCleaner 创建留存清理器。
func NewRetentionCleaner(db *pgxpool.Pool, settingsSvc *settings.Service) *RetentionCleaner {
	return &RetentionCleaner{db: db, settings: settingsSvc}
}

// CleanOnce 执行一轮清理（分批删除，直到删完）；返回删除总行数。
func (rc *RetentionCleaner) CleanOnce(ctx context.Context) (int64, error) {
	days := rc.settings.GetInt(ctx, "logging", "retention_days", 7)
	if days <= 0 {
		days = 7
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	var total int64
	for {
		res, err := rc.db.Exec(ctx, `
DELETE FROM access_logs WHERE id IN (
  SELECT id FROM access_logs WHERE occurred_at < $1 LIMIT $2
)`, cutoff, retentionBatchSize)
		if err != nil {
			return total, err
		}
		n := res.RowsAffected()
		total += n
		if n < retentionBatchSize {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(retentionBatchSleep):
		}
	}
}

// Run 定期清理（默认每 10 分钟；每次读最新 retention_days，设置修改即时生效）。
func (rc *RetentionCleaner) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("access log retention cleaner started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("access log retention cleaner stopped")
			return
		case <-ticker.C:
			n, err := rc.CleanOnce(ctx)
			if err != nil {
				slog.Error("access log retention clean error", "error", err)
			} else if n > 0 {
				slog.Info("access log retention cleaned", "rows", n)
			}
		}
	}
}
