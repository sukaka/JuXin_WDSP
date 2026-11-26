package tlssessions

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/settings"
)

const (
	retentionBatchSize  = 10000
	retentionBatchSleep = time.Second
	defaultRetentionDay = 7
)

// RetentionDaysProvider 返回日志留存天数（解耦 settings.Service，方便测试）。
type RetentionDaysProvider interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// RetentionCleaner 加密会话握手事件留存清理器（复用 logging.retention_days，默认 7 天）。
type RetentionCleaner struct {
	db       DBTX
	settings RetentionDaysProvider
}

// NewRetentionCleaner 创建加密会话事件留存清理器。
func NewRetentionCleaner(db *pgxpool.Pool, settingsSvc *settings.Service) *RetentionCleaner {
	var d DBTX
	if db != nil {
		d = db
	}
	var provider RetentionDaysProvider
	if settingsSvc != nil {
		provider = settingsSvc
	}
	return &RetentionCleaner{db: d, settings: provider}
}

// CleanOnce 执行一轮分批清理（单批最多 10000 行，避免长事务与锁表），返回删除总行数。
// 当 tls_handshake_events 已迁移为按日声明式分区表（relkind = 'p'）时跳过逐行 DELETE，
// 由 partitions.Manager 通过 DETACH PARTITION CONCURRENTLY / DROP TABLE 完成 O(1) 清理。
func (rc *RetentionCleaner) CleanOnce(ctx context.Context) (int64, error) {
	if rc.db == nil {
		return 0, nil
	}
	if row := rc.db.QueryRow(ctx, `
SELECT c.relkind::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relname = 'tls_handshake_events'
LIMIT 1`); row != nil {
		var relkind string
		if err := row.Scan(&relkind); err == nil && relkind == "p" {
			return 0, nil
		} else if err != nil && ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}

	days := defaultRetentionDay
	if rc.settings != nil {
		days = rc.settings.GetInt(ctx, "logging", "retention_days", defaultRetentionDay)
	}
	if days <= 0 {
		days = defaultRetentionDay
	}
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	var total int64
	for {
		res, err := rc.db.Exec(ctx, `
DELETE FROM tls_handshake_events WHERE id IN (
  SELECT id FROM tls_handshake_events WHERE occurred_at < $1 LIMIT $2
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

// Run 周期执行留存清理（默认每 10 分钟；实时读取最新 retention_days）。
func (rc *RetentionCleaner) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("tls session retention cleaner started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("tls session retention cleaner stopped")
			return
		case <-ticker.C:
			n, err := rc.CleanOnce(ctx)
			if err != nil {
				slog.Error("tls session retention clean error", "error", err)
			} else if n > 0 {
				slog.Info("tls session retention cleaned", "rows", n)
			}
		}
	}
}
