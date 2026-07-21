package securityevents

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Collector 是安全事件采集器。
type Collector struct {
	db          *pgxpool.Pool
	store       *Store
	collectorID string
	logPath     string
	nodeName    string
	batchSize   int
	// 指标
	processedCount int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。
func NewCollector(db *pgxpool.Pool, collectorID, logPath, nodeName string) *Collector {
	return &Collector{
		db:          db,
		store:       NewStore(db),
		collectorID: collectorID,
		logPath:     logPath,
		nodeName:    nodeName,
		batchSize:   100,
	}
}

// Metrics 返回采集指标。
func (c *Collector) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"collector_id":    c.collectorID,
		"processed_count": c.processedCount,
		"failed_count":    c.failedCount,
		"last_processed":  c.lastProcessed,
		"log_path":        c.logPath,
	}
}

// checkpoint 是采集断点。
type checkpoint struct {
	offset int64
	inode  uint64
}

// loadCheckpoint 从数据库加载断点。
func (c *Collector) loadCheckpoint(ctx context.Context) (*checkpoint, error) {
	var cp checkpoint
	err := c.db.QueryRow(ctx,
		`SELECT file_offset, file_inode FROM event_collector_checkpoints WHERE collector_id = $1`, c.collectorID).Scan(&cp.offset, &cp.inode)
	if err != nil {
		// 无断点，从头开始
		return &checkpoint{offset: 0, inode: 0}, nil
	}
	return &cp, nil
}

// saveCheckpoint 保存断点。
func (c *Collector) saveCheckpoint(ctx context.Context, offset, inode int64) error {
	_, err := c.db.Exec(ctx, `
INSERT INTO event_collector_checkpoints (collector_id, file_path, file_offset, file_inode, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (collector_id) DO UPDATE SET file_offset=$3, file_inode=$4, updated_at=now()`,
		c.collectorID, c.logPath, offset, inode)
	return err
}

// fileInode 获取文件 inode（用于轮转检测，Unix 系统）。
func fileInode(f *os.File) uint64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat != nil {
		return stat.Ino
	}
	return 0
}

// CollectOnce 执行一次采集（读取新增内容并入库）。返回处理行数。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	cp, err := c.loadCheckpoint(ctx)
	if err != nil {
		return 0, err
	}

	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 日志文件尚未生成（无攻击事件时正常）
		}
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	currentInode := fileInode(f)

	// 轮转检测：inode 变化或文件变小（被截断）→ 从头读取
	offset := cp.offset
	if (cp.inode != 0 && currentInode != cp.inode) || info.Size() < offset {
		slog.Info("audit log rotated, resetting offset", "collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
	}
	if info.Size() == offset {
		return 0, nil // 无新内容
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(f)
	processed := 0
	batch := 0
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			batch++
			c.processLine(ctx, line)
			if batch >= c.batchSize {
				// 批量后保存断点
				newOffset, _ := f.Seek(0, io.SeekCurrent)
				newOffset -= int64(reader.Buffered())
				_ = c.saveCheckpoint(ctx, newOffset, int64(currentInode))
				batch = 0
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return processed, err
		}
	}
	// 最终断点
	finalOffset, _ := f.Seek(0, io.SeekCurrent)
	finalOffset -= int64(reader.Buffered())
	_ = c.saveCheckpoint(ctx, finalOffset, int64(currentInode))
	return processed, nil
}

// processLine 处理单行（解析→入库/错误队列）。
func (c *Collector) processLine(ctx context.Context, line []byte) {
	evt, err := ParseAuditLine(line, c.nodeName)
	if err != nil {
		c.failedCount++
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), err.Error()); dbErr != nil {
			slog.Error("insert parse failure failed", "error", dbErr)
		}
		return
	}
	if _, err := c.store.InsertEvent(ctx, evt); err != nil {
		c.failedCount++
		slog.Error("insert event failed", "error", err, "request_id", evt.RequestID)
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), "insert: "+err.Error()); dbErr != nil {
			slog.Error("insert failure queue failed", "error", dbErr)
		}
		return
	}
	c.processedCount++
	c.lastProcessed = time.Now()
}

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("event collector started", "collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("event collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected events", "collector", c.collectorID, "count", n)
			}
		}
	}
}
