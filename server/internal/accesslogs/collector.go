package accesslogs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/syslogfw"
)

// Collector 是全量访问日志采集器（tail 网关 JSON Lines 文件，DB 断点续传）。
type Collector struct {
	db            *pgxpool.Pool
	store         *Store
	syslog        *syslogfw.Forwarder // nil 时跳过 syslog 外发
	collectorID   string
	logPath       string
	flushBatch    int           // 批量落断点阈值（处理行数，W20）
	flushInterval time.Duration // 周期落断点阈值（距上次落盘时长，W20）
	// batchTxFactory 批次事务工厂（W22；nil 时逐行 autocommit，行为与 W20 一致；
	// 接线后每个 flush 批次一个 DB 事务，行数据 + 失败队列 + 断点原子提交）。
	batchTxFactory func(ctx context.Context) (pgx.Tx, error)
	// 指标
	processedCount int64
	failedCount    int64
	lastProcessed  time.Time
}

// 默认 flush 阈值（与 apiruntime 采集器同口径，W20 批量化修复；SetFlushPolicy 或
// WAF_COLLECTOR_FLUSH_BATCH / WAF_COLLECTOR_FLUSH_INTERVAL 可覆盖）：崩溃/重建后
// 重扫量有界（≤2000 行 + ≤2s，重放由 request_id 唯一索引去重）。
const (
	defaultFlushBatch    = 2000
	defaultFlushInterval = 2 * time.Second
)

// NewCollector 创建访问日志采集器（断点存 event_collector_checkpoints，collector_id 如 accesslog-01）。
func NewCollector(db *pgxpool.Pool, collectorID, logPath string) *Collector {
	return &Collector{
		db:            db,
		store:         NewStore(db),
		collectorID:   collectorID,
		logPath:       logPath,
		flushBatch:    defaultFlushBatch,
		flushInterval: defaultFlushInterval,
	}
}

// SetSyslogForwarder 设置 syslog 外发器（应用装配时使用，可为 nil）。
func (c *Collector) SetSyslogForwarder(fw *syslogfw.Forwarder) { c.syslog = fw }

// SetFlushPolicy 设置批量/周期落断点阈值（W20 批量化修复；非正值保持默认）。
// 未接线批次事务时行数据逐行即时入库，flush 仅推进断点；接线后（W22）flush
// 同时承担批次提交：batchSize 每处理 batchSize 行、interval 距上次落盘超过
// 该时长且有新数据时，各提交一个批次事务（行数据 + 断点原子落盘）。
func (c *Collector) SetFlushPolicy(batchSize int, interval time.Duration) {
	if batchSize > 0 {
		c.flushBatch = batchSize
	}
	if interval > 0 {
		c.flushInterval = interval
	}
}

// SetBatchTxFactory 设置批次事务工厂（W22 事务批量化，应用装配时使用；
// 未设置时保持逐行 autocommit，采集行为与 W20 完全一致）。
// factory 返回的事务必须来自与 store 同一个数据库。
func (c *Collector) SetBatchTxFactory(f func(ctx context.Context) (pgx.Tx, error)) {
	c.batchTxFactory = f
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

// saveCheckpoint 保存断点（autocommit 路径，经连接池即时提交）。
func (c *Collector) saveCheckpoint(ctx context.Context, offset, inode int64) error {
	return c.saveCheckpointOn(ctx, c.db, offset, inode)
}

// saveCheckpointOn 在给定句柄上保存断点（W22 批次事务路径传 pgx.Tx：
// 断点与行数据、失败队列并入同一事务原子提交，消除「数据已落、断点未前移」的重放窗口）。
func (c *Collector) saveCheckpointOn(ctx context.Context, q DBTX, offset, inode int64) error {
	_, err := q.Exec(ctx, `
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
			return 0, nil // 日志文件尚未生成（开关未开启时正常）
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
		slog.Info("access log rotated, resetting offset", "collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
		// 立即落断点：文件截断为空期间若无新内容，断点不前进会导致每轮采集重复判定轮转刷日志
		if err := c.saveCheckpoint(ctx, 0, int64(currentInode)); err != nil {
			slog.Warn("save checkpoint after rotation failed", "collector", c.collectorID, "error", err)
		}
	}
	if info.Size() == offset {
		return 0, nil // 无新内容
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReaderSize(f, 1024*1024)
	processed := 0
	// committedOffset 只计完整行（结尾无 \n 的残行不入断点，下轮补全后重读；
	// 与 apiruntime 采集器同一口径）。
	committedOffset := offset
	// W20 批量/周期落断点：深 backlog 下不再等 EOF 才唯一一次落盘，
	// 崩溃/容器重建后的重扫量有界（重放由 request_id 唯一索引去重）。
	lastFlush := time.Now()
	processedAtFlush := 0

	// W22 事务批量化（与 apiruntime 采集器同手法）：factory 接线后，批次窗口内的
	// 行插入、失败队列与断点写入并入一个 DB 事务，flush 整体 COMMIT（原子提交，
	// request_id 去重仍兜底崩溃重放）；未接线保持逐行 autocommit 零行为变化。
	var batchTx pgx.Tx
	var syslogBatch []*LogEntry // 本批次新插入行（提交成功后才外发，见 flush）
	origStore := c.store
	// beginBatch 首行前懒开启事务（无数据不开空事务），store 切到 tx 作用域浅拷贝。
	beginBatch := func() error {
		if c.batchTxFactory == nil || batchTx != nil {
			return nil
		}
		tx, err := c.batchTxFactory(ctx)
		if err != nil {
			return fmt.Errorf("begin batch tx: %w", err)
		}
		batchTx = tx
		c.store = origStore.WithDB(tx)
		return nil
	}
	endBatch := func() { c.store = origStore }
	// abortBatch 回滚未提交批次并恢复 store（回滚错误仅告警，不覆盖主错误）；
	// 外发缓冲随回滚丢弃——重放时去重命中不重复外发，真实新行届时补发。
	abortBatch := func() {
		if batchTx != nil {
			if err := batchTx.Rollback(ctx); err != nil {
				slog.Warn("rollback batch tx failed", "collector", c.collectorID, "error", err)
			}
			batchTx = nil
		}
		syslogBatch = syslogBatch[:0]
		endBatch()
	}
	// 任意返回路径兜底（读取失败等绕过 flush 的路径）：正常 flush 后 batchTx 已置 nil，此处 no-op。
	defer abortBatch()
	// flush 推进断点；批次事务模式下断点先入事务、整批 COMMIT（数据+断点原子），
	// 提交成功才外发本批次 syslog（回滚批次不产生幻影外发）；任一失败整体回滚，
	// 断点不前移，下轮重放由 request_id 去重。
	flush := func() error {
		if batchTx == nil {
			return c.saveCheckpoint(ctx, committedOffset, int64(currentInode))
		}
		if err := c.saveCheckpointOn(ctx, batchTx, committedOffset, int64(currentInode)); err != nil {
			abortBatch()
			return fmt.Errorf("save checkpoint: %w", err)
		}
		if err := batchTx.Commit(ctx); err != nil {
			abortBatch()
			return fmt.Errorf("commit batch tx: %w", err)
		}
		batchTx = nil
		endBatch()
		for _, e := range syslogBatch {
			c.syslog.Enqueue(syslogfw.KindAccessLog, "", e)
		}
		syslogBatch = syslogBatch[:0]
		return nil
	}

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			if berr := beginBatch(); berr != nil {
				return processed, berr
			}
			if batchTx != nil {
				if entry := c.processLineInTx(ctx, batchTx, line); entry != nil {
					syslogBatch = append(syslogBatch, entry)
				}
			} else {
				c.processLine(ctx, line)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return processed, err
		}
		if processed > processedAtFlush &&
			(processed-processedAtFlush >= c.flushBatch || time.Since(lastFlush) >= c.flushInterval) {
			if ferr := flush(); ferr != nil {
				return processed, ferr
			}
			lastFlush = time.Now()
			processedAtFlush = processed
		}
	}
	// 全部行入库后才推进断点（崩溃恢复不丢数据；重读由 request_id 唯一索引去重）
	if err := flush(); err != nil {
		return processed, err
	}
	return processed, nil
}

// processLine 处理单行（解析→入库/错误队列）。
func (c *Collector) processLine(ctx context.Context, line []byte) {
	entry, err := ParseLine(line)
	if err != nil {
		c.failedCount++
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), err.Error()); dbErr != nil {
			slog.Error("insert access log parse failure failed", "error", dbErr)
		}
		return
	}
	inserted, err := c.store.Insert(ctx, entry)
	if err != nil {
		c.failedCount++
		slog.Error("insert access log failed", "error", err, "request_id", entry.RequestID)
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), "insert: "+err.Error()); dbErr != nil {
			slog.Error("insert failure queue failed", "error", dbErr)
		}
		return
	}
	c.processedCount++
	c.lastProcessed = time.Now()
	// syslog 外发（三期）：仅新插入的日志外发（去重跳过的不重复外发），非阻塞投递
	if inserted {
		c.syslog.Enqueue(syslogfw.KindAccessLog, "", entry)
	}
}

// lineSavepoint 批次事务内包裹单行写入的子事务名（固定复用，逐行 RELEASE 后重建）。
const lineSavepoint = "accesslogs_rec"

// processLineInTx 批次事务内处理单行（W22；行级 SAVEPOINT 包裹，与 apiruntime
// 记录级子事务同一纪律：PG 中失败语句会令全事务 aborted，必须 ROLLBACK TO 恢复）。
// 返回非 nil 表示本行新插入（去重命中/失败/坏行返回 nil），调用方在批次提交
// 成功后统一外发 syslog——回滚批次不外发，重放批次去重后仅对真实新行补发。
func (c *Collector) processLineInTx(ctx context.Context, tx pgx.Tx, line []byte) *LogEntry {
	if _, err := tx.Exec(ctx, "SAVEPOINT "+lineSavepoint); err != nil {
		// 事务本身已不可用（连接断开等）：走原路径让错误逐条记日志（不静默），
		// flush 的断点写入/Commit 会如实失败并整体回滚。
		slog.Error("batch tx savepoint failed", "collector", c.collectorID, "error", err)
		c.processLine(ctx, line)
		return nil
	}
	entry, err := ParseLine(line)
	if err != nil {
		c.failedCount++
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), err.Error()); dbErr != nil {
			slog.Error("insert access log parse failure failed", "error", dbErr)
		}
		c.endLineTx(ctx, tx)
		return nil
	}
	inserted, err := c.store.Insert(ctx, entry)
	if err != nil {
		c.failedCount++
		slog.Error("insert access log failed", "error", err, "request_id", entry.RequestID)
		// 原语义：失败行写失败队列、断点照常前移。先回滚行子事务恢复事务，
		// 再于新子事务内补写失败队列（失败队列行与断点同批次原子提交，重放不重复）。
		c.rollbackLineTx(ctx, tx)
		if _, serr := tx.Exec(ctx, "SAVEPOINT "+lineSavepoint); serr != nil {
			slog.Error("batch tx savepoint for failure queue failed", "collector", c.collectorID, "error", serr)
			return nil
		}
		if dbErr := c.store.InsertFailure(ctx, c.collectorID, string(line), "insert: "+err.Error()); dbErr != nil {
			slog.Error("insert failure queue failed", "error", dbErr)
		}
		c.endLineTx(ctx, tx)
		return nil
	}
	c.processedCount++
	c.lastProcessed = time.Now()
	c.endLineTx(ctx, tx)
	if !inserted {
		return nil
	}
	return entry
}

// endLineTx 释放行子事务；行内语句失败令事务 aborted 时 RELEASE 会报错，
// 此时回滚到行子事务恢复事务后再释放（本行已写内容随子事务丢弃，错误已逐条记日志）。
func (c *Collector) endLineTx(ctx context.Context, tx pgx.Tx) {
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+lineSavepoint); err != nil {
		c.rollbackLineTx(ctx, tx)
	}
}

// rollbackLineTx 回滚行子事务并释放（ROLLBACK TO 后 RELEASE 不回撤销回滚）。
func (c *Collector) rollbackLineTx(ctx context.Context, tx pgx.Tx) {
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+lineSavepoint); err != nil {
		slog.Error("rollback line savepoint failed", "collector", c.collectorID, "error", err)
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+lineSavepoint); err != nil {
		slog.Error("release line savepoint failed", "collector", c.collectorID, "error", err)
	}
}

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("access log collector started", "collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("access log collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("access log collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected access logs", "collector", c.collectorID, "count", n)
			}
		}
	}
}
