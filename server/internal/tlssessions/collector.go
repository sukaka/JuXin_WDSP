package tlssessions

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
)

const (
	// DefaultCollectorID 默认采集器断点标识（存入 event_collector_checkpoints）。
	DefaultCollectorID = "tlssession-01"

	defaultFlushBatch    = 2000
	defaultFlushInterval = 2 * time.Second
	lineSavepoint        = "tlssessions_rec"
)

// checkpoint 是采集器文件读取断点（偏移量 + inode）。
type checkpoint struct {
	offset int64
	inode  uint64
}

// checkpointStore 抽象断点持久化（生产由 PostgreSQL event_collector_checkpoints 承载，单测可注入内存实现）。
type checkpointStore interface {
	load(ctx context.Context, collectorID string) (*checkpoint, error)
	save(ctx context.Context, collectorID, logPath string, offset, inode int64) error
}

// entrySink 抽象采集器行写入接口（PostgreSQL Store 与 MemStore 均支持）。
type entrySink interface {
	Insert(ctx context.Context, e *HandshakeEntry) error
}

type failureSink interface {
	InsertFailure(ctx context.Context, collectorID, rawLine, reason string) error
}

// Collector 是加密会话握手事件 JSONL 采集器（tail + DB 断点续传 + 轮转检测 + 批次事务）。
type Collector struct {
	db             *pgxpool.Pool
	pgStore        *Store
	sink           entrySink
	failures       failureSink
	checkpoints    checkpointStore
	collectorID    string
	logPath        string
	flushBatch     int
	flushInterval  time.Duration
	batchTxFactory func(ctx context.Context) (pgx.Tx, error)

	processedCount int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建基于 PostgreSQL 的加密会话事件采集器（断点写入 event_collector_checkpoints）。
func NewCollector(db *pgxpool.Pool, collectorID, logPath string) *Collector {
	if collectorID == "" {
		collectorID = DefaultCollectorID
	}
	store := NewStore(db)
	return &Collector{
		db:            db,
		pgStore:       store,
		sink:          store,
		failures:      store,
		collectorID:   collectorID,
		logPath:       logPath,
		flushBatch:    defaultFlushBatch,
		flushInterval: defaultFlushInterval,
	}
}

// NewCollectorWithRepository 创建基于自定义 Repository 与内存断点的采集器（便于单测完整验证 tail 与轮转）。
func NewCollectorWithRepository(repo Repository, collectorID, logPath string) *Collector {
	if collectorID == "" {
		collectorID = DefaultCollectorID
	}
	var fs failureSink
	if f, ok := repo.(failureSink); ok {
		fs = f
	}
	return &Collector{
		sink:          repo,
		failures:      fs,
		checkpoints:   &memCheckpointStore{},
		collectorID:   collectorID,
		logPath:       logPath,
		flushBatch:    defaultFlushBatch,
		flushInterval: defaultFlushInterval,
	}
}

// SetFlushPolicy 设置批量与周期落断点阈值（非正值保持默认）。
func (c *Collector) SetFlushPolicy(batchSize int, interval time.Duration) {
	if batchSize > 0 {
		c.flushBatch = batchSize
	}
	if interval > 0 {
		c.flushInterval = interval
	}
}

// SetBatchTxFactory 设置批次事务工厂（每批行写入 + 失败队列 + 断点原子提交）。
func (c *Collector) SetBatchTxFactory(f func(ctx context.Context) (pgx.Tx, error)) {
	c.batchTxFactory = f
}

// Metrics 返回采集器运行指标。
func (c *Collector) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"collector_id":    c.collectorID,
		"processed_count": c.processedCount,
		"failed_count":    c.failedCount,
		"last_processed":  c.lastProcessed,
		"log_path":        c.logPath,
	}
}

func (c *Collector) loadCheckpoint(ctx context.Context) (*checkpoint, error) {
	if c.checkpoints != nil {
		return c.checkpoints.load(ctx, c.collectorID)
	}
	if c.db == nil {
		return &checkpoint{}, nil
	}
	var cp checkpoint
	err := c.db.QueryRow(ctx,
		`SELECT file_offset, file_inode FROM event_collector_checkpoints WHERE collector_id = $1`, c.collectorID).
		Scan(&cp.offset, &cp.inode)
	if err != nil {
		return &checkpoint{offset: 0, inode: 0}, nil
	}
	return &cp, nil
}

func (c *Collector) saveCheckpoint(ctx context.Context, offset, inode int64) error {
	if c.checkpoints != nil {
		return c.checkpoints.save(ctx, c.collectorID, c.logPath, offset, inode)
	}
	if c.db == nil {
		return nil
	}
	return c.saveCheckpointOn(ctx, c.db, offset, inode)
}

func (c *Collector) saveCheckpointOn(ctx context.Context, q DBTX, offset, inode int64) error {
	_, err := q.Exec(ctx, `
INSERT INTO event_collector_checkpoints (collector_id, file_path, file_offset, file_inode, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (collector_id) DO UPDATE SET file_offset=$3, file_inode=$4, updated_at=now()`,
		c.collectorID, c.logPath, offset, inode)
	return err
}

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

// CollectOnce 执行一次增量采集（支持文件未生成静默空转、inode/截断轮转重置、半行留待下轮、坏行告警跳过不阻塞）。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	if c.logPath == "" {
		return 0, nil
	}
	cp, err := c.loadCheckpoint(ctx)
	if err != nil {
		return 0, err
	}

	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 日志文件尚未生成（正常空转）
		}
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	currentInode := fileInode(f)

	offset := cp.offset
	if (cp.inode != 0 && currentInode != cp.inode) || info.Size() < offset {
		slog.Info("tls session log rotated, resetting offset",
			"collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
		if err := c.saveCheckpoint(ctx, 0, int64(currentInode)); err != nil {
			slog.Warn("save tls session checkpoint after rotation failed",
				"collector", c.collectorID, "error", err)
		}
	}
	if info.Size() == offset {
		return 0, nil
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReaderSize(f, 256*1024)
	processed := 0
	committedOffset := offset
	lastFlush := time.Now()
	processedAtFlush := 0

	var batchTx pgx.Tx
	origSink := c.sink
	origFailures := c.failures

	beginBatch := func() error {
		if c.batchTxFactory == nil || c.pgStore == nil || batchTx != nil {
			return nil
		}
		tx, err := c.batchTxFactory(ctx)
		if err != nil {
			return fmt.Errorf("begin batch tx: %w", err)
		}
		batchTx = tx
		txStore := c.pgStore.WithDB(tx)
		c.sink = txStore
		c.failures = txStore
		return nil
	}
	endBatch := func() {
		c.sink = origSink
		c.failures = origFailures
	}
	abortBatch := func() {
		if batchTx != nil {
			if err := batchTx.Rollback(ctx); err != nil {
				slog.Warn("rollback tls session batch tx failed", "collector", c.collectorID, "error", err)
			}
			batchTx = nil
		}
		endBatch()
	}
	defer abortBatch()

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
				c.processLineInTx(ctx, batchTx, line)
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

	if committedOffset != offset || processed > 0 {
		if err := flush(); err != nil {
			return processed, err
		}
	}
	return processed, nil
}

func (c *Collector) recordFailure(ctx context.Context, rawLine, reason string) {
	if c.failures == nil {
		return
	}
	if dbErr := c.failures.InsertFailure(ctx, c.collectorID, rawLine, reason); dbErr != nil {
		slog.Warn("insert tls session parse failure failed", "collector", c.collectorID, "error", dbErr)
	}
}

func (c *Collector) processLine(ctx context.Context, line []byte) {
	entry, err := ParseLine(line)
	if err != nil {
		c.failedCount++
		slog.Warn("skip malformed tls handshake event line", "collector", c.collectorID, "error", err)
		c.recordFailure(ctx, string(line), err.Error())
		return
	}
	if err := c.sink.Insert(ctx, entry); err != nil {
		c.failedCount++
		slog.Warn("insert tls handshake event failed", "collector", c.collectorID, "error", err)
		c.recordFailure(ctx, string(line), "insert: "+err.Error())
		return
	}
	c.processedCount++
	c.lastProcessed = time.Now()
}

func (c *Collector) processLineInTx(ctx context.Context, tx pgx.Tx, line []byte) {
	if _, err := tx.Exec(ctx, "SAVEPOINT "+lineSavepoint); err != nil {
		slog.Warn("tls session batch tx savepoint failed", "collector", c.collectorID, "error", err)
		c.processLine(ctx, line)
		return
	}
	entry, err := ParseLine(line)
	if err != nil {
		c.failedCount++
		slog.Warn("skip malformed tls handshake event line", "collector", c.collectorID, "error", err)
		c.recordFailure(ctx, string(line), err.Error())
		c.endLineTx(ctx, tx)
		return
	}
	if err := c.sink.Insert(ctx, entry); err != nil {
		c.failedCount++
		slog.Warn("insert tls handshake event failed", "collector", c.collectorID, "error", err)
		c.rollbackLineTx(ctx, tx)
		if _, serr := tx.Exec(ctx, "SAVEPOINT "+lineSavepoint); serr != nil {
			slog.Warn("tls session batch tx savepoint for failure queue failed", "collector", c.collectorID, "error", serr)
			return
		}
		c.recordFailure(ctx, string(line), "insert: "+err.Error())
		c.endLineTx(ctx, tx)
		return
	}
	c.processedCount++
	c.lastProcessed = time.Now()
	c.endLineTx(ctx, tx)
}

func (c *Collector) endLineTx(ctx context.Context, tx pgx.Tx) {
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+lineSavepoint); err != nil {
		c.rollbackLineTx(ctx, tx)
	}
}

func (c *Collector) rollbackLineTx(ctx context.Context, tx pgx.Tx) {
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+lineSavepoint); err != nil {
		slog.Warn("rollback tls session line savepoint failed", "collector", c.collectorID, "error", err)
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+lineSavepoint); err != nil {
		slog.Warn("release tls session line savepoint failed", "collector", c.collectorID, "error", err)
	}
}

// Run 持续轮询采集加密会话握手事件。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("tls session collector started", "collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("tls session collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("tls session collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected tls handshake events", "collector", c.collectorID, "count", n)
			}
		}
	}
}

// memCheckpointStore 内存断点存储（用于单测验证增量 tail、断点续传与日志轮转）。
type memCheckpointStore struct {
	cp checkpoint
}

func (m *memCheckpointStore) load(_ context.Context, _ string) (*checkpoint, error) {
	cp := m.cp
	return &cp, nil
}

func (m *memCheckpointStore) save(_ context.Context, _, _ string, offset, inode int64) error {
	m.cp = checkpoint{offset: offset, inode: uint64(inode)}
	return nil
}
