// collector.go client_identity 体系事件采集器（WDSP AI 自动化渗透防护增强 阶段1）。
// 读取网关 jiuzhang_guard 输出的 identity-events.log JSONL，断点续传入库：
//   - 与 accesscontrolevents/apiruntime 采集器同一套断点纪律：offset+inode+前缀指纹
//     断点续传、轮转检测（inode 变化/文件变小/已提交前缀变化 → 从头读取）、
//     原子保存断点（临时文件 + rename）；
//   - 按 record_type 分发入库（identity_observation/behavior_snapshot/recon_signal），
//     每个 flush 批次一个 DB 事务（整批一次 COMMIT；失败整体回滚、断点不前移，
//     下轮重放由 UPSERT 幂等兜底）；
//   - 解析失败的行写错误文件 + event_parse_failures 通用队列（不静默丢弃）。
package identityevents

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

// BatchBeginner 批次事务开启接口（*pgxpool.Pool.Begin 直接满足）。
type BatchBeginner func(ctx context.Context) (pgx.Tx, error)

// 默认 flush 阈值（与 apiruntime 采集器同一取值依据：深 backlog 下入库滞后与
// 崩溃/重建重扫量有界——≤flushBatch 行 + ≤flushInterval 的重放上界）。
const (
	defaultFlushBatch    = 2000
	defaultFlushInterval = 2 * time.Second
)

// Collector 是 client_identity 体系事件采集器。
type Collector struct {
	store          *Store
	beginner       BatchBeginner
	collectorID    string
	logPath        string
	checkpointPath string
	errorPath      string
	nodeName       string
	flushBatch     int
	flushInterval  time.Duration
	// 指标
	processedCount int64
	savedCount     int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
func NewCollector(store *Store, beginner BatchBeginner, collectorID, logPath, checkpointPath, nodeName string) *Collector {
	if checkpointPath == "" {
		checkpointPath = logPath + ".checkpoint"
	}
	return &Collector{
		store:          store,
		beginner:       beginner,
		collectorID:    collectorID,
		logPath:        logPath,
		checkpointPath: checkpointPath,
		errorPath:      logPath + ".errors",
		nodeName:       nodeName,
		flushBatch:     defaultFlushBatch,
		flushInterval:  defaultFlushInterval,
	}
}

// SetFlushPolicy 设置批量/周期 flush 阈值（非正值保持默认）。
func (c *Collector) SetFlushPolicy(batchSize int, interval time.Duration) {
	if batchSize > 0 {
		c.flushBatch = batchSize
	}
	if interval > 0 {
		c.flushInterval = interval
	}
}

// Metrics 返回采集指标。
func (c *Collector) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"collector_id":    c.collectorID,
		"processed_count": c.processedCount,
		"saved_count":     c.savedCount,
		"failed_count":    c.failedCount,
		"last_processed":  c.lastProcessed,
		"log_path":        c.logPath,
	}
}

// checkpoint 是采集断点（JSON 文件持久化）。
type checkpoint struct {
	Offset       int64  `json:"offset"`
	Inode        uint64 `json:"inode"`
	PrefixSize   int64  `json:"prefix_size,omitempty"`
	PrefixSHA256 string `json:"prefix_sha256,omitempty"`
}

const checkpointPrefixLimit int64 = 4096

func (cp checkpoint) valid() bool {
	return cp.Offset >= 0 &&
		cp.PrefixSize >= 0 &&
		cp.PrefixSize <= checkpointPrefixLimit &&
		cp.PrefixSize <= cp.Offset
}

// loadCheckpoint 从 checkpoint 文件加载断点；文件不存在时从头开始，
// 文件损坏时告警并从头开始（不静默吞错：slog.Warn 记录）。
func (c *Collector) loadCheckpoint() checkpoint {
	data, err := os.ReadFile(c.checkpointPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("checkpoint file unreadable, restarting from offset 0",
				"collector", c.collectorID, "path", c.checkpointPath, "error", err)
		}
		return checkpoint{}
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		slog.Warn("checkpoint file corrupted, restarting from offset 0",
			"collector", c.collectorID, "path", c.checkpointPath, "error", err)
		return checkpoint{}
	}
	if !cp.valid() {
		slog.Warn("checkpoint values invalid, restarting from offset 0",
			"collector", c.collectorID, "path", c.checkpointPath)
		return checkpoint{}
	}
	return cp
}

// saveCheckpoint 原子保存断点（临时文件 + rename）。
func (c *Collector) saveCheckpoint(cp checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	tmp := c.checkpointPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.checkpointPath)
}

// persistCheckpoint 计算已提交前缀指纹并原子保存断点（调用方保证对应批次已 COMMIT）。
func (c *Collector) persistCheckpoint(f *os.File, offset int64, inode uint64) error {
	prefixSize, prefixSHA256, err := checkpointFingerprint(f, offset)
	if err != nil {
		return fmt.Errorf("fingerprint checkpoint: %w", err)
	}
	if err := c.saveCheckpoint(checkpoint{
		Offset:       offset,
		Inode:        inode,
		PrefixSize:   prefixSize,
		PrefixSHA256: prefixSHA256,
	}); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
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

// prefixFingerprint 返回文件开头指定长度内容的 SHA-256。
// ReadAt 不改变采集器当前读取位置。
func prefixFingerprint(f *os.File, size int64) (string, error) {
	if size <= 0 {
		return "", nil
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	if int64(n) != size {
		return "", io.ErrUnexpectedEOF
	}
	return fmt.Sprintf("%x", sha256.Sum256(buf)), nil
}

func checkpointFingerprint(f *os.File, offset int64) (int64, string, error) {
	prefixSize := min(offset, checkpointPrefixLimit)
	hash, err := prefixFingerprint(f, prefixSize)
	return prefixSize, hash, err
}

// CollectOnce 执行一次采集（读取新增内容并入库）。返回处理行数。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	cp := c.loadCheckpoint()

	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 日志文件尚未生成（无事件时正常）
		}
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	currentInode := fileInode(f)

	// 轮转检测：inode 变化、文件变小或已提交前缀变化 → 从头读取。
	offset := cp.Offset
	rotated := (cp.Inode != 0 && currentInode != cp.Inode) || info.Size() < offset
	if !rotated && cp.PrefixSize > 0 && cp.PrefixSHA256 != "" {
		currentPrefix, err := prefixFingerprint(f, cp.PrefixSize)
		if err != nil {
			return 0, fmt.Errorf("fingerprint identity event log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("identity event log rotated, resetting offset",
			"collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
		// 立即落断点（空前缀指纹）：文件截断为空期间若无新内容，断点不前进会导致每轮采集重复判定轮转刷日志
		if err := c.persistCheckpoint(f, 0, currentInode); err != nil {
			slog.Warn("save checkpoint after rotation failed", "collector", c.collectorID, "error", err)
		}
	}
	if info.Size() == offset {
		return 0, nil // 无新内容
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(f)
	processed := 0
	committedOffset := offset
	var pending []*Record

	// flush 批次入库（单事务）+ 保存断点；失败时断点不前移，下轮重读
	// （UPSERT 幂等兜底重放安全；request_count 自增的重放窗口见 store.go 注释）。
	flush := func() error {
		if len(pending) == 0 {
			return c.persistCheckpoint(f, committedOffset, currentInode)
		}
		tx, err := c.beginner(ctx)
		if err != nil {
			return fmt.Errorf("begin batch tx: %w", err)
		}
		for _, rec := range pending {
			var aerr error
			switch rec.RecordType {
			case RecordTypeObservation:
				aerr = c.store.UpsertObservation(ctx, tx, rec)
			case RecordTypeSnapshot:
				aerr = c.store.UpsertSnapshot(ctx, tx, rec)
			case RecordTypeSignal:
				aerr = c.store.RecordSignal(ctx, tx, rec)
			}
			if aerr != nil {
				_ = tx.Rollback(ctx)
				return aerr
			}
		}
		if err := tx.Commit(ctx); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("commit batch tx: %w", err)
		}
		c.savedCount += int64(len(pending))
		pending = pending[:0]
		return c.persistCheckpoint(f, committedOffset, currentInode)
	}

	lastFlush := time.Now()
	processedAtFlush := 0

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			rec, perr := parseRecordLine(line)
			if perr != nil {
				c.failedCount++
				c.appendError(line, perr)
				// 通用解析失败队列（best-effort：写失败仅记日志，不阻断采集）
				if ferr := c.store.InsertParseFailure(ctx, c.collectorID, string(line), perr.Error()); ferr != nil {
					slog.Warn("insert parse failure queue failed", "collector", c.collectorID, "error", ferr)
				}
			} else {
				pending = append(pending, rec)
				c.processedCount++
				c.lastProcessed = time.Now()
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
	if err := flush(); err != nil {
		return processed, err
	}
	return processed, nil
}

// errorRecord 是错误文件中的一行。
type errorRecord struct {
	Time        time.Time `json:"time"`
	CollectorID string    `json:"collector_id"`
	Reason      string    `json:"reason"`
	RawLine     string    `json:"raw_line"`
}

// maxErrorFileBytes 错误文件大小上限（10MiB）：超限先单份轮转再写新档，
// 防网关持续产出坏行时错误文件无限增长撑爆磁盘。
const maxErrorFileBytes = 10 << 20

// appendError 把解析失败的行追加到错误文件（不静默丢弃）。
func (c *Collector) appendError(line []byte, cause error) {
	raw := string(line)
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	rec, err := json.Marshal(errorRecord{
		Time:        time.Now().UTC(),
		CollectorID: c.collectorID,
		Reason:      cause.Error(),
		RawLine:     raw,
	})
	if err != nil {
		slog.Error("marshal error record failed", "collector", c.collectorID, "error", err)
		return
	}
	c.rotateErrorFileIfNeeded(len(rec) + 1)
	f, err := os.OpenFile(c.errorPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("open error file failed", "collector", c.collectorID, "path", c.errorPath, "error", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(rec, '\n')); err != nil {
		slog.Error("write error file failed", "collector", c.collectorID, "error", err)
	}
}

// rotateErrorFileIfNeeded 错误文件写入 incoming 字节将超上限时单份轮转：
// .errors → .errors.1（覆盖旧档，仅保留最近一份）。轮转失败仅记日志后继续追加
// ——宁可文件超限也不静默丢错误行（与 appendError 不静默丢弃同一纪律）。
func (c *Collector) rotateErrorFileIfNeeded(incoming int) {
	fi, err := os.Stat(c.errorPath)
	if err != nil {
		return // 文件不存在（新档必然不超）或状态读取失败：交给打开/写入时报错
	}
	if fi.Size()+int64(incoming) <= maxErrorFileBytes {
		return
	}
	if err := os.Rename(c.errorPath, c.errorPath+".1"); err != nil {
		slog.Error("rotate error file failed", "collector", c.collectorID, "path", c.errorPath, "error", err)
	}
}

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("identity event collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("identity event collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected identity events", "collector", c.collectorID, "count", n)
			}
		}
	}
}
