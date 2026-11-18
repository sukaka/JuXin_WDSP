// collector.go 执行覆盖观测采集器（NG-COV-01/02 摄入段 server 侧）。
// 读取网关 coverage.FileSink 输出的 coverage-observations.jsonl，断点续传入库：
//   - 与 identityevents/accesscontrolevents/apiruntime 采集器同一套断点纪律：
//     offset+inode+前缀指纹断点续传、轮转检测（inode 变化/文件变小/已提交前缀变化 →
//     从头读取）、原子保存断点（临时文件 + rename）；
//   - 逐行 JSON 解析进 gwcov.Observation 并做契约校验（o.Validate()，两端同一校验口径）；
//     失败行进错误文件 + event_parse_failures 通用队列（不静默丢弃）；
//   - 每个 flush 批次一个 DB 事务（整批一次 COMMIT；失败整体回滚、断点不前移，
//     下轮重放由明细 WHERE NOT EXISTS / 聚合增量重加幂等兜底）；
//   - 明细经 Sampler 确定性 1/N 采样留存（聚合不受影响——五态计数全量记账）；
//   - 每条合法观测喂 Aggregator.Add，flush 时 Drain 分钟桶增量 upsert coverage_minute_agg；
//   - 每次 flush 落一组 coverage_counter_snapshots（cov_ingest.* 阶段计数，
//     丢弃事实本身入聚合展示）。
package coverage

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

	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

// BatchBeginner 批次事务开启接口（*pgxpool.Pool.Begin 直接满足）。
type BatchBeginner func(ctx context.Context) (pgx.Tx, error)

// 默认 flush 阈值（与 identityevents 采集器同一取值依据：深 backlog 下入库滞后与
// 崩溃/重建重扫量有界——≤flushBatch 行 + ≤flushInterval 的重放上界）。
const (
	defaultFlushBatch    = 2000
	defaultFlushInterval = 2 * time.Second
	// DefaultSampleN 明细默认采样率 1/10：观测量级与请求量同阶（每请求每检测器一条），
	// 明细只用于取证抽查，1/10 在保留取证价值与控表体量之间取平衡（聚合不受影响）。
	DefaultSampleN = 10
	// DefaultAggMaxKeys 单窗口维度键上限（同 Aggregator 默认）。
	DefaultAggMaxKeys = 10000
)

// 摄入管线阶段计数名（coverage_counter_snapshots.stage 命名空间；delta=本批增量，
// cumulative=进程启动以来累计值——口径在 stage 名后缀自明）。
const (
	stageProcessed       = "cov_ingest.processed_delta"
	stageParseFailures   = "cov_ingest.parse_failures_delta"
	stageSampleKept      = "cov_ingest.sample_kept_delta"
	stageSampleDropped   = "cov_ingest.sample_dropped_delta"
	stageObsInserted     = "cov_ingest.observations_inserted_delta"
	stageAggRowsUpserted = "cov_ingest.agg_rows_upserted_delta"
	stageAggOverflow     = "cov_ingest.agg_overflow_cumulative"
	stageAggInvalid      = "cov_ingest.agg_invalid_cumulative"
)

// Collector 是执行覆盖观测采集器。
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
	sampler        *Sampler
	aggregator     *Aggregator
	// 指标
	processedCount int64
	savedCount     int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
// 默认明细采样 1/10（SetSampleN 可改）、聚合维度上限 10000（SetAggregator 可换）。
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
		sampler:        NewSampler(DefaultSampleN),
		aggregator:     NewAggregator(DefaultAggMaxKeys),
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

// SetSampleN 设置明细采样率 1/N（N<=1 全保留；装配启动前调用）。
func (c *Collector) SetSampleN(n uint64) {
	c.sampler = NewSampler(n)
}

// SetAggregator 注入聚合器（测试与小上限场景；装配启动前调用，nil 忽略）。
func (c *Collector) SetAggregator(a *Aggregator) {
	if a != nil {
		c.aggregator = a
	}
}

// Metrics 返回采集指标。
func (c *Collector) Metrics() map[string]interface{} {
	seen, kept, dropped := c.sampler.Stats()
	return map[string]interface{}{
		"collector_id":    c.collectorID,
		"processed_count": c.processedCount,
		"saved_count":     c.savedCount,
		"failed_count":    c.failedCount,
		"last_processed":  c.lastProcessed,
		"log_path":        c.logPath,
		"sample_seen":     seen,
		"sample_kept":     kept,
		"sample_dropped":  dropped,
		"agg_overflow":    c.aggregator.Overflow(),
		"agg_invalid":     c.aggregator.Invalid(),
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

// counterSnapshotLine guard 节点计数快照行（record_type=counter_snapshot 路由键；
// 与 jiuzhang_guard coverage_out.go 的输出结构同形，stage 标签为 guard 冻结集合）。
type counterSnapshotLine struct {
	RecordType string `json:"record_type"`
	NodeID     string `json:"node_id"`
	CapturedAt string `json:"captured_at"`
	Counts     []struct {
		Stage string `json:"stage"`
		Count uint64 `json:"count"`
	} `json:"counts"`
}

// recordTypeCounterSnapshot 计数快照行的 record_type 值（guard 产出侧与采集路由共用此字面量）。
const recordTypeCounterSnapshot = "counter_snapshot"

// parseObservationLine 解析一行 JSONL 并按契约校验（与网关 Emitter 同一 Validate 口径）。
// 坏行返回错误（采集器写错误文件 + event_parse_failures 队列，不静默丢弃）。
// occurred_at 缺省视为坏行（采集侧不补时间戳——分钟桶归属必须忠实于发生时刻）。
func parseObservationLine(line []byte) (gwcov.Observation, error) {
	var o gwcov.Observation
	if err := json.Unmarshal(line, &o); err != nil {
		return o, fmt.Errorf("bad json: %w", err)
	}
	if o.OccurredAt.IsZero() {
		return o, fmt.Errorf("missing occurred_at")
	}
	if msg := o.Validate(); msg != "" {
		return o, fmt.Errorf("contract violated: %s", msg)
	}
	return o, nil
}

// isOtherKey 维度键是否 Aggregator 维度超限归拢桶（与 agg.go otherKey 口径一致）。
func isOtherKey(k DimKey) bool { return k.EndpointKey == "other" && k.Detector == "other" }

// CollectOnce 执行一次采集（读取新增内容并入库）。返回处理行数。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	cp := c.loadCheckpoint()

	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 日志文件尚未生成（网关未发射覆盖观测时正常，空转不 crash）
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
			return 0, fmt.Errorf("fingerprint coverage observation log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("coverage observation log rotated, resetting offset",
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
	var pending []gwcov.Observation
	var pendingCounters []counterSnapshotLine
	var deltaProcessed, deltaFailures, deltaKept, deltaDropped uint64

	// flush 批次入库（单事务）+ 保存断点；失败时断点不前移，下轮重读
	// （明细 WHERE NOT EXISTS 幂等；聚合桶 Drain 的是增量，重放行会重新 Add 恢复）。
	flush := func() error {
		if len(pending) == 0 && len(pendingCounters) == 0 {
			return c.persistCheckpoint(f, committedOffset, currentInode)
		}
		// 聚合增量在 Begin 前 Drain：若本批提交失败，断点不前移、重放行重新
		// Add 回聚合器，计数不丢（与既有采集器「重放幂等」同一断点纪律；在
		// 「提交成功但断点保存失败」的极小窗口内聚合计数可能重复累计，
		// 指标口径可接受，同 identityevents store.go 注释）。
		aggRows := c.drainAggRows()
		snapshot := []StageCount{
			{Stage: stageProcessed, Count: deltaProcessed},
			{Stage: stageParseFailures, Count: deltaFailures},
			{Stage: stageSampleKept, Count: deltaKept},
			{Stage: stageSampleDropped, Count: deltaDropped},
			{Stage: stageObsInserted, Count: uint64(len(pending))},
			{Stage: stageAggRowsUpserted, Count: uint64(len(aggRows))},
			{Stage: stageAggOverflow, Count: c.aggregator.Overflow()},
			{Stage: stageAggInvalid, Count: c.aggregator.Invalid()},
		}
		tx, err := c.beginner(ctx)
		if err != nil {
			return fmt.Errorf("begin batch tx: %w", err)
		}
		if err := c.store.InsertObservations(ctx, tx, pending); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := c.store.UpsertMinuteAgg(ctx, tx, aggRows); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		for _, cs := range pendingCounters {
			ts, perr := time.Parse(time.RFC3339, cs.CapturedAt)
			if perr != nil {
				ts = time.Now().UTC() // 上游时间戳异常时以入库时刻兜底（行级合法性已校验过格式）
			}
			counts := make([]StageCount, 0, len(cs.Counts))
			for _, cc := range cs.Counts {
				counts = append(counts, StageCount{Stage: cc.Stage, Count: cc.Count})
			}
			if err := c.store.InsertCounterSnapshot(ctx, tx, cs.NodeID, counts, ts); err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
		}
		if err := c.store.InsertCounterSnapshot(ctx, tx, c.nodeName, snapshot, time.Now().UTC()); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("commit batch tx: %w", err)
		}
		c.savedCount += int64(len(pending))
		pending = pending[:0]
		pendingCounters = pendingCounters[:0]
		deltaProcessed, deltaFailures, deltaKept, deltaDropped = 0, 0, 0, 0
		return c.persistCheckpoint(f, committedOffset, currentInode)
	}

	lastFlush := time.Now()
	processedAtFlush := 0

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			// record_type 路由：counter_snapshot 行（guard 计数快照 janitor 产出）走
			// 独立入库通道，不经观测校验/采样/聚合；缺省/其他一律按观测行处理。
			var probe struct {
				RecordType string `json:"record_type"`
			}
			if jerr := json.Unmarshal(line, &probe); jerr == nil && probe.RecordType == recordTypeCounterSnapshot {
				var cs counterSnapshotLine
				if jerr := json.Unmarshal(line, &cs); jerr != nil || cs.NodeID == "" || len(cs.Counts) == 0 {
					c.failedCount++
					deltaFailures++
					c.appendError(line, fmt.Errorf("bad counter_snapshot line"))
				} else if _, terr := time.Parse(time.RFC3339, cs.CapturedAt); terr != nil {
					c.failedCount++
					deltaFailures++
					c.appendError(line, fmt.Errorf("bad counter_snapshot captured_at"))
				} else {
					pendingCounters = append(pendingCounters, cs)
					c.processedCount++
					c.lastProcessed = time.Now()
				}
				continue
			}
			o, perr := parseObservationLine(line)
			if perr != nil {
				c.failedCount++
				deltaFailures++
				c.appendError(line, perr)
				// 通用解析失败队列（best-effort：写失败仅记日志，不阻断采集）
				if ferr := c.store.InsertParseFailure(ctx, c.collectorID, string(line), perr.Error()); ferr != nil {
					slog.Warn("insert parse failure queue failed", "collector", c.collectorID, "error", ferr)
				}
			} else {
				deltaProcessed++
				c.aggregator.Add(o) // 五态计数全量记账（采样只影响明细留存）
				if c.sampler.Keep() {
					pending = append(pending, o)
					deltaKept++
				} else {
					deltaDropped++
				}
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

// drainAggRows 取出聚合增量并组装落库行（含 other 归拢标记）。
func (c *Collector) drainAggRows() []AggRow {
	drained := c.aggregator.Drain()
	rows := make([]AggRow, 0, len(drained))
	for k, b := range drained {
		rows = append(rows, AggRow{Key: k, Bucket: b, IsOther: isOtherKey(k)})
	}
	return rows
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
	slog.Info("coverage observation collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("coverage observation collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected coverage observations", "collector", c.collectorID, "count", n)
			}
		}
	}
}
