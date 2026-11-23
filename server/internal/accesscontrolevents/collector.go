package accesscontrolevents

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

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/syslogfw"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
)

// EventStore 是采集器依赖的事件入库接口（*Store 实现，测试可注入内存实现）。
type EventStore interface {
	Insert(ctx context.Context, events []Event) (int, error)
	InsertRuntimeSummary(ctx context.Context, sum RuntimeSummary) error
}

// BlockUpserter 是临时封禁入库接口（*temporaryblocks.Store 实现，可为 nil）。
type BlockUpserter interface {
	UpsertFromEvent(ctx context.Context, block *temporaryblocks.Block) error
}

// RuleHitRecorder 是规则命中计数接口（accessrules.Store.IncrementHit，可为 nil）。
type RuleHitRecorder interface {
	IncrementHit(ctx context.Context, ruleID uuid.UUID, at time.Time) error
}

// Collector 是访问控制事件采集器。
// 读取网关 guard 事件 JSONL 文件，断点续传（checkpoint 文件记录 offset、inode
// 和文件前缀指纹，用于轮转检测），批量插入 access_control_events；
// 解析失败的行写入错误文件，不静默丢弃。
type Collector struct {
	store          EventStore
	blocks         BlockUpserter       // nil 时跳过封禁入库
	hits           RuleHitRecorder     // nil 时跳过命中计数
	urlHits        RuleHitRecorder     // nil 时跳过 URL 白名单命中计数
	syslog         *syslogfw.Forwarder // nil 时跳过 syslog 外发
	collectorID    string
	logPath        string
	checkpointPath string
	errorPath      string
	nodeName       string
	batchSize      int
	// 指标
	processedCount int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
func NewCollector(store EventStore, collectorID, logPath, checkpointPath, nodeName string) *Collector {
	if checkpointPath == "" {
		checkpointPath = logPath + ".checkpoint"
	}
	return &Collector{
		store:          store,
		collectorID:    collectorID,
		logPath:        logPath,
		checkpointPath: checkpointPath,
		errorPath:      logPath + ".errors",
		nodeName:       nodeName,
		batchSize:      100,
	}
}

// SetBlockUpserter 设置临时封禁入库接口（应用装配时使用）。
func (c *Collector) SetBlockUpserter(u BlockUpserter) { c.blocks = u }

// SetHitRecorder 设置规则命中计数接口（应用装配时使用）。
func (c *Collector) SetHitRecorder(h RuleHitRecorder) { c.hits = h }

// SetURLWhitelistHitRecorder 设置 URL 白名单命中计数接口（应用装配时使用）。
func (c *Collector) SetURLWhitelistHitRecorder(h RuleHitRecorder) { c.urlHits = h }

// SetSyslogForwarder 设置 syslog 外发器（应用装配时使用，可为 nil）。
func (c *Collector) SetSyslogForwarder(fw *syslogfw.Forwarder) { c.syslog = fw }

// SetBatchSize 设置批量大小（测试用）。
func (c *Collector) SetBatchSize(n int) {
	if n > 0 {
		c.batchSize = n
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

// policyCounter 按策略聚合计数。
type policyCounter struct {
	total    int64
	rejected int64
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
	// 前缀指纹覆盖删除重建时 inode 被系统立即复用且文件大小相同的情况。
	offset := cp.Offset
	rotated := (cp.Inode != 0 && currentInode != cp.Inode) || info.Size() < offset
	if !rotated && cp.PrefixSize > 0 && cp.PrefixSHA256 != "" {
		currentPrefix, err := prefixFingerprint(f, cp.PrefixSize)
		if err != nil {
			return 0, fmt.Errorf("fingerprint guard event log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("guard event log rotated, resetting offset",
			"collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
		// 立即落断点（空前缀指纹）：文件截断为空期间若无新内容，断点不前进会导致每轮采集重复判定轮转刷日志
		if err := c.saveCheckpoint(checkpoint{Offset: 0, Inode: currentInode}); err != nil {
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
	var batch []Event
	agg := map[uuid.UUID]*policyCounter{}

	// flush 批量入库 + 策略汇总 + 保存断点
	flush := func() error {
		if len(batch) > 0 {
			if _, err := c.store.Insert(ctx, batch); err != nil {
				return fmt.Errorf("insert events batch: %w", err)
			}
			// syslog 外发（三期）：入库成功后非阻塞投递，不拖慢采集主流程。
			// 注意必须传值拷贝：batch 复用底层数组，下一批会覆盖本批元素。
			for i := range batch {
				evt := batch[i]
				c.syslog.Enqueue(syslogfw.KindAccessControlEvent, "", evt)
			}
			batch = batch[:0]
		}
		if len(agg) > 0 {
			c.insertSummaries(ctx, agg)
			agg = map[uuid.UUID]*policyCounter{}
		}
		prefixSize, prefixSHA256, err := checkpointFingerprint(f, committedOffset)
		if err != nil {
			return fmt.Errorf("fingerprint checkpoint: %w", err)
		}
		if err := c.saveCheckpoint(checkpoint{
			Offset:       committedOffset,
			Inode:        currentInode,
			PrefixSize:   prefixSize,
			PrefixSHA256: prefixSHA256,
		}); err != nil {
			return fmt.Errorf("save checkpoint: %w", err)
		}
		return nil
	}

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			evt, perr := ParseEventLine(line, c.nodeName)
			if perr != nil {
				c.failedCount++
				c.appendError(line, perr)
			} else {
				c.handleSideEffects(ctx, evt)
				if pid, ok := policyUUID(evt.PolicyID); ok {
					pc := agg[pid]
					if pc == nil {
						pc = &policyCounter{}
						agg[pid] = pc
					}
					pc.total++
					if isRejected(evt) {
						pc.rejected++
					}
				}
				batch = append(batch, *evt)
				c.processedCount++
				c.lastProcessed = time.Now()
			}
			if len(batch) >= c.batchSize {
				if ferr := flush(); ferr != nil {
					return processed, ferr
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return processed, err
		}
	}
	if err := flush(); err != nil {
		return processed, err
	}
	return processed, nil
}

// handleSideEffects 事件副作用：临时封禁入库 + 规则命中计数。
func (c *Collector) handleSideEffects(ctx context.Context, evt *Event) {
	switch evt.EventType {
	case EventTypeCCTempBlockCreated:
		if c.blocks == nil || evt.BlockExpiresAt == nil {
			return
		}
		block := &temporaryblocks.Block{
			ClientIP:        evt.ClientIP,
			ApplicationID:   evt.ApplicationID,
			TriggerType:     temporaryblocks.TriggerCCAuto,
			BlockExpiresAt:  *evt.BlockExpiresAt,
			Status:          temporaryblocks.StatusActive,
			TriggerEventIDs: []string{},
		}
		if pid, ok := policyUUID(evt.PolicyID); ok {
			block.TriggerPolicyID = &pid
		}
		if evt.RequestID != "" {
			block.TriggerEventIDs = []string{evt.RequestID}
		}
		if err := c.blocks.UpsertFromEvent(ctx, block); err != nil {
			slog.Error("upsert temporary block failed",
				"collector", c.collectorID, "client_ip", evt.ClientIP, "error", err)
		}
	case EventTypeURLAllowMatch:
		if c.urlHits == nil || evt.AccessRuleID == "" {
			return
		}
		ruleID, err := uuid.Parse(evt.AccessRuleID)
		if err != nil {
			slog.Warn("url whitelist access_rule_id is not a UUID, skip hit record",
				"collector", c.collectorID, "access_rule_id", evt.AccessRuleID)
			return
		}
		if err := c.urlHits.IncrementHit(ctx, ruleID, evt.OccurredAt); err != nil {
			slog.Error("increment url whitelist hit failed",
				"collector", c.collectorID, "access_rule_id", evt.AccessRuleID, "error", err)
		}
	case EventTypeCCThresholdExceeded, EventTypeCCRequestRejected:
		if c.hits == nil || evt.AccessRuleID == "" {
			return
		}
		ruleID, err := uuid.Parse(evt.AccessRuleID)
		if err != nil {
			slog.Warn("access_rule_id is not a UUID, skip hit record",
				"collector", c.collectorID, "access_rule_id", evt.AccessRuleID)
			return
		}
		if err := c.hits.IncrementHit(ctx, ruleID, evt.OccurredAt); err != nil {
			slog.Error("increment rule hit failed",
				"collector", c.collectorID, "access_rule_id", evt.AccessRuleID, "error", err)
		}
	}
}

// insertSummaries 按策略写入本批运行汇总（window_start 取批处理时间）。
func (c *Collector) insertSummaries(ctx context.Context, agg map[uuid.UUID]*policyCounter) {
	windowStart := time.Now().UTC()
	for pid, pc := range agg {
		sum := RuntimeSummary{
			PolicyID:         pid,
			WindowStart:      windowStart,
			TotalRequests:    pc.total,
			RejectedRequests: pc.rejected,
		}
		if err := c.store.InsertRuntimeSummary(ctx, sum); err != nil {
			slog.Error("insert runtime summary failed",
				"collector", c.collectorID, "policy_id", pid, "error", err)
		}
	}
}

// errorRecord 是错误文件中的一行。
type errorRecord struct {
	Time        time.Time `json:"time"`
	CollectorID string    `json:"collector_id"`
	Reason      string    `json:"reason"`
	RawLine     string    `json:"raw_line"`
}

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

// policyUUID 解析 policy_id 为 UUID（空或非 UUID 返回 false）。
func policyUUID(s string) (uuid.UUID, bool) {
	if s == "" {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("access control event collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("access control event collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected access control events", "collector", c.collectorID, "count", n)
			}
		}
	}
}
