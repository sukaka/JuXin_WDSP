// collector.go 站点发现采集器：tail 网关 mirrorcap 输出的 site-discovery.jsonl，
// 断点续传 upsert 入库（幂等键 domain+ip+port）。
//
// 断点纪律与 apiruntime / accesscontrolevents 采集器同一套：
// offset+inode+前缀指纹、轮转检测、原子保存断点（临时文件+rename）、批量 flush
// （batchSize 行或 EOF）、解析失败行写错误文件（不静默丢弃）、失败断点不前移
// （下轮重放由唯一键 upsert 兜底；seen_count 累加语义下重放会重复计数，
// 接受为近似指标，见 Store.Upsert 注释）。
//
// type != "site_discovery" 的行跳过（共享日志容忍其他类型行；不写错误文件，
// 单独计 skipped_count）。
package sitediscovery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Upserter 是采集器依赖的发现入库接口（*Store / *MemStore 实现）。
type Upserter interface {
	Upsert(ctx context.Context, in DiscoveryInput) (*Discovery, error)
}

// Record 是网关 site-discovery.jsonl 一行的采集端镜像（字段名与 JSON 输出一一对应）。
type Record struct {
	Type        string    `json:"type"`
	Node        string    `json:"node"`
	Domain      string    `json:"domain"`
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	SourceMode  string    `json:"source_mode"`
	Hits        int64     `json:"hits"`
	ClientCount int64     `json:"client_count"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

// parseRecordLine 解析一行 JSONL：
//   - 合法 JSON 且 type == site_discovery：返回记录（字段合法性由 normalizeInput 校验）；
//   - 合法 JSON 但 type 不符：返回 (nil, nil)，调用方跳过；
//   - 非法 JSON / 字段非法：返回错误（写错误文件）。
func parseRecordLine(line []byte) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if rec.Type != RecordType {
		return nil, nil
	}
	if _, err := normalizeInput(DiscoveryInput{
		Node: rec.Node, Domain: rec.Domain, IP: rec.IP, Port: rec.Port,
		Protocol: rec.Protocol, SourceMode: rec.SourceMode,
		Hits: rec.Hits, ClientCount: rec.ClientCount,
		WindowStart: rec.WindowStart, WindowEnd: rec.WindowEnd,
	}); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Collector 是站点发现采集器。
type Collector struct {
	store          Upserter
	collectorID    string
	logPath        string
	checkpointPath string
	errorPath      string
	nodeName       string
	batchSize      int
	// 指标
	processedCount int64
	savedCount     int64
	skippedCount   int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
// 当 checkpointPath 位于与 logPath 不同的可写目录（如容器内日志卷只读、checkpoint 落在 DataDir）时，
// 错误文件自动落入 checkpoint 同目录，避免向只读日志卷写入 .errors 失败。
func NewCollector(store Upserter, collectorID, logPath, checkpointPath, nodeName string) *Collector {
	errorPath := logPath + ".errors"
	if checkpointPath == "" {
		checkpointPath = logPath + ".checkpoint"
	} else if logPath != "" && filepath.Dir(checkpointPath) != filepath.Dir(logPath) {
		errorPath = filepath.Join(filepath.Dir(checkpointPath), filepath.Base(logPath)+".errors")
	}
	return &Collector{
		store:          store,
		collectorID:    collectorID,
		logPath:        logPath,
		checkpointPath: checkpointPath,
		errorPath:      errorPath,
		nodeName:       nodeName,
		batchSize:      100,
	}
}

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
		"saved_count":     c.savedCount,
		"skipped_count":   c.skippedCount,
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

// persistCheckpoint 计算已提交前缀指纹并原子保存断点（调用方保证对应数据已持久化）。
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

// pendingItem 待入库记录（raw 保留原始行，入库失败写错误文件用）。
type pendingItem struct {
	in  DiscoveryInput
	raw []byte
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
			return 0, fmt.Errorf("fingerprint site discovery log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("site discovery log rotated, resetting offset",
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
	var pending []pendingItem

	// flush 批量入库 + 保存断点；失败时断点不前移，下轮重读（upsert 按唯一键幂等）。
	// 单条输入非法（ErrInvalidInput，理论上 parse 阶段已拦截，此为兜底）不阻塞整批：
	// 写错误文件跳过该条，断点照常前移（数据问题重试无意义，避免毒行卡死队列）。
	flush := func() error {
		for i := range pending {
			if _, err := c.store.Upsert(ctx, pending[i].in); err != nil {
				if errors.Is(err, ErrInvalidInput) {
					c.failedCount++
					c.appendError(pending[i].raw, err)
					continue
				}
				return fmt.Errorf("upsert site discovery: %w", err)
			}
			c.savedCount++
		}
		pending = pending[:0]
		return c.persistCheckpoint(f, committedOffset, currentInode)
	}

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			rec, perr := parseRecordLine(line)
			if perr != nil {
				c.failedCount++
				c.appendError(line, perr)
			} else if rec == nil {
				// 非 site_discovery 类型行：跳过（不写错误文件）
				c.skippedCount++
			} else {
				node := rec.Node
				if node == "" {
					node = c.nodeName // 网关缺 node 字段时回落采集器配置节点名
				}
				pending = append(pending, pendingItem{
					in: DiscoveryInput{
						Node: node, Domain: rec.Domain, IP: rec.IP, Port: rec.Port,
						Protocol: rec.Protocol, SourceMode: rec.SourceMode,
						Hits: rec.Hits, ClientCount: rec.ClientCount,
						WindowStart: rec.WindowStart, WindowEnd: rec.WindowEnd,
					},
					raw: append([]byte(nil), line...),
				})
				c.processedCount++
				c.lastProcessed = time.Now()
			}
			if len(pending) >= c.batchSize {
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

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("site discovery collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("site discovery collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected site discoveries", "collector", c.collectorID, "count", n)
			}
		}
	}
}
