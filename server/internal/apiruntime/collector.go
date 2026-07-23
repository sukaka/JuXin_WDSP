// collector.go API 动态防护运行时事件采集器（阶段8 / WDSP）。
// 读取网关 jiuzhang_guard 输出的 api-runtime-events JSONL，断点续传入库：
//   - 全部记录按 endpoint 发现信息 upsert 端点资产（持续发现数据源）；
//   - 含检测明细或动作非 ALLOW 的记录写入 api_runtime_events（按 request_id 幂等）。
//
// 与 accesscontrolevents 采集器同一套断点纪律：offset+inode+前缀指纹、轮转检测、
// 原子保存断点、解析失败行写错误文件（不静默丢弃）。
package apiruntime

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

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// PrimarySaver 主事件入库接口（*Store 实现，测试可注入内存实现）。
type PrimarySaver interface {
	SavePrimary(ctx context.Context, ev *events.PrimaryEvent) error
}

// DiscoveryUpserter 端点发现入库接口（*apiassets.Store 实现，可为 nil）。
type DiscoveryUpserter interface {
	UpsertDiscovery(ctx context.Context, method, pathTemplate string, confidence float64, isAPI bool) (*apiassets.Endpoint, error)
}

// Record 网关 apievents.Record 的采集端镜像（字段名与 JSON 输出一一对应）。
type Record struct {
	ID            string                `json:"id"`
	RequestID     string                `json:"request_id"`
	OccurredAt    time.Time             `json:"occurred_at"`
	ApplicationID string                `json:"application_id"`
	AppCode       string                `json:"app_code"`
	EndpointKey   string                `json:"endpoint_key"`
	Method        string                `json:"method"`
	PathTemplate  string                `json:"path_template"`
	IsAPI         bool                  `json:"is_api"`
	APIConfidence float64               `json:"api_confidence"`
	RiskScore     int                   `json:"risk_score"`
	RiskLevel     string                `json:"risk_level"`
	FinalAction   string                `json:"final_action"`
	Details       []dsctx.DetectorMatch `json:"details"`
	GatewayNode   string                `json:"gateway_node_id"`
}

// notable 是否需要写入主事件表（有检测明细或动作非 ALLOW；纯通行的 API 请求只喂发现）。
func (r *Record) notable() bool {
	return len(r.Details) > 0 || (r.FinalAction != "" && r.FinalAction != "ALLOW")
}

// Collector 是 API 运行时事件采集器。
type Collector struct {
	saver          PrimarySaver
	discovery      DiscoveryUpserter // nil 时跳过端点发现
	collectorID    string
	logPath        string
	checkpointPath string
	errorPath      string
	nodeName       string
	// 指标
	processedCount int64
	savedCount     int64
	failedCount    int64
	lastProcessed  time.Time
}

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
func NewCollector(saver PrimarySaver, collectorID, logPath, checkpointPath, nodeName string) *Collector {
	if checkpointPath == "" {
		checkpointPath = logPath + ".checkpoint"
	}
	return &Collector{
		saver:          saver,
		collectorID:    collectorID,
		logPath:        logPath,
		checkpointPath: checkpointPath,
		errorPath:      logPath + ".errors",
		nodeName:       nodeName,
	}
}

// SetDiscoveryUpserter 设置端点发现入库接口（应用装配时使用）。
func (c *Collector) SetDiscoveryUpserter(u DiscoveryUpserter) { c.discovery = u }

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
			return 0, fmt.Errorf("fingerprint api event log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("api runtime event log rotated, resetting offset",
			"collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
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
	committedOffset := offset
	var pending []events.PrimaryEvent

	// flush 主事件入库 + 保存断点；失败时断点不前移，下轮重读（SavePrimary 按 request_id 幂等）。
	flush := func() error {
		for i := range pending {
			if err := c.saver.SavePrimary(ctx, &pending[i]); err != nil {
				return fmt.Errorf("save primary event: %w", err)
			}
			c.savedCount++
		}
		pending = pending[:0]
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
			rec, perr := parseRecordLine(line)
			if perr != nil {
				c.failedCount++
				c.appendError(line, perr)
			} else {
				c.handleRecord(ctx, rec)
				if rec.notable() {
					pending = append(pending, events.PrimaryEvent{
						ID:            rec.ID,
						RequestID:     rec.RequestID,
						OccurredAt:    rec.OccurredAt,
						ApplicationID: rec.ApplicationID,
						EndpointKey:   rec.EndpointKey,
						RiskScore:     rec.RiskScore,
						RiskLevel:     rec.RiskLevel,
						FinalAction:   rec.FinalAction,
						Details:       rec.Details,
					})
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
	}
	if err := flush(); err != nil {
		return processed, err
	}
	return processed, nil
}

// handleRecord 记录副作用：端点发现 upsert（错误仅记录日志，不影响主流程）。
func (c *Collector) handleRecord(ctx context.Context, rec *Record) {
	if c.discovery == nil || rec.Method == "" || rec.PathTemplate == "" {
		return
	}
	if _, err := c.discovery.UpsertDiscovery(ctx, rec.Method, rec.PathTemplate, rec.APIConfidence, rec.IsAPI); err != nil {
		slog.Error("upsert api endpoint discovery failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
	}
}

// parseRecordLine 解析一行 JSONL 为记录；空 request_id 且空 endpoint_key 视为坏行。
func parseRecordLine(line []byte) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if rec.RequestID == "" && rec.EndpointKey == "" {
		return nil, fmt.Errorf("missing request_id and endpoint_key")
	}
	return &rec, nil
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
	slog.Info("api runtime event collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api runtime event collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected api runtime events", "collector", c.collectorID, "count", n)
			}
		}
	}
}
