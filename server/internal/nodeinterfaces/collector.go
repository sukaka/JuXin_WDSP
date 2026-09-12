// collector.go 节点网口清单采集器（WDSP 阶段A）。
// 网关在共享日志卷写 node-interfaces.jsonl 全量快照（每行一个接口），
// 采集器每 60s 全量读取并按节点重建清单（UPSERT 语义见包注释）。
// 与 apiruntime 采集器同一纪律：坏行写 .errors 文件，不静默丢弃；文件缺失视为正常空转。
package nodeinterfaces

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// SnapshotStore 快照入库接口（*Store 与 *MemStore 实现）。
type SnapshotStore interface {
	ApplySnapshot(ctx context.Context, nodeName string, items []SnapshotItem, seenAt time.Time) error
}

// Collector 是节点网口清单采集器。
type Collector struct {
	store       SnapshotStore
	collectorID string
	logPath     string
	errorPath   string
	// 指标
	runCount      int64
	appliedCount  int64
	failedCount   int64
	lastCollected time.Time
}

// NewCollector 创建采集器。
func NewCollector(store SnapshotStore, collectorID, logPath string) *Collector {
	return &Collector{
		store:       store,
		collectorID: collectorID,
		logPath:     logPath,
		errorPath:   logPath + ".errors",
	}
}

// Metrics 返回采集指标。
func (c *Collector) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"collector_id":   c.collectorID,
		"run_count":      c.runCount,
		"applied_count":  c.appliedCount,
		"failed_count":   c.failedCount,
		"last_collected": c.lastCollected,
		"log_path":       c.logPath,
	}
}

// CollectOnce 执行一次全量采集。返回快照行数。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 快照文件尚未生成（网关未上报时正常）
		}
		return 0, err
	}
	defer f.Close()

	// 按节点分组（保持文件内先后次序，作为新口排尾依据）
	byNode := map[string][]SnapshotItem{}
	var nodeOrder []string
	seenAt := map[string]time.Time{}
	lines := 0
	reader := bufio.NewReader(f)
	for {
		line, rerr := reader.ReadBytes('\n')
		trimmed := strings.TrimSpace(string(line))
		if trimmed != "" {
			lines++
			var item SnapshotItem
			if perr := json.Unmarshal([]byte(trimmed), &item); perr != nil {
				c.failedCount++
				c.appendError(trimmed, fmt.Errorf("bad json: %w", perr))
			} else if item.NodeName == "" || item.Ifname == "" {
				c.failedCount++
				c.appendError(trimmed, fmt.Errorf("missing node_name or ifname"))
			} else {
				if _, ok := byNode[item.NodeName]; !ok {
					nodeOrder = append(nodeOrder, item.NodeName)
				}
				byNode[item.NodeName] = append(byNode[item.NodeName], item)
				if item.CollectedAt.After(seenAt[item.NodeName]) {
					seenAt[item.NodeName] = item.CollectedAt
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return lines, rerr
		}
	}

	for _, node := range nodeOrder {
		at := seenAt[node]
		if at.IsZero() {
			at = time.Now().UTC()
		}
		if err := c.store.ApplySnapshot(ctx, node, byNode[node], at); err != nil {
			return lines, fmt.Errorf("apply snapshot for node %s: %w", node, err)
		}
		c.appliedCount += int64(len(byNode[node]))
	}
	c.runCount++
	c.lastCollected = time.Now().UTC()
	return lines, nil
}

// errorRecord 是错误文件中的一行。
type errorRecord struct {
	Time        time.Time `json:"time"`
	CollectorID string    `json:"collector_id"`
	Reason      string    `json:"reason"`
	RawLine     string    `json:"raw_line"`
}

// appendError 把解析失败的行追加到错误文件（不静默丢弃）。
func (c *Collector) appendError(raw string, cause error) {
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

// Run 持续采集（默认 60s 周期；启动时先采集一次）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 60 * time.Second
	}
	slog.Info("node interface collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	if _, err := c.CollectOnce(ctx); err != nil {
		slog.Error("collect error", "collector", c.collectorID, "error", err)
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("node interface collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected node interfaces", "collector", c.collectorID, "count", n)
			}
		}
	}
}
