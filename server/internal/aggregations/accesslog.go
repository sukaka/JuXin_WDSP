// accesslog.go Caddy 访问日志采集器：解析 JSON 行，按分钟聚合成请求指标。
package aggregations

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// AccessLogEntry Caddy 访问日志行（字段按 Caddy 2.11 JSON 结构）。
type AccessLogEntry struct {
	Ts      float64 `json:"ts"`
	Request struct {
		RemoteIP string `json:"remote_ip"`
		Method   string `json:"method"`
		Host     string `json:"host"`
		URI      string `json:"uri"`
	} `json:"request"`
	Status   int     `json:"status"`
	Size     int64   `json:"size"`
	Duration float64 `json:"duration"` // 秒
}

// minuteBucket 单分钟请求聚合桶。
type minuteBucket struct {
	byAppStatus map[string]float64 // app|statusClass -> count
	durCounts   map[string][]int   // app -> duration bucket counts
	total       float64
}

func newMinuteBucket() *minuteBucket {
	return &minuteBucket{
		byAppStatus: map[string]float64{},
		durCounts:   map[string][]int{},
	}
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	default:
		return "2xx"
	}
}

func (b *minuteBucket) add(app string, status int, durationSec float64) {
	b.byAppStatus[app+"|"+statusClass(status)]++
	counts := b.durCounts[app]
	if counts == nil {
		counts = make([]int, len(metrics.DurationBucketsMs)+1)
		b.durCounts[app] = counts
	}
	counts[metrics.BucketIndex(durationSec*1000)]++
	b.total++
}

// rows 转换为聚合行。
func (b *minuteBucket) rows() []AggRow {
	var out []AggRow
	for k, v := range b.byAppStatus {
		parts := strings.SplitN(k, "|", 2)
		out = append(out, AggRow{
			Metric: metrics.HTTPRequestsTotal,
			Labels: map[string]string{"app": parts[0], "status_class": parts[1]},
			Value:  v,
		})
	}
	for app, counts := range b.durCounts {
		extra := map[string]interface{}{"buckets": counts}
		var total float64
		for _, c := range counts {
			total += float64(c)
		}
		out = append(out, AggRow{
			Metric: metrics.HTTPRequestDurationMs,
			Labels: map[string]string{"app": app},
			Value:  total,
			Extra:  extra,
		})
	}
	return out
}

// AccessLogCollector 访问日志采集器（断点续传）。
type AccessLogCollector struct {
	store     *Store
	logPath   string
	chkPath   string
	domainMap *DomainAppMap
	mapMu     sync.RWMutex
	lastMapAt time.Time
	onLag     func(seconds float64)
}

// NewAccessLogCollector 创建采集器。
func NewAccessLogCollector(store *Store, logPath, checkpointPath string) *AccessLogCollector {
	return &AccessLogCollector{store: store, logPath: logPath, chkPath: checkpointPath}
}

// SetLagCallback 设置采集延迟上报（供监控指标）。
func (c *AccessLogCollector) SetLagCallback(f func(seconds float64)) { c.onLag = f }

type checkpoint struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

func (c *AccessLogCollector) loadCheckpoint() (checkpoint, error) {
	var cp checkpoint
	data, err := os.ReadFile(c.chkPath)
	if err != nil {
		return cp, err
	}
	return cp, json.Unmarshal(data, &cp)
}

func (c *AccessLogCollector) saveCheckpoint(cp checkpoint) error {
	data, _ := json.Marshal(cp)
	tmp := c.chkPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.chkPath)
}

// refreshDomainMap 刷新域名映射（60s 缓存）。
func (c *AccessLogCollector) appForHost(ctx context.Context, host string) string {
	c.mapMu.RLock()
	m := c.domainMap
	stale := time.Since(c.lastMapAt) > time.Minute
	c.mapMu.RUnlock()
	if m == nil || stale {
		nm, err := c.store.RefreshDomainAppMap(ctx)
		if err == nil {
			c.mapMu.Lock()
			c.domainMap = nm
			c.lastMapAt = time.Now()
			c.mapMu.Unlock()
			m = nm
		}
	}
	host = strings.ToLower(host)
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if m != nil {
		if code, ok := m.ByHost[host]; ok {
			return code
		}
	}
	return "unknown"
}

// CollectOnce 执行一轮采集（增量读取并分钟聚合落库）。
func (c *AccessLogCollector) CollectOnce(ctx context.Context) (int, error) {
	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	cp, _ := c.loadCheckpoint()
	// 轮转检测：inode 变化或文件变短 → 从头读
	inode := inodeOf(st)
	if cp.Inode != inode || cp.Offset > st.Size() {
		cp = checkpoint{Inode: inode}
	}
	if _, err := f.Seek(cp.Offset, 0); err != nil {
		return 0, err
	}
	// 逐行解析（只处理完整行）
	buckets := map[time.Time]*minuteBucket{}
	var lastComplete time.Time
	n := 0
	pos := cp.Offset
	var line []byte
	buf := make([]byte, 0, 65536)
	for {
		chunk := make([]byte, 32768)
		m, rerr := f.Read(chunk)
		if m > 0 {
			buf = append(buf, chunk[:m]...)
			for {
				idx := indexByte(buf, '\n')
				if idx < 0 {
					break
				}
				line = buf[:idx]
				buf = buf[idx+1:]
				pos += int64(idx + 1)
				var e AccessLogEntry
				if err := json.Unmarshal(line, &e); err != nil {
					continue // 坏行跳过（访问日志行级容错，不中断采集）
				}
				if e.Ts == 0 {
					continue
				}
				ts := time.Unix(int64(e.Ts), int64((e.Ts-float64(int64(e.Ts)))*1e9)).UTC()
				bucket := ts.Truncate(time.Minute)
				mb := buckets[bucket]
				if mb == nil {
					mb = newMinuteBucket()
					buckets[bucket] = mb
				}
				mb.add(c.appForHost(ctx, e.Request.Host), e.Status, e.Duration)
				n++
				if ts.After(lastComplete) {
					lastComplete = ts
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	// 落库（只写完整过去的分钟桶；当前进行中的分钟也写入（下一轮重算覆盖））
	written := 0
	for bucket, mb := range buckets {
		w, err := c.store.upsertMinute(ctx, bucket, mb.rows())
		if err != nil {
			return n, fmt.Errorf("upsert minute: %w", err)
		}
		written += w
	}
	if err := c.saveCheckpoint(checkpoint{Offset: pos, Inode: inode}); err != nil {
		return n, fmt.Errorf("save checkpoint: %w", err)
	}
	if c.onLag != nil && !lastComplete.IsZero() {
		c.onLag(time.Since(lastComplete).Seconds())
	}
	_ = written
	return n, nil
}

// Run 周期采集。
func (c *AccessLogCollector) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = c.CollectOnce(ctx)
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func inodeOf(st os.FileInfo) uint64 {
	if st == nil {
		return 0
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return uint64(st.ModTime().Unix())
}
