package runtimehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/upstreams"
)

// 默认采集参数
const (
	DefaultInterval           = 30 * time.Second
	defaultGuardStaleAfter    = 5 * time.Minute
	defaultUpstreamTimeout    = 3 * time.Second
	defaultEventLagDegraded   = 120.0 // 秒
	defaultDiskLowFreePercent = 10.0
	// defaultAccessLogStaleAfter accesslog-01 链路停滞降级阈值（与事件采集滞后同档；
	// settings logging.access_log_stale_seconds 可覆盖）。
	defaultAccessLogStaleAfter = 120 * time.Second
	// defaultAPIEventStaleAfter API 运行时事件停滞降级阈值（默认 10 分钟）。
	// 低流量站点分钟级无事件属正常，阈值取保守值避免误报。
	defaultAPIEventStaleAfter = 10 * time.Minute
	maxUpstreamProbes         = 20 // 单轮最多探测的源站数（控制采集耗时）
	maxUpstreamFailDetails    = 5  // metrics 中最多记录的失败明细
	probeDBTimeout            = 5 * time.Second
)

// startedAt 记录进程启动时间（API 自测 uptime）。
var startedAt = time.Now()

// Options 是采集器选项。
type Options struct {
	// Caddy 网关 Admin 客户端；nil 时 GATEWAY/CORAZA/GUARD 为 UNKNOWN
	Caddy *gatewayconfig.CaddyClient
	// Cache Valkey 客户端；nil 时 VALKEY 为 UNKNOWN
	Cache *cache.Client
	// GuardEventsLog jiuzhang_guard 事件日志路径（mtime 停滞判断）
	GuardEventsLog string
	// SecurityCollectorID 安全事件采集器 collector_id（DB checkpoint）
	SecurityCollectorID string
	// GuardEventsCheckpoint 访问控制事件采集 checkpoint 文件路径
	GuardEventsCheckpoint string
	// AccessLogCheckpoint access-log 采集 checkpoint 文件路径
	AccessLogCheckpoint string
	// AccessLogPath Caddy 访问日志路径（滞后积压计算）
	AccessLogPath string
	// AccessLogFullCollectorID 全量访问日志采集器 collector_id（DB checkpoint，默认 accesslog-01）
	AccessLogFullCollectorID string
	// AccessLogStaleAfter accesslog-01 链路停滞降级阈值（默认 120 秒；
	// settings logging.access_log_stale_seconds 可覆盖）
	AccessLogStaleAfter time.Duration
	// Settings 系统设置读取源（accesslog-01 链路开关 logging.access_log_enabled 与
	// 停滞阈值覆盖）；nil 时该链路不纳入 EVENT_COLLECTOR 判级（默认部署零行为变化）
	Settings SettingsReader
	// APMClickHouse APM ClickHouse 数据面探针（APM_ENABLED 且 DSN 连接成功时由装配层
	// 注入）；nil 时 APM_CLICKHOUSE 组件不采集不判级（默认部署零行为变化）
	APMClickHouse ClickHouseProber
	// DiskPath 磁盘检测挂载点（默认 /app）
	DiskPath string
	// GuardStaleAfter guard 日志停滞阈值（默认 5 分钟）
	GuardStaleAfter time.Duration
	// APIEventStaleAfter API 运行时事件停滞降级阈值（默认 10 分钟）
	APIEventStaleAfter time.Duration
	// UpstreamTimeout 源站健康探测超时（默认 3 秒）
	UpstreamTimeout time.Duration
	// EventLagDegradedSeconds 事件采集滞后降级阈值（默认 120 秒）
	EventLagDegradedSeconds float64
	// DiskLowFreePercent 磁盘剩余不足降级阈值（默认 10%）
	DiskLowFreePercent float64
	// FDUsageHighPercent 文件句柄使用率降级阈值（默认 80%）
	FDUsageHighPercent float64
	// CertExpiringDays 证书临期阈值（默认 30 天）
	CertExpiringDays int
	// Now 时钟（测试注入）
	Now func() time.Time
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.SecurityCollectorID == "" {
		out.SecurityCollectorID = "collector-01"
	}
	if out.DiskPath == "" {
		out.DiskPath = "/app"
	}
	if out.GuardStaleAfter <= 0 {
		out.GuardStaleAfter = defaultGuardStaleAfter
	}
	if out.APIEventStaleAfter <= 0 {
		out.APIEventStaleAfter = defaultAPIEventStaleAfter
	}
	if out.AccessLogFullCollectorID == "" {
		out.AccessLogFullCollectorID = defaultAccessLogFullCollectorID
	}
	if out.AccessLogStaleAfter <= 0 {
		out.AccessLogStaleAfter = defaultAccessLogStaleAfter
	}
	if out.UpstreamTimeout <= 0 {
		out.UpstreamTimeout = defaultUpstreamTimeout
	}
	if out.EventLagDegradedSeconds <= 0 {
		out.EventLagDegradedSeconds = defaultEventLagDegraded
	}
	if out.DiskLowFreePercent <= 0 {
		out.DiskLowFreePercent = defaultDiskLowFreePercent
	}
	if out.FDUsageHighPercent <= 0 {
		out.FDUsageHighPercent = defaultFDUsageHighPercent
	}
	if out.CertExpiringDays <= 0 {
		out.CertExpiringDays = 30
	}
	if out.Now == nil {
		out.Now = func() time.Time { return time.Now().UTC() }
	}
	return out
}

// Collector 周期性采集组件健康并写入快照表。
type Collector struct {
	db    *pgxpool.Pool
	store *Store
	opts  Options

	lastHealthPurge time.Time // 上次源站健康记录清理时间（按周期节流）
}

// NewCollector 创建采集器。
func NewCollector(db *pgxpool.Pool, opts Options) *Collector {
	return &Collector{db: db, store: NewStore(db), opts: opts.withDefaults()}
}

// Store 返回快照仓储（供查询复用）。
func (c *Collector) Store() *Store { return c.store }

// Run 周期采集，直到 ctx 取消。启动时立即采集一轮。
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("runtime health collector started", "interval", interval)
	c.collectSafe(ctx)
	for {
		select {
		case <-ctx.Done():
			slog.Info("runtime health collector stopped")
			return
		case <-ticker.C:
			c.collectSafe(ctx)
		}
	}
}

// collectSafe 采集一轮；单组件失败不影响其他组件，整体不返回错误。
func (c *Collector) collectSafe(ctx context.Context) {
	if err := c.CollectOnce(ctx); err != nil {
		slog.Error("runtime health collect error", "error", err)
	}
}

// CollectOnce 执行一轮采集并落库。单组件探针错误转为 DOWN/UNKNOWN 快照而非中断。
func (c *Collector) CollectOnce(ctx context.Context) error {
	snaps := c.collectAll(ctx)
	for _, snap := range snaps {
		if err := c.store.Insert(ctx, snap); err != nil {
			return fmt.Errorf("insert %s snapshot: %w", snap.Component, err)
		}
	}
	return nil
}

// LatestAll 查询各组件最新快照。
func (c *Collector) LatestAll(ctx context.Context) ([]Snapshot, error) {
	return c.store.LatestAll(ctx)
}

// collectAll 采集全部组件（顺序执行，单轮总耗时受各探针超时约束）。
func (c *Collector) collectAll(ctx context.Context) []*Snapshot {
	gw := c.probeGateway(ctx)
	disk := c.probeDisk()
	pg := c.probePostgres(ctx, disk)
	snaps := []*Snapshot{
		gw,
		c.deriveCoraza(gw),
		c.probeGuard(gw),
		c.probeAPI(),
		pg,
		c.probeValkey(ctx),
		c.probeEventCollector(ctx),
		c.probeAPISecurity(ctx),
		c.probeUpstreams(ctx),
		c.probeCertificates(ctx),
		disk,
	}
	// APM ClickHouse 数据面：仅注入探针时纳入采集（DSN 空/未接入不判级，见 apm_clickhouse.go）
	if c.apmClickHouseIncluded() {
		snaps = append(snaps, c.probeAPMClickHouse(ctx))
	}
	return snaps
}

// ---------- GATEWAY ----------

func (c *Collector) probeGateway(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentGateway, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	if c.opts.Caddy == nil {
		snap.Message = "未配置网关 Admin Socket"
		return snap
	}
	pingCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	start := c.opts.Now()
	if err := c.opts.Caddy.Ping(pingCtx); err != nil {
		snap.Status = StatusDown
		snap.Message = "网关 Admin Socket 不可达"
		return snap
	}
	latency := int(c.opts.Now().Sub(start).Milliseconds())
	snap.LatencyMs = &latency
	hash, err := c.opts.Caddy.GetConfigHash(pingCtx)
	if err != nil {
		snap.Status = StatusDegraded
		snap.Message = "网关可达但读取当前配置失败"
		return snap
	}
	snap.Status = StatusUp
	snap.Metrics[MetricConfigHash] = hash
	return snap
}

// ---------- CORAZA / GUARD（间接判定） ----------

// deriveCoraza Coraza 嵌入网关进程：网关可达即 UP，网关 DOWN 则 DOWN。
func (c *Collector) deriveCoraza(gw *Snapshot) *Snapshot {
	snap := &Snapshot{Component: ComponentCoraza, Metrics: map[string]interface{}{}}
	switch gw.Status {
	case StatusUp, StatusDegraded:
		snap.Status = StatusUp
		snap.Message = "间接判定：网关进程可达"
	case StatusDown:
		snap.Status = StatusDown
		snap.Message = "间接判定：网关不可达"
	default:
		snap.Status = StatusUnknown
		snap.Message = "间接判定：网关状态未知"
	}
	return snap
}

// probeGuard guard 嵌入网关进程；网关可达且事件日志持续写入为 UP，
// 日志停滞超过阈值（GuardStaleAfter）判 DEGRADED。
func (c *Collector) probeGuard(gw *Snapshot) *Snapshot {
	snap := &Snapshot{Component: ComponentGuard, Metrics: map[string]interface{}{}}
	switch gw.Status {
	case StatusDown:
		snap.Status = StatusDown
		snap.Message = "间接判定：网关不可达"
		return snap
	case StatusUnknown:
		snap.Status = StatusUnknown
		snap.Message = "间接判定：网关状态未知"
		return snap
	}
	staleSecs := fileStaleSeconds(c.opts.GuardEventsLog, c.opts.Now())
	if staleSecs < 0 {
		// 日志尚未生成：无事件写入属正常（无命中），不判降级
		snap.Status = StatusUp
		snap.Message = "guard 事件日志尚未生成"
		return snap
	}
	snap.Metrics[MetricGuardLogStaleSecs] = staleSecs
	if staleSecs > c.opts.GuardStaleAfter.Seconds() {
		snap.Status = StatusDegraded
		snap.Message = fmt.Sprintf("guard 事件日志 %d 秒无写入", int(staleSecs))
		return snap
	}
	snap.Status = StatusUp
	snap.Message = "间接判定：网关可达，事件日志写入正常"
	return snap
}

// fileStaleSeconds 返回文件 mtime 距 now 的秒数；文件不存在返回 -1。
func fileStaleSeconds(path string, now time.Time) float64 {
	if path == "" {
		return -1
	}
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return now.Sub(info.ModTime()).Seconds()
}

// ---------- API（自测） ----------

func (c *Collector) probeAPI() *Snapshot {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	now := c.opts.Now()
	snap := &Snapshot{
		Component: ComponentAPI,
		Status:    StatusUp,
		Message:   "进程运行中",
		Metrics: map[string]interface{}{
			MetricGoroutines:     runtime.NumGoroutine(),
			MetricHeapAllocBytes: mem.HeapAlloc,
			MetricMemorySysBytes: mem.Sys,
			MetricUptimeSeconds:  int64(now.Sub(startedAt).Seconds()),
		},
	}
	// 文件句柄（阶段6 §10.2）：采集不可用（非 Linux / 读取失败）时不产出指标、不判级
	if open, max, ok := fdUsage(); ok {
		usage := fdUsagePercent(open, max)
		snap.Metrics[MetricFDOpenFiles] = open
		snap.Metrics[MetricFDMaxOpenFiles] = max
		snap.Metrics[MetricFDUsagePercent] = usage
		if fdStatus(usage, c.opts.FDUsageHighPercent) == StatusDegraded {
			snap.Status = StatusDegraded
			snap.Message = fmt.Sprintf("文件句柄使用率 %.1f%%（阈值 %.0f%%）", usage, c.opts.FDUsageHighPercent)
		}
	}
	return snap
}

// ---------- POSTGRES ----------

func (c *Collector) probePostgres(ctx context.Context, disk *Snapshot) *Snapshot {
	snap := &Snapshot{Component: ComponentPostgres, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	pgCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	start := c.opts.Now()
	if err := c.db.Ping(pgCtx); err != nil {
		snap.Status = StatusDown
		snap.Message = "数据库不可达"
		return snap
	}
	latency := int(c.opts.Now().Sub(start).Milliseconds())
	snap.LatencyMs = &latency
	var sizeBytes int64
	var conns int
	err := c.db.QueryRow(pgCtx, `
SELECT pg_database_size(current_database()),
       (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database())`).Scan(&sizeBytes, &conns)
	if err != nil {
		snap.Status = StatusDegraded
		snap.Message = "数据库可达但容量指标查询失败"
		return snap
	}
	snap.Status = StatusUp
	snap.Metrics[MetricDatabaseSizeBytes] = sizeBytes
	snap.Metrics[MetricDBConnections] = conns
	// 数据库容量占磁盘比例（同卷部署假设，供 DATABASE_CAPACITY_HIGH 评估）
	if total, ok := metricFloat(disk.Metrics, MetricDiskTotalBytes); ok && total > 0 {
		snap.Metrics[MetricDBCapacityPercent] = float64(sizeBytes) / total * 100
	}
	return snap
}

// ---------- VALKEY ----------

func (c *Collector) probeValkey(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentValkey, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	if c.opts.Cache == nil {
		snap.Message = "未配置 Valkey 客户端"
		return snap
	}
	vCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	start := c.opts.Now()
	info, err := c.opts.Cache.Redis().Info(vCtx, "memory", "clients").Result()
	if err != nil {
		snap.Status = StatusDown
		snap.Message = "Valkey 不可达"
		return snap
	}
	latency := int(c.opts.Now().Sub(start).Milliseconds())
	snap.LatencyMs = &latency
	dbsize, err := c.opts.Cache.Redis().DBSize(vCtx).Result()
	if err != nil {
		snap.Status = StatusDegraded
		snap.Message = "Valkey 可达但 DBSize 查询失败"
		return snap
	}
	snap.Status = StatusUp
	snap.Metrics[MetricUsedMemoryBytes] = parseInfoInt(info, "used_memory")
	snap.Metrics[MetricConnectedClients] = parseInfoInt(info, "connected_clients")
	snap.Metrics[MetricDBSizeKeys] = dbsize
	return snap
}

// parseInfoInt 解析 Redis INFO 文本中的整型字段。
func parseInfoInt(info, key string) int64 {
	prefix := key + ":"
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			var n int64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, prefix), "%d", &n); err == nil {
				return n
			}
		}
	}
	return 0
}

// ---------- EVENT_COLLECTOR ----------

// CheckpointLag 是单个采集 checkpoint 的滞后情况。
type CheckpointLag struct {
	Name    string  `json:"name"`
	LagSecs float64 `json:"lag_seconds"`
	Missing bool    `json:"missing"`
}

// backlogLag 计算采集滞后语义：日志文件无未消费字节时滞后为 0；
// 有积压时为「当前时间 - checkpoint 最后推进时间」。
func backlogLag(logPath string, offset int64, checkpointAt, now time.Time) float64 {
	st, err := os.Stat(logPath)
	if err != nil {
		// 日志不存在：无积压
		return 0
	}
	if offset >= st.Size() {
		return 0
	}
	return now.Sub(checkpointAt).Seconds()
}

// fileCheckpoint 文件型 checkpoint 结构（与采集器实现一致）。
type fileCheckpoint struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

// readFileCheckpoint 读取文件型 checkpoint（offset+inode）。
func readFileCheckpoint(path string) (fileCheckpoint, time.Time, bool) {
	var cp fileCheckpoint
	data, err := os.ReadFile(path)
	if err != nil {
		return cp, time.Time{}, false
	}
	if err := json.Unmarshal(data, &cp); err != nil {
		return cp, time.Time{}, false
	}
	st, err := os.Stat(path)
	if err != nil {
		return cp, time.Time{}, false
	}
	return cp, st.ModTime(), true
}

// probeEventCollector 汇总采集 checkpoint 的滞后：
// 安全事件（DB 表 event_collector_checkpoints）、访问控制事件与 access-log（文件 checkpoint），
// 以及 accesslog-01 全量访问日志（DB checkpoint；仅 logging.access_log_enabled=true
// 时纳入判级，见 accesslog_freshness.go）。
// 滞后语义：存在未消费日志字节时才算滞后（checkpoint 推进时间至今），无积压为 0。
func (c *Collector) probeEventCollector(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentEventCollector, Metrics: map[string]interface{}{}}
	now := c.opts.Now()
	var cps []CheckpointLag

	// 1. 安全事件采集（DB checkpoint：offset + 文件路径 + 推进时间）
	dbCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	var offset int64
	var filePath string
	var updatedAt time.Time
	err := c.db.QueryRow(dbCtx,
		`SELECT file_offset, file_path, updated_at FROM event_collector_checkpoints WHERE collector_id = $1`,
		c.opts.SecurityCollectorID).Scan(&offset, &filePath, &updatedAt)
	switch {
	case err == nil:
		cps = append(cps, CheckpointLag{Name: "security_events", LagSecs: backlogLag(filePath, offset, updatedAt, now)})
	case err == pgx.ErrNoRows:
		cps = append(cps, CheckpointLag{Name: "security_events", Missing: true})
	default:
		snap.Status = StatusUnknown
		snap.Message = "checkpoint 查询失败"
		return snap
	}

	// 2. 访问控制事件采集（文件 checkpoint）
	if cp, at, ok := readFileCheckpoint(c.opts.GuardEventsCheckpoint); ok {
		cps = append(cps, CheckpointLag{Name: "access_control_events", LagSecs: backlogLag(c.opts.GuardEventsLog, cp.Offset, at, now)})
	} else {
		cps = append(cps, CheckpointLag{Name: "access_control_events", Missing: true})
	}

	// 3. access-log 采集（文件 checkpoint）
	if cp, at, ok := readFileCheckpoint(c.opts.AccessLogCheckpoint); ok {
		cps = append(cps, CheckpointLag{Name: "access_log", LagSecs: backlogLag(c.opts.AccessLogPath, cp.Offset, at, now)})
	} else {
		cps = append(cps, CheckpointLag{Name: "access_log", Missing: true})
	}

	// 4. accesslog-01 全量访问日志采集（APM 阶段1 WP5，DB checkpoint）；
	// 仅 logging.access_log_enabled=true 时纳入判级（开关关闭无日志产出，不报停滞）
	al := c.probeAccessLogFull(ctx, now)
	if al.err != nil {
		snap.Status = StatusUnknown
		snap.Message = "checkpoint 查询失败"
		return snap
	}
	if al.included {
		cps = append(cps, al.cp)
		if !al.cp.Missing {
			snap.Metrics[MetricAccessLogStaleSecs] = al.cp.LagSecs
		}
	}

	maxLag, _ := SummarizeCheckpoints(cps) // missing 计数在 eventCollectorStatus 内判级
	snap.Metrics[MetricMaxLagSeconds] = maxLag
	snap.Metrics[MetricCheckpoints] = cps
	snap.Status, snap.Message = eventCollectorStatus(cps, c.opts.EventLagDegradedSeconds, al)
	return snap
}

// SummarizeCheckpoints 返回最大滞后秒数与缺失数量（缺失不参与滞后计算）。
func SummarizeCheckpoints(cps []CheckpointLag) (maxLag float64, missing int) {
	for _, cp := range cps {
		if cp.Missing {
			missing++
			continue
		}
		if cp.LagSecs > maxLag {
			maxLag = cp.LagSecs
		}
	}
	return maxLag, missing
}

// ---------- UPSTREAM ----------

// probeUpstreams 探测启用健康检查的 HTTP 源站（SSRF 防护复用 upstreams 包，仅 http 协议）。
func (c *Collector) probeUpstreams(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentUpstream, Metrics: map[string]interface{}{}}
	qCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	rows, err := c.db.Query(qCtx, `
SELECT id, name, host, port, health_check_path, expected_status_codes
FROM upstreams
WHERE status = 'ACTIVE' AND health_check_enabled = TRUE AND deleted_at IS NULL AND scheme = 'http'
ORDER BY created_at ASC LIMIT $1`, maxUpstreamProbes)
	if err != nil {
		snap.Status = StatusUnknown
		snap.Message = "源站清单查询失败"
		return snap
	}
	defer rows.Close()
	type target struct {
		id                         uuid.UUID
		name, host, path, expected string
		port                       int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.name, &t.host, &t.port, &t.path, &t.expected); err != nil {
			snap.Status = StatusUnknown
			snap.Message = "源站清单读取失败"
			return snap
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		snap.Status = StatusUnknown
		snap.Message = "源站清单读取失败"
		return snap
	}
	if len(targets) == 0 {
		snap.Status = StatusUp
		snap.Message = "无启用健康检查的 HTTP 源站"
		snap.Metrics[MetricUpstreamTotal] = 0
		snap.Metrics[MetricUpstreamHealthy] = 0
		snap.Metrics[MetricUpstreamUnhealthy] = 0
		return snap
	}

	healthy := 0
	var failures []map[string]interface{}
	var records []upstreamHealthRecord
	for _, t := range targets {
		probeCtx, probeCancel := context.WithTimeout(ctx, c.opts.UpstreamTimeout)
		res := upstreams.TestConnectivity(probeCtx, upstreams.TestInput{
			Scheme:          "http",
			Host:            t.host,
			Port:            t.port,
			HealthCheckPath: t.path,
		})
		probeCancel()
		rec := upstreamHealthRecord{
			upstreamID:     t.id,
			responseStatus: res.HTTPStatus,
			responseTimeMs: res.ResponseTimeMs,
			errorCode:      res.ErrorCode,
			errorMessage:   res.ErrorMessage,
		}
		if res.ErrorCode == "" && upstreams.CheckExpectedStatus(res.HTTPStatus, t.expected) {
			healthy++
			rec.status = StatusUp
		} else {
			rec.status = StatusDown
			if len(failures) < maxUpstreamFailDetails {
				failures = append(failures, map[string]interface{}{
					"name": t.name, "host": t.host, "port": t.port,
					"error_code": res.ErrorCode, "http_status": res.HTTPStatus,
				})
			}
		}
		records = append(records, rec)
	}
	// 逐源站健康记录落库（报告/仪表盘数据源；此前该表无写入方，报告只能显示 UNKNOWN）
	c.writeUpstreamHealthRecords(ctx, records)
	total := len(targets)
	unhealthy := total - healthy
	snap.Metrics[MetricUpstreamTotal] = total
	snap.Metrics[MetricUpstreamHealthy] = healthy
	snap.Metrics[MetricUpstreamUnhealthy] = unhealthy
	snap.Metrics[MetricUpstreamFailures] = failures
	snap.Status = upstreamStatus(total, healthy)
	snap.Message = fmt.Sprintf("源站健康 %d/%d", healthy, total)
	return snap
}

// upstreamHealthRecord 单条源站健康探测记录。
type upstreamHealthRecord struct {
	upstreamID     uuid.UUID
	status         string
	responseStatus int
	responseTimeMs int64
	errorCode      string
	errorMessage   string
}

// upstreamHealthRetention 源站健康记录保留时长（超出即清理）。
const upstreamHealthRetention = 7 * 24 * time.Hour

// writeUpstreamHealthRecords 批量写入源站健康记录（含连续成功/失败计数），
// 并按保留时长节流清理历史记录。写库失败只记日志，不影响快照采集主流程。
func (c *Collector) writeUpstreamHealthRecords(ctx context.Context, records []upstreamHealthRecord) {
	if len(records) == 0 {
		return
	}
	qCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()

	ids := make([]uuid.UUID, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.upstreamID)
	}
	// 上一轮各源站连续计数（DISTINCT ON 取最新一条）
	prev := map[uuid.UUID][2]int{}
	rows, err := c.db.Query(qCtx, `
SELECT DISTINCT ON (upstream_id) upstream_id, status, consecutive_successes, consecutive_failures
FROM upstream_health_records WHERE upstream_id = ANY($1)
ORDER BY upstream_id, checked_at DESC`, ids)
	if err != nil {
		slog.Error("query previous upstream health records failed", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var status string
			var succ, fail int
			if err := rows.Scan(&id, &status, &succ, &fail); err == nil {
				if status == StatusUp {
					prev[id] = [2]int{succ, 0}
				} else {
					prev[id] = [2]int{0, fail}
				}
			}
		}
	}

	for _, r := range records {
		succ, fail := 0, 0
		if p, ok := prev[r.upstreamID]; ok {
			succ, fail = p[0], p[1]
		}
		if r.status == StatusUp {
			succ, fail = succ+1, 0
		} else {
			succ, fail = 0, fail+1
		}
		errMsg := r.errorMessage
		if len(errMsg) > 512 {
			errMsg = errMsg[:512]
		}
		if _, err := c.db.Exec(qCtx, `
INSERT INTO upstream_health_records
  (upstream_id, status, response_status, response_time_ms, error_code, error_message, consecutive_successes, consecutive_failures)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			r.upstreamID, r.status, r.responseStatus, r.responseTimeMs, r.errorCode, errMsg, succ, fail); err != nil {
			slog.Error("insert upstream health record failed", "upstream_id", r.upstreamID, "error", err)
		}
	}

	// 节流清理历史记录（每小时一次；采集间隔 30s，避免每轮全表扫描）
	if time.Since(c.lastHealthPurge) > time.Hour {
		if _, err := c.db.Exec(qCtx,
			`DELETE FROM upstream_health_records WHERE checked_at < now() - $1::interval`,
			upstreamHealthRetention.String()); err != nil {
			slog.Error("purge upstream health records failed", "error", err)
		} else {
			c.lastHealthPurge = time.Now()
		}
	}
}

// upstreamStatus 源站总体状态：全部健康 UP；部分健康 DEGRADED；全部失败 DOWN。
func upstreamStatus(total, healthy int) string {
	switch {
	case total == 0 || healthy == total:
		return StatusUp
	case healthy == 0:
		return StatusDown
	default:
		return StatusDegraded
	}
}

// ---------- CERTIFICATE ----------

func (c *Collector) probeCertificates(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentCertificate, Metrics: map[string]interface{}{}}
	cCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	var minDays *float64
	var expiring, expired int
	err := c.db.QueryRow(cCtx, `
SELECT
  min(EXTRACT(EPOCH FROM (not_after - now())) / 86400),
  count(*) FILTER (WHERE not_after > now() AND not_after <= now() + $1::interval),
  count(*) FILTER (WHERE not_after <= now())
FROM certificates
WHERE status = 'VALID' AND deleted_at IS NULL AND not_after IS NOT NULL`,
		fmt.Sprintf("%d days", c.opts.CertExpiringDays)).Scan(&minDays, &expiring, &expired)
	if err != nil {
		snap.Status = StatusUnknown
		snap.Message = "证书指标查询失败"
		return snap
	}
	snap.Metrics[MetricExpiringCount] = expiring
	snap.Metrics[MetricExpiredCount] = expired
	if minDays == nil {
		snap.Status = StatusUp
		snap.Message = "无在役证书"
		snap.Metrics[MetricMinDaysRemaining] = nil
		return snap
	}
	days := int(*minDays)
	snap.Metrics[MetricMinDaysRemaining] = days
	snap.Status = certStatus(days, expired, c.opts.CertExpiringDays)
	snap.Message = certMessage(days, expired)
	return snap
}

// certStatus 证书组件状态：有已过期 DOWN；临期 DEGRADED；否则 UP。
func certStatus(minDays, expired, expiringDays int) string {
	switch {
	case expired > 0:
		return StatusDown
	case minDays <= expiringDays:
		return StatusDegraded
	default:
		return StatusUp
	}
}

func certMessage(minDays, expired int) string {
	if expired > 0 {
		return fmt.Sprintf("%d 张证书已过期", expired)
	}
	return fmt.Sprintf("证书剩余 %d 天", minDays)
}

// ---------- DISK ----------

func (c *Collector) probeDisk() *Snapshot {
	snap := &Snapshot{Component: ComponentDisk, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	total, free, err := diskUsage(c.opts.DiskPath)
	if err != nil {
		snap.Message = "磁盘检测路径不可用"
		return snap
	}
	freePercent := 0.0
	if total > 0 {
		freePercent = float64(free) / float64(total) * 100
	}
	snap.Metrics[MetricDiskTotalBytes] = total
	snap.Metrics[MetricDiskFreeBytes] = free
	snap.Metrics[MetricDiskFreePercent] = freePercent
	snap.Status = diskStatus(freePercent, c.opts.DiskLowFreePercent)
	if snap.Status == StatusDegraded {
		snap.Message = fmt.Sprintf("磁盘剩余 %.1f%%", freePercent)
	} else {
		snap.Message = "磁盘空间正常"
	}
	return snap
}

// diskUsage 返回挂载点总空间与可用空间（字节）。
func diskUsage(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	total = st.Blocks * uint64(st.Bsize)
	free = st.Bavail * uint64(st.Bsize)
	return total, free, nil
}

// diskStatus 磁盘状态：剩余低于阈值 DEGRADED。
func diskStatus(freePercent, lowThreshold float64) string {
	if freePercent <= lowThreshold {
		return StatusDegraded
	}
	return StatusUp
}

// metricFloat 从 metrics 取浮点值（JSON 反序列化后数字均为 float64）。
func metricFloat(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}
