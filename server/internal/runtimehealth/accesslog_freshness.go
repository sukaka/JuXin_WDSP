// accesslog_freshness.go accesslog-01 全量访问日志采集链路新鲜度探针（APM 阶段1 WP5）。
//
// 链路：网关 JSON 全量访问日志 → accesslogs.Collector（collector_id=accesslog-01，
// DB 断点 event_collector_checkpoints）→ access_logs 表 → 端点级分钟聚合。
// 仅当注入 Settings 且 logging.access_log_enabled=true 时纳入 EVENT_COLLECTOR 判级：
// 开关关闭时网关不产出该日志、断点不推进属正常，不报停滞；未注入 Settings 保持
// 既有行为（默认部署零行为变化）。判级复用既有 EVENT_COLLECTOR → EVENT_COLLECTOR_LAG
// 告警映射（systemalerts/evaluator.go），不新建告警类型。
//
// 滞后语义与 probeEventCollector 既有链路一致（backlogLag）：日志文件无未消费字节
// 时滞后为 0（低流量/无流量不误报），有积压时为「当前时间 - 断点最后推进时间」。
package runtimehealth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SettingsReader 系统设置读取接口（settings.Service 实现；nil 时 accesslog-01
// 链路不纳入判级）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// logging 组设置键（总开关为既有种子键；停滞阈值键不种子化，带默认值读取，
// 非法值回退 Options.AccessLogStaleAfter——参照 systemalerts 各评估器消费侧先例）。
const (
	accessLogSettingsGroup   = "logging"
	accessLogKeyEnabled      = "access_log_enabled"
	accessLogKeyStaleSeconds = "access_log_stale_seconds"

	// 停滞阈值合法区间（秒），超出回退 Options 默认
	minAccessLogStaleSeconds = 10
	maxAccessLogStaleSeconds = 86400

	// CheckpointAccessLogFull 是 accesslog-01 链路在 EVENT_COLLECTOR 快照
	// checkpoints 列表中的名称（区别于阶段6 文件断点的 "access_log" 链路）。
	CheckpointAccessLogFull = "accesslog_full"

	// defaultAccessLogFullCollectorID 全量访问日志采集器默认 collector_id
	// （cmd/api/main.go 装配值 accesslog-01）。
	defaultAccessLogFullCollectorID = "accesslog-01"
)

// accessLogChainResult 是 accesslog-01 链路本轮探针结果。
type accessLogChainResult struct {
	included   bool          // 是否纳入本轮判级
	cp         CheckpointLag // 断点滞后
	staleAfter float64       // 本轮生效的停滞阈值（秒）
	err        error         // 断点查询错误
}

// stale 停滞判定：纳入判级、断点存在且滞后超阈。
func (r accessLogChainResult) stale() bool {
	return r.included && !r.cp.Missing && r.cp.LagSecs > r.staleAfter
}

// accessLogChainIncluded 判定本轮是否纳入判级：未注入 Settings 或总开关关闭时不纳入。
func accessLogChainIncluded(ctx context.Context, s SettingsReader) bool {
	return s != nil && s.GetBool(ctx, accessLogSettingsGroup, accessLogKeyEnabled, false)
}

// accessLogStaleAfterSecs 本轮生效的停滞阈值（秒）：settings 覆盖优先，非法值回退
// Options.AccessLogStaleAfter（withDefaults 已保证其为正）。
func (c *Collector) accessLogStaleAfterSecs(ctx context.Context) float64 {
	after := c.opts.AccessLogStaleAfter.Seconds()
	if c.opts.Settings != nil {
		if v := c.opts.Settings.GetInt(ctx, accessLogSettingsGroup, accessLogKeyStaleSeconds, int(after)); v >= minAccessLogStaleSeconds && v <= maxAccessLogStaleSeconds {
			after = float64(v)
		}
	}
	return after
}

// probeAccessLogFull 探测 accesslog-01 链路断点滞后（DB checkpoint + backlogLag 语义）。
// 开关关闭/未注入 Settings 时返回 included=false（不读库），保持既有判级行为。
func (c *Collector) probeAccessLogFull(ctx context.Context, now time.Time) accessLogChainResult {
	if !accessLogChainIncluded(ctx, c.opts.Settings) {
		return accessLogChainResult{}
	}
	res := accessLogChainResult{included: true, staleAfter: c.accessLogStaleAfterSecs(ctx)}
	qCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	var offset int64
	var filePath string
	var updatedAt time.Time
	err := c.db.QueryRow(qCtx,
		`SELECT file_offset, file_path, updated_at FROM event_collector_checkpoints WHERE collector_id = $1`,
		c.opts.AccessLogFullCollectorID).Scan(&offset, &filePath, &updatedAt)
	switch {
	case err == nil:
		res.cp = CheckpointLag{Name: CheckpointAccessLogFull, LagSecs: backlogLag(filePath, offset, updatedAt, now)}
	case errors.Is(err, pgx.ErrNoRows):
		// 开关刚开启、采集器尚未落首个断点：记缺失但不判停滞（与既有链路同口径）
		res.cp = CheckpointLag{Name: CheckpointAccessLogFull, Missing: true}
	default:
		res.err = err
	}
	return res
}

// eventCollectorStatus EVENT_COLLECTOR 组件判级（纯逻辑，单测直接覆盖）：
// 全部断点缺失 UNKNOWN；accesslog-01 链路停滞（其结果自带阈值）优先判 DEGRADED 并
// 如实指明停滞链路；通用最大滞后超阈 DEGRADED（既有口径）；否则 UP。
func eventCollectorStatus(cps []CheckpointLag, genericDegradedSecs float64, al accessLogChainResult) (status, message string) {
	maxLag, missing := SummarizeCheckpoints(cps)
	switch {
	case missing == len(cps):
		return StatusUnknown, "采集器尚未产生 checkpoint"
	case al.stale():
		return StatusDegraded, fmt.Sprintf("访问日志采集链路停滞 %d 秒（阈值 %d 秒）", int(al.cp.LagSecs), int(al.staleAfter))
	case maxLag > genericDegradedSecs:
		return StatusDegraded, fmt.Sprintf("事件采集最大滞后 %d 秒", int(maxLag))
	default:
		return StatusUp, "事件采集滞后正常"
	}
}
