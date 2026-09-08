// api_security.go API 安全组件探针（阶段8 / 补全任务书 §158 配套）。
//
// 采集器存活判定 = api_runtime_events 最近事件时间（apiruntime.Collector 落库主事件）：
// 事件持续更新说明「网关上报 → 日志采集 → 事件落库」链路存活。
//
// learning worker 心跳如实不做：learningjobs.Worker 只有内存 Stats 与 slog 输出，
// api_learning_jobs 无 heartbeat/updated_at 列，无持久化心跳源；严格心跳需表结构
// 加列（超出本分片范围）。探针以 api_learning_samples 最近落样时间作为学习链路
// 活动参考信号纳入 metrics（不参与状态判定）。
package runtimehealth

import (
	"context"
	"fmt"
	"time"
)

// probeAPISecurity 采集 API 安全链路状态（API_SECURITY 组件）。
func (c *Collector) probeAPISecurity(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentAPISecurity, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	qCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	var lastEvent, lastSample *time.Time
	var eventsTotal int64
	err := c.db.QueryRow(qCtx, `
SELECT (SELECT max(occurred_at) FROM api_runtime_events),
       (SELECT count(*) FROM api_runtime_events),
       (SELECT max(collected_at) FROM api_learning_samples)`).Scan(&lastEvent, &eventsTotal, &lastSample)
	if err != nil {
		snap.Message = "API 安全探针查询失败"
		return snap
	}
	snap.Metrics[MetricAPIEventsTotal] = eventsTotal
	if lastSample != nil {
		snap.Metrics[MetricAPILastSampleAt] = lastSample.UTC().Format(time.RFC3339)
	}
	status, staleSecs, msg := apiSecurityStatus(lastEvent, c.opts.Now(), c.opts.APIEventStaleAfter)
	snap.Status = status
	snap.Message = msg
	if lastEvent != nil {
		snap.Metrics[MetricAPILastEventAt] = lastEvent.UTC().Format(time.RFC3339)
		snap.Metrics[MetricAPIEventStaleSecs] = staleSecs
	}
	return snap
}

// apiSecurityStatus 由最近事件时间判定 API 安全采集链路状态：
// 从未有事件 UNKNOWN（功能未启用/无流量/采集器异常无法区分，如实不报 UP）；
// 停滞超过阈值 DEGRADED（可能采集停滞或低流量）；否则 UP。
// lastEvent 晚于 now（时钟回拨/跨节点时钟差）时停滞按 0 处理。
func apiSecurityStatus(lastEvent *time.Time, now time.Time, staleAfter time.Duration) (status string, staleSecs float64, message string) {
	if lastEvent == nil {
		return StatusUnknown, 0, "尚未采集到 API 运行时事件（可能功能未启用或无 API 流量）"
	}
	staleSecs = now.Sub(lastEvent.UTC()).Seconds()
	if staleSecs < 0 {
		staleSecs = 0
	}
	if staleAfter > 0 && staleSecs > staleAfter.Seconds() {
		return StatusDegraded, staleSecs, fmt.Sprintf("API 运行时事件 %d 秒未更新（采集停滞或低流量）", int(staleSecs))
	}
	return StatusUp, staleSecs, "API 运行时事件采集正常"
}
