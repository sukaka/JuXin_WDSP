// apm_clickhouse.go APM ClickHouse 数据面组件探针（APM 阶段2 数据面健康，
// 设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §20「ClickHouse 不可用 → 存储不可用/
// 采集滞后」）。
//
// 仅当注入探针且本轮有可用连接（APM 开启且 APM_CLICKHOUSE_DSN/界面 DSN 连接成功）
// 时产生 APM_CLICKHOUSE 快照；不可用（功能关闭/DSN 空/连接失败降级）不采集不判级——
// 组件不进 AllComponents() 固定清单（SystemHealth 对清单内无快照组件按 UNKNOWN
// 计入整体判级，默认部署须零行为变化）。
//
// 判级口径（两步，仿 probePostgres/probeValkey 先例）：
//   - 轻查询（SELECT 1）失败 → DOWN（数据面不可达）；
//   - 可达但 otel_traces 表检查失败 → DEGRADED；表不存在 → DEGRADED（数据面未初始化，
//     查询面此时降级 agentless 空数据，如实上报）；
//   - 延迟毫秒记 Snapshot.LatencyMs（与 GATEWAY/POSTGRES/VALKEY 同口径）。
//
// 本组件不新建 Evaluate 快照→告警映射：采集滞后告警由 systemalerts 独立评估器
// （APM_INGEST_LAG，30s 周期查最新遥测时间）承担，避免双口径重复告警。
package runtimehealth

import (
	"context"
)

// ClickHouseProber APM ClickHouse 数据面探测接口（生产为 apm.CHHealth，duck-type
// 适配，本包不依赖 apm；单测 fake）。
type ClickHouseProber interface {
	// Ping 数据面连通性轻探测（SELECT 1 等价查询）
	Ping(ctx context.Context) error
	// TracesTableExists 核心表 otel_traces 存在性检查（元数据查询，不扫数据）
	TracesTableExists(ctx context.Context) (bool, error)
}

// apmClickHouseIncluded 本轮是否采集 APM_CLICKHOUSE 快照（注入探针才纳入）。
// 运行期热生效适配器（apm.CHProberAdapter，实现 Available() bool）：无可用连接时
// 本轮不采集不判级，与"未注入探针"形态等价（DSN 被清空/连接失败降级后组件自动
// 退出判级，默认部署零行为变化）。
func (c *Collector) apmClickHouseIncluded() bool {
	p := c.opts.APMClickHouse
	if p == nil {
		return false
	}
	if dyn, ok := p.(interface{ Available() bool }); ok {
		return dyn.Available()
	}
	return true
}

// probeAPMClickHouse 探测 APM ClickHouse 数据面健康（两步判级，见文件头注释）。
func (c *Collector) probeAPMClickHouse(ctx context.Context) *Snapshot {
	snap := &Snapshot{Component: ComponentAPMClickHouse, Status: StatusUnknown, Metrics: map[string]interface{}{}}
	p := c.opts.APMClickHouse
	if p == nil {
		snap.Message = "未接入 APM ClickHouse 数据面"
		return snap
	}
	pCtx, cancel := context.WithTimeout(ctx, probeDBTimeout)
	defer cancel()
	start := c.opts.Now()
	if err := p.Ping(pCtx); err != nil {
		snap.Status = StatusDown
		snap.Message = "ClickHouse 数据面不可达"
		return snap
	}
	latency := int(c.opts.Now().Sub(start).Milliseconds())
	snap.LatencyMs = &latency
	exists, err := p.TracesTableExists(pCtx)
	if err != nil {
		snap.Status = StatusDegraded
		snap.Message = "ClickHouse 可达但数据面表检查失败"
		return snap
	}
	if !exists {
		snap.Status = StatusDegraded
		snap.Message = "otel_traces 表不存在（数据面未初始化）"
		return snap
	}
	snap.Status = StatusUp
	snap.Message = "ClickHouse 数据面正常"
	return snap
}
