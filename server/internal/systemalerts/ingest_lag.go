// ingest_lag.go APM 数据面采集滞后告警评估（APM 阶段2 数据面容量/健康告警，
// 设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §18.1 数据质量「Collector 丢弃/
// trace 不完整」与 §20「ClickHouse 不可用 → 存储不可用/采集滞后」）：周期读取
// ClickHouse otel_traces 最新遥测时间（供给方 apm.CHHealth），与当前时间差超阈
// 触发 APM_INGEST_LAG；触发/合并/冷却/抖动/自动恢复全部复用引擎既有机制
// （Raise/AutoRecover，与 slo_breach.go 同构）。
//
// 去重维度：component 固定 "clickhouse"（数据面逻辑组件，不按表/服务/实例放大——
// 设计 §18.2「不按实例创建海量告警」）。告警详情只含滞后秒数与阈值，
// 不含任何遥测内容/请求数据。
package systemalerts

import (
	"context"
	"fmt"
	"time"
)

// system_settings 的 apm_alert 组采集滞后阈值键与默认值（消费侧校验，非法值回退
// 默认；种子行见迁移 000094，可经系统设置 Update API 在线调整——键已登记
// settings 白名单）。
const (
	apmAlertKeyIngestLagSeconds = "ingest_lag_seconds" // 采集滞后阈值（秒）

	defaultIngestLagSeconds = 300 // 默认 5 分钟（评估周期 30s，留足采集/聚合抖动余量）
	// 配置合法区间（超出回退默认，防误配导致告警风暴或永久静默）
	minIngestLagSeconds = 30
	maxIngestLagSeconds = 86400

	// ingestLagComponent 告警去重组件标识（数据面逻辑组件，固定值；
	// 与 EVENT_COLLECTOR_LAG 的 EVENT_COLLECTOR 组件口径并列）。
	ingestLagComponent = "clickhouse"
)

// IngestLagStatsStore 提供数据面最新遥测时间（apm.CHHealth 实现；nil 时
// EvaluateIngestLag 空转——APM_ENABLED 关闭或 DSN 空/连接失败降级形态）。
type IngestLagStatsStore interface {
	// LatestIngestAt 返回 otel_traces 最新 Timestamp（UTC）；表空无数据 ok=false。
	LatestIngestAt(ctx context.Context) (time.Time, bool, error)
}

// ingestLagThresholdSeconds 本轮生效的滞后阈值（秒）：settings 覆盖优先，
// 非法值回退默认（不因误配放大或关闭告警）。
func ingestLagThresholdSeconds(ctx context.Context, s SettingsReader) float64 {
	if s == nil {
		return defaultIngestLagSeconds
	}
	if v := s.GetInt(ctx, apmAlertSettingsGroup, apmAlertKeyIngestLagSeconds, defaultIngestLagSeconds); v >= minIngestLagSeconds && v <= maxIngestLagSeconds {
		return float64(v)
	}
	return defaultIngestLagSeconds
}

// EvaluateIngestLag 评估采集滞后告警（装配层 30s 周期调用，与 EvaluateEndpointPerf
// 同 ticker）。滞后超阈 Raise（走合并/冷却/抖动；同组件重复评估自动合并）；
// 未超阈或本轮无数据（表空，滞后条件不成立）AutoRecover 既有未关闭告警；
// 读数失败整体中止（不清动既有告警）。
func (e *Engine) EvaluateIngestLag(ctx context.Context) error {
	if e.ingestLag == nil {
		return nil
	}
	// APM 总开关关闭：空转（运行期热生效；不清动既有告警）
	if !e.apmEnabledNow(ctx) {
		return nil
	}
	threshold := ingestLagThresholdSeconds(ctx, e.settings)
	latest, ok, err := e.ingestLag.LatestIngestAt(ctx)
	if err != nil {
		return fmt.Errorf("ingest lag stats: %w", err)
	}
	if ok {
		if lag := e.now().Sub(latest).Seconds(); lag > threshold {
			_, err = e.Raise(ctx, RaiseRequest{
				AlertType: TypeAPMIngestLag,
				Component: ingestLagComponent,
				Title:     "APM 数据采集滞后",
				Message: fmt.Sprintf("APM 数据面最新遥测距今 %d 秒（阈值 %d 秒），采集链路可能停滞",
					int(lag), int(threshold)),
			})
			return err
		}
	}
	_, err = e.AutoRecover(ctx, ingestLagComponent, TypeAPMIngestLag)
	return err
}
