// security_spike.go 安全事件聚合告警评估（告警通知二期 / Tier 2）：评估器周期统计
// security_events 与 access_control_events（数据源只读，生产方为事件采集器），
// 按 system_settings 的 notify 组阈值触发 SECURITY_EVENT_SPIKE / CC_BAN_SPIKE 告警；
// 触发/合并/冷却/抖动/自动恢复全部复用引擎既有机制（Raise/AutoRecover）。
// LOGIN_BRUTE_FORCE 不在此处评估——它是事件驱动（登录失败锁定触发点，见 auth 包挂点）。
//
// 信号口径说明：
//   - SECURITY_EVENT_SPIKE：窗口（1 分钟）内 security_events 中 severity ∈
//     ('HIGH','CRITICAL') 的事件条数 ≥ 阈值（组件 "waf"）。
//     注：security_events.severity 由采集器从 Coraza 级别映射，实际取值为
//     HIGH/MEDIUM/LOW/INFO（coraza critical→HIGH，见 securityevents/normalize.go），
//     词表保留 CRITICAL 以兼容未来映射调整（当前不会命中，无副作用）。
//   - CC_BAN_SPIKE：窗口（1 分钟）内 access_control_events 中封禁类事件
//     （event_type='CC_TEMP_BLOCK_CREATED'）条数 ≥ 阈值（组件 "cc"）。
//
// 聚合告警本身就是防风暴设计：引擎同 type+component 去重合并 + 通知层抑制，
// 永不逐条外发安全事件。
package systemalerts

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// 聚合告警组件名（区别于 runtimehealth 运维组件词表）。
const (
	ComponentWAF = "waf"
	ComponentCC  = "cc"
)

// system_settings 的 notify 组配置键与默认值（消费侧校验，非法值回退默认）。
// 评估窗口固定 1 分钟（与引擎 30s 评估周期匹配：窗口约为周期的 2 倍，
// 既不会因采集延迟漏计，也不会因窗口过长重复放大）。
const (
	notifySettingsGroup = "notify"

	notifyKeySecuritySpikeThreshold = "notify_security_spike_threshold"
	notifyKeyCCSpikeThreshold       = "notify_cc_spike_threshold"

	defaultSecuritySpikeThreshold = 10
	defaultCCSpikeThreshold       = 20

	// spikeEvalWindow 是聚合统计窗口（固定 1 分钟）。
	spikeEvalWindow = time.Minute

	// 阈值合法上限（超出回退默认，防误配导致告警风暴或永久静默）
	maxSpikeCountThreshold = 100000
)

// SecuritySpikeStatsStore 提供安全事件/CC 封禁聚合统计（security_events /
// access_control_events 只读）。窗口口径统一为 occurred_at >= now() - window。
type SecuritySpikeStatsStore interface {
	// CountRecentHighSeveritySecurityEvents 返回窗口内 HIGH/CRITICAL 级安全事件条数。
	CountRecentHighSeveritySecurityEvents(ctx context.Context, window time.Duration) (int64, error)
	// CountRecentCCBans 返回窗口内 CC 封禁（CC_TEMP_BLOCK_CREATED）事件条数。
	CountRecentCCBans(ctx context.Context, window time.Duration) (int64, error)
}

// spikeThresholds 是一次评估生效的阈值配置（每次评估时读取，运行期改配置即时生效）。
type spikeThresholds struct {
	Security int64
	CC       int64
}

// loadSpikeThresholds 读取并校验 notify 组阈值：缺省/非法值一律回退默认，
// 不因误配放大或关闭告警。
func loadSpikeThresholds(ctx context.Context, s SettingsReader) spikeThresholds {
	th := spikeThresholds{
		Security: defaultSecuritySpikeThreshold,
		CC:       defaultCCSpikeThreshold,
	}
	if s == nil {
		return th
	}
	if v := s.GetInt(ctx, notifySettingsGroup, notifyKeySecuritySpikeThreshold, defaultSecuritySpikeThreshold); v > 0 && v <= maxSpikeCountThreshold {
		th.Security = int64(v)
	}
	if v := s.GetInt(ctx, notifySettingsGroup, notifyKeyCCSpikeThreshold, defaultCCSpikeThreshold); v > 0 && v <= maxSpikeCountThreshold {
		th.CC = int64(v)
	}
	return th
}

// EvaluateSecuritySpikes 评估安全事件/CC 封禁聚合告警（需配置 SecuritySpikes；
// 周期调用，装配层与 Evaluate/EvaluateAPIFindings 同 ticker）。
// 达阈则 Raise（走合并/冷却/抖动），回落则 AutoRecover；
// 单类型评估失败不阻断另一类型，错误聚合返回。
func (e *Engine) EvaluateSecuritySpikes(ctx context.Context) error {
	if e.securitySpikes == nil {
		return nil
	}
	th := loadSpikeThresholds(ctx, e.settings)
	var errs []error

	// SECURITY_EVENT_SPIKE：窗口内 HIGH/CRITICAL 安全事件 ≥ 阈值
	highCount, err := e.securitySpikes.CountRecentHighSeveritySecurityEvents(ctx, spikeEvalWindow)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("count high severity security events: %w", err))
	case highCount >= th.Security:
		if _, err := e.Raise(ctx, RaiseRequest{
			AlertType: TypeSecurityEventSpike,
			Component: ComponentWAF,
			Title:     "安全事件激增",
			Message: fmt.Sprintf("最近 %d 分钟 HIGH/CRITICAL 级安全事件 %d 条（阈值 %d）",
				int(spikeEvalWindow.Minutes()), highCount, th.Security),
		}); err != nil {
			errs = append(errs, err)
		}
	default:
		if _, err := e.AutoRecover(ctx, ComponentWAF, TypeSecurityEventSpike); err != nil {
			errs = append(errs, err)
		}
	}

	// CC_BAN_SPIKE：窗口内 CC 封禁 ≥ 阈值
	banCount, err := e.securitySpikes.CountRecentCCBans(ctx, spikeEvalWindow)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("count cc bans: %w", err))
	case banCount >= th.CC:
		if _, err := e.Raise(ctx, RaiseRequest{
			AlertType: TypeCCBanSpike,
			Component: ComponentCC,
			Title:     "CC封禁激增",
			Message: fmt.Sprintf("最近 %d 分钟 CC 封禁 %d 个 IP（阈值 %d）",
				int(spikeEvalWindow.Minutes()), banCount, th.CC),
		}); err != nil {
			errs = append(errs, err)
		}
	default:
		if _, err := e.AutoRecover(ctx, ComponentCC, TypeCCBanSpike); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ---------- Store 实现（security_events / access_control_events 只读统计） ----------

// CountRecentHighSeveritySecurityEvents 实现 SecuritySpikeStatsStore。
func (s *Store) CountRecentHighSeveritySecurityEvents(ctx context.Context, window time.Duration) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `
SELECT count(*) FROM security_events
WHERE severity IN ('HIGH','CRITICAL') AND occurred_at >= now() - $1::interval`,
		window.String()).Scan(&n)
	return n, err
}

// CountRecentCCBans 实现 SecuritySpikeStatsStore。
func (s *Store) CountRecentCCBans(ctx context.Context, window time.Duration) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `
SELECT count(*) FROM access_control_events
WHERE event_type = 'CC_TEMP_BLOCK_CREATED' AND occurred_at >= now() - $1::interval`,
		window.String()).Scan(&n)
	return n, err
}
