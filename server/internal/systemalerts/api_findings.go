// api_findings.go API 安全告警评估（W6-B / P1-08）：评估器周期扫描
// api_runtime_findings（数据源只读，生产方为 apiruntime 采集器），按 system_settings
// 的 api_alert 组配置触发 API_CRITICAL_FINDING / API_FINDING_SPIKE / API_MASK_FAILURE
// 三类告警；触发/合并/冷却/抖动/自动恢复全部复用引擎既有机制（Raise/AutoRecover）。
//
// 信号来源说明：
//   - API_CRITICAL_FINDING：窗口内新增（first_seen_at ∈ 窗口）且未处置（status=NEW）
//     的 CRITICAL 级 finding；
//   - API_FINDING_SPIKE：窗口内同 finding_type 的新增未处置 finding 数超阈值；
//   - API_MASK_FAILURE：MASK_RESPONSE 脱敏执行失败——网关侧失败时产生
//     DetectorMatch{RuleID: "response.mask_failed", Severity: HIGH}（apiprotect.go
//     finishAPIResponse），采集器按 findingTypeOf 机械映射物化为
//     finding_type='RESPONSE_MASK_FAILED' 的 finding（apiruntime/findings.go）。
package systemalerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ComponentAPISecurity 是 API 安全告警的组件名（区别于 runtimehealth 运维组件词表）。
const ComponentAPISecurity = "API_SECURITY"

// MaskFailureFindingType 是 MASK_RESPONSE 失败对应的 finding_type
// （response.mask_failed 机械映射大写下划线化，见 apiruntime/findings.go findingTypeOf）。
const MaskFailureFindingType = "RESPONSE_MASK_FAILED"

// system_settings 的 api_alert 组配置键与默认值（消费侧校验，非法值回退默认）。
const (
	apiAlertSettingsGroup = "api_alert"

	apiAlertKeyCriticalEnabled = "critical_finding_enabled"
	apiAlertKeyMaskEnabled     = "mask_failure_enabled"
	apiAlertKeySpikeEnabled    = "spike_enabled"
	apiAlertKeySpikeThreshold  = "spike_threshold"
	apiAlertKeySpikeWindowMin  = "spike_window_minutes"
	apiAlertKeyScanWindowMin   = "scan_window_minutes"

	defaultCriticalEnabled = true
	defaultMaskEnabled     = true
	defaultSpikeEnabled    = true
	defaultSpikeThreshold  = 20
	defaultSpikeWindowMin  = 60
	defaultScanWindowMin   = 10

	// 配置合法区间（超出回退默认，防误配导致告警风暴或永久静默）
	maxSpikeThreshold = 100000
	maxWindowMinutes  = 1440

	// criticalSampleLimit 是 CRITICAL 告警 message 中列举的样本条数上限。
	criticalSampleLimit = 3
	// spikeTopLimit 是 SPIKE 告警 message 中列举的超阈类型条数上限。
	spikeTopLimit = 3
)

// FindingSample 是一条 CRITICAL finding 摘要（告警 message 展示用）。
type FindingSample struct {
	FindingType string
	Title       string
	SubjectType string
}

// FindingTypeCount 是窗口内同 finding_type 的新增未处置 finding 计数。
type FindingTypeCount struct {
	FindingType string
	Count       int64
}

// APIFindingsStatsStore 提供 API 安全 findings 统计（api_runtime_findings 只读）。
// 窗口口径统一为 first_seen_at >= now() - window（「新增」）且 status='NEW'（未处置）。
type APIFindingsStatsStore interface {
	// CountNewCritical 返回窗口内新增未处置 CRITICAL findings 总数与样本（按
	// first_seen_at 倒序取 sampleLimit 条）。
	CountNewCritical(ctx context.Context, window time.Duration, sampleLimit int) (total int64, samples []FindingSample, err error)
	// CountNewByType 返回窗口内新增未处置 findings 按 finding_type 分组计数（计数倒序）。
	CountNewByType(ctx context.Context, window time.Duration) ([]FindingTypeCount, error)
	// CountNewMaskFailures 返回窗口内新增未处置 MASK_RESPONSE 失败 findings 数。
	CountNewMaskFailures(ctx context.Context, window time.Duration) (int64, error)
}

// SettingsReader 是评估规则配置读取接口（settings.Service 实现；nil 时全默认）。
// 消费组：api_alert（本文件）、notify（security_spike.go）、
// apm_alert（endpoint_perf.go、ingest_lag.go）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
	GetFloat(ctx context.Context, group, key string, def float64) float64
}

// apiAlertConfig 是一次评估生效的规则配置（每次评估时读取，运行期改配置即时生效）。
type apiAlertConfig struct {
	CriticalEnabled bool
	MaskEnabled     bool
	SpikeEnabled    bool
	SpikeThreshold  int64
	SpikeWindow     time.Duration
	ScanWindow      time.Duration // CRITICAL / MASK_FAILURE 共用扫描窗口
}

// loadAPIAlertConfig 读取并校验 api_alert 组配置：缺省/非法值一律回退默认，
// 不因误配放大或关闭告警。
func loadAPIAlertConfig(ctx context.Context, s SettingsReader) apiAlertConfig {
	cfg := apiAlertConfig{
		CriticalEnabled: defaultCriticalEnabled,
		MaskEnabled:     defaultMaskEnabled,
		SpikeEnabled:    defaultSpikeEnabled,
		SpikeThreshold:  defaultSpikeThreshold,
		SpikeWindow:     defaultSpikeWindowMin * time.Minute,
		ScanWindow:      defaultScanWindowMin * time.Minute,
	}
	if s == nil {
		return cfg
	}
	cfg.CriticalEnabled = s.GetBool(ctx, apiAlertSettingsGroup, apiAlertKeyCriticalEnabled, defaultCriticalEnabled)
	cfg.MaskEnabled = s.GetBool(ctx, apiAlertSettingsGroup, apiAlertKeyMaskEnabled, defaultMaskEnabled)
	cfg.SpikeEnabled = s.GetBool(ctx, apiAlertSettingsGroup, apiAlertKeySpikeEnabled, defaultSpikeEnabled)
	if th := s.GetInt(ctx, apiAlertSettingsGroup, apiAlertKeySpikeThreshold, defaultSpikeThreshold); th > 0 && th <= maxSpikeThreshold {
		cfg.SpikeThreshold = int64(th)
	}
	if m := s.GetInt(ctx, apiAlertSettingsGroup, apiAlertKeySpikeWindowMin, defaultSpikeWindowMin); m > 0 && m <= maxWindowMinutes {
		cfg.SpikeWindow = time.Duration(m) * time.Minute
	}
	if m := s.GetInt(ctx, apiAlertSettingsGroup, apiAlertKeyScanWindowMin, defaultScanWindowMin); m > 0 && m <= maxWindowMinutes {
		cfg.ScanWindow = time.Duration(m) * time.Minute
	}
	return cfg
}

// EvaluateAPIFindings 评估 API 安全 findings（需配置 APIFindings；周期调用，
// 装配层与 Evaluate/EvaluateParseFailures 同 ticker）。
// 各类型独立评估：触发则 Raise（走合并/冷却/抖动），未触发则 AutoRecover；
// 开关关闭的类型跳过评估（不清动既有告警，避免运行期关开关误恢复在办告警）。
// 单类型评估失败不阻断其他类型，错误聚合返回。
func (e *Engine) EvaluateAPIFindings(ctx context.Context) error {
	if e.apiFindings == nil {
		return nil
	}
	cfg := loadAPIAlertConfig(ctx, e.settings)
	var errs []error

	// API_CRITICAL_FINDING：窗口内新增 CRITICAL findings
	if cfg.CriticalEnabled {
		total, samples, err := e.apiFindings.CountNewCritical(ctx, cfg.ScanWindow, criticalSampleLimit)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("count new critical findings: %w", err))
		case total > 0:
			if _, err := e.Raise(ctx, RaiseRequest{
				AlertType: TypeAPICriticalFinding,
				Component: ComponentAPISecurity,
				Title:     "新增严重级别API风险发现",
				Message:   criticalFindingMessage(cfg.ScanWindow, total, samples),
			}); err != nil {
				errs = append(errs, err)
			}
		default:
			if _, err := e.AutoRecover(ctx, ComponentAPISecurity, TypeAPICriticalFinding); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// API_FINDING_SPIKE：窗口内同 finding_type 新增数超阈
	if cfg.SpikeEnabled {
		counts, err := e.apiFindings.CountNewByType(ctx, cfg.SpikeWindow)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("count new findings by type: %w", err))
		default:
			if spiked := spikeExceeded(counts, cfg.SpikeThreshold); len(spiked) > 0 {
				if _, err := e.Raise(ctx, RaiseRequest{
					AlertType: TypeAPIFindingSpike,
					Component: ComponentAPISecurity,
					Title:     "API风险发现激增",
					Message:   spikeMessage(cfg.SpikeWindow, cfg.SpikeThreshold, spiked),
				}); err != nil {
					errs = append(errs, err)
				}
			} else {
				if _, err := e.AutoRecover(ctx, ComponentAPISecurity, TypeAPIFindingSpike); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	// API_MASK_FAILURE：窗口内新增 MASK_RESPONSE 失败 findings
	if cfg.MaskEnabled {
		n, err := e.apiFindings.CountNewMaskFailures(ctx, cfg.ScanWindow)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("count new mask failures: %w", err))
		case n > 0:
			if _, err := e.Raise(ctx, RaiseRequest{
				AlertType: TypeAPIMaskFailure,
				Component: ComponentAPISecurity,
				Title:     "响应脱敏执行失败",
				Message: fmt.Sprintf("最近 %d 分钟新增 %d 条响应脱敏失败记录，存在未脱敏数据外发风险",
					int(cfg.ScanWindow.Minutes()), n),
			}); err != nil {
				errs = append(errs, err)
			}
		default:
			if _, err := e.AutoRecover(ctx, ComponentAPISecurity, TypeAPIMaskFailure); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// criticalFindingMessage 组装 CRITICAL 告警内容（总数 + 样本摘要）。
func criticalFindingMessage(window time.Duration, total int64, samples []FindingSample) string {
	var b strings.Builder
	fmt.Fprintf(&b, "最近 %d 分钟新增 %d 条严重级风险发现", int(window.Minutes()), total)
	if len(samples) > 0 {
		parts := make([]string, 0, len(samples))
		for _, s := range samples {
			label := findingTypeLabel(s.FindingType)
			title := strings.TrimSpace(s.Title)
			if title != "" && title != label && !strings.EqualFold(title, s.FindingType) {
				parts = append(parts, label+"（"+title+"）")
			} else {
				parts = append(parts, label)
			}
		}
		fmt.Fprintf(&b, "：%s", strings.Join(parts, "；"))
		if int64(len(samples)) < total {
			b.WriteString(" 等")
		}
	}
	return b.String()
}

// spikeExceeded 筛出计数超阈的 finding_type（输入已按计数倒序）。
func spikeExceeded(counts []FindingTypeCount, threshold int64) []FindingTypeCount {
	out := make([]FindingTypeCount, 0, len(counts))
	for _, c := range counts {
		if c.Count > threshold {
			out = append(out, c)
		}
	}
	return out
}

// spikeMessage 组装 SPIKE 告警内容（窗口/阈值 + 超阈类型 Top N）。
func spikeMessage(window time.Duration, threshold int64, spiked []FindingTypeCount) string {
	top := spiked
	if len(top) > spikeTopLimit {
		top = top[:spikeTopLimit]
	}
	parts := make([]string, 0, len(top))
	for _, c := range top {
		parts = append(parts, fmt.Sprintf("%s %d 条", findingTypeLabel(c.FindingType), c.Count))
	}
	msg := fmt.Sprintf("最近 %d 分钟同类型风险发现超过阈值 %d：%s", int(window.Minutes()), threshold, strings.Join(parts, "；"))
	if len(spiked) > len(top) {
		msg += fmt.Sprintf(" 等 %d 类", len(spiked))
	}
	return msg
}

// ---------- Store 实现（api_runtime_findings 只读统计） ----------

// CountNewCritical 实现 APIFindingsStatsStore。
func (s *Store) CountNewCritical(ctx context.Context, window time.Duration, sampleLimit int) (int64, []FindingSample, error) {
	const cond = `FROM api_runtime_findings
WHERE status='NEW' AND severity='CRITICAL' AND first_seen_at >= now() - $1::interval`
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) `+cond, window.String()).Scan(&total); err != nil {
		return 0, nil, err
	}
	if total == 0 || sampleLimit <= 0 {
		return total, nil, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT finding_type, title, COALESCE(subject_type, '') `+cond+`
ORDER BY first_seen_at DESC LIMIT $2`, window.String(), sampleLimit)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var samples []FindingSample
	for rows.Next() {
		var f FindingSample
		if err := rows.Scan(&f.FindingType, &f.Title, &f.SubjectType); err != nil {
			return 0, nil, err
		}
		samples = append(samples, f)
	}
	return total, samples, rows.Err()
}

// CountNewByType 实现 APIFindingsStatsStore。
func (s *Store) CountNewByType(ctx context.Context, window time.Duration) ([]FindingTypeCount, error) {
	rows, err := s.db.Query(ctx, `
SELECT finding_type, count(*) FROM api_runtime_findings
WHERE status='NEW' AND first_seen_at >= now() - $1::interval
GROUP BY finding_type ORDER BY count(*) DESC`, window.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingTypeCount
	for rows.Next() {
		var c FindingTypeCount
		if err := rows.Scan(&c.FindingType, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountNewMaskFailures 实现 APIFindingsStatsStore。
func (s *Store) CountNewMaskFailures(ctx context.Context, window time.Duration) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings
WHERE status='NEW' AND finding_type=$2 AND first_seen_at >= now() - $1::interval`,
		window.String(), MaskFailureFindingType).Scan(&n)
	return n, err
}
