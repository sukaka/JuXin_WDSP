// slo_types.go APM SLO 目标定义与评估口径（纯类型与纯函数；不依赖 PG，单测直接覆盖）。
//
// 指标口径（v1，设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §18.1）：
//   - availability：只把 5xx 计为失败（4xx 属客户端语义，v1 不计失败）——
//     availability = 1 − 5xx/总请求数，target ∈ (0,1) 为达标率下界；
//   - latency_p95：窗口内 http_request_duration_ms 直方图合并后线性插值估算 P95
//     （毫秒），target 为毫秒阈值（>0 且 ≤600000）。
//
// 错误预算（标准口径）：
//   - availability：预算 budget = 1 − target（允许的 5xx 违约率）；
//     remaining = (budget − 实际违约率) / budget；
//   - latency_p95：以 P95 相对阈值的余量表达预算——
//     remaining = (target − p95) / target（P95 达阈值即预算耗尽）；
//   - 统一夹紧到 [−1,1]：0 为恰好踩线，负值为已违约（深度封顶 −1）。
//
// 状态机：BREACHED = remaining < 0（availability 即窗口达标率 < target，
// latency_p95 即 P95 > 阈值）；AT_RISK = 预算消耗 > 80%（remaining < 0.2）；
// 否则 OK。窗口内无数据：current_value = null、状态保持 OK、note 如实说明
// （无失败证据不误报，符合 §18.2 最小请求量护栏理念）。
package apm

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// SLO 指标类型（apm_slos.metric_type，迁移 000092 CHECK 约束同口径）。
const (
	SLOMetricAvailability = "availability"
	SLOMetricLatencyP95   = "latency_p95"
)

// SLO 评估窗口（apm_slos.window，CHECK 约束同口径）。
const (
	SLOWindow7d  = "7d"
	SLOWindow30d = "30d"
)

// SLO 状态词表。
const (
	SLOStatusOK       = "OK"
	SLOStatusAtRisk   = "AT_RISK"
	SLOStatusBreached = "BREACHED"
)

const (
	// sloNameMaxLen / sloServiceMaxLen 与迁移 000092 VARCHAR(128) 同口径（按字符数）。
	sloNameMaxLen    = 128
	sloServiceMaxLen = 128
	// sloLatencyTargetMaxMs latency_p95 阈值上限（10 分钟，超出视为误配）。
	sloLatencyTargetMaxMs = 600000
	// sloAtRiskRemaining 预算剩余水位线：低于该值（消耗 >80%）状态升 AT_RISK。
	sloAtRiskRemaining = 0.2
)

// SLO SLO 定义（apm_slos 行）。
type SLO struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Service    string     `json:"service"` // 应用编码（聚合指标 app 标签）
	MetricType string     `json:"metric_type"`
	Target     float64    `json:"target"`
	Window     string     `json:"window"`
	CreatedBy  *uuid.UUID `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// SLOListItem GET /api/v1/apm/slos 列表项（定义 + 当前窗口实时评估结果）。
type SLOListItem struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Service    string    `json:"service"`
	MetricType string    `json:"metric_type"`
	Target     float64   `json:"target"`
	Window     string    `json:"window"`
	// CurrentValue 当前值：availability 为达标率（0~1），latency_p95 为毫秒；
	// 窗口内无数据为 null。
	CurrentValue         *float64  `json:"current_value"`
	ComplianceRatio      float64   `json:"compliance_ratio"`       // 达标率：availability=可用性；latency=≤阈值请求占比
	ErrorBudgetRemaining float64   `json:"error_budget_remaining"` // 错误预算剩余比（[−1,1]，公式见包注释）
	Status               string    `json:"status"`
	Note                 string    `json:"note"` // 口径说明（当前仅无数据场景非空）
	UpdatedAt            time.Time `json:"updated_at"`
}

// SLOTrendPoint SLO 达标率趋势点（7d 窗口按小时桶、30d 窗口按天桶；
// 零流量桶达标率计 1——无失败证据）。
type SLOTrendPoint struct {
	BucketStart     time.Time `json:"bucket_start"`
	ComplianceRatio float64   `json:"compliance_ratio"`
}

// SLODetail GET /api/v1/apm/slos/{id} 详情（列表项 + 窗口内达标率趋势）。
type SLODetail struct {
	SLOListItem
	Trend []SLOTrendPoint `json:"trend"`
}

// sloWindowDuration SLO 评估窗口长度。
func sloWindowDuration(window string) time.Duration {
	if window == SLOWindow30d {
		return 30 * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// sloTrendStep 趋势桶粒度：7d 按小时桶、30d 按天桶（聚合源固定为小时表，
// 天桶由小时桶合并，不扫分钟表）。
func sloTrendStep(window string) time.Duration {
	if window == SLOWindow30d {
		return 24 * time.Hour
	}
	return time.Hour
}

// validateSLOInput 校验 SLO 写接口入参（创建/全量更新共用；错误文案面向用户）。
func validateSLOInput(name, service, metricType string, target float64, window string) error {
	if name == "" {
		return fmt.Errorf("name 不能为空")
	}
	if utf8.RuneCountInString(name) > sloNameMaxLen {
		return fmt.Errorf("name 不能超过 %d 字符", sloNameMaxLen)
	}
	if service == "" {
		return fmt.Errorf("service 不能为空")
	}
	if utf8.RuneCountInString(service) > sloServiceMaxLen {
		return fmt.Errorf("service 不能超过 %d 字符", sloServiceMaxLen)
	}
	switch metricType {
	case SLOMetricAvailability:
		if target <= 0 || target >= 1 {
			return fmt.Errorf("availability 的 target 须在 (0,1) 区间内（达标率，如 0.999）")
		}
	case SLOMetricLatencyP95:
		if target <= 0 || target > sloLatencyTargetMaxMs {
			return fmt.Errorf("latency_p95 的 target 须为毫秒正数且不超过 %d", sloLatencyTargetMaxMs)
		}
	default:
		return fmt.Errorf("无效的 metric_type（支持 availability/latency_p95）")
	}
	switch window {
	case SLOWindow7d, SLOWindow30d:
	default:
		return fmt.Errorf("无效的 window（支持 7d/30d）")
	}
	return nil
}

// clampBudgetRemaining 错误预算剩余比夹紧到 [−1,1]（0=恰好踩线，负值=已违约）。
func clampBudgetRemaining(v float64) float64 {
	if v < -1 {
		return -1
	}
	if v > 1 {
		return 1
	}
	return v
}

// sloStatusFromBudget 状态机：BREACHED = remaining < 0；AT_RISK = 预算消耗 >80%
// （remaining < 0.2）；否则 OK。
func sloStatusFromBudget(remaining float64) string {
	if remaining < 0 {
		return SLOStatusBreached
	}
	if remaining < sloAtRiskRemaining {
		return SLOStatusAtRisk
	}
	return SLOStatusOK
}

// countLEFromBuckets 估算直方图中 ≤ t 毫秒的样本数（桶内线性插值；
// counts 布局与 metrics.PercentileFromBuckets 一致：len = len(DurationBucketsMs)+1，
// 末桶为 (5000,+∞)）。
func countLEFromBuckets(counts []int, t float64) float64 {
	if t <= 0 {
		return 0
	}
	var total float64
	prevLe := 0.0
	for i, le := range metrics.DurationBucketsMs {
		if i >= len(counts) {
			break
		}
		if t >= float64(le) {
			total += float64(counts[i])
			prevLe = float64(le)
			continue
		}
		// t 落在 (prevLe, le] 桶内：按桶宽线性插值估算 ≤t 的部分
		total += float64(counts[i]) * (t - prevLe) / (float64(le) - prevLe)
		return total
	}
	// t 超过最大桶边界：全部样本（含溢出末桶）均 ≤t
	for i := len(metrics.DurationBucketsMs); i < len(counts); i++ {
		total += float64(counts[i])
	}
	return total
}

// sloWindowStats 单服务窗口聚合（数据源固定 metric_hour_aggregates；
// dur 为合并直方图，nil/无样本 = 无耗时数据）。
type sloWindowStats struct {
	requests float64 // 窗口内总请求数
	err5xx   float64 // 窗口内 5xx 数
	dur      []int   // 合并耗时直方图
}

// histogramTotal 直方图样本总数。
func (s *sloWindowStats) histogramTotal() int {
	var n int
	for _, c := range s.dur {
		n += c
	}
	return n
}

// evalSLO 由窗口聚合计算评估结果（纯函数，handler 列表/详情与告警评估共用同一口径）。
// now 不参与计算（评估窗口由 store 查询决定），仅保留签名一致便于演进。
func evalSLO(def *SLO, stats *sloWindowStats) *SLOListItem {
	item := &SLOListItem{
		ID:         def.ID,
		Name:       def.Name,
		Service:    def.Service,
		MetricType: def.MetricType,
		Target:     def.Target,
		Window:     def.Window,
		UpdatedAt:  def.UpdatedAt,
	}

	// 无数据判定：availability 看请求量，latency_p95 看直方图样本量。
	noData := stats.requests <= 0
	if def.MetricType == SLOMetricLatencyP95 {
		noData = stats.histogramTotal() == 0
	}
	if noData {
		item.CurrentValue = nil
		item.ComplianceRatio = 1
		item.ErrorBudgetRemaining = 1
		item.Status = SLOStatusOK
		item.Note = "窗口内无流量数据，按达标处理（无失败证据不误报）"
		return item
	}

	var value, remaining float64
	if def.MetricType == SLOMetricAvailability {
		bad := stats.err5xx / stats.requests // v1 口径：仅 5xx 计失败
		value = 1 - bad
		budget := 1 - def.Target // 校验保证 target ∈ (0,1)，budget 恒正
		remaining = clampBudgetRemaining((budget - bad) / budget)
		item.ComplianceRatio = value
	} else {
		p95 := metrics.PercentileFromBuckets(stats.dur, 0.95)
		value = p95
		remaining = clampBudgetRemaining((def.Target - p95) / def.Target) // 校验保证 target > 0
		item.ComplianceRatio = countLEFromBuckets(stats.dur, def.Target) / float64(stats.histogramTotal())
	}
	item.CurrentValue = &value
	item.ErrorBudgetRemaining = remaining
	item.Status = sloStatusFromBudget(remaining)
	return item
}

// normalizeSLOStrings 规整写接口字符串入参（去首尾空白）。
func normalizeSLOStrings(name, service string) (string, string) {
	return strings.TrimSpace(name), strings.TrimSpace(service)
}
