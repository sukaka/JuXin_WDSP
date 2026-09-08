// slo_types_test.go SLO 校验、错误预算公式与状态机的纯函数单测（不依赖 PG）。
package apm

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// almostEq 浮点近似比较（预算公式含除法，避免二进制浮点尾数误判）。
func almostEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestValidateSLOInput(t *testing.T) {
	cases := []struct {
		name             string
		sloName, service string
		metricType       string
		target           float64
		window           string
		wantErr          bool
	}{
		{"valid availability", "可用性", "shop", SLOMetricAvailability, 0.999, SLOWindow7d, false},
		{"valid latency", "时延", "shop", SLOMetricLatencyP95, 500, SLOWindow30d, false},
		{"latency target boundary max", "时延", "shop", SLOMetricLatencyP95, 600000, SLOWindow7d, false},
		{"empty name", "", "shop", SLOMetricAvailability, 0.99, SLOWindow7d, true},
		{"name too long", strings.Repeat("甲", 129), "shop", SLOMetricAvailability, 0.99, SLOWindow7d, true},
		{"name 128 ok", strings.Repeat("甲", 128), "shop", SLOMetricAvailability, 0.99, SLOWindow7d, false},
		{"empty service", "n", "", SLOMetricAvailability, 0.99, SLOWindow7d, true},
		{"service too long", "n", strings.Repeat("s", 129), SLOMetricAvailability, 0.99, SLOWindow7d, true},
		{"availability target zero", "n", "shop", SLOMetricAvailability, 0, SLOWindow7d, true},
		{"availability target one", "n", "shop", SLOMetricAvailability, 1, SLOWindow7d, true},
		{"availability target negative", "n", "shop", SLOMetricAvailability, -0.5, SLOWindow7d, true},
		{"latency target zero", "n", "shop", SLOMetricLatencyP95, 0, SLOWindow7d, true},
		{"latency target over max", "n", "shop", SLOMetricLatencyP95, 600001, SLOWindow7d, true},
		{"bad metric type", "n", "shop", "error_rate", 0.99, SLOWindow7d, true},
		{"bad window", "n", "shop", SLOMetricAvailability, 0.99, "1d", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSLOInput(c.sloName, c.service, c.metricType, c.target, c.window)
			if c.wantErr && err == nil {
				t.Error("want error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("want nil, got %v", err)
			}
		})
	}
}

// TestSLOWindowAndTrendStep 窗口长度与趋势桶粒度（7d 小时桶 / 30d 天桶）。
func TestSLOWindowAndTrendStep(t *testing.T) {
	if d := sloWindowDuration(SLOWindow7d); d != 7*24*time.Hour {
		t.Errorf("7d window = %v", d)
	}
	if d := sloWindowDuration(SLOWindow30d); d != 30*24*time.Hour {
		t.Errorf("30d window = %v", d)
	}
	if s := sloTrendStep(SLOWindow7d); s != time.Hour {
		t.Errorf("7d trend step = %v", s)
	}
	if s := sloTrendStep(SLOWindow30d); s != 24*time.Hour {
		t.Errorf("30d trend step = %v", s)
	}
}

// TestClampBudgetRemaining 预算剩余比夹紧 [−1,1]。
func TestClampBudgetRemaining(t *testing.T) {
	if v := clampBudgetRemaining(2.5); v != 1 {
		t.Errorf("clamp(2.5) = %v", v)
	}
	if v := clampBudgetRemaining(-3); v != -1 {
		t.Errorf("clamp(-3) = %v", v)
	}
	if v := clampBudgetRemaining(0.15); v != 0.15 {
		t.Errorf("clamp(0.15) = %v", v)
	}
}

// TestSLOStatusFromBudget 状态机边界：remaining<0 → BREACHED；<0.2 → AT_RISK；否则 OK。
func TestSLOStatusFromBudget(t *testing.T) {
	cases := []struct {
		remaining float64
		want      string
	}{
		{-1, SLOStatusBreached},
		{-0.001, SLOStatusBreached},
		{0, SLOStatusAtRisk},   // 恰好踩线未违约，但预算消耗 100% > 80%
		{0.1, SLOStatusAtRisk}, // 消耗 90%
		{0.1999, SLOStatusAtRisk},
		{0.2, SLOStatusOK}, // 消耗恰好 80%（>80% 才升 AT_RISK）
		{1, SLOStatusOK},
	}
	for _, c := range cases {
		if got := sloStatusFromBudget(c.remaining); got != c.want {
			t.Errorf("sloStatusFromBudget(%v) = %s, want %s", c.remaining, got, c.want)
		}
	}
}

// TestCountLEFromBuckets 直方图 ≤t 样本数估算（桶内线性插值）。
func TestCountLEFromBuckets(t *testing.T) {
	// 每桶 10 个样本（11 桶：≤5, ≤10, ≤25, ≤50, ≤100, ≤250, ≤500, ≤1000, ≤2500, ≤5000, >5000）
	counts := []int{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}

	if got := countLEFromBuckets(counts, 0); got != 0 {
		t.Errorf("t=0: %v", got)
	}
	// t=5（首桶边界）：首桶全计
	if got := countLEFromBuckets(counts, 5); got != 10 {
		t.Errorf("t=5: %v, want 10", got)
	}
	// t=500：前 7 桶（≤500）全计
	if got := countLEFromBuckets(counts, 500); got != 70 {
		t.Errorf("t=500: %v, want 70", got)
	}
	// t=17.5（(10,25] 桶中点）：10+10+ 10*(17.5-10)/(25-10)=20+5=25
	if got := countLEFromBuckets(counts, 17.5); got != 25 {
		t.Errorf("t=17.5: %v, want 25", got)
	}
	// t=99999（超最大桶）：全部样本
	if got := countLEFromBuckets(counts, 99999); got != 110 {
		t.Errorf("t=99999: %v, want 110", got)
	}
	// 空直方图
	if got := countLEFromBuckets([]int{}, 100); got != 0 {
		t.Errorf("empty: %v", got)
	}
}

// TestEvalSLOAvailability availability 评估：预算公式 + 状态机联动。
func TestEvalSLOAvailability(t *testing.T) {
	def := &SLO{ID: uuid.New(), Name: "可用性", Service: "shop",
		MetricType: SLOMetricAvailability, Target: 0.99, Window: SLOWindow7d}

	// 达标：1000 请求 5xx 5（违约率 0.005，预算 0.01 → remaining 0.5 → OK）
	item := evalSLO(def, &sloWindowStats{requests: 1000, err5xx: 5})
	if item.CurrentValue == nil || *item.CurrentValue != 0.995 {
		t.Fatalf("current_value = %v, want 0.995", item.CurrentValue)
	}
	if !almostEq(item.ErrorBudgetRemaining, 0.5) {
		t.Errorf("remaining = %v, want 0.5", item.ErrorBudgetRemaining)
	}
	if item.Status != SLOStatusOK || item.ComplianceRatio != 0.995 {
		t.Errorf("status/compliance = %s/%v", item.Status, item.ComplianceRatio)
	}
	if item.Note != "" {
		t.Errorf("note = %q, want empty", item.Note)
	}

	// AT_RISK：违约率 0.009（消耗 90% → remaining 0.1）
	item = evalSLO(def, &sloWindowStats{requests: 1000, err5xx: 9})
	if item.Status != SLOStatusAtRisk {
		t.Errorf("status = %s, want AT_RISK (remaining %v)", item.Status, item.ErrorBudgetRemaining)
	}

	// BREACHED：违约率 0.02 > 预算 0.01 → remaining = (0.01−0.02)/0.01 = −1（夹紧下界）
	item = evalSLO(def, &sloWindowStats{requests: 1000, err5xx: 20})
	if item.Status != SLOStatusBreached {
		t.Errorf("status = %s, want BREACHED", item.Status)
	}
	if !almostEq(item.ErrorBudgetRemaining, -1) {
		t.Errorf("remaining = %v, want -1 (clamped)", item.ErrorBudgetRemaining)
	}

	// 4xx 不计失败（v1 口径）：err5xx 只含 5xx，4xx 由 stats.requests 计入总量
	// （requests 含全部类别，err5xx 单列——4xx 不进入 err5xx 即不计失败）
	item = evalSLO(def, &sloWindowStats{requests: 1000, err5xx: 0})
	if item.Status != SLOStatusOK || *item.CurrentValue != 1 || item.ErrorBudgetRemaining != 1 {
		t.Errorf("all-clean: status=%s value=%v remaining=%v", item.Status, *item.CurrentValue, item.ErrorBudgetRemaining)
	}

	// 无数据：current_value=null、OK、预算满、note 说明
	item = evalSLO(def, &sloWindowStats{})
	if item.CurrentValue != nil || item.Status != SLOStatusOK ||
		item.ComplianceRatio != 1 || item.ErrorBudgetRemaining != 1 || item.Note == "" {
		t.Errorf("no-data: %+v", item)
	}
}

// TestEvalSLOLatency latency_p95 评估：P95 估算 + 余量预算 + 达标请求占比。
func TestEvalSLOLatency(t *testing.T) {
	def := &SLO{ID: uuid.New(), Name: "时延", Service: "shop",
		MetricType: SLOMetricLatencyP95, Target: 500, Window: SLOWindow30d}

	fast := make([]int, len(metrics.DurationBucketsMs)+1)
	fast[0] = 100 // 全部 ≤5ms（p95 ≈ 4.75ms）
	item := evalSLO(def, &sloWindowStats{requests: 100, dur: fast})
	if item.CurrentValue == nil || *item.CurrentValue <= 0 || *item.CurrentValue > 5 {
		t.Fatalf("current_value = %v", item.CurrentValue)
	}
	// remaining = (500−4.75)/500 ≈ 0.9905 → OK；达标占比 1
	if item.Status != SLOStatusOK || item.ComplianceRatio != 1 {
		t.Errorf("fast: status=%s compliance=%v", item.Status, item.ComplianceRatio)
	}

	slow := make([]int, len(metrics.DurationBucketsMs)+1)
	slow[9] = 100 // 全部 (2500,5000]ms（p95 ≈ 4875ms > 500 → BREACHED，remaining 夹紧 −1）
	item = evalSLO(def, &sloWindowStats{requests: 100, dur: slow})
	if item.Status != SLOStatusBreached || item.ErrorBudgetRemaining != -1 {
		t.Errorf("slow: status=%s remaining=%v", item.Status, item.ErrorBudgetRemaining)
	}
	if item.ComplianceRatio != 0 {
		t.Errorf("slow compliance = %v, want 0", item.ComplianceRatio)
	}

	// AT_RISK：p95 ≈ 475ms（(250,500] 桶 95% 处）→ remaining = (500−475)/500 = 0.05 < 0.2
	mixed := make([]int, len(metrics.DurationBucketsMs)+1)
	mixed[5] = 100 // 全部 (100,250]ms → p95 ≈ 237.5ms → remaining ≈ 0.525 → OK
	item = evalSLO(def, &sloWindowStats{requests: 100, dur: mixed})
	if item.Status != SLOStatusOK {
		t.Errorf("mid: status=%s remaining=%v", item.Status, item.ErrorBudgetRemaining)
	}
	risky := make([]int, len(metrics.DurationBucketsMs)+1)
	risky[6] = 95 // (250,500]ms
	risky[0] = 5  // ≤5ms
	// 累计到 95 处命中第 6 桶：p95 = 250 + (95−5)/95×250 ≈ 486.8ms → remaining ≈ 0.026 → AT_RISK
	item = evalSLO(def, &sloWindowStats{requests: 100, dur: risky})
	if item.Status != SLOStatusAtRisk {
		t.Errorf("risky: status=%s remaining=%v p95=%v", item.Status, item.ErrorBudgetRemaining, *item.CurrentValue)
	}

	// 无直方图样本（有请求数但无耗时数据）：按无数据处理
	item = evalSLO(def, &sloWindowStats{requests: 100})
	if item.CurrentValue != nil || item.Status != SLOStatusOK || item.Note == "" {
		t.Errorf("no-histogram: %+v", item)
	}
}
