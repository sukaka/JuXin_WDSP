// store_test.go APM 仓储纯逻辑单元测试（聚合表分层、端点键拆分、比率与分位数估算）。
package apm

import (
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// TestAggTableFor 聚合表分层：≤6h 分钟表，>6h 小时表（窗口上限 31 天由 handler 强制）。
func TestAggTableFor(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name  string
		start time.Time
		end   time.Time
		want  string
	}{
		{"1h minute", now.Add(-time.Hour), now, "metric_minute_aggregates"},
		{"6h minute", now.Add(-6 * time.Hour), now, "metric_minute_aggregates"},
		{"6h1m hour", now.Add(-6*time.Hour - time.Minute), now, "metric_hour_aggregates"},
		{"31d hour", now.Add(-31 * 24 * time.Hour), now, "metric_hour_aggregates"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aggTableFor(c.start, c.end); got != c.want {
				t.Errorf("aggTableFor = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTrendStep 趋势粒度与聚合表一致。
func TestTrendStep(t *testing.T) {
	if trendStep("metric_minute_aggregates") != time.Minute {
		t.Error("minute table must yield minute step")
	}
	if trendStep("metric_hour_aggregates") != time.Hour {
		t.Error("hour table must yield hour step")
	}
}

// TestSplitEndpoint 端点键拆分：正常键拆 method/path_template；保留桶与畸形键返回空。
func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		method   string
		path     string
	}{
		{"GET /orders/{id}", "GET", "/orders/{id}"},
		{"POST /api/v1/users", "POST", "/api/v1/users"},
		{"DELETE /a/{uuid}", "DELETE", "/a/{uuid}"},
		{"__OTHER__", "", ""},
		{"__UNCLASSIFIED__", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		m, p := splitEndpoint(c.endpoint)
		if m != c.method || p != c.path {
			t.Errorf("splitEndpoint(%q) = (%q, %q), want (%q, %q)", c.endpoint, m, p, c.method, c.path)
		}
	}
}

// TestRate 比率安全除法（分母为 0/负数返回 0）。
func TestRate(t *testing.T) {
	if got := rate(5, 100); got != 0.05 {
		t.Errorf("rate(5,100) = %v, want 0.05", got)
	}
	if got := rate(1, 0); got != 0 {
		t.Errorf("rate(1,0) = %v, want 0", got)
	}
}

// TestLatencyFromBuckets 直方图分位数估算与 metrics 包口径一致；无样本全 0。
func TestLatencyFromBuckets(t *testing.T) {
	if lat := latencyFromBuckets(make([]int, len(metrics.DurationBucketsMs)+1)); lat.P50 != 0 || lat.P95 != 0 || lat.P99 != 0 {
		t.Errorf("empty buckets must yield zero latency, got %+v", lat)
	}
	// 100 个样本全部落在 (100,250] 桶（idx 5）：p50/p95/p99 均在该桶区间内
	counts := make([]int, len(metrics.DurationBucketsMs)+1)
	counts[5] = 100
	lat := latencyFromBuckets(counts)
	for name, v := range map[string]float64{"p50": lat.P50, "p95": lat.P95, "p99": lat.P99} {
		if v <= 100 || v > 250 {
			t.Errorf("%s = %v, want within (100, 250]", name, v)
		}
	}
	if !(lat.P50 <= lat.P95 && lat.P95 <= lat.P99) {
		t.Errorf("percentiles must be monotonic, got %+v", lat)
	}
}

// TestAppCond 应用过滤子句：空集合不加条件；非空参数化 ANY。
func TestAppCond(t *testing.T) {
	cond, args := appCond(nil, []interface{}{"m"})
	if cond != "" || len(args) != 1 {
		t.Errorf("empty codes must add no condition, got %q args=%v", cond, args)
	}
	cond, args = appCond([]string{"shop", "mall"}, []interface{}{"m"})
	if cond != " AND labels->>'app' = ANY($2)" {
		t.Errorf("cond = %q", cond)
	}
	if len(args) != 2 {
		t.Errorf("args len = %d, want 2", len(args))
	}
	codes, ok := args[1].([]string)
	if !ok || len(codes) != 2 || codes[0] != "shop" {
		t.Errorf("codes arg = %v", args[1])
	}
}
