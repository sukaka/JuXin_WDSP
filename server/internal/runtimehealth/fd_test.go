package runtimehealth

import (
	"runtime"
	"testing"
)

// TestParseMaxOpenFiles /proc/self/limits 文本解析：正常、unlimited、缺失与格式非法。
func TestParseMaxOpenFiles(t *testing.T) {
	// 真实 /proc/self/limits 行首有对齐空格与多列
	normal := "Limit                     Soft Limit           Hard Limit           Units\n" +
		"Max cpu time              unlimited            unlimited            seconds\n" +
		"Max open files            1024                 1048576              files\n" +
		"Max processes             62945                62945                processes\n"
	cases := []struct {
		name string
		data string
		want uint64
	}{
		{"正常", normal, 1024},
		{"soft unlimited 回退", "Max open files            unlimited            unlimited            files\n", 0},
		{"缺失", "Max cpu time              unlimited            unlimited            seconds\n", 0},
		{"空文本", "", 0},
		{"列数不足", "Max open files            1024\n", 0},
		{"soft 非数字", "Max open files            abc                  1048576              files\n", 0},
	}
	for _, c := range cases {
		if got := parseMaxOpenFiles(c.data); got != c.want {
			t.Errorf("%s: parseMaxOpenFiles = %d，期望 %d", c.name, got, c.want)
		}
	}
}

// TestFDUsagePercent 句柄使用率计算：max 为 0 返回 0（防除零）。
func TestFDUsagePercent(t *testing.T) {
	cases := []struct {
		open, max uint64
		want      float64
	}{
		{0, 1024, 0},
		{512, 1024, 50},
		{1024, 1024, 100},
		{100, 0, 0},
	}
	for _, c := range cases {
		if got := fdUsagePercent(c.open, c.max); got != c.want {
			t.Errorf("fdUsagePercent(%d,%d) = %v，期望 %v", c.open, c.max, got, c.want)
		}
	}
}

// TestFDStatus 句柄状态：使用率 ≥ 阈值 DEGRADED，否则 UP（边界达阈即降级）。
func TestFDStatus(t *testing.T) {
	if got := fdStatus(79.9, 80); got != StatusUp {
		t.Errorf("79.9%% = %s，期望 UP", got)
	}
	if got := fdStatus(80, 80); got != StatusDegraded {
		t.Errorf("80%% = %s，期望 DEGRADED", got)
	}
	if got := fdStatus(100, 80); got != StatusDegraded {
		t.Errorf("100%% = %s，期望 DEGRADED", got)
	}
}

// TestFDUsage 平台行为：Linux 采集可用且 open ≤ max；非 Linux 返回不可用。
func TestFDUsage(t *testing.T) {
	open, max, ok := fdUsage()
	if runtime.GOOS == "linux" {
		if !ok {
			t.Fatal("Linux 平台句柄采集应可用")
		}
		if open == 0 || max == 0 || open > max {
			t.Errorf("open=%d max=%d 应满足 0 < open ≤ max", open, max)
		}
		return
	}
	if ok {
		t.Errorf("%s 平台句柄采集应不可用", runtime.GOOS)
	}
}

// TestProbeAPIFDMetrics API 组件自测：平台支持时产出句柄指标，阈值配置生效。
func TestProbeAPIFDMetrics(t *testing.T) {
	c := NewCollector(nil, Options{})
	snap := c.probeAPI()
	if runtime.GOOS != "linux" {
		if _, ok := snap.Metrics[MetricFDUsagePercent]; ok {
			t.Error("非 Linux 平台不应产出句柄指标")
		}
		if snap.Status != StatusUp {
			t.Errorf("非 Linux 平台不判级，status = %s，期望 UP", snap.Status)
		}
		return
	}
	for _, key := range []string{MetricFDOpenFiles, MetricFDMaxOpenFiles, MetricFDUsagePercent} {
		if _, ok := snap.Metrics[key]; !ok {
			t.Errorf("Linux 平台应产出指标 %s", key)
		}
	}
	if snap.Status != StatusUp {
		t.Errorf("正常使用率下 status = %s，期望 UP", snap.Status)
	}
	// 阈值降到 0 以上任意使用率必达阈：验证可配置阈值驱动降级与文案
	c2 := NewCollector(nil, Options{FDUsageHighPercent: 0.0001})
	snap2 := c2.probeAPI()
	if snap2.Status != StatusDegraded {
		t.Errorf("极低阈值下 status = %s，期望 DEGRADED", snap2.Status)
	}
	if snap2.Message == "" || snap2.Message == "进程运行中" {
		t.Error("降级时应给出句柄使用率文案")
	}
}
