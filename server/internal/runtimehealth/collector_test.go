package runtimehealth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestOverallStatus 整体状态取最差：DOWN > DEGRADED > UNKNOWN > UP。
func TestOverallStatus(t *testing.T) {
	cases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"全部健康", []string{StatusUp, StatusUp}, StatusUp},
		{"含未知", []string{StatusUp, StatusUnknown}, StatusUnknown},
		{"含降级", []string{StatusUp, StatusDegraded}, StatusDegraded},
		{"含宕机", []string{StatusDegraded, StatusDown, StatusUp}, StatusDown},
		{"空列表", nil, StatusUp},
	}
	for _, c := range cases {
		if got := OverallStatus(c.statuses); got != c.want {
			t.Errorf("%s: OverallStatus = %s，期望 %s", c.name, got, c.want)
		}
	}
}

// TestCertStatus 证书状态：有已过期 DOWN；临期 DEGRADED；否则 UP。
func TestCertStatus(t *testing.T) {
	cases := []struct {
		minDays, expired, expiringDays int
		want                           string
	}{
		{60, 0, 30, StatusUp},
		{30, 0, 30, StatusDegraded},
		{7, 0, 30, StatusDegraded},
		{10, 2, 30, StatusDown},
		{60, 1, 30, StatusDown},
	}
	for _, c := range cases {
		if got := certStatus(c.minDays, c.expired, c.expiringDays); got != c.want {
			t.Errorf("certStatus(%d,%d,%d) = %s，期望 %s",
				c.minDays, c.expired, c.expiringDays, got, c.want)
		}
	}
}

// TestDiskStatus 磁盘状态：剩余 ≤10% 降级。
func TestDiskStatus(t *testing.T) {
	if got := diskStatus(50, 10); got != StatusUp {
		t.Errorf("剩余 50%% = %s，期望 UP", got)
	}
	if got := diskStatus(10, 10); got != StatusDegraded {
		t.Errorf("剩余 10%% = %s，期望 DEGRADED", got)
	}
	if got := diskStatus(3.5, 10); got != StatusDegraded {
		t.Errorf("剩余 3.5%% = %s，期望 DEGRADED", got)
	}
}

// TestUpstreamStatus 源站状态：全健康 UP；部分 DEGRADED；全失败 DOWN。
func TestUpstreamStatus(t *testing.T) {
	cases := []struct {
		total, healthy int
		want           string
	}{
		{0, 0, StatusUp},
		{3, 3, StatusUp},
		{3, 1, StatusDegraded},
		{3, 0, StatusDown},
	}
	for _, c := range cases {
		if got := upstreamStatus(c.total, c.healthy); got != c.want {
			t.Errorf("upstreamStatus(%d,%d) = %s，期望 %s", c.total, c.healthy, got, c.want)
		}
	}
}

// TestSummarizeCheckpoints checkpoint 滞后汇总：取最大值，缺失不计。
func TestSummarizeCheckpoints(t *testing.T) {
	maxLag, missing := SummarizeCheckpoints([]CheckpointLag{
		{Name: "a", LagSecs: 30},
		{Name: "b", LagSecs: 95},
		{Name: "c", Missing: true},
	})
	if maxLag != 95 {
		t.Errorf("maxLag = %v，期望 95", maxLag)
	}
	if missing != 1 {
		t.Errorf("missing = %d，期望 1", missing)
	}
	maxLag, missing = SummarizeCheckpoints(nil)
	if maxLag != 0 || missing != 0 {
		t.Errorf("空列表 maxLag=%v missing=%d，期望 0/0", maxLag, missing)
	}
}

// TestParseInfoInt Redis INFO 字段解析。
func TestParseInfoInt(t *testing.T) {
	info := "# Memory\r\nused_memory:1048576\r\nused_memory_peak:2097152\r\n" +
		"# Clients\r\nconnected_clients:12\r\nblocked_clients:0\r\n"
	if got := parseInfoInt(info, "used_memory"); got != 1048576 {
		t.Errorf("used_memory = %d，期望 1048576", got)
	}
	if got := parseInfoInt(info, "connected_clients"); got != 12 {
		t.Errorf("connected_clients = %d，期望 12", got)
	}
	if got := parseInfoInt(info, "no_such_key"); got != 0 {
		t.Errorf("缺失字段 = %d，期望 0", got)
	}
	// 前缀不得误匹配（used_memory 不应命中 used_memory_peak）
	if got := parseInfoInt("used_memory_peak:999\n", "used_memory"); got != 0 {
		t.Errorf("前缀误匹配 = %d，期望 0", got)
	}
}

// TestFileStaleSeconds 文件 mtime 滞后计算；缺失返回 -1。
func TestFileStaleSeconds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guard-events.log")
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-90 * time.Second)
	if err := os.Chtimes(p, past, past); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	got := fileStaleSeconds(p, now)
	if got < 80 || got > 100 {
		t.Errorf("滞后 = %v 秒，期望约 90", got)
	}
	if got := fileStaleSeconds(filepath.Join(dir, "missing.log"), now); got != -1 {
		t.Errorf("缺失文件 = %v，期望 -1", got)
	}
	if got := fileStaleSeconds("", now); got != -1 {
		t.Errorf("空路径 = %v，期望 -1", got)
	}
}

// TestDirSizeOf 目录占用统计；不存在目录 Available=false。
func TestDirSizeOf(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), make([]byte, 100), 0600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.bin"), make([]byte, 50), 0600); err != nil {
		t.Fatal(err)
	}
	ds := DirSizeOf(dir)
	if !ds.Available {
		t.Error("存在目录应 Available")
	}
	if ds.FileCount != 2 {
		t.Errorf("FileCount = %d，期望 2", ds.FileCount)
	}
	if ds.TotalBytes != 150 {
		t.Errorf("TotalBytes = %d，期望 150", ds.TotalBytes)
	}
	ds = DirSizeOf(filepath.Join(dir, "not-exist"))
	if ds.Available {
		t.Error("不存在目录不应 Available")
	}
}

// TestMetricFloat metrics 数值提取（JSON 与原生类型）。
func TestMetricFloat(t *testing.T) {
	m := map[string]interface{}{
		"f": float64(1.5), "i": int(2), "i64": int64(3), "u64": uint64(4), "s": "x",
	}
	if v, ok := metricFloat(m, "f"); !ok || v != 1.5 {
		t.Errorf("float64 提取失败 %v %v", v, ok)
	}
	if v, ok := metricFloat(m, "i"); !ok || v != 2 {
		t.Errorf("int 提取失败 %v %v", v, ok)
	}
	if v, ok := metricFloat(m, "i64"); !ok || v != 3 {
		t.Errorf("int64 提取失败 %v %v", v, ok)
	}
	if v, ok := metricFloat(m, "u64"); !ok || v != 4 {
		t.Errorf("uint64 提取失败 %v %v", v, ok)
	}
	if _, ok := metricFloat(m, "s"); ok {
		t.Error("字符串不应可提取")
	}
	if _, ok := metricFloat(m, "missing"); ok {
		t.Error("缺失键不应可提取")
	}
}
