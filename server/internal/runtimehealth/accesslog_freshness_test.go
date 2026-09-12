package runtimehealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSettingsReader 是 runtimehealth SettingsReader 的 map 实现。
type fakeSettingsReader struct {
	bools map[string]bool
	ints  map[string]int
}

func (f *fakeSettingsReader) GetBool(_ context.Context, group, key string, def bool) bool {
	if v, ok := f.bools[group+"/"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettingsReader) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := f.ints[group+"/"+key]; ok {
		return v
	}
	return def
}

// TestAccessLogChainIncluded 开关门控：未注入 Settings 或 access_log_enabled=false
// 时不纳入判级（默认部署零行为变化）；开启时纳入。
func TestAccessLogChainIncluded(t *testing.T) {
	ctx := context.Background()
	if accessLogChainIncluded(ctx, nil) {
		t.Error("未注入 Settings 不应纳入判级")
	}
	if accessLogChainIncluded(ctx, &fakeSettingsReader{}) {
		t.Error("开关缺失（默认 false）不应纳入判级")
	}
	if accessLogChainIncluded(ctx, &fakeSettingsReader{bools: map[string]bool{
		accessLogSettingsGroup + "/" + accessLogKeyEnabled: false,
	}}) {
		t.Error("开关关闭不应纳入判级")
	}
	if !accessLogChainIncluded(ctx, &fakeSettingsReader{bools: map[string]bool{
		accessLogSettingsGroup + "/" + accessLogKeyEnabled: true,
	}}) {
		t.Error("开关开启应纳入判级")
	}
}

// TestProbeAccessLogFullDisabled 开关关闭：探针不纳入判级且不读库
// （db 为 nil，若误触库会 panic）。
func TestProbeAccessLogFullDisabled(t *testing.T) {
	c := NewCollector(nil, Options{
		Settings: &fakeSettingsReader{bools: map[string]bool{
			accessLogSettingsGroup + "/" + accessLogKeyEnabled: false,
		}},
	})
	res := c.probeAccessLogFull(context.Background(), time.Now())
	if res.included {
		t.Error("开关关闭不应纳入判级")
	}
	if res.err != nil {
		t.Errorf("关闭路径不应产生错误, got %v", res.err)
	}
	if res.stale() {
		t.Error("关闭路径不得判停滞")
	}
}

// TestAccessLogStaleAfterSecs 停滞阈值：Options 默认、settings 覆盖、非法值回退。
func TestAccessLogStaleAfterSecs(t *testing.T) {
	ctx := context.Background()
	// 未注入 Settings → Options 默认 120 秒
	c := NewCollector(nil, Options{})
	if got := c.accessLogStaleAfterSecs(ctx); got != 120 {
		t.Errorf("默认阈值 = %v, want 120", got)
	}
	// settings 合法覆盖
	c = NewCollector(nil, Options{Settings: &fakeSettingsReader{ints: map[string]int{
		accessLogSettingsGroup + "/" + accessLogKeyStaleSeconds: 300,
	}}})
	if got := c.accessLogStaleAfterSecs(ctx); got != 300 {
		t.Errorf("覆盖阈值 = %v, want 300", got)
	}
	// 非法值（低于下限/超上限）→ 回退默认
	for _, bad := range []int{0, 5, 100000} {
		c = NewCollector(nil, Options{Settings: &fakeSettingsReader{ints: map[string]int{
			accessLogSettingsGroup + "/" + accessLogKeyStaleSeconds: bad,
		}}})
		if got := c.accessLogStaleAfterSecs(ctx); got != 120 {
			t.Errorf("非法阈值 %d 应回退 120, got %v", bad, got)
		}
	}
	// Options 级覆盖（无 settings 覆盖时生效）
	c = NewCollector(nil, Options{AccessLogStaleAfter: 5 * time.Minute})
	if got := c.accessLogStaleAfterSecs(ctx); got != 300 {
		t.Errorf("Options 覆盖阈值 = %v, want 300", got)
	}
}

// TestAccessLogChainStale 停滞判定：纳入判级 + 断点存在 + 滞后超阈才停滞。
func TestAccessLogChainStale(t *testing.T) {
	cases := []struct {
		name string
		res  accessLogChainResult
		want bool
	}{
		{"未纳入", accessLogChainResult{}, false},
		{"断点缺失", accessLogChainResult{included: true, cp: CheckpointLag{Name: CheckpointAccessLogFull, Missing: true}, staleAfter: 120}, false},
		{"正常断点", accessLogChainResult{included: true, cp: CheckpointLag{LagSecs: 30}, staleAfter: 120}, false},
		{"恰好达阈不停滞", accessLogChainResult{included: true, cp: CheckpointLag{LagSecs: 120}, staleAfter: 120}, false},
		{"停滞", accessLogChainResult{included: true, cp: CheckpointLag{LagSecs: 121}, staleAfter: 120}, true},
	}
	for _, c := range cases {
		if got := c.res.stale(); got != c.want {
			t.Errorf("%s: stale() = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBacklogLag 滞后语义：断点已消费完全（含日志不存在）滞后为 0（正常断点健康）；
// 有未消费字节时滞后为「当前时间 - 断点推进时间」。
func TestBacklogLag(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.log")
	if err := os.WriteFile(logPath, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// 断点 offset == 文件大小：无积压 → 0（无论断点多旧）
	if got := backlogLag(logPath, 10, now.Add(-time.Hour), now); got != 0 {
		t.Errorf("无积压滞后 = %v, want 0", got)
	}
	// 断点落后文件大小：滞后 = now - 断点推进时间
	if got := backlogLag(logPath, 4, now.Add(-90*time.Second), now); got < 89 || got > 91 {
		t.Errorf("积压滞后 = %v, want ≈90", got)
	}
	// 日志文件不存在（开关刚开/轮转间隙）：无积压 → 0
	if got := backlogLag(filepath.Join(dir, "missing.log"), 0, now.Add(-time.Hour), now); got != 0 {
		t.Errorf("日志缺失滞后 = %v, want 0", got)
	}
}

// TestEventCollectorStatus EVENT_COLLECTOR 判级：全缺失 UNKNOWN；accesslog-01 停滞
// 优先判 DEGRADED 并指明链路；通用最大滞后超阈 DEGRADED（既有口径不变）；正常 UP。
func TestEventCollectorStatus(t *testing.T) {
	fresh := []CheckpointLag{{Name: "security_events", LagSecs: 10}}

	// 全部缺失 → UNKNOWN（含 accesslog 链路缺失的情形）
	status, _ := eventCollectorStatus([]CheckpointLag{{Missing: true}, {Missing: true}}, 120, accessLogChainResult{
		included: true, cp: CheckpointLag{Name: CheckpointAccessLogFull, Missing: true}, staleAfter: 120,
	})
	if status != StatusUnknown {
		t.Errorf("全部缺失 = %s, want UNKNOWN", status)
	}

	// accesslog-01 停滞 → DEGRADED，message 指明访问日志链路
	stale := accessLogChainResult{included: true, cp: CheckpointLag{Name: CheckpointAccessLogFull, LagSecs: 300}, staleAfter: 120}
	status, msg := eventCollectorStatus(fresh, 120, stale)
	if status != StatusDegraded || !strings.Contains(msg, "访问日志采集链路停滞 300 秒") {
		t.Errorf("accesslog 停滞 = %s %q, want DEGRADED 且指明链路", status, msg)
	}

	// accesslog-01 健康 + 通用链路超阈 → 既有 DEGRADED 口径（message 不变）
	ok := accessLogChainResult{included: true, cp: CheckpointLag{Name: CheckpointAccessLogFull, LagSecs: 5}, staleAfter: 120}
	status, msg = eventCollectorStatus([]CheckpointLag{{Name: "security_events", LagSecs: 200}}, 120, ok)
	if status != StatusDegraded || msg != "事件采集最大滞后 200 秒" {
		t.Errorf("通用超阈 = %s %q, want DEGRADED 事件采集最大滞后 200 秒", status, msg)
	}

	// 全部健康 → UP；未注入/未纳入（零值结果）不影响既有判级
	status, msg = eventCollectorStatus(fresh, 120, accessLogChainResult{})
	if status != StatusUp || msg != "事件采集滞后正常" {
		t.Errorf("正常 = %s %q, want UP 事件采集滞后正常", status, msg)
	}
}
