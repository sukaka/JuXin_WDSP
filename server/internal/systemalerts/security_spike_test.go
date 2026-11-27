package systemalerts

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeSecuritySpikes 是 SecuritySpikeStatsStore 的可编程内存实现。
type fakeSecuritySpikes struct {
	highEvents int64
	ccBans     int64
	err        error

	calls int // 统计方法被调用次数
}

func (f *fakeSecuritySpikes) CountRecentHighSeveritySecurityEvents(_ context.Context, _ time.Duration) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	return f.highEvents, nil
}

func (f *fakeSecuritySpikes) CountRecentCCBans(_ context.Context, _ time.Duration) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	return f.ccBans, nil
}

// newSecuritySpikeEngine 创建注入安全事件统计源的引擎（可控时钟）。
func newSecuritySpikeEngine(store *fakeStore, spikes *fakeSecuritySpikes, settings SettingsReader, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:            func() time.Time { return *now },
		Cooldown:       time.Minute,
		FlapWindow:     10 * time.Minute,
		FlapThreshold:  3,
		MaxOpen:        500,
		SecuritySpikes: spikes,
		Settings:       settings,
	})
}

// TestEvaluateSecurityEventSpike 安全事件激增：达阈触发（≥ 阈值）→合并→回落自动恢复。
func TestEvaluateSecurityEventSpike(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	spikes := &fakeSecuritySpikes{highEvents: 12} // 默认阈值 10
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newSecuritySpikeEngine(store, spikes, nil, &now)

	if err := e.EvaluateSecuritySpikes(ctx); err != nil {
		t.Fatalf("EvaluateSecuritySpikes: %v", err)
	}
	var raised Alert
	found := false
	for _, a := range store.alerts {
		if a.AlertType == TypeSecurityEventSpike {
			raised, found = *a, true
		}
	}
	if !found {
		t.Fatal("达阈应触发 SECURITY_EVENT_SPIKE")
	}
	if raised.Component != ComponentWAF {
		t.Errorf("component = %s, want %s", raised.Component, ComponentWAF)
	}
	if raised.Severity != SeverityHigh {
		t.Errorf("等级 = %s, want HIGH", raised.Severity)
	}
	if !strings.Contains(raised.Message, "高危/严重级安全事件 12 条") || !strings.Contains(raised.Message, "阈值 10") {
		t.Errorf("message 应含中文级别、计数与阈值: %q", raised.Message)
	}
	if strings.Contains(raised.Message, "HIGH/CRITICAL") {
		t.Errorf("message 不应包含英文级别枚举: %q", raised.Message)
	}

	// 持续达阈 → 合并不新建
	if err := e.EvaluateSecuritySpikes(ctx); err != nil {
		t.Fatalf("再次评估: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Fatalf("持续触发应合并为同一条, got %d 条 OPEN", n)
	}

	// 回落至阈值以下 → 自动恢复
	spikes.highEvents = 3
	if err := e.EvaluateSecuritySpikes(ctx); err != nil {
		t.Fatalf("回落评估: %v", err)
	}
	if got := store.get(raised.ID); got.Status != StatusResolved || got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("回落后应 RESOLVED(RECOVERED), got status=%s", got.Status)
	}
}

// TestEvaluateCCBanSpike CC 封禁激增：自定义阈值生效；恰好等于阈值也触发（≥ 口径）。
func TestEvaluateCCBanSpike(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	spikes := &fakeSecuritySpikes{ccBans: 30}
	settings := &fakeSettings{ints: map[string]int{
		notifySettingsGroup + "/" + notifyKeyCCSpikeThreshold: 30,
	}}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newSecuritySpikeEngine(store, spikes, settings, &now)

	if err := e.EvaluateSecuritySpikes(ctx); err != nil {
		t.Fatalf("EvaluateSecuritySpikes: %v", err)
	}
	found := false
	for _, a := range store.alerts {
		if a.AlertType == TypeCCBanSpike {
			found = true
			if a.Component != ComponentCC {
				t.Errorf("component = %s, want %s", a.Component, ComponentCC)
			}
			if a.Severity != SeverityMedium {
				t.Errorf("等级 = %s, want MEDIUM", a.Severity)
			}
			if !strings.Contains(a.Message, "30 个 IP") || !strings.Contains(a.Message, "阈值 30") {
				t.Errorf("message 应含计数与自定义阈值: %q", a.Message)
			}
		}
	}
	if !found {
		t.Fatal("计数等于阈值应触发 CC_BAN_SPIKE（≥ 口径）")
	}
}

// TestEvaluateSecuritySpikesBelowThreshold 未达阈不触发。
func TestEvaluateSecuritySpikesBelowThreshold(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	spikes := &fakeSecuritySpikes{highEvents: 9, ccBans: 19} // 默认阈值 10/20
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	e := newSecuritySpikeEngine(store, spikes, nil, &now)

	if err := e.EvaluateSecuritySpikes(ctx); err != nil {
		t.Fatalf("EvaluateSecuritySpikes: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("未达阈不应产生告警, got %d", n)
	}
}

// TestEvaluateSecuritySpikesNilStore 未注入统计源时不执行（装配缺省形态）。
func TestEvaluateSecuritySpikesNilStore(t *testing.T) {
	e := NewEngine(newFakeStore(), EngineOptions{})
	if err := e.EvaluateSecuritySpikes(context.Background()); err != nil {
		t.Fatalf("未注入统计源应为无操作, got %v", err)
	}
}

// TestLoadSpikeThresholds 阈值读取：默认值、覆盖、非法值回退。
func TestLoadSpikeThresholds(t *testing.T) {
	ctx := context.Background()

	// nil 配置源 → 全默认
	th := loadSpikeThresholds(ctx, nil)
	if th.Security != defaultSecuritySpikeThreshold || th.CC != defaultCCSpikeThreshold {
		t.Errorf("默认阈值错误: %+v", th)
	}

	// 合法覆盖
	custom := &fakeSettings{ints: map[string]int{
		notifySettingsGroup + "/" + notifyKeySecuritySpikeThreshold: 50,
		notifySettingsGroup + "/" + notifyKeyCCSpikeThreshold:       100,
	}}
	th = loadSpikeThresholds(ctx, custom)
	if th.Security != 50 || th.CC != 100 {
		t.Errorf("覆盖值未生效: %+v", th)
	}

	// 非法值（0/负/超上限）→ 回退默认
	bad := &fakeSettings{ints: map[string]int{
		notifySettingsGroup + "/" + notifyKeySecuritySpikeThreshold: -1,
		notifySettingsGroup + "/" + notifyKeyCCSpikeThreshold:       0,
	}}
	th = loadSpikeThresholds(ctx, bad)
	if th.Security != defaultSecuritySpikeThreshold || th.CC != defaultCCSpikeThreshold {
		t.Errorf("非法配置应回退默认: %+v", th)
	}
}

// TestSecuritySpikeAlertTypes 通知二期新告警类型注册与默认等级（防回归）。
func TestSecuritySpikeAlertTypes(t *testing.T) {
	cases := []struct {
		alertType string
		severity  string
	}{
		{TypeSecurityEventSpike, SeverityHigh},
		{TypeLoginBruteForce, SeverityMedium},
		{TypeCCBanSpike, SeverityMedium},
	}
	for _, c := range cases {
		if !IsValidType(c.alertType) {
			t.Errorf("%s 未注册为合法告警类型", c.alertType)
		}
		if got := SeverityFor(c.alertType); got != c.severity {
			t.Errorf("%s 等级 = %s, want %s", c.alertType, got, c.severity)
		}
	}
}

// TestOpsAlertTypesRegistered 业务方实际 Raise 但此前不在 severityRules 的 4 个类型
// （upgrades/backups/restores 静默拒绝隐患修复）防回归：必须合法且等级符合语义。
func TestOpsAlertTypesRegistered(t *testing.T) {
	cases := []struct {
		alertType string
		severity  string
	}{
		{TypeUpgradeRollbackFailed, SeverityCritical}, // 升级失败且回滚失败：最严重
		{TypeBackupVerifyFailed, SeverityHigh},        // 备份产物校验失败
		{TypeRestoreCleanupFailed, SeverityMedium},    // 隔离环境清理失败
		{TypeUpgradeRolledBack, SeverityMedium},       // 升级失败已自动回滚（告知性）
	}
	for _, c := range cases {
		if !IsValidType(c.alertType) {
			t.Errorf("%s 未注册为合法告警类型（引擎会拒绝该 Raise）", c.alertType)
		}
		if got := SeverityFor(c.alertType); got != c.severity {
			t.Errorf("%s 等级 = %s, want %s", c.alertType, got, c.severity)
		}
	}
}
