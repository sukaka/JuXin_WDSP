package temporaryblocks

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeSettingsReader 内存设置读取器（键 "group:key" 缺失时返回默认值，与
// settings.Service 未命中回落默认同口径）。
type fakeSettingsReader struct {
	bools map[string]bool
	ints  map[string]int
}

func (f fakeSettingsReader) GetBool(_ context.Context, group, key string, def bool) bool {
	if v, ok := f.bools[group+":"+key]; ok {
		return v
	}
	return def
}

func (f fakeSettingsReader) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := f.ints[group+":"+key]; ok {
		return v
	}
	return def
}

func natTestStore(r SettingsReader, counter natIdentityCounter) *Store {
	s := &Store{natCounter: counter}
	s.SetNATGuardSettings(r)
	return s
}

// TestApplyNATGuardDisabled 未注入设置读取器或开关关闭时不做任何降档。
func TestApplyNATGuardDisabled(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}

	var noSettings Store
	if d := noSettings.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("no settings reader: expected no downgrade")
	}

	s := natTestStore(fakeSettingsReader{bools: map[string]bool{"cc_auto_block:nat_guard_enabled": false}},
		func(context.Context, string, time.Time) (int64, error) { return 10, nil })
	if d := s.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("guard disabled: expected no downgrade")
	}
	if !b.BlockExpiresAt.Equal(now.Add(time.Hour)) {
		t.Error("expiry must remain untouched when guard disabled")
	}
}

// TestApplyNATGuardDowngrade 身份数达阈且原时长超过降档上限时夹紧到期时间。
func TestApplyNATGuardDowngrade(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{}, func(_ context.Context, ip string, _ time.Time) (int64, error) {
		if ip != "203.0.113.10" {
			t.Errorf("unexpected ip %q", ip)
		}
		return 3, nil
	})
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}
	d := s.applyNATGuard(context.Background(), b, now)
	if d == nil {
		t.Fatal("expected downgrade for shared egress suspect")
	}
	want := now.Add(DefaultNATBlockMinutes * time.Minute)
	if !b.BlockExpiresAt.Equal(want) || !d.DowngradedExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want capped %v", b.BlockExpiresAt, want)
	}
	if !d.OriginalExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("original expiry not recorded: %v", d.OriginalExpiresAt)
	}
	if d.IdentityCount != 3 || d.IdentityThreshold != DefaultNATIdentityThreshold || d.Reason != natDowngradeReason {
		t.Errorf("unexpected detail: %+v", d)
	}
}

// TestApplyNATGuardBelowThreshold 身份数未达阈不降档（阈值边界：n == threshold-1）。
func TestApplyNATGuardBelowThreshold(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{},
		func(context.Context, string, time.Time) (int64, error) { return DefaultNATIdentityThreshold - 1, nil })
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}
	if d := s.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("below threshold: expected no downgrade")
	}
}

// TestApplyNATGuardNoExtend 原时长已短于降档上限时不延长（降档只缩短不延长）。
func TestApplyNATGuardNoExtend(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{},
		func(context.Context, string, time.Time) (int64, error) { return 100, nil })
	short := now.Add(5 * time.Minute)
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: short}
	if d := s.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("original duration shorter than cap: expected no downgrade")
	}
	if !b.BlockExpiresAt.Equal(short) {
		t.Error("expiry must not be extended by downgrade")
	}
}

// TestApplyNATGuardInvalidSettingsFallback 非法设置值回落默认（阈值 0、时长 0/超界）。
func TestApplyNATGuardInvalidSettingsFallback(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{ints: map[string]int{
		"cc_auto_block:nat_identity_threshold": 0,
		"cc_auto_block:nat_block_minutes":      2000,
	}}, func(context.Context, string, time.Time) (int64, error) { return 2, nil })
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}
	d := s.applyNATGuard(context.Background(), b, now)
	if d == nil {
		t.Fatal("invalid settings should fall back to defaults (threshold 2, 15min)")
	}
	if d.IdentityThreshold != DefaultNATIdentityThreshold || d.BlockMinutes != DefaultNATBlockMinutes {
		t.Errorf("fallback values wrong: %+v", d)
	}
	if want := now.Add(DefaultNATBlockMinutes * time.Minute); !b.BlockExpiresAt.Equal(want) {
		t.Errorf("expiry = %v, want default cap %v", b.BlockExpiresAt, want)
	}
}

// TestApplyNATGuardCounterError 身份数查询失败不误判共享出口：按原样封禁（错误由
// 实现侧 slog.Error 记录，不静默）。
func TestApplyNATGuardCounterError(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{},
		func(context.Context, string, time.Time) (int64, error) { return 0, errors.New("db down") })
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}
	if d := s.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("counter error: expected no downgrade (keep original block)")
	}
	if !b.BlockExpiresAt.Equal(now.Add(time.Hour)) {
		t.Error("expiry must remain untouched on counter error")
	}
}

// TestApplyNATGuardCustomThreshold 自定义阈值生效（阈值 5、身份数 3 不降档）。
func TestApplyNATGuardCustomThreshold(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	s := natTestStore(fakeSettingsReader{ints: map[string]int{
		"cc_auto_block:nat_identity_threshold": 5,
	}}, func(context.Context, string, time.Time) (int64, error) { return 3, nil })
	b := &Block{ClientIP: "203.0.113.10", BlockExpiresAt: now.Add(time.Hour)}
	if d := s.applyNATGuard(context.Background(), b, now); d != nil {
		t.Error("count 3 < threshold 5: expected no downgrade")
	}
}
