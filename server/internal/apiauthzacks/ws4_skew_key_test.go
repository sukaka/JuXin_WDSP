package apiauthzacks

import (
	"context"
	"testing"
)

type legacyOnlySettings struct{}

func (legacyOnlySettings) GetInt(_ context.Context, group, key string, def int) int {
	if group == "authz" && key == "clock_skew_max_seconds" {
		return 180
	}
	return def
}

// TestClockSkewSettingKeyAlignedWithGatewayRuntime 验证：
// 1) 不再读取已废弃/不存在的 authz.clock_skew_max_seconds；
// 2) ClampClockSkewMax 将任意输入稳定夹紧到 [10, 300]。
func TestClockSkewSettingKeyAlignedWithGatewayRuntime(t *testing.T) {
	if ClockSkewSettingGroup != "gateway_runtime" || ClockSkewSettingKey != "authz_clock_skew_max_seconds" {
		t.Fatalf("unexpected clock skew setting key: %s.%s", ClockSkewSettingGroup, ClockSkewSettingKey)
	}
	h := NewHandler(&fakeAckStore{}, legacyOnlySettings{})
	if got := h.clockSkewMaxSeconds(context.Background()); got != DefaultClockSkewMaxSeconds {
		t.Fatalf("legacy authz.clock_skew_max_seconds should not override default 60, got %d", got)
	}
	if got := ClampClockSkewMax(1); got != 10 {
		t.Fatalf("ClampClockSkewMax(1) = %d, want 10", got)
	}
	if got := ClampClockSkewMax(999); got != 300 {
		t.Fatalf("ClampClockSkewMax(999) = %d, want 300", got)
	}
	if got := ClampClockSkewMax(120); got != 120 {
		t.Fatalf("ClampClockSkewMax(120) = %d, want 120", got)
	}
}
