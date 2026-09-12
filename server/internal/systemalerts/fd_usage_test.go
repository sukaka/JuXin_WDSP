package systemalerts

import "testing"

// TestFDUsageHighRuleRegistered 文件句柄使用率告警类型注册（阶段6 §10.2：
// FD_USAGE_HIGH=HIGH，参照 DISK_SPACE_LOW 档；阈值判级在 runtimehealth 采集器）。
func TestFDUsageHighRuleRegistered(t *testing.T) {
	if !IsValidType(TypeFDUsageHigh) {
		t.Error("FD_USAGE_HIGH 应为合法类型")
	}
	if got := SeverityFor(TypeFDUsageHigh); got != SeverityHigh {
		t.Errorf("FD_USAGE_HIGH 等级 = %s，期望 %s", got, SeverityHigh)
	}
}
