// api_security_test.go API 安全组件探针状态判定单测（纯逻辑，不依赖 PG）。
package runtimehealth

import (
	"testing"
	"time"
)

// TestAPISecurityStatus 由最近事件时间判定链路状态：
// 无事件 UNKNOWN；停滞超阈值 DEGRADED；新鲜 UP；未来时间（时钟回拨）按 0 停滞处理。
func TestAPISecurityStatus(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	threshold := 10 * time.Minute

	// 从未有事件
	status, stale, msg := apiSecurityStatus(nil, now, threshold)
	if status != StatusUnknown || stale != 0 || msg == "" {
		t.Errorf("无事件 = %s/%v/%q, want UNKNOWN/0/非空消息", status, stale, msg)
	}

	// 新鲜事件
	last := now.Add(-time.Minute)
	status, stale, msg = apiSecurityStatus(&last, now, threshold)
	if status != StatusUp || stale != 60 || msg == "" {
		t.Errorf("新鲜事件 = %s/%v/%q, want UP/60/非空消息", status, stale, msg)
	}

	// 停滞超阈值
	last = now.Add(-30 * time.Minute)
	status, stale, msg = apiSecurityStatus(&last, now, threshold)
	if status != StatusDegraded || stale != 1800 || msg == "" {
		t.Errorf("停滞事件 = %s/%v/%q, want DEGRADED/1800/非空消息", status, stale, msg)
	}

	// 边界：恰好等于阈值不降级
	last = now.Add(-threshold)
	status, _, _ = apiSecurityStatus(&last, now, threshold)
	if status != StatusUp {
		t.Errorf("阈值边界 = %s, want UP", status)
	}

	// 未来时间（跨节点时钟差）：停滞按 0，不误报
	last = now.Add(time.Minute)
	status, stale, _ = apiSecurityStatus(&last, now, threshold)
	if status != StatusUp || stale != 0 {
		t.Errorf("未来事件 = %s/%v, want UP/0", status, stale)
	}
}

// TestAllComponentsIncludesAPISecurity 新组件纳入组件清单（missing 计算与汇总依赖）。
func TestAllComponentsIncludesAPISecurity(t *testing.T) {
	for _, comp := range AllComponents() {
		if comp == ComponentAPISecurity {
			return
		}
	}
	t.Errorf("AllComponents() 缺少 %s", ComponentAPISecurity)
}
