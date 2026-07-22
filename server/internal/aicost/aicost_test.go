package aicost

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestDefaultQuotas 默认配额值（与产品设计一致）。
func TestDefaultQuotas(t *testing.T) {
	q := DefaultQuotas()
	want := Quotas{
		UserDailyTokens: 200000, RoleDailyTokens: 500000, PerRequestTokens: 12000,
		MaxToolCalls: 20, ConcurrentTasks: 10, HighCostTaskDaily: 20,
	}
	if q != want {
		t.Errorf("DefaultQuotas() = %+v, want %+v", q, want)
	}
}

// TestCheckQuotaPerRequestLimit 单次输入超限直接拒绝（纯逻辑，无需数据库）。
// 注：未超限后的用户/角色日配额统计需访问数据库，不在纯单元测试范围内。
func TestCheckQuotaPerRequestLimit(t *testing.T) {
	r := NewRecorder(nil, DefaultQuotas())
	err := r.CheckQuota(context.Background(), uuid.New(), "admin", 12001)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("err = %v, want ErrQuotaExceeded", err)
	}
	// 自定义配额的边界：limit+1 拒绝
	r2 := NewRecorder(nil, Quotas{PerRequestTokens: 100})
	err2 := r2.CheckQuota(context.Background(), uuid.New(), "admin", 101)
	if !errors.Is(err2, ErrQuotaExceeded) {
		t.Errorf("err = %v, want ErrQuotaExceeded", err2)
	}
	// 错误信息包含具体数值便于排查
	if !strings.Contains(err2.Error(), "101 > limit 100") {
		t.Errorf("err = %q, 应包含超限数值", err2)
	}
}
