package aicost

import (
	"context"
	"errors"
	"reflect"
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
		HighCostTaskTokens: 20000, HighCostTaskTypes: DefaultHighCostTaskTypes(),
	}
	if !reflect.DeepEqual(q, want) {
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

// TestCheckQuotaNilDBFailsClosed 配额存储未装配/不可用时拒绝放行（fail-closed）：
// 用量查询失败不得按 0 用量静默通过（本地 LLM 成本的唯一服务端闸门）。
func TestCheckQuotaNilDBFailsClosed(t *testing.T) {
	r := NewRecorder(nil, DefaultQuotas())
	err := r.CheckQuota(context.Background(), uuid.New(), "admin", 100)
	if err == nil {
		t.Fatal("db 为 nil 时 CheckQuota 应返回错误，不得静默放行")
	}
	if errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("err = %v, 存储不可用不应误报为配额超限（避免前端误导为 429）", err)
	}
}

// TestIsHighCostTask 高成本任务判定口径：类型名单命中，或 Token 估算达到阈值。
func TestIsHighCostTask(t *testing.T) {
	r := NewRecorder(nil, DefaultQuotas())
	cases := []struct {
		name     string
		taskType string
		tokens   int
		want     bool
	}{
		{"名单内类型（多Agent重分析）", "ROOT_CAUSE_ANALYSIS", 100, true},
		{"名单内类型（What-If模拟）", "WHAT_IF_ANALYSIS", 100, true},
		{"轻量类型未达阈值", "GENERAL_SECURITY_QA", 100, false},
		{"轻量类型达到Token阈值", "GENERAL_SECURITY_QA", 20000, true},
		{"轻量类型恰好低于阈值", "EVENT_ANALYSIS", 19999, false},
		{"未知类型", "NO_SUCH_TYPE", 100, false},
	}
	for _, c := range cases {
		if got := r.IsHighCostTask(c.taskType, c.tokens); got != c.want {
			t.Errorf("%s: IsHighCostTask(%q, %d) = %v, want %v", c.name, c.taskType, c.tokens, got, c.want)
		}
	}
	// Token 口径关闭（≤0）时仅凭名单判定
	r2 := NewRecorder(nil, Quotas{HighCostTaskTokens: 0, HighCostTaskTypes: []string{"ATTACK_CHAIN"}})
	if r2.IsHighCostTask("GENERAL_SECURITY_QA", 999999) {
		t.Error("Token 口径关闭后不应因 Token 数判定高成本")
	}
	if !r2.IsHighCostTask("ATTACK_CHAIN", 1) {
		t.Error("名单内类型应判定为高成本")
	}
	// 名单为空时关闭类型口径
	r3 := NewRecorder(nil, Quotas{HighCostTaskTokens: 20000})
	if r3.IsHighCostTask("ROOT_CAUSE_ANALYSIS", 100) {
		t.Error("名单为空时不应因类型判定高成本")
	}
}

// TestCheckHighCostQuotaDisabled 上限 ≤0 表示不限制（无需访问数据库）。
func TestCheckHighCostQuotaDisabled(t *testing.T) {
	r := NewRecorder(nil, Quotas{HighCostTaskDaily: 0})
	if err := r.CheckHighCostQuota(context.Background(), uuid.New()); err != nil {
		t.Errorf("上限为 0 时应放行, got %v", err)
	}
}

// TestCheckHighCostQuotaNilDBFailsClosed 配额存储未装配/不可用时拒绝放行（fail-closed）：
// 与 CheckQuota 同一安全纪律，DB 抖动不得按 0 次静默通过。
func TestCheckHighCostQuotaNilDBFailsClosed(t *testing.T) {
	r := NewRecorder(nil, DefaultQuotas())
	err := r.CheckHighCostQuota(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("db 为 nil 时 CheckHighCostQuota 应返回错误，不得静默放行")
	}
	if errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("err = %v, 存储不可用不应误报为配额超限（避免前端误导为 429）", err)
	}
}
