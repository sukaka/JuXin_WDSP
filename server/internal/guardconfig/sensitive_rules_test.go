package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeSensitiveValueRuleLister 内存版值级敏感规则读取（可注入错误路径）。
type fakeSensitiveValueRuleLister struct {
	rules []gatewayconfig.GuardSensitiveValueRule
	err   error
}

func (f *fakeSensitiveValueRuleLister) ListEnabledSensitiveValueRules(ctx context.Context) ([]gatewayconfig.GuardSensitiveValueRule, error) {
	_ = ctx
	return f.rules, f.err
}

// TestLoadAPISensitiveValueRulesTolerance 值级敏感规则：未注入 nil；查询失败（如 000040 表未建立）
// Warn 跳过返回 nil；空规则不下发；正常读取透传。
func TestLoadAPISensitiveValueRulesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPISensitiveValueRules(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过
	p = &Provider{sensitiveValueRules: &fakeSensitiveValueRuleLister{err: errors.New(`relation "api_sensitive_data_types" does not exist`)}}
	if got := p.loadAPISensitiveValueRules(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空规则 → 不下发
	p = &Provider{sensitiveValueRules: &fakeSensitiveValueRuleLister{rules: []gatewayconfig.GuardSensitiveValueRule{}}}
	if got := p.loadAPISensitiveValueRules(context.Background()); got != nil {
		t.Fatalf("empty rules must yield nil: %v", got)
	}
	// 正常读取（含 exclude_fields 透传）
	want := []gatewayconfig.GuardSensitiveValueRule{
		{
			DataType: "phone", Regex: `^1[3-9]\d{9}$`,
			Locations:     []string{"query", "json", "form", "xml", "response_body"},
			Level:         "SENSITIVE",
			ExcludeFields: []string{"phone_verified", "has_phone"},
		},
	}
	p = &Provider{sensitiveValueRules: &fakeSensitiveValueRuleLister{rules: want}}
	got := p.loadAPISensitiveValueRules(context.Background())
	if len(got) != 1 || got[0].DataType != "phone" || got[0].Level != "SENSITIVE" || len(got[0].Locations) != 5 || len(got[0].ExcludeFields) != 2 {
		t.Fatalf("rules = %+v", got)
	}
}
