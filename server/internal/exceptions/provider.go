package exceptions

import (
	"context"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// GetEnabledExceptions 返回当前启用例外的 SecLang 规则（供配置生成器下发到网关）。
// 例外 ID 使用 8000000+ 段（与自定义规则 7100000+ 区分）。
func (s *Store) GetEnabledExceptions(ctx context.Context) ([]gatewayconfig.ExceptionRule, error) {
	list, _, err := s.List(ctx, "", "ENABLED", 1, 1000)
	if err != nil {
		return nil, err
	}
	var out []gatewayconfig.ExceptionRule
	baseID := 8000001
	now := time.Now()
	for _, e := range list {
		// 临时例外：过期的不下发
		if e.IsTemporary && e.EffectiveUntil != nil && e.EffectiveUntil.Before(now) {
			continue
		}
		// 未到生效时间的不下发
		if e.EffectiveFrom != nil && e.EffectiveFrom.After(now) {
			continue
		}
		secLang := GenerateSecLang(&e, baseID)
		out = append(out, gatewayconfig.ExceptionRule{
			RuleID:  baseID,
			SecLang: secLang,
		})
		baseID++
	}
	return out, nil
}
