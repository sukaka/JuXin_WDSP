package guardconfig

import (
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
)

// toGuardL7Rules 将 L7 规则转换为下发载荷（契约一 l7_rules 段）。
// 入参须已按 (priority, created_at) 升序（l7rules.Store.ListAllOrdered），此处保持顺序；
// 返回值恒非 nil 且 Rules 至少为空数组——发布空集时网关据此清空旧规则。
func toGuardL7Rules(rules []l7rules.Rule) *gatewayconfig.GuardL7Rules {
	out := &gatewayconfig.GuardL7Rules{Rules: []gatewayconfig.GuardL7Rule{}}
	for _, r := range rules {
		gr := gatewayconfig.GuardL7Rule{
			ID:         r.ID.String(),
			Name:       r.Name,
			Priority:   r.Priority,
			Enabled:    r.Enabled,
			Action:     r.Action,
			Conditions: make([]gatewayconfig.GuardL7Condition, 0, len(r.Conditions)),
			ActionConfig: gatewayconfig.GuardL7ActionConfig{
				Status:            r.ActionConfig.Status,
				Message:           r.ActionConfig.Message,
				RedirectURL:       r.ActionConfig.RedirectURL,
				RedirectStatus:    r.ActionConfig.RedirectStatus,
				PreservePathQuery: r.ActionConfig.PreservePathQuery,
				ContentType:       r.ActionConfig.ContentType,
				Body:              r.ActionConfig.Body,
			},
		}
		for _, c := range r.Conditions {
			gc := gatewayconfig.GuardL7Condition{
				Type:  c.Type,
				Name:  c.Name,
				Op:    c.Op,
				Value: c.Value,
			}
			if len(c.Values) > 0 {
				gc.Values = append([]string(nil), c.Values...)
			}
			gr.Conditions = append(gr.Conditions, gc)
		}
		out.Rules = append(out.Rules, gr)
	}
	return out
}
