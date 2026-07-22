// Package accesscontrol IP黑白名单规则评估（全局/应用分层，显式优先级，临时到期）。
package accesscontrol

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
)

// Action 执行动作。
type Action string

const (
	ActionNone  Action = "NONE"
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

// Rule 一条访问控制规则（白或黑，由所在层决定）。
type Rule struct {
	ID             string
	Address        string // 原始输入（日志用）
	Prefix         netip.Prefix
	Priority       int        // 数值小者优先
	EffectiveFrom  *time.Time // nil 立即生效
	EffectiveUntil *time.Time // nil 永久
}

// RuleSet 同层规则集合（按优先级升序）。
type RuleSet struct {
	rules   []Rule
	matcher *cidr.Matcher
}

// NewRuleSet 构建规则集合。
func NewRuleSet(rules []Rule) (*RuleSet, error) {
	if len(rules) > 200000 {
		return nil, fmt.Errorf("too many rules: %d", len(rules))
	}
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	for i := range cp {
		if !cp[i].Prefix.IsValid() {
			return nil, fmt.Errorf("rule %q: invalid address", cp[i].ID)
		}
	}
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Priority < cp[j].Priority })
	entries := make([]cidr.Entry, len(cp))
	for i, r := range cp {
		entries[i] = cidr.Entry{Prefix: r.Prefix, Meta: r.ID}
	}
	return &RuleSet{rules: cp, matcher: cidr.NewMatcher(entries)}, nil
}

// active 规则在给定时间是否生效。
func (r Rule) active(now time.Time) bool {
	if r.EffectiveFrom != nil && now.Before(*r.EffectiveFrom) {
		return false
	}
	if r.EffectiveUntil != nil && !now.Before(*r.EffectiveUntil) {
		return false
	}
	return true
}

// Decision 评估结果。
type Decision struct {
	Action         Action
	RuleID         string   // 最终决定规则
	MatchedRuleIDs []string // 全部匹配（审计用）
}

// Match 单层评估：返回命中的最高优先级生效规则。
func (s *RuleSet) Match(ip netip.Addr, now time.Time) Decision {
	if s == nil {
		return Decision{Action: ActionNone}
	}
	idx := s.matcher.Match(ip)
	if len(idx) == 0 {
		return Decision{Action: ActionNone}
	}
	// 按优先级取第一个生效规则（rules 已按优先级排序，下标小者优先）
	sort.Ints(idx)
	d := Decision{Action: ActionNone}
	for _, i := range idx {
		r := s.rules[i]
		if !r.active(now) {
			continue
		}
		d.MatchedRuleIDs = append(d.MatchedRuleIDs, r.ID)
	}
	if len(d.MatchedRuleIDs) > 0 {
		d.RuleID = d.MatchedRuleIDs[0]
	}
	return d
}

// Evaluate 分层评估：全局白 → 应用白 → 全局黑 → 应用黑。
// 第一层命中即决定最终动作（记录全部匹配）。
func Evaluate(ip netip.Addr, now time.Time, globalAllow, appAllow, globalDeny, appDeny *RuleSet) Decision {
	if d := globalAllow.Match(ip, now); d.RuleID != "" {
		d.Action = ActionAllow
		return d
	}
	if d := appAllow.Match(ip, now); d.RuleID != "" {
		d.Action = ActionAllow
		return d
	}
	if d := globalDeny.Match(ip, now); d.RuleID != "" {
		d.Action = ActionDeny
		return d
	}
	if d := appDeny.Match(ip, now); d.RuleID != "" {
		d.Action = ActionDeny
		return d
	}
	return Decision{Action: ActionNone}
}
