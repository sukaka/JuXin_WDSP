// Package urlwhitelist 提供 URL 白名单规则评估（全局/应用分层，显式优先级，临时到期）。
// 与 IP 白名单处于同一访问控制放行层：命中后跳过 IP 黑名单、L7 访问控制、
// 自动临时封禁、身份风险策略、授权全局限速与 CC，但不绕过人工临时封禁、
// 身份手工封禁、Bot 挑战、API 动态防护、JWT PROTECT 与 WAF（安全底线）。
package urlwhitelist

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// 匹配方式。
const (
	MatchExact  = "EXACT"
	MatchPrefix = "PREFIX"
	MatchRegex  = "REGEX"
)

// 最大规则数与正则/模式长度上限（防配置膨胀与正则编译开销）。
const (
	MaxRules      = 20000
	MaxPatternLen = 512
)

// Rule 是一条 URL 白名单规则。
type Rule struct {
	ID             string
	MatchType      string     // EXACT | PREFIX | REGEX
	URIPattern     string     // 规范路径（EXACT/PREFIX）或 RE2 正则（REGEX）
	Methods        []string   // 空表示匹配全部 HTTP 方法；非空按大写精确匹配
	Priority       int        // 数值小者优先
	EffectiveFrom  *time.Time // nil 立即生效
	EffectiveUntil *time.Time // nil 永久
}

type compiledRule struct {
	rule    Rule
	pattern string
	methods map[string]bool
	re      *regexp.Regexp
}

// RuleSet 同层 URL 白名单集合（按优先级升序）。
type RuleSet struct {
	rules []compiledRule
}

// NewRuleSet 构建并校验 URL 白名单集合（fail-closed：非法匹配方式、空模式或非法正则拒绝加载）。
func NewRuleSet(rules []Rule) (*RuleSet, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("too many url whitelist rules: %d", len(rules))
	}
	if len(rules) == 0 {
		return &RuleSet{}, nil
	}
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Priority < cp[j].Priority })

	compiled := make([]compiledRule, 0, len(cp))
	for _, r := range cp {
		if r.ID == "" {
			return nil, fmt.Errorf("url whitelist rule missing id")
		}
		mt := strings.ToUpper(strings.TrimSpace(r.MatchType))
		pat := strings.TrimSpace(r.URIPattern)
		if pat == "" {
			return nil, fmt.Errorf("url whitelist rule %q: empty uri_pattern", r.ID)
		}
		if len(pat) > MaxPatternLen {
			return nil, fmt.Errorf("url whitelist rule %q: uri_pattern too long", r.ID)
		}
		cr := compiledRule{rule: r}
		cr.rule.MatchType = mt
		switch mt {
		case MatchExact, MatchPrefix:
			if !strings.HasPrefix(pat, "/") {
				return nil, fmt.Errorf("url whitelist rule %q: uri_pattern must start with /", r.ID)
			}
			if strings.Contains(pat, "?") {
				return nil, fmt.Errorf("url whitelist rule %q: uri_pattern must not contain query string", r.ID)
			}
			cr.pattern = normalizer.CanonicalPath(pat)
			// 保留前缀末尾斜杠语义（如 "/static/" 仅匹配目录内子路径）
			if mt == MatchPrefix && strings.HasSuffix(pat, "/") && !strings.HasSuffix(cr.pattern, "/") {
				cr.pattern += "/"
			}
		case MatchRegex:
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("url whitelist rule %q: invalid regex: %w", r.ID, err)
			}
			cr.pattern = pat
			cr.re = re
		default:
			return nil, fmt.Errorf("url whitelist rule %q: unknown match_type %q", r.ID, r.MatchType)
		}
		if len(r.Methods) > 0 {
			cr.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				u := strings.ToUpper(strings.TrimSpace(m))
				if u != "" {
					cr.methods[u] = true
				}
			}
		}
		compiled = append(compiled, cr)
	}
	return &RuleSet{rules: compiled}, nil
}

// Decision 评估结果。
type Decision struct {
	Matched        bool
	RuleID         string
	MatchedRuleIDs []string
}

func (r compiledRule) active(now time.Time) bool {
	if r.rule.EffectiveFrom != nil && now.Before(*r.rule.EffectiveFrom) {
		return false
	}
	if r.rule.EffectiveUntil != nil && !now.Before(*r.rule.EffectiveUntil) {
		return false
	}
	return true
}

func (r compiledRule) matchMethod(method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	return r.methods[strings.ToUpper(strings.TrimSpace(method))]
}

func (r compiledRule) matchPath(canonicalPath string) bool {
	switch r.rule.MatchType {
	case MatchExact:
		return canonicalPath == r.pattern
	case MatchPrefix:
		if r.pattern == "/" {
			return strings.HasPrefix(canonicalPath, "/")
		}
		if strings.HasSuffix(r.pattern, "/") {
			return strings.HasPrefix(canonicalPath, r.pattern)
		}
		// 路径段边界匹配：/api 匹配 /api 与 /api/...，不误放 /api-admin
		return canonicalPath == r.pattern || strings.HasPrefix(canonicalPath, r.pattern+"/")
	case MatchRegex:
		return r.re != nil && r.re.MatchString(canonicalPath)
	default:
		return false
	}
}

// Match 单层评估：对规范化路径（不含 query）与 HTTP 方法评估，返回命中的最高优先级规则。
func (s *RuleSet) Match(rawPath, method string, now time.Time) Decision {
	if s == nil || len(s.rules) == 0 {
		return Decision{}
	}
	canonicalPath := normalizer.CanonicalPath(rawPath)
	var d Decision
	for _, r := range s.rules {
		if !r.active(now) {
			continue
		}
		if !r.matchMethod(method) {
			continue
		}
		if !r.matchPath(canonicalPath) {
			continue
		}
		d.MatchedRuleIDs = append(d.MatchedRuleIDs, r.rule.ID)
	}
	if len(d.MatchedRuleIDs) > 0 {
		d.Matched = true
		d.RuleID = d.MatchedRuleIDs[0]
	}
	return d
}

// Evaluate 分层评估：全局 URL 白名单 → 应用 URL 白名单。
func Evaluate(rawPath, method string, now time.Time, globalAllow, appAllow *RuleSet) Decision {
	if d := globalAllow.Match(rawPath, method, now); d.Matched {
		return d
	}
	if d := appAllow.Match(rawPath, method, now); d.Matched {
		return d
	}
	return Decision{}
}
