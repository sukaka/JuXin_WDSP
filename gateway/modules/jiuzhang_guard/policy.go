package jiuzhang_guard

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/accesscontrol"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
)

// compiledPolicy 编译后的 CC 策略。
type compiledPolicy struct {
	cfg   policyJSON
	uriRe *regexp.Regexp
	from  *time.Time
	until *time.Time
}

// buildRuleSet 解析规则 JSON。
func buildRuleSet(rules []ruleJSON) (*accesscontrol.RuleSet, error) {
	out := make([]accesscontrol.Rule, 0, len(rules))
	for _, r := range rules {
		pfx, err := cidr.ParseAddress(r.Address)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		rule := accesscontrol.Rule{
			ID:       r.ID,
			Address:  r.Address,
			Prefix:   pfx,
			Priority: r.Priority,
		}
		if r.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_from", r.ID)
			}
			rule.EffectiveFrom = &t
		}
		if r.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_until", r.ID)
			}
			rule.EffectiveUntil = &t
		}
		out = append(out, rule)
	}
	return accesscontrol.NewRuleSet(out)
}

// maxURIPatternLen 正则/模式长度上限（配合 RE2 线性时间引擎防正则拒绝服务）。
const maxURIPatternLen = 256

// compilePolicies 编译 CC 策略（优先级升序）。
func compilePolicies(in []policyJSON) ([]*compiledPolicy, error) {
	out := make([]*compiledPolicy, 0, len(in))
	for _, p := range in {
		cp := &compiledPolicy{cfg: p}
		switch p.Dimension {
		case "CLIENT_IP", "APPLICATION", "CLIENT_IP_AND_URI", "CLIENT_IP_AND_APPLICATION":
		default:
			return nil, fmt.Errorf("policy %q: unknown dimension %q", p.ID, p.Dimension)
		}
		switch p.Algorithm {
		case string(ratelimit.TokenBucket), string(ratelimit.SlidingWindow):
		default:
			return nil, fmt.Errorf("policy %q: unknown algorithm %q", p.ID, p.Algorithm)
		}
		switch p.Action {
		case "LOG", "OBSERVE", "REJECT", "TEMP_BLOCK":
		default:
			return nil, fmt.Errorf("policy %q: unknown action %q", p.ID, p.Action)
		}
		if p.Action == "TEMP_BLOCK" && p.BlockDurationSeconds <= 0 {
			return nil, fmt.Errorf("policy %q: block_duration required for TEMP_BLOCK", p.ID)
		}
		if len(p.URIPattern) > maxURIPatternLen {
			return nil, fmt.Errorf("policy %q: uri_pattern too long", p.ID)
		}
		switch p.URIMatchType {
		case "", "ALL":
		case "EXACT", "PREFIX":
			if p.URIPattern == "" {
				return nil, fmt.Errorf("policy %q: uri_pattern required", p.ID)
			}
		case "REGEX":
			re, err := regexp.Compile(p.URIPattern)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad regex: %w", p.ID, err)
			}
			cp.uriRe = re
		default:
			return nil, fmt.Errorf("policy %q: unknown uri_match_type %q", p.ID, p.URIMatchType)
		}
		if p.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_from", p.ID)
			}
			cp.from = &t
		}
		if p.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_until", p.ID)
			}
			cp.until = &t
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cfg.Priority < out[j].cfg.Priority })
	return out, nil
}

// matchURI URI 匹配（对请求路径与 EXACT/PREFIX 规则模式统一执行规范化，防止 '//'/'.'/'..' 绕过）。
func (p *compiledPolicy) matchURI(path string) bool {
	canonPath := normalizer.CanonicalPath(path)
	switch p.cfg.URIMatchType {
	case "", "ALL":
		return true
	case "EXACT":
		return canonPath == normalizer.CanonicalPath(p.cfg.URIPattern)
	case "PREFIX":
		return strings.HasPrefix(canonPath, normalizer.CanonicalPath(p.cfg.URIPattern))
	case "REGEX":
		return p.uriRe.MatchString(canonPath)
	}
	return false
}

// dimensionKey 按限速维度生成键（哈希化，禁止拼接原始输入）。
// CLIENT_IP_AND_URI 使用策略的 URI 模式而非具体路径：
// 策略本身即 URI 分组，用具体路径会导致随机 URI 绕过与键爆炸。
func (p *compiledPolicy) dimensionKey(clientIP netip.Addr, appID string) string {
	switch p.cfg.Dimension {
	case "CLIENT_IP":
		return counters.HashParts("ip", clientIP.String())
	case "APPLICATION":
		return counters.HashParts("app", appID)
	case "CLIENT_IP_AND_URI":
		pattern := p.cfg.URIPattern
		if pattern == "" {
			pattern = "*"
		}
		return counters.HashParts("ipuri", clientIP.String(), pattern)
	case "CLIENT_IP_AND_APPLICATION":
		return counters.HashParts("ipapp", clientIP.String(), appID)
	}
	return counters.HashParts("ip", clientIP.String())
}
