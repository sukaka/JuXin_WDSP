package accesscontrol

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
)

func rule(t *testing.T, id, addr string, prio int, from, until *time.Time) Rule {
	t.Helper()
	p, err := cidr.ParseAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	return Rule{ID: id, Address: addr, Prefix: p, Priority: prio, EffectiveFrom: from, EffectiveUntil: until}
}

func rset(t *testing.T, rules ...Rule) *RuleSet {
	t.Helper()
	s, err := NewRuleSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ip(t *testing.T, s string) netip.Addr {
	t.Helper()
	v, err := cidr.ParseIP(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLayerPriority(t *testing.T) {
	now := time.Now()
	ga := rset(t, rule(t, "ga1", "10.0.0.0/8", 100, nil, nil))
	gd := rset(t, rule(t, "gd1", "10.0.0.0/8", 1, nil, nil))
	// 全局白 > 全局黑，即使黑名单优先级数值更小
	d := Evaluate(ip(t, "10.1.1.1"), now, ga, nil, gd, nil)
	if d.Action != ActionAllow || d.RuleID != "ga1" {
		t.Errorf("global allow should win over global deny: %+v", d)
	}
}

func TestAppLayer(t *testing.T) {
	now := time.Now()
	ad := rset(t, rule(t, "ad1", "10.1.1.1", 100, nil, nil))
	aa := rset(t, rule(t, "aa1", "10.1.1.1", 200, nil, nil))
	// 应用白 > 全局黑（无全局黑），应用白 vs 应用黑：白先评估
	d := Evaluate(ip(t, "10.1.1.1"), now, nil, aa, nil, ad)
	if d.Action != ActionAllow {
		t.Errorf("app allow should win: %+v", d)
	}
	d = Evaluate(ip(t, "10.1.1.1"), now, nil, nil, nil, ad)
	if d.Action != ActionDeny || d.RuleID != "ad1" {
		t.Errorf("app deny: %+v", d)
	}
}

func TestInLayerPriority(t *testing.T) {
	now := time.Now()
	gd := rset(t,
		rule(t, "broad", "10.0.0.0/8", 100, nil, nil),
		rule(t, "specific", "10.1.1.1", 10, nil, nil),
	)
	d := gd.Match(ip(t, "10.1.1.1"), now)
	if d.RuleID != "specific" || len(d.MatchedRuleIDs) != 2 {
		t.Errorf("in-layer priority: %+v", d)
	}
}

func TestTemporaryExpiry(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	now := time.Now()
	s := rset(t, rule(t, "temp", "10.1.1.1", 1, &past, &future))
	if d := s.Match(ip(t, "10.1.1.1"), now); d.RuleID != "temp" {
		t.Errorf("temp rule should be active: %+v", d)
	}
	if d := s.Match(ip(t, "10.1.1.1"), future.Add(time.Minute)); d.RuleID != "" {
		t.Errorf("temp rule should expire: %+v", d)
	}
	// 未到生效时间
	notYet := time.Now().Add(time.Hour)
	s2 := rset(t, rule(t, "future", "10.1.1.1", 1, &notYet, nil))
	if d := s2.Match(ip(t, "10.1.1.1"), now); d.RuleID != "" {
		t.Errorf("future rule should not be active: %+v", d)
	}
}

func TestCIDRv6(t *testing.T) {
	now := time.Now()
	gd := rset(t, rule(t, "v6", "2001:db8::/32", 1, nil, nil))
	if d := gd.Match(ip(t, "2001:db8::1234"), now); d.RuleID != "v6" {
		t.Errorf("v6 cidr: %+v", d)
	}
	if d := gd.Match(ip(t, "2001:db9::1"), now); d.RuleID != "" {
		t.Errorf("v6 miss: %+v", d)
	}
}
