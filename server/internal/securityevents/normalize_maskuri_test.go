package securityevents

import (
	"strings"
	"testing"
)

// 回归（docs/evidence/code-review-2026-09-05 MED-2）：maskURI 比对前须先 URL 解码
// 参数名，pass%77ord= 等编码键不得绕过掩码导致敏感值明文入库。
func TestMaskURIEncodedParamName(t *testing.T) {
	cases := []struct{ name, in, wantNotContain, wantContain string }{
		{"encoded password key", "/p?pass%77ord=Secret123&a=1", "Secret123", "pass%77ord=masked"},
		{"encoded token key", "/p?%74oken=t123", "t123", "%74oken=masked"},
		{"mixed case encoded key", "/p?%50assword=Pw123", "Pw123", "%50assword=masked"},
	}
	for _, c := range cases {
		got := maskURI(c.in)
		if strings.Contains(got, c.wantNotContain) {
			t.Errorf("%s: maskURI(%q) = %q, still contains %q", c.name, c.in, got, c.wantNotContain)
		}
		if !strings.Contains(got, c.wantContain) {
			t.Errorf("%s: maskURI(%q) = %q, want %q", c.name, c.in, got, c.wantContain)
		}
	}
	// 非法 % 转义的键解码失败：保持原样不过掩（无法确证敏感）
	if got := maskURI("/p?pass%zzord=Secret123"); got != "/p?pass%zzord=Secret123" {
		t.Errorf("undecodable key should stay untouched, got %q", got)
	}
	// 无查询串与无等号分段不受影响
	if got := maskURI("/p"); got != "/p" {
		t.Errorf("path without query changed: %q", got)
	}
	if got := maskURI("/p?flag&token=t"); got != "/p?flag&token=masked" {
		t.Errorf("flag-only segment should pass through: %q", got)
	}
}

// 回归（批次3-C 新发现，与 MED-2 同根因）：splitURI 的查询摘要经 maskQuery 脱敏，
// 参数名同样须先 URL 解码再比对敏感名单，pass%77ord= 编码键不得绕过掩码进入
// query_summary 落库。
func TestMaskQueryEncodedParamName(t *testing.T) {
	cases := []struct{ name, in, wantNotContain, wantContain string }{
		{"encoded password key", "/p?pass%77ord=Secret123&a=1", "Secret123", "pass%77ord=masked"},
		{"encoded token key", "/p?%74oken=t123", "t123", "%74oken=masked"},
		{"mixed case encoded key", "/p?%50assword=Pw123", "Pw123", "%50assword=masked"},
	}
	for _, c := range cases {
		_, got := splitURI(c.in)
		if strings.Contains(got, c.wantNotContain) {
			t.Errorf("%s: splitURI(%q) query_summary = %q, still contains %q", c.name, c.in, got, c.wantNotContain)
		}
		if !strings.Contains(got, c.wantContain) {
			t.Errorf("%s: splitURI(%q) query_summary = %q, want %q", c.name, c.in, got, c.wantContain)
		}
	}
	// 非法 % 转义的键解码失败：保持原样不过掩
	if _, got := splitURI("/p?pass%zzord=Secret123"); got != "pass%zzord=Secret123" {
		t.Errorf("undecodable key should stay untouched, got %q", got)
	}
	// 常规未编码键不受影响
	if _, got := splitURI("/p?a=1&token=t"); got != "a=1&token=masked" {
		t.Errorf("plain keys mismatch: %q", got)
	}
}
