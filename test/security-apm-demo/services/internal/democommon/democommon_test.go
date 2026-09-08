package democommon

import (
	"strconv"
	"testing"
)

func TestParseScenarioDisabledIgnoresEverything(t *testing.T) {
	for _, in := range []string{"", "slow-sql", "exception", "'; DROP TABLE x;--", "NORMAL"} {
		got, ok := ParseScenario(false, in)
		if !ok || got != ScenarioNormal {
			t.Errorf("ParseScenario(false, %q) = %q,%v；开关关闭时必须忽略输入并返回 normal", in, got, ok)
		}
	}
}

func TestParseScenarioEnabledWhitelist(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", ScenarioNormal, true},
		{"normal", ScenarioNormal, true},
		{"slow-sql", ScenarioSlowSQL, true},
		{"exception", ScenarioException, true},
		{"SLOW-SQL", "", false},          // 大小写不放宽
		{"slow_sql", "", false},          // 近形不放宽
		{"rm -rf /", "", false},          // 命令注入尝试拒绝
		{"http://evil.example", "", false}, // 外部 URL 拒绝
	}
	for _, c := range cases {
		got, ok := ParseScenario(true, c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseScenario(true, %q) = %q,%v，期望 %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidDemoRequestID(t *testing.T) {
	valid := []string{"a", "run1-0001", "A_9-z", "d20260907-abc123"}
	for _, v := range valid {
		if !ValidDemoRequestID(v) {
			t.Errorf("ValidDemoRequestID(%q) = false，期望 true", v)
		}
	}
	long65 := "a"
	for len(long65) < 65 {
		long65 += "b"
	}
	invalid := []string{"", "-lead", "has space", "有中文", "semi;colon", long65, "'or'1'='1"}
	for _, v := range invalid {
		if ValidDemoRequestID(v) {
			t.Errorf("ValidDemoRequestID(%q) = true，期望 false", v)
		}
	}
}

func TestParseItemIDBounds(t *testing.T) {
	if _, ok := ParseItemID(""); ok {
		t.Error("空 id 应拒绝")
	}
	for _, in := range []string{"0", "-1", "101", "99999999999999999999", "1.5", "abc", "1 OR 1=1"} {
		if _, ok := ParseItemID(in); ok {
			t.Errorf("ParseItemID(%q) 应拒绝（允许区间 %d..%d）", in, ItemIDMin, ItemIDMax)
		}
	}
	for _, n := range []int{ItemIDMin, 50, ItemIDMax} {
		got, ok := ParseItemID(strconv.Itoa(n))
		if !ok || got != n {
			t.Errorf("ParseItemID(%d) = %d,%v，期望 %d,true", n, got, ok, n)
		}
	}
}

func TestTelemetryDisabled(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"", false},
		{"false", false},
		{"TRUE", false}, // 大小写不放宽，与 ScenariosEnabled 同口径
		{"1", false},
	}
	for _, c := range cases {
		got := TelemetryDisabled(func(string) string { return c.val })
		if got != c.want {
			t.Errorf("TelemetryDisabled(%q) = %v，期望 %v", c.val, got, c.want)
		}
	}
}
