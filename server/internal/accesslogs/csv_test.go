package accesslogs

import "testing"

// TestCSVEscape 导出转义回归（审查 HIGH-10）：= + - @ 开头的单元格须加 ' 前缀
// 防公式注入（domain/URI 攻击者可控），分隔符/引号/换行走 RFC4180 转义。
func TestCSVEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "shop.example.com", "shop.example.com"},
		{"formula =", "=1+1", "'=1+1"},
		{"formula +", "+1+1", "'+1+1"},
		{"formula -", "-2-3", "'-2-3"},
		{"formula @", "@SUM(A1)", "'@SUM(A1)"},
		{"comma", "a,b", `"a,b"`},
		{"quote", `a"b`, `"a""b"`},
		{"newline", "a\nb", "\"a\nb\""},
		{"formula with comma", "=cmd|'/c calc'!A1,b", `"'=cmd|'/c calc'!A1,b"`},
	}
	for _, c := range cases {
		if got := csvEscape(c.in); got != c.want {
			t.Errorf("%s: csvEscape(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
