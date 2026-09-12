package systemalerts

import (
	"strings"
	"testing"
)

// TestCSVCellFormulaInjection CSV 导出防公式注入。
func TestCSVCellFormulaInjection(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"普通文本", "网关不可用", "网关不可用"},
		{"等号公式", "=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"加号公式", "+1+2", "'+1+2"},
		{"减号公式", "-2+3", "'-2+3"},
		{"at 公式", "@SUM(1)", "'@SUM(1)"},
		{"换行剥离", "line1\nline2\r", "line1 line2 "},
		{"含逗号引用", "a,b", `"a,b"`},
		{"含引号转义", `say "hi"`, `"say ""hi"""`},
		{"空串", "", ""},
	}
	for _, c := range cases {
		if got := csvCell(c.input); got != c.want {
			t.Errorf("%s: csvCell(%q) = %q，期望 %q", c.name, c.input, got, c.want)
		}
	}
	// 注入后的单元格必须以单引号开头
	for _, payload := range []string{"=1+1", "+1", "-1", "@x"} {
		if !strings.HasPrefix(csvCell(payload), "'") {
			t.Errorf("payload %q 未加防护前缀", payload)
		}
	}
}

// TestMarkFlapping 抖动标记幂等。
func TestMarkFlapping(t *testing.T) {
	msg := markFlapping("磁盘空间不足")
	if !strings.Contains(msg, "抖动") {
		t.Errorf("标记后应含\"抖动\"，实际 %q", msg)
	}
	if again := markFlapping(msg); again != msg {
		t.Errorf("重复标记应幂等，实际 %q", again)
	}
}
