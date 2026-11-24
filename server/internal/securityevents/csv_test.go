package securityevents

import (
	"strings"
	"testing"
	"time"
)

// TestCSVEscape 导出转义回归（审查 HIGH-10）：= + - @ \t \r 开头的单元格须加 ' 前缀
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
		{"formula tab", "\t=1", "'\t=1"},
		{"formula cr", "\r=1", "\"'\r=1\""},
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

func TestRenderExportCSV(t *testing.T) {
	ts := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	events := []Event{
		{
			OccurredAt:        ts,
			ClientIP:          "198.51.100.10",
			Domain:            "shop.example.com",
			Method:            "POST",
			URI:               "/api/login?q=1",
			AttackType:        "SQL_INJECTION",
			Severity:          "HIGH",
			AnomalyScore:      15,
			Action:            "BLOCK",
			ResponseStatus:    403,
			DispositionStatus: "CONFIRMED_ATTACK",
			RequestID:         "req-sec-1",
		},
		{
			OccurredAt:        ts,
			ClientIP:          "198.51.100.20",
			Domain:            "=evil.example.com",
			Method:            "GET",
			URI:               "/search?k=a,b",
			AttackType:        "FUTURE_ATTACK",
			Severity:          "CUSTOM_SEV",
			AnomalyScore:      0,
			Action:            "OBSERVE",
			ResponseStatus:    200,
			DispositionStatus: "UNPROCESSED",
			RequestID:         "req-sec-2",
		},
	}

	out := renderExportCSV(events)
	wantHeader := "\xef\xbb\xbf发生时间,客户端 IP,域名,请求方法,请求路径,攻击类型,严重级别,异常评分,动作,响应状态码,处置状态,请求 ID\n"
	if !strings.HasPrefix(out, wantHeader) {
		t.Fatalf("missing UTF-8 BOM or Chinese header: %q", out[:min(len(out), 120)])
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count=%d want 3", len(lines))
	}
	wantRow1 := "2026-11-24T09:00:00Z,198.51.100.10,shop.example.com,POST,/api/login?q=1,SQL注入,高,15,阻断,403,确认攻击,req-sec-1"
	if lines[1] != wantRow1 {
		t.Fatalf("row1 mismatch:\n got: %s\nwant: %s", lines[1], wantRow1)
	}
	wantRow2 := `2026-11-24T09:00:00Z,198.51.100.20,'=evil.example.com,GET,"/search?k=a,b",FUTURE_ATTACK,CUSTOM_SEV,0,观察,200,未处置,req-sec-2`
	if lines[2] != wantRow2 {
		t.Fatalf("row2 mismatch:\n got: %s\nwant: %s", lines[2], wantRow2)
	}

	// 校验自定义规则攻击类型词表全量覆盖
	for at := range customRuleAttackTypes {
		if _, ok := exportAttackTypeLabels[at]; !ok {
			t.Errorf("attack_type %q missing Chinese label", at)
		}
	}
	for raw, want := range map[string]string{
		"CRITICAL": "严重", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "INFO": "信息", "": "",
	} {
		if got := exportSeverityLabel(raw); got != want {
			t.Errorf("exportSeverityLabel(%q)=%q want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"BLOCK": "阻断", "OBSERVE": "观察", "ALLOW": "放行", "": "",
	} {
		if got := exportActionLabel(raw); got != want {
			t.Errorf("exportActionLabel(%q)=%q want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"UNPROCESSED": "未处置", "ANALYZING": "分析中", "CONFIRMED_ATTACK": "确认攻击",
		"CONFIRMED_FALSE_POSITIVE": "确认误报", "IGNORED": "已忽略", "RESOLVED": "已处置", "": "",
	} {
		if got := exportDispositionLabel(raw); got != want {
			t.Errorf("exportDispositionLabel(%q)=%q want %q", raw, got, want)
		}
	}
}
