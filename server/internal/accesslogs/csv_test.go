package accesslogs

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
	ts := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	logs := []AccessLog{
		{
			OccurredAt:     ts,
			ClientIP:       "203.0.113.1",
			Domain:         "api.example.com",
			RequestMethod:  "GET",
			RequestURI:     "/v1/items",
			ResponseStatus: 200,
			WAFAction:      "ALLOW",
			BytesIn:        128,
			BytesOut:       1024,
			DurationMS:     12,
			GatewayNodeID:  "gw-1",
			RequestID:      "req-al-1",
		},
		{
			OccurredAt:     ts,
			ClientIP:       "203.0.113.2",
			Domain:         "=bad.example.com",
			RequestMethod:  "POST",
			RequestURI:     "/v1/pay?a=1,2",
			ResponseStatus: 403,
			WAFAction:      "BLOCK",
			BytesIn:        256,
			BytesOut:       64,
			DurationMS:     3,
			GatewayNodeID:  "gw-2",
			RequestID:      "req-al-2",
		},
		{
			OccurredAt:     ts,
			ClientIP:       "203.0.113.3",
			Domain:         "legacy.example.com",
			RequestMethod:  "GET",
			RequestURI:     "/legacy",
			ResponseStatus: 200,
			WAFAction:      "",
			BytesIn:        0,
			BytesOut:       10,
			DurationMS:     1,
			GatewayNodeID:  "gw-1",
			RequestID:      "req-al-3",
		},
		{
			OccurredAt:     ts,
			ClientIP:       "203.0.113.4",
			Domain:         "obs.example.com",
			RequestMethod:  "PUT",
			RequestURI:     "/obs",
			ResponseStatus: 200,
			WAFAction:      "CUSTOM_ACT",
			BytesIn:        10,
			BytesOut:       20,
			DurationMS:     2,
			GatewayNodeID:  "gw-1",
			RequestID:      "req-al-4",
		},
	}

	out := renderExportCSV(logs)
	wantHeader := "\xef\xbb\xbf发生时间,客户端 IP,域名,请求方法,请求路径,响应状态码,WAF 动作,请求大小（字节）,响应大小（字节）,耗时（ms）,网关节点,请求 ID\n"
	if !strings.HasPrefix(out, wantHeader) {
		t.Fatalf("missing UTF-8 BOM or Chinese header: %q", out[:min(len(out), 120)])
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("line count=%d want 5", len(lines))
	}
	if lines[1] != "2026-11-24T10:00:00Z,203.0.113.1,api.example.com,GET,/v1/items,200,放行,128,1024,12,gw-1,req-al-1" {
		t.Fatalf("row1 mismatch: %s", lines[1])
	}
	if lines[2] != `2026-11-24T10:00:00Z,203.0.113.2,'=bad.example.com,POST,"/v1/pay?a=1,2",403,阻断,256,64,3,gw-2,req-al-2` {
		t.Fatalf("row2 mismatch: %s", lines[2])
	}
	if !strings.Contains(lines[3], ",200,放行,") {
		t.Fatalf("empty waf_action should map to 放行: %s", lines[3])
	}
	if !strings.Contains(lines[4], ",200,CUSTOM_ACT,") {
		t.Fatalf("unknown waf_action should fallback to raw: %s", lines[4])
	}
	if got := exportWAFActionLabel("OBSERVE"); got != "观察" {
		t.Errorf("exportWAFActionLabel(OBSERVE) = %q, want 观察", got)
	}
}
