package audits

import (
	"strings"
	"testing"
	"time"
)

// TestCSVEscape 导出转义回归（审查 HIGH-10）：= + - @ \t \r 开头的单元格须加 ' 前缀
// 防公式注入（username 等用户输入可落审计），分隔符/引号/换行走 RFC4180 转义。
func TestCSVEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "admin", "admin"},
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

func TestRenderExportCSVChineseHeadersAndLabels(t *testing.T) {
	ts := time.Date(2026, 11, 24, 15, 30, 0, 0, time.UTC)

	// 校验风险等级与结果全量映射
	for code, want := range map[string]string{
		"NONE":     "无",
		"INFO":     "信息",
		RiskLow:    "低",
		RiskMedium: "中",
		RiskHigh:   "高",
		"CRITICAL": "严重",
		"UNKNOWN":  "UNKNOWN",
		"":         "",
	} {
		if got := formatAuditUpper(code, auditRiskLevelLabels); got != want {
			t.Errorf("risk_level %q = %q, want %q", code, got, want)
		}
	}

	out := renderExportCSV([]Entry{
		{
			OccurredAt: ts,
			Username:   "secops",
			SourceIP:   "198.51.100.1",
			Module:     "access_control",
			Action:     "create",
			ObjectType: "ip_access_rule",
			ObjectID:   "rule-123",
			Result:     ResultSuccess,
			RiskLevel:  RiskMedium,
			RequestID:  "req-a1",
		},
		{
			OccurredAt: ts,
			Username:   "=HYPERLINK(\"http://evil\")",
			SourceIP:   "198.51.100.2",
			Module:     "WAF",
			Action:     "learning_start_batch",
			ObjectType: "api_endpoint",
			ObjectID:   "ep-9",
			Result:     ResultFailure,
			RiskLevel:  RiskCritical,
			RequestID:  "req-a2",
		},
		{
			OccurredAt: ts,
			Username:   "auditor",
			SourceIP:   "198.51.100.3",
			Module:     "custom_unknown_mod",
			Action:     "=raw_action",
			ObjectType: "unknown_obj",
			ObjectID:   "",
			Result:     "PARTIAL",
			RiskLevel:  "INFO",
			RequestID:  "req-a3",
		},
	})

	if !strings.HasPrefix(out, csvUTF8BOM) {
		t.Fatalf("missing UTF-8 BOM")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(lines))
	}
	wantHeader := csvUTF8BOM + "操作时间,操作人,来源 IP,模块,操作,对象类型,对象标识,结果,风险等级,请求 ID"
	if lines[0] != wantHeader {
		t.Fatalf("header = %q, want %q", lines[0], wantHeader)
	}
	if lines[1] != "2026-11-24T15:30:00Z,secops,198.51.100.1,访问控制,创建,IP 黑白名单规则,rule-123,成功,中,req-a1" {
		t.Fatalf("row 1 = %q", lines[1])
	}
	if lines[2] != `2026-11-24T15:30:00Z,"'=HYPERLINK(""http://evil"")",198.51.100.2,WAF 防护,批量启动学习,API 接口,ep-9,失败,严重,req-a2` {
		t.Fatalf("row 2 = %q", lines[2])
	}
	if lines[3] != "2026-11-24T15:30:00Z,auditor,198.51.100.3,custom_unknown_mod,'=raw_action,unknown_obj,,PARTIAL,信息,req-a3" {
		t.Fatalf("row 3 = %q", lines[3])
	}
}
