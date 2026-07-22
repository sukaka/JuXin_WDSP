package accessrules

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseCSVContent(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		content := "address,rule_type,scope_type,application_code,effective_until,reason\n" +
			"192.168.1.0/24,DENY,GLOBAL,,,批量封禁\n" +
			"10.0.0.1,ALLOW,APPLICATION,myapp,2027-01-01T00:00:00Z,白名单\n"
		recs, err := parseCSVContent(content)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("应解析 2 行, 得到 %d", len(recs))
		}
		if recs[0].line != 2 || recs[0].address != "192.168.1.0/24" || recs[0].ruleType != "DENY" {
			t.Fatalf("第1行解析错误: %+v", recs[0])
		}
		if recs[1].line != 3 || recs[1].applicationCode != "myapp" || recs[1].effectiveUntil != "2027-01-01T00:00:00Z" {
			t.Fatalf("第2行解析错误: %+v", recs[1])
		}
	})
	t.Run("header_case_and_order_insensitive", func(t *testing.T) {
		content := "Reason,Address\n测试,1.2.3.4\n"
		recs, err := parseCSVContent(content)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if len(recs) != 1 || recs[0].address != "1.2.3.4" || recs[0].reason != "测试" {
			t.Fatalf("列名大小写/顺序应不敏感: %+v", recs)
		}
	})
	t.Run("missing_address_column", func(t *testing.T) {
		_, err := parseCSVContent("rule_type,reason\nDENY,x\n")
		if err == nil || !strings.Contains(err.Error(), "address") {
			t.Fatalf("缺少 address 列应报错: %v", err)
		}
	})
	t.Run("empty_content", func(t *testing.T) {
		if _, err := parseCSVContent(""); err == nil {
			t.Fatalf("空内容应报错")
		}
	})
	t.Run("blank_lines_skipped", func(t *testing.T) {
		content := "address\n1.2.3.4\n\n5.6.7.8\n"
		recs, err := parseCSVContent(content)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("空行应跳过, 得到 %d 行", len(recs))
		}
	})
	t.Run("line_limit", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("address\n")
		for i := 0; i < ImportMaxLines+1; i++ {
			b.WriteString("1.2.3.4\n")
		}
		if _, err := parseCSVContent(b.String()); err == nil || !strings.Contains(err.Error(), "上限") {
			t.Fatalf("超过行数上限应报错: %v", err)
		}
	})
}

func TestParseTextLines(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		content := "# 注释行\n1.2.3.4\n\n  10.0.0.0/8  \r\n2001:db8::1\n"
		recs, err := parseTextLines(content)
		if err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if len(recs) != 3 {
			t.Fatalf("应解析 3 行, 得到 %d: %+v", len(recs), recs)
		}
		if recs[0].line != 2 || recs[0].address != "1.2.3.4" {
			t.Fatalf("行号/内容错误: %+v", recs[0])
		}
		if recs[1].line != 4 || recs[1].address != "10.0.0.0/8" {
			t.Fatalf("行号/内容错误: %+v", recs[1])
		}
	})
	t.Run("line_limit", func(t *testing.T) {
		content := strings.Repeat("1.2.3.4\n", ImportMaxLines+1)
		if _, err := parseTextLines(content); err == nil || !strings.Contains(err.Error(), "上限") {
			t.Fatalf("超过行数上限应报错: %v", err)
		}
	})
}

func TestNormalizeImportModeAndFormat(t *testing.T) {
	if m, err := normalizeImportMode(""); err != nil || m != ImportModeAllOrNothing {
		t.Fatalf("空模式应默认 ALL_OR_NOTHING: %v %v", m, err)
	}
	if m, err := normalizeImportMode("skip_errors"); err != nil || m != ImportModeSkipErrors {
		t.Fatalf("模式应大小写不敏感: %v %v", m, err)
	}
	if _, err := normalizeImportMode("PARTIAL"); err == nil {
		t.Fatalf("无效模式应报错")
	}
	if f, err := normalizeImportFormat(""); err != nil || f != "csv" {
		t.Fatalf("空格式应默认 csv: %v %v", f, err)
	}
	if f, err := normalizeImportFormat("TEXT"); err != nil || f != "text" {
		t.Fatalf("格式应大小写不敏感: %v %v", f, err)
	}
	if _, err := normalizeImportFormat("json"); err == nil {
		t.Fatalf("无效格式应报错")
	}
}

func TestCSVEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "hello", "hello"},
		{"formula_eq", "=cmd|'/c calc'!A1", `'=cmd|'/c calc'!A1`},
		{"formula_plus", "+1+1", `'+1+1`},
		{"formula_minus", "-2+3", `'-2+3`},
		{"formula_at", "@SUM(1)", `'@SUM(1)`},
		{"comma", "a,b", `"a,b"`},
		{"quote", `say "hi"`, `"say ""hi"""`},
		{"newline", "a\nb", "\"a\nb\""},
		{"ip_plain", "192.168.1.0/24", "192.168.1.0/24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := csvEscape(c.in); got != c.want {
				t.Fatalf("csvEscape(%q) = %q, 期望 %q", c.in, got, c.want)
			}
		})
	}
}

func TestRenderExportCSV(t *testing.T) {
	id := uuid.New()
	appID := uuid.New()
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	rules := []Rule{
		{
			ID: id, Name: "=HYPERLINK(\"http://evil\")", RuleType: RuleTypeDeny,
			ScopeType: ScopeApplication, ApplicationID: &appID, Address: "192.168.1.0/24",
			IPVersion: IPVersion4, Priority: 100, Status: StatusActive,
			ValidityType: ValidityTemporary, EffectiveUntil: &until,
			Reason: "封禁,含逗号", SourceType: SourceImport, HitCount: 7,
			CreatedAt: until,
		},
		{
			ID: uuid.New(), Name: "普通规则", RuleType: RuleTypeAllow,
			ScopeType: ScopeGlobal, Address: "10.0.0.1", IPVersion: IPVersion4,
			Priority: 100, Status: StatusActive, ValidityType: ValidityPermanent,
			SourceType: SourceManual, CreatedAt: until,
		},
	}
	out := RenderExportCSV(rules, map[uuid.UUID]string{appID: "myapp"})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("应为表头+2行, 得到 %d 行", len(lines))
	}
	if lines[0] != strings.Join(exportHeader, ",") {
		t.Fatalf("表头错误: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"'=HYPERLINK(""http://evil"")"`) {
		t.Fatalf("公式注入字段应被转义: %s", lines[1])
	}
	if !strings.Contains(lines[1], `"封禁,含逗号"`) {
		t.Fatalf("含逗号字段应加引号: %s", lines[1])
	}
	if !strings.Contains(lines[1], "myapp") || !strings.Contains(lines[1], "192.168.1.0/24") {
		t.Fatalf("应用编码/地址缺失: %s", lines[1])
	}
	if !strings.Contains(lines[1], "2027-01-01T00:00:00Z") {
		t.Fatalf("时间格式错误: %s", lines[1])
	}
	if strings.Contains(lines[2], "myapp") {
		t.Fatalf("全局规则不应有应用编码: %s", lines[2])
	}
}
