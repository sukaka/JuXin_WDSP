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
	t.Run("chinese_headers_and_utf8_bom", func(t *testing.T) {
		content := "\ufeff地址,规则类型,生效范围,应用编码,失效时间,原因\n" +
			"192.168.1.0/24,黑名单,全局,,,批量封禁\n" +
			"10.0.0.1,白名单,指定应用,myapp,2027-01-01T00:00:00Z,业务白名单\n"
		recs, err := parseCSVContent(content)
		if err != nil {
			t.Fatalf("中文表头+BOM解析失败: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("应解析 2 行, 得到 %d", len(recs))
		}
		if recs[0].address != "192.168.1.0/24" || recs[0].ruleType != "黑名单" || recs[0].scopeType != "全局" || recs[0].reason != "批量封禁" {
			t.Fatalf("第1行解析错误: %+v", recs[0])
		}
		if recs[1].address != "10.0.0.1" || recs[1].ruleType != "白名单" || recs[1].scopeType != "指定应用" || recs[1].applicationCode != "myapp" {
			t.Fatalf("第2行解析错误: %+v", recs[1])
		}
	})
	t.Run("mixed_headers_and_bom_in_quoted_cell", func(t *testing.T) {
		content := "\"\ufeff地址\",rule_type,生效范围,reason\n1.2.3.4,黑名单,GLOBAL,混合表头\n"
		recs, err := parseCSVContent(content)
		if err != nil {
			t.Fatalf("混合表头解析失败: %v", err)
		}
		if len(recs) != 1 || recs[0].address != "1.2.3.4" || recs[0].ruleType != "黑名单" || recs[0].scopeType != "GLOBAL" || recs[0].reason != "混合表头" {
			t.Fatalf("混合表头解析结果错误: %+v", recs)
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
	t.Run("utf8_bom", func(t *testing.T) {
		recs, err := parseTextLines("\ufeff1.2.3.4\n")
		if err != nil || len(recs) != 1 || recs[0].address != "1.2.3.4" {
			t.Fatalf("带 BOM 纯文本解析失败: err=%v recs=%+v", err, recs)
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
		{"formula_tab", "\t=1", "'\t=1"},
		{"formula_cr", "\r=1", "\"'\r=1\""},
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
	if !strings.HasPrefix(out, csvUTF8BOM) {
		t.Fatalf("导出 CSV 缺少 UTF-8 BOM")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("应为表头+2行, 得到 %d 行", len(lines))
	}
	wantHeader := csvUTF8BOM + "规则 ID,规则名称,规则类型,生效范围,应用编码,地址,IP 版本,优先级,状态,有效期类型,生效开始时间,失效时间,原因,来源,命中次数,最近命中时间,创建时间"
	if lines[0] != wantHeader {
		t.Fatalf("表头错误: got=%q want=%q", lines[0], wantHeader)
	}
	if !strings.Contains(lines[1], `"'=HYPERLINK(""http://evil"")"`) {
		t.Fatalf("公式注入字段应被转义: %s", lines[1])
	}
	if !strings.Contains(lines[1], ",黑名单,指定应用,myapp,192.168.1.0/24,IPv4,100,生效中,临时,") {
		t.Fatalf("第1行中文枚举值错误: %s", lines[1])
	}
	if !strings.Contains(lines[1], `"封禁,含逗号",批量导入,7,`) {
		t.Fatalf("含逗号字段或来源枚举错误: %s", lines[1])
	}
	if !strings.Contains(lines[1], "2027-01-01T00:00:00Z") {
		t.Fatalf("时间格式错误: %s", lines[1])
	}
	if !strings.Contains(lines[2], ",白名单,全局,,10.0.0.1,IPv4,100,生效中,永久,,,,手工创建,0,") {
		t.Fatalf("第2行中文枚举值错误: %s", lines[2])
	}
	if strings.Contains(lines[2], "myapp") {
		t.Fatalf("全局规则不应有应用编码: %s", lines[2])
	}
}

func TestRenderExportCSVAllEnumsAndFallback(t *testing.T) {
	ts := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	rules := []Rule{
		{
			ID: uuid.New(), Name: "草稿v6", RuleType: RuleTypeDeny, ScopeType: ScopeGlobal,
			Address: "2001:db8::1", IPVersion: IPVersion6, Priority: 10, Status: StatusDraft,
			ValidityType: ValidityPermanent, SourceType: SourceSecurityEvent, CreatedAt: ts,
		},
		{
			ID: uuid.New(), Name: "停用自动", RuleType: RuleTypeAllow, ScopeType: ScopeGlobal,
			Address: "10.0.0.2", IPVersion: IPVersion4, Priority: 20, Status: StatusDisabled,
			ValidityType: ValidityTemporary, SourceType: SourceAutoBlock, CreatedAt: ts,
		},
		{
			ID: uuid.New(), Name: "过期系统", RuleType: RuleTypeDeny, ScopeType: ScopeGlobal,
			Address: "10.0.0.3", IPVersion: IPVersion4, Priority: 30, Status: StatusExpired,
			ValidityType: ValidityPermanent, SourceType: SourceSystem, CreatedAt: ts,
		},
		{
			ID: uuid.New(), Name: "删除未知兜底", RuleType: "FUTURE_TYPE", ScopeType: "FUTURE_SCOPE",
			Address: "10.0.0.4", IPVersion: "IPV9", Priority: 40, Status: StatusDeleted,
			ValidityType: "CUSTOM_VALID", SourceType: "CUSTOM_SRC", CreatedAt: ts,
		},
	}
	out := RenderExportCSV(rules, nil)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines = %d, want 5", len(lines))
	}
	if !strings.Contains(lines[1], ",IPv6,10,草稿,永久,,,,安全事件,") {
		t.Fatalf("row 1 mismatch: %s", lines[1])
	}
	if !strings.Contains(lines[2], ",IPv4,20,已停用,临时,,,,自动封禁,") {
		t.Fatalf("row 2 mismatch: %s", lines[2])
	}
	if !strings.Contains(lines[3], ",IPv4,30,已过期,永久,,,,系统内置,") {
		t.Fatalf("row 3 mismatch: %s", lines[3])
	}
	if !strings.Contains(lines[4], ",FUTURE_TYPE,FUTURE_SCOPE,,10.0.0.4,IPV9,40,已删除,CUSTOM_VALID,,,,CUSTOM_SRC,") {
		t.Fatalf("row 4 fallback mismatch: %s", lines[4])
	}
}

func TestRenderExportCSVNegativePriorityNotEscaped(t *testing.T) {
	ts := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	out := RenderExportCSV([]Rule{
		{
			ID: uuid.New(), Name: "高优规则", RuleType: RuleTypeAllow, ScopeType: ScopeGlobal,
			Address: "10.0.0.9", IPVersion: IPVersion4, Priority: -10, Status: StatusActive,
			ValidityType: ValidityPermanent, SourceType: SourceManual, HitCount: 42, CreatedAt: ts,
		},
	}, nil)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[1], ",IPv4,-10,生效中,永久,,,,手工创建,42,,2027-06-01T00:00:00Z") {
		t.Fatalf("negative priority should not be formula-escaped: %s", lines[1])
	}
	if strings.Contains(lines[1], "'-10") {
		t.Fatalf("negative priority was wrongly escaped: %s", lines[1])
	}
}
