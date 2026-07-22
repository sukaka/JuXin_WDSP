package reports

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------- 报告编号 ----------

func TestFormatReportNo(t *testing.T) {
	at := time.Date(2026, 7, 22, 15, 4, 0, 0, time.UTC)
	cases := []struct {
		name   string
		format string
		seq    int
		want   string
	}{
		{"default-empty-format", "", 1, "JZ-202607-0001"},
		{"yyyymm-seq", "JZ-{YYYYMM}-{SEQ}", 12, "JZ-202607-0012"},
		{"seq-no-pad-overflow", "R-{YYYYMM}-{SEQ}", 12345, "R-202607-12345"},
		{"only-seq", "{SEQ}", 7, "0007"},
		{"literal-kept", "REPORT-2026", 3, "REPORT-2026"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FormatReportNo(c.format, at, c.seq); got != c.want {
				t.Fatalf("FormatReportNo(%q, seq=%d) = %q, want %q", c.format, c.seq, got, c.want)
			}
		})
	}
}

// ---------- 时间范围 ----------

func TestComputeTimeRangeDaily(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	s, e, err := ComputeTimeRange(TypeDaily, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Equal(time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)) || !e.Equal(time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("daily range = %s ~ %s", s, e)
	}
}

func TestComputeTimeRangeWeekly(t *testing.T) {
	// 2026-07-22 是周三；上周为 07-13(周一) ~ 07-20(周一)
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	s, e, err := ComputeTimeRange(TypeWeekly, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Weekday() != time.Monday || !s.Equal(time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("weekly start = %s", s)
	}
	if !e.Equal(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("weekly end = %s", e)
	}
	// 周一当天也应归到上一周
	monday := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	s2, e2, _ := ComputeTimeRange(TypeWeekly, nil, nil, monday)
	if !s2.Equal(time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)) || !e2.Equal(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("weekly(monday) = %s ~ %s", s2, e2)
	}
}

func TestComputeTimeRangeMonthly(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	s, e, err := ComputeTimeRange(TypeMonthly, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) || !e.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("monthly range = %s ~ %s", s, e)
	}
	// 跨年：2026-01 → 2025-12
	jan := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	s2, e2, _ := ComputeTimeRange(TypeMonthly, nil, nil, jan)
	if !s2.Equal(time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)) || !e2.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("monthly(jan) = %s ~ %s", s2, e2)
	}
}

func TestComputeTimeRangeCustom(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	s0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// 缺少起止时间
	if _, _, err := ComputeTimeRange(TypeCustom, nil, nil, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("custom without range should fail: %v", err)
	}
	if _, _, err := ComputeTimeRange(TypeCustom, &s0, nil, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("custom without end should fail: %v", err)
	}
	// 结束早于开始
	if _, _, err := ComputeTimeRange(TypeCustom, &e0, &s0, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("custom reversed should fail: %v", err)
	}
	// 跨度超过366天
	far := s0.AddDate(1, 0, 2)
	if _, _, err := ComputeTimeRange(TypeCustom, &s0, &far, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("custom >366d should fail: %v", err)
	}
	// 恰好366天允许
	exact := s0.Add(MaxCustomRangeHours * time.Hour)
	if _, _, err := ComputeTimeRange(TypeCustom, &s0, &exact, now); err != nil {
		t.Fatalf("custom 366d should pass: %v", err)
	}
	// 正常范围
	gotS, gotE, err := ComputeTimeRange(TypeCustom, &s0, &e0, now)
	if err != nil || !gotS.Equal(s0) || !gotE.Equal(e0) {
		t.Fatalf("custom range = %s ~ %s, err=%v", gotS, gotE, err)
	}
}

func TestComputeTimeRangeUnknownType(t *testing.T) {
	if _, _, err := ComputeTimeRange("HOURLY", nil, nil, time.Now()); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("unknown type should fail: %v", err)
	}
}

// ---------- 结论与建议（确定性） ----------

func sampleData() *ReportData {
	d := &ReportData{
		ReportType:     TypeMonthly,
		RangeStart:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		RangeEnd:       time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		TotalRequests:  10000,
		EventsTotal:    100,
		EventsBlocked:  40,
		EventsObserved: 60,
		HighSeverity:   10,
		AttackTypes:    []KV{{Key: "SQL_INJECTION", Value: 60}, {Key: "XSS", Value: 25}},
		TopSourceIPs:   []KV{{Key: "1.2.3.4", Value: 50}},
		Unprocessed:    40,
		FalsePositives: 3,
	}
	d.RiskLevel = computeRiskLevel(d)
	return d
}

func TestComputeRiskLevel(t *testing.T) {
	d := &ReportData{}
	if got := computeRiskLevel(d); got != "LOW" {
		t.Fatalf("empty data risk = %s", got)
	}
	d = &ReportData{EventsTotal: 100, HighSeverity: 5, EventsBlocked: 0}
	if got := computeRiskLevel(d); got != "CRITICAL" {
		t.Fatalf("unblocked high severity risk = %s", got)
	}
	d = &ReportData{EventsTotal: 100, HighSeverity: 40, EventsBlocked: 80}
	if got := computeRiskLevel(d); got != "HIGH" {
		t.Fatalf("high ratio risk = %s", got)
	}
	d = &ReportData{EventsTotal: 100, HighSeverity: 1, EventsBlocked: 80}
	if got := computeRiskLevel(d); got != "MEDIUM" {
		t.Fatalf("some high severity risk = %s", got)
	}
}

func TestBuildConclusionsDeterministic(t *testing.T) {
	d := sampleData()
	c1 := BuildConclusions(d)
	c2 := BuildConclusions(d)
	if len(c1) != len(c2) {
		t.Fatal("conclusions not deterministic")
	}
	for i := range c1 {
		if c1[i] != c2[i] {
			t.Fatalf("conclusions differ at %d: %q vs %q", i, c1[i], c2[i])
		}
	}
	joined := strings.Join(c1, "\n")
	mustContain := []string{
		"报告期内共检测到安全事件100起，其中阻断40起（阻断率40.0%），观察60起。",
		"其中高危及以上事件10起，占全部事件的10.0%。",
		"SQL注入为报告期内最主要的攻击类型，共60起，占全部攻击事件的60.0%。",
		"攻击源IP 1.2.3.4 最为活跃，报告期内共产生安全事件50起。",
		"综合评估本期风险等级为：MEDIUM。",
	}
	for _, m := range mustContain {
		if !strings.Contains(joined, m) {
			t.Fatalf("conclusions missing %q:\n%s", m, joined)
		}
	}
}

func TestBuildConclusionsNoEvents(t *testing.T) {
	d := &ReportData{RiskLevel: "LOW"}
	c := BuildConclusions(d)
	if len(c) == 0 || !strings.Contains(c[0], "未检测到Web攻击事件") {
		t.Fatalf("no-event conclusion wrong: %v", c)
	}
}

func TestBuildSuggestionsDeterministic(t *testing.T) {
	d := sampleData()
	s1 := BuildSuggestions(d)
	s2 := BuildSuggestions(d)
	if len(s1) != len(s2) {
		t.Fatal("suggestions not deterministic")
	}
	joined := strings.Join(s1, "\n")
	mustContain := []string{
		"当前攻击阻断率仅为40.0%",
		"SQL注入攻击占比60.0%，建议重点检查被攻击应用的输入校验与参数化查询实现",
		"仍有40起安全事件未处置",
		"报告期内确认误报3起",
	}
	for _, m := range mustContain {
		if !strings.Contains(joined, m) {
			t.Fatalf("suggestions missing %q:\n%s", m, joined)
		}
	}
}

func TestBuildSuggestionsDefault(t *testing.T) {
	d := &ReportData{}
	s := BuildSuggestions(d)
	if len(s) != 1 || !strings.Contains(s[0], "运行良好") {
		t.Fatalf("default suggestion wrong: %v", s)
	}
}

func TestBuildSuggestionsCertExpiry(t *testing.T) {
	exp := time.Now().Add(15 * 24 * time.Hour)
	d := &ReportData{Certificates: []CertStatus{{Name: "门户证书", NotAfter: &exp, DaysRemaining: 15}}}
	s := BuildSuggestions(d)
	if !strings.Contains(strings.Join(s, "\n"), "证书 门户证书 将于15天后到期") {
		t.Fatalf("cert expiry suggestion missing: %v", s)
	}
}

// ---------- HTML 渲染与转义 ----------

func testTemplate() *Template {
	t := BuiltinTemplate()
	t.CompanyName = `<script>alert("xss")</script>`
	t.HeaderText = `<img src=x onerror=alert(1)>`
	t.FooterText = `</div><script>evil()</script>`
	return t
}

func TestRenderHTMLEscapesInjection(t *testing.T) {
	d := sampleData()
	d.Conclusions = BuildConclusions(d)
	d.Suggestions = BuildSuggestions(d)
	html, err := RenderHTML(testTemplate(), d, "JZ-202607-0001")
	if err != nil {
		t.Fatal(err)
	}
	out := string(html)
	// 注入的脚本必须被转义
	if strings.Contains(out, `<script>alert("xss")</script>`) {
		t.Fatal("template field script not escaped")
	}
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Fatal("header html not escaped")
	}
	if strings.Contains(out, "<script>evil()</script>") {
		t.Fatal("footer script not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("expected escaped script tag in output")
	}
}

func TestRenderHTMLNoExternalResources(t *testing.T) {
	d := sampleData()
	d.Conclusions = BuildConclusions(d)
	d.Suggestions = BuildSuggestions(d)
	html, err := RenderHTML(BuiltinTemplate(), d, "JZ-202607-0001")
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ToLower(string(html))
	for _, bad := range []string{"http://", "https://", "<script", "<link", "@import", "url(", "src="} {
		if strings.Contains(out, bad) {
			t.Fatalf("html report must not contain external resource %q", bad)
		}
	}
}

func TestRenderHTMLSectionSwitch(t *testing.T) {
	d := sampleData()
	d.Conclusions = BuildConclusions(d)
	d.Suggestions = BuildSuggestions(d)
	tpl := BuiltinTemplate()
	tpl.Sections = map[string]bool{SectionSourceIPs: false, SectionConclusions: true}
	html, err := RenderHTML(tpl, d, "JZ-202607-0001")
	if err != nil {
		t.Fatal(err)
	}
	out := string(html)
	if strings.Contains(out, "攻击源IP TOP10") {
		t.Fatal("disabled section should not render")
	}
	if !strings.Contains(out, "结论和建议") {
		t.Fatal("enabled section should render")
	}
}

// ---------- 文件名安全 ----------

func TestReportFileNameSafety(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	name := ReportFileName(id, FormatHTML)
	if name != "report-11111111-2222-3333-4444-555555555555.html" {
		t.Fatalf("unexpected file name %q", name)
	}
	if !ValidateReportFileName(name, id, FormatHTML) {
		t.Fatal("own file name should validate")
	}
	bad := []string{
		"../etc/passwd",
		"report-../../x.html",
		"report-11111111-2222-3333-4444-555555555555.html/..",
		"report-11111111-2222-3333-4444-555555555555.exe",
		"report-not-a-uuid.html",
		"/etc/report-11111111-2222-3333-4444-555555555555.html",
	}
	for _, b := range bad {
		if ValidateReportFileName(b, id, FormatHTML) {
			t.Fatalf("path traversal name %q should be rejected", b)
		}
	}
	// 属于其他任务的文件不得下载
	other := uuid.New()
	if ValidateReportFileName(ReportFileName(other, FormatHTML), id, FormatHTML) {
		t.Fatal("file of another job should be rejected")
	}
	// 格式不匹配不得下载
	if ValidateReportFileName(ReportFileName(id, FormatPDF), id, FormatHTML) {
		t.Fatal("format mismatch should be rejected")
	}
}

// ---------- 报告文件读写 ----------

func TestWriteAndReadReportFile(t *testing.T) {
	dir := t.TempDir()
	id := uuid.New()
	name := ReportFileName(id, FormatHTML)
	content := []byte("<html>report</html>")
	hash, size, err := writeReportFile(dir, name, content)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) || hash != sha256Bytes(content) {
		t.Fatalf("hash/size mismatch")
	}
	got, err := readReportFile(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("content mismatch")
	}
	// 权限应为 0600
	info, err := os.Stat(filepath.Join(dir, "reports", name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file perm = %o, want 600", info.Mode().Perm())
	}
	// 路径穿越写入被拒绝
	if _, _, err := writeReportFile(dir, "../evil.html", content); err == nil {
		t.Fatal("traversal write should fail")
	}
	// 超限被拒绝
	if _, _, err := writeReportFile(dir, name, make([]byte, MaxReportFileSize+1)); err == nil {
		t.Fatal("oversize write should fail")
	}
	// 删除
	if err := removeReportFile(dir, name); err != nil {
		t.Fatal(err)
	}
	if err := removeReportFile(dir, name); err != nil {
		t.Fatal("remove missing file should be idempotent")
	}
}

// ---------- 聚合表/趋势粒度选择 ----------

func TestChooseAggTableAndTrendUnit(t *testing.T) {
	now := time.Now()
	if got := chooseAggTable(now, now.Add(24*time.Hour)); got != "metric_hour_aggregates" {
		t.Fatalf("1d span table = %s", got)
	}
	if got := chooseAggTable(now, now.Add(30*24*time.Hour)); got != "metric_daily_aggregates" {
		t.Fatalf("30d span table = %s", got)
	}
	if got := chooseTrendUnit(now, now.Add(24*time.Hour)); got != "hour" {
		t.Fatalf("1d trend unit = %s", got)
	}
	if got := chooseTrendUnit(now, now.Add(72*time.Hour)); got != "day" {
		t.Fatalf("3d trend unit = %s", got)
	}
}

// ---------- PDF 渲染 ----------

func pdfTestData() *ReportData {
	d := sampleData()
	d.Conclusions = BuildConclusions(d)
	d.Suggestions = BuildSuggestions(d)
	return d
}

func TestRenderPDFWithFont(t *testing.T) {
	fontPath := filepath.Join("..", "..", "assets", "fonts", FontFileName)
	if _, err := os.Stat(fontPath); err != nil {
		t.Skipf("font not available: %v", err)
	}
	pdf, err := RenderPDF(BuiltinTemplate(), pdfTestData(), "JZ-202607-0001", fontPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF") {
		t.Fatal("output is not a PDF")
	}
	if len(pdf) < 2000 {
		t.Fatalf("pdf suspiciously small: %d", len(pdf))
	}
}

func TestRenderPDFASCIIFallback(t *testing.T) {
	// 字体文件缺失 → 降级 ASCII 摘要而非崩溃
	pdf, err := RenderPDF(BuiltinTemplate(), pdfTestData(), "JZ-202607-0001", "/nonexistent/font.ttf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF") {
		t.Fatal("fallback output is not a PDF")
	}
}

func TestRenderPDFInvalidFont(t *testing.T) {
	// 字体文件存在但内容非法 → 返回明确错误
	bad := filepath.Join(t.TempDir(), "bad.ttf")
	if err := os.WriteFile(bad, []byte("not a font"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := RenderPDF(BuiltinTemplate(), pdfTestData(), "JZ-202607-0001", bad)
	if err == nil {
		t.Fatal("invalid font should return error")
	}
	if !errors.Is(err, errPDFFont) {
		t.Fatalf("error should wrap errPDFFont: %v", err)
	}
}

// ---------- 模板校验 ----------

func TestValidateTemplateInput(t *testing.T) {
	tpl := BuiltinTemplate()
	if err := ValidateTemplateInput(tpl); err != nil {
		t.Fatalf("builtin template should be valid: %v", err)
	}
	tpl.Name = ""
	if err := ValidateTemplateInput(tpl); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty name should fail: %v", err)
	}
	tpl = BuiltinTemplate()
	tpl.Sections = map[string]bool{"not_a_section": true}
	if err := ValidateTemplateInput(tpl); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown section key should fail: %v", err)
	}
}

// ---------- 章节开关 ----------

func TestShowSection(t *testing.T) {
	if !Show(nil, SectionCover) {
		t.Fatal("nil sections should default to show")
	}
	if !Show(map[string]bool{}, SectionCover) {
		t.Fatal("missing key should default to show")
	}
	if Show(map[string]bool{SectionCover: false}, SectionCover) {
		t.Fatal("explicit false should hide")
	}
}
