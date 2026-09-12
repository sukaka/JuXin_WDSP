package reports

import (
	"strings"
	"testing"
	"time"
)

func TestNewAttention(t *testing.T) {
	// 全零数据 → 无关注项
	if a := NewAttention(&ReportData{}); a.HighSeverity || a.RiskHigh || a.BlockRateLow || a.CCNoBlock || a.PublishFailed {
		t.Fatal("empty data should have no attention flags")
	}
	// 命中全部规则
	d := &ReportData{
		EventsTotal:   100,
		EventsBlocked: 30, // 阻断率 30% < 50%
		HighSeverity:  5,
		RiskLevel:     "CRITICAL",
		CCExceeded:    10,
		CCRejected:    0,
	}
	d.Publish.Failed = 2
	a := NewAttention(d)
	if !a.HighSeverity || !a.RiskHigh || !a.BlockRateLow || !a.CCNoBlock || !a.PublishFailed {
		t.Fatalf("all flags should be set: %+v", a)
	}
	// 无事件 → 阻断率不标
	a = NewAttention(&ReportData{EventsTotal: 0, EventsBlocked: 0})
	if a.BlockRateLow {
		t.Fatal("no events should not flag block rate")
	}
	// 阻断率 50% 恰好不标（阈值 <50%）
	a = NewAttention(&ReportData{EventsTotal: 10, EventsBlocked: 5})
	if a.BlockRateLow {
		t.Fatal("50% block rate should not flag")
	}
	// CC 触发且有拦截 → 不标
	a = NewAttention(&ReportData{CCExceeded: 5, CCRejected: 3})
	if a.CCNoBlock {
		t.Fatal("cc blocked should not flag")
	}
	// nil 数据安全
	if a := NewAttention(nil); a.HighSeverity {
		t.Fatal("nil data should have no flags")
	}
}

func TestNewAPIAttention(t *testing.T) {
	d := &APIReportData{
		Asset:    &APIAssetReport{ShadowOpen: 2, Zombie: 1},
		Risk:     &APIRiskReport{OpenFindings: 3},
		Weakness: &APIWeaknessReport{OverdueOpen: 1, RetestFail: 1},
	}
	a := NewAPIAttention(d)
	if !a.ShadowOpen || !a.Zombie || !a.OpenFindings || !a.Overdue || !a.RetestFail {
		t.Fatalf("all api flags should be set: %+v", a)
	}
	if a := NewAPIAttention(nil); a.ShadowOpen {
		t.Fatal("nil data should have no flags")
	}
}

func TestAttentionPredicates(t *testing.T) {
	if !severityAttention("HIGH") || !severityAttention("CRITICAL") || severityAttention("LOW") {
		t.Fatal("severity predicate wrong")
	}
	if !certAttention(30) || !certAttention(-1) || certAttention(31) {
		t.Fatal("cert predicate wrong")
	}
	if !upstreamAttention("DOWN") || !upstreamAttention("DEGRADED") || upstreamAttention("UP") || upstreamAttention("UNKNOWN") {
		t.Fatal("upstream predicate wrong")
	}
	if !componentAttention("DOWN") || !componentAttention("DEGRADED") || componentAttention("UP") || componentAttention("UNKNOWN") {
		t.Fatal("component predicate wrong")
	}
}

func TestRenderHTMLAttention(t *testing.T) {
	data := sampleReportData() // HighSeverity=3（sampleReportData 无 HighSeverity，显式设置）
	data.HighSeverity = 3
	data.RiskLevel = "CRITICAL"
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0020", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	if !strings.Contains(out, `<span class="warn">3</span>`) {
		t.Fatal("high severity value should be red-highlighted")
	}
	// 无风险数据 → 无 warn 标记
	html2, err := RenderHTML(BuiltinTemplate(), &ReportData{}, "JZ-202608-0021", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	if strings.Contains(string(html2), `<span class="warn">`) {
		t.Fatal("clean report should have no warn highlight")
	}
}

func TestRenderAPIHTMLAttention(t *testing.T) {
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	d := &APIReportData{
		ReportType: TypeAPIRisk, RangeStart: now, RangeEnd: now.Add(7 * 24 * time.Hour), GeneratedAt: now,
		Risk: &APIRiskReport{
			OpenFindings: 4,
			SeverityDist: []KV{{Key: "CRITICAL", Value: 2}, {Key: "LOW", Value: 5}},
		},
	}
	html, err := RenderAPIHTML(BuiltinTemplate(), d, "JZ-202608-0022", nil)
	if err != nil {
		t.Fatalf("render api html: %v", err)
	}
	out := string(html)
	if !strings.Contains(out, `<span class="warn">4</span>`) {
		t.Fatal("open findings should be red-highlighted")
	}
	if !strings.Contains(out, `<span class="warn">严重</span>`) {
		t.Fatal("critical severity row should be red-highlighted (chinese label)")
	}
	if strings.Contains(out, `<span class="warn">LOW</span>`) || strings.Contains(out, `<span class="warn">低危</span>`) {
		t.Fatal("low severity row should not be highlighted")
	}
}

func TestRenderDOCXAttention(t *testing.T) {
	data := sampleReportData()
	data.HighSeverity = 3
	out, err := RenderDOCX(BuiltinTemplate(), data, "JZ-202608-0023", nil)
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	_, docXML := unzipDocx(t, out)
	if !strings.Contains(docXML, attentionColorHex) {
		t.Fatal("docx should contain red highlight color for attention row")
	}
}
