package reports

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBuildComparisonRows(t *testing.T) {
	d := &ReportData{
		TotalRequests: 1200, EventsTotal: 150, EventsBlocked: 60, HighSeverity: 10,
		Comparison: ComparisonData{
			PrevRangeStart: 1, PrevRangeEnd: 2,
			PrevTotalRequests: 1000, PrevEventsTotal: 100, PrevEventsBlocked: 50, PrevHighSeverity: 5,
		},
	}
	rows := BuildComparisonRows(d)
	if len(rows) != 5 {
		t.Fatalf("expect 5 rows, got %d", len(rows))
	}
	// 事件数 100→150 上升 50% 恶化
	if rows[1].Delta != "+50.0%" || rows[1].Tone != "bad" {
		t.Fatalf("events row wrong: %+v", rows[1])
	}
	// 流量 1000→1200 上升但中性
	if rows[0].Delta != "+20.0%" || rows[0].Tone != "" {
		t.Fatalf("traffic row wrong: %+v", rows[0])
	}
	// 阻断率 60%→40% 下降恶化（pp 文本）
	if rows[4].Delta != "-10.0pp" || rows[4].Tone != "bad" {
		t.Fatalf("block rate row wrong: %+v", rows[4])
	}
	// 上期 0 → 新增/恶化
	d2 := &ReportData{EventsTotal: 5, Comparison: ComparisonData{PrevRangeEnd: 1}}
	rows2 := BuildComparisonRows(d2)
	if rows2[1].Delta != "新增" || rows2[1].Tone != "bad" {
		t.Fatalf("new-from-zero row wrong: %+v", rows2[1])
	}
	// 未采集 → nil
	if rows3 := BuildComparisonRows(&ReportData{}); rows3 != nil {
		t.Fatalf("unavailable comparison should be nil, got %+v", rows3)
	}
}

func TestCnNumeral(t *testing.T) {
	cases := map[int]string{1: "一", 9: "九", 10: "十", 11: "十一", 19: "十九", 20: "二十", 25: "二十五", 30: "三十", 99: "九十九"}
	for n, want := range cases {
		if got := cnNumeral(n); got != want {
			t.Fatalf("cnNumeral(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPeakHour(t *testing.T) {
	hours := make([]KV, 24)
	hours[14] = KV{Key: "14", Value: 30}
	hours[2] = KV{Key: "02", Value: 55}
	name, n := peakHour(hours)
	if name != "02" || n != 55 {
		t.Fatalf("peak = %s/%d, want 02/55", name, n)
	}
	if txt := peakHourText(hours); !strings.Contains(txt, "02:00-02:59（55 起）") {
		t.Fatalf("peak text wrong: %q", txt)
	}
	if name, n := peakHour(make([]KV, 24)); name != "" || n != 0 {
		t.Fatal("empty hours should have no peak")
	}
}

func TestTopKVs(t *testing.T) {
	sums := map[string]int64{}
	for i := 0; i < 15; i++ {
		sums[fmt.Sprintf("c%02d", i)] = int64(100 - i)
	}
	out := topKVs(sums, 10, "其他")
	if len(out) != 11 {
		t.Fatalf("expect 10 top + other, got %d", len(out))
	}
	if out[0].Key != "c00" || out[9].Key != "c09" {
		t.Fatalf("top order wrong: %+v", out[:3])
	}
	if out[10].Key != "其他" || out[10].Value != 440 {
		t.Fatalf("other sum wrong: %+v", out[10])
	}
}

func TestRenderHTMLDetailSections(t *testing.T) {
	data := sampleReportData()
	data.Comparison = ComparisonData{PrevRangeStart: 1, PrevRangeEnd: 2, PrevEventsTotal: 5, PrevEventsBlocked: 2}
	data.AttackHours = make([]KV, 24)
	data.AttackHours[3] = KV{Key: "03", Value: 9}
	data.GeoEnabled = true
	data.SourceGeo = []KV{{Key: "中国", Value: 8}, {Key: "内网地址", Value: 4}}
	data.TargetPaths = []KV{{Key: "/api/login", Value: 12}}
	data.EventSamples = []EventSample{{
		OccurredAt: time.Date(2026, 8, 26, 3, 4, 5, 0, time.UTC),
		ClientIP:   "1.2.3.4", AppName: "shop", Method: "POST", Path: "/api/login",
		AttackType: "SQL_INJECTION", Severity: "CRITICAL", Action: "BLOCK",
	}}
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0300", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, want := range []string{"环比对比", "攻击时段分布", "攻击高峰时段：03:00-03:59（9 起）", "攻击源地区 TOP10", "被攻击路径 TOP10", "高危事件明细 TOP20", "/api/login", "严重", "新增"} {
		if !strings.Contains(out, want) {
			t.Fatalf("html missing %q", want)
		}
	}
	// GeoIP 未启用占位
	data2 := sampleReportData()
	html2, _ := RenderHTML(BuiltinTemplate(), data2, "JZ-202608-0301", nil)
	if !strings.Contains(string(html2), "GeoIP 数据未启用") {
		t.Fatal("html should show geo disabled placeholder")
	}
}

func TestRenderHTMLSectionNumbering(t *testing.T) {
	tpl := BuiltinTemplate()
	tpl.Sections = DefaultSections()
	// 关闭部分章节后编号必须连续无跳号
	for _, k := range []string{SectionTraffic, SectionRiskLevel, SectionAttackTrend, SectionCCProtection} {
		tpl.Sections[k] = false
	}
	html, err := RenderHTML(tpl, sampleReportData(), "JZ-202608-0302", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	// 期望序列：一报告周期 二报告范围 三管理摘要 四环比对比 五安全事件总览 六攻击类型分布 七攻击时段分布 ...
	seq := []string{"一、报告周期", "二、报告范围", "三、管理摘要", "四、环比对比", "五、安全事件总览", "六、攻击类型分布", "七、攻击时段分布", "八、攻击源IP"}
	pos := -1
	for _, s := range seq {
		idx := strings.Index(out, s)
		if idx < 0 {
			t.Fatalf("missing section title %q", s)
		}
		if idx < pos {
			t.Fatalf("section %q out of order", s)
		}
		pos = idx
	}
	// 被关闭章节不得出现
	for _, absent := range []string{"请求流量</h2>", "风险等级</h2>", "CC防护</h2>"} {
		if strings.Contains(out, absent) {
			t.Fatalf("disabled section present: %q", absent)
		}
	}
}

func TestRenderDOCXDetailSections(t *testing.T) {
	data := sampleReportData()
	data.Comparison = ComparisonData{PrevRangeStart: 1, PrevRangeEnd: 2, PrevEventsTotal: 5}
	data.EventSamples = []EventSample{{OccurredAt: time.Now(), ClientIP: "1.2.3.4", AttackType: "XSS", Severity: "HIGH", Action: "BLOCK"}}
	out, err := RenderDOCX(BuiltinTemplate(), data, "JZ-202608-0303", nil)
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	_, docXML := unzipDocx(t, out)
	for _, want := range []string{"环比对比", "高危事件明细 TOP20", "攻击时段分布"} {
		if !strings.Contains(docXML, want) {
			t.Fatalf("docx missing %q", want)
		}
	}
}
