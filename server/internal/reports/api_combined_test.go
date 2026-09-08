package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// sampleCombinedData 含 API 安全部分的测试数据。
func sampleCombinedData() *ReportData {
	d := sampleReportData()
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	d.API = &APIReportData{
		ReportType:  "COMBINED",
		RangeStart:  now,
		RangeEnd:    now.Add(24 * time.Hour),
		GeneratedAt: now,
		Asset: &APIAssetReport{
			TotalEndpoints: 42, NewEndpoints: 5, Confirmed: 30, Zombie: 2, ShadowOpen: 3,
			StatusDist: []KV{{Key: "CONFIRMED", Value: 30}, {Key: "DISCOVERED", Value: 10}, {Key: "ZOMBIE", Value: 2}},
			NewList:    []APIEndpointDigest{{Method: "GET", Path: "/api/order/{id}", Status: "DISCOVERED", Hits: 88, FirstSeen: now, LastSeen: now}},
			ShadowList: []APIEndpointDigest{{Method: "POST", Path: "/inner/debug", Status: "DISCOVERED", Hits: 3, FirstSeen: now, LastSeen: now}},
		},
		Risk: &APIRiskReport{
			NewFindings: 9, ClosedFindings: 4, OpenFindings: 6,
			TypeDist:     []KV{{Key: "SHADOW", Value: 5}, {Key: "BOLA", Value: 4}},
			SeverityDist: []KV{{Key: "HIGH", Value: 4}, {Key: "MEDIUM", Value: 5}},
			TopEndpoints: []APIRiskEndpoint{{Method: "GET", Path: "/api/user/{id}", Findings: 6, High: 3}},
			TopSubjects:  []APIRiskSubject{{SubjectType: "token", SubjectID: "abc123def456", Findings: 5}},
		},
		Weakness: &APIWeaknessReport{
			NewInRange: 2, FixedInRange: 1, OverdueOpen: 3, RetestFail: 1,
			StatusDist:   []KV{{Key: "TO_FIX", Value: 4}},
			SeverityDist: []KV{{Key: "HIGH", Value: 3}},
			OverdueList:  []APIWeaknessItem{{Name: "缺少速率限制", Code: "API4-2023-004", Severity: "HIGH", Status: "TO_FIX"}},
		},
		Sensitive: &APISensitiveReport{
			TotalFields: 120, NewInRange: 8,
			TypeDist:     []KV{{Key: "phone", Value: 60}, {Key: "id_card", Value: 40}},
			TopEndpoints: []APISensitiveEndpoint{{Method: "GET", Path: "/api/profile", Fields: 12, Types: 3}},
			DailyNew:     []Point{{Time: now, Value: 8}},
		},
		Conclusions: []string{"API 资产存在未确认端点。"},
		Suggestions: []string{"建议尽快确认资产。"},
	}
	return d
}

func TestRenderHTMLCombinedAPIPart(t *testing.T) {
	data := sampleCombinedData()
	charts, err := BuildMainCharts(data, testFontPath(t))
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0500", charts)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, want := range []string{
		"下篇：API 动态防护", "API 资产总览", "新增 API 端点 TOP20", "Shadow API 清单",
		"API 风险发现", "发现类型与严重度分布", "风险端点 TOP10", "风险主体 TOP10",
		"API 弱点整改", "超期未修清单", "API 敏感数据", "涉敏端点 TOP10",
		"/api/order/{id}", "/inner/debug", "缺少速率限制", "API 安全结论", "API 安全建议",
		"影子API", "对象级越权", "手机号码",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("combined html missing %q", want)
		}
	}
	// Shadow/僵尸/超期 红标
	if !strings.Contains(out, `<span class="warn">3</span>`) {
		t.Fatal("shadow/overdue attention highlight missing")
	}
}

func TestRenderHTMLNoAPIPartWhenNil(t *testing.T) {
	html, err := RenderHTML(BuiltinTemplate(), sampleReportData(), "JZ-202608-0501", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, absent := range []string{"下篇：API 动态防护", "API 资产总览", "涉敏端点 TOP10", "API 端点数"} {
		if strings.Contains(out, absent) {
			t.Fatalf("api part should be absent when data.API is nil: %q", absent)
		}
	}
}

func TestRenderHTMLScopeEndpointCounts(t *testing.T) {
	data := sampleCombinedData()
	data.Applications = []AppInfo{
		{Code: "shop-mall", Name: "电商商城", APIEndpoints: 128},
		{Code: "user-center", Name: "用户中心", APIEndpoints: 36},
	}
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0504", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, want := range []string{"API 端点数", "128", "36", "合计", "164"} {
		if !strings.Contains(out, want) {
			t.Fatalf("scope endpoint counts missing %q", want)
		}
	}
}

func TestRenderHTMLAPIAssetList(t *testing.T) {
	data := sampleCombinedData()
	data.API.AssetList = []APIAssetListItem{
		{Method: "GET", Path: "/api/order/{id}", Purpose: "交易支付", Status: "CONFIRMED", Hits: 88},
		{Method: "POST", Path: "/inner/debug", Status: "DISCOVERED", IsShadow: true, Hits: 3},
		{Method: "GET", Path: "/legacy/v1/user", Status: "ZOMBIE", IsZombie: true, Hits: 1},
	}
	data.API.AssetListTotal = 3
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0505", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, want := range []string{"API 资产清单（全量）", "共 3 条 API 资产", "交易支付", "影子API", "僵尸API", "未分类"} {
		if !strings.Contains(out, want) {
			t.Fatalf("api asset list missing %q", want)
		}
	}
	// 影子/僵尸行红标
	if !strings.Contains(out, `<span class="warn">影子API</span>`) || !strings.Contains(out, `<span class="warn">僵尸API</span>`) {
		t.Fatal("shadow/zombie rows should be red-highlighted")
	}
	// 未开启选项（AssetList 为 nil）→ 不显示清单章节
	data2 := sampleCombinedData()
	html2, err := RenderHTML(BuiltinTemplate(), data2, "JZ-202608-0506", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	if strings.Contains(string(html2), "API 资产清单（全量）") {
		t.Fatal("asset list section should be absent when AssetList is nil")
	}
}

func TestRenderPDFAndDOCXCombinedAPIPart(t *testing.T) {
	data := sampleCombinedData()
	fontPath := testFontPath(t)
	charts, err := BuildMainCharts(data, fontPath)
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	pdf, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0502", fontPath, charts)
	if err != nil {
		t.Fatalf("render pdf: %v", err)
	}
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		t.Fatal("pdf magic invalid")
	}
	docx, err := RenderDOCX(BuiltinTemplate(), data, "JZ-202608-0503", charts)
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	_, docXML := unzipDocx(t, docx)
	for _, want := range []string{"下篇：API 动态防护", "API 资产总览", "涉敏端点 TOP10", "API 安全建议"} {
		if !strings.Contains(docXML, want) {
			t.Fatalf("combined docx missing %q", want)
		}
	}
}

func TestAppCond(t *testing.T) {
	// 空范围 → 空片段
	if s, args := appCond(nil, "application_id", 3); s != "" || args != nil {
		t.Fatalf("nil appIDs should produce empty cond, got %q %v", s, args)
	}
	// 非空范围 → 片段与参数
	ids := sampleUUIDs()
	s, args := appCond(ids, "e.application_id", 4)
	if !strings.Contains(s, "e.application_id = ANY($4)") || len(args) != 1 {
		t.Fatalf("appCond wrong: %q %v", s, args)
	}
	// 端点子查询
	s2, args2 := appEndpointSubquery(ids, "f.endpoint_id", 2)
	if !strings.Contains(s2, "f.endpoint_id IN (SELECT id FROM api_endpoints WHERE application_id = ANY($2))") || len(args2) != 1 {
		t.Fatalf("appEndpointSubquery wrong: %q %v", s2, args2)
	}
}

func TestBuildCombinedAPIConclusions(t *testing.T) {
	d := sampleCombinedData().API
	c := BuildCombinedAPIConclusions(d)
	s := BuildCombinedAPISuggestions(d)
	if len(c) == 0 || len(c) > 4 {
		t.Fatalf("combined conclusions count wrong: %d", len(c))
	}
	if len(s) == 0 || len(s) > 4 {
		t.Fatalf("combined suggestions count wrong: %d", len(s))
	}
	// 空数据不panic
	empty := &APIReportData{}
	_ = BuildCombinedAPIConclusions(empty)
	_ = BuildCombinedAPISuggestions(empty)
}

func sampleUUIDs() []uuid.UUID {
	return []uuid.UUID{uuid.MustParse("11111111-1111-1111-1111-111111111111")}
}
