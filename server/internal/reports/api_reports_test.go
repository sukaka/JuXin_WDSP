package reports

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------- API 报告类型词表 ----------

func TestIsAPIReportType(t *testing.T) {
	for _, typ := range []string{TypeAPIAsset, TypeAPIRisk, TypeAPIWeak, TypeAPISens} {
		if !IsAPIReportType(typ) {
			t.Fatalf("%s should be api report type", typ)
		}
		if !validReportType(typ) {
			t.Fatalf("%s should be valid report type", typ)
		}
		if len(typ) > 10 {
			t.Fatalf("%s exceeds report_type VARCHAR(10)", typ)
		}
	}
	for _, typ := range []string{"DAILY", "API", "API_XXX", ""} {
		if IsAPIReportType(typ) {
			t.Fatalf("%q should not be api report type", typ)
		}
	}
	if got := APIReportTypeName(TypeAPIAsset); got != "API资产周报" {
		t.Fatalf("type name = %q", got)
	}
	if got := APIReportTypeName("UNKNOWN"); got != "UNKNOWN" {
		t.Fatalf("unknown type name = %q", got)
	}
}

// ---------- 时间范围 ----------

func TestComputeTimeRangeAPIDefaultWeekly(t *testing.T) {
	// 2026-07-22 是周三；默认按周报口径取上周 07-13(周一) ~ 07-20(周一)
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	for _, typ := range []string{TypeAPIAsset, TypeAPIRisk, TypeAPIWeak, TypeAPISens} {
		s, e, err := ComputeTimeRange(typ, nil, nil, now)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !s.Equal(time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)) || !e.Equal(time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("%s default range = %s ~ %s", typ, s, e)
		}
	}
}

func TestComputeTimeRangeAPICustom(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	s0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	e0 := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)

	// 显式起止按自定义校验
	s, e, err := ComputeTimeRange(TypeAPIWeak, &s0, &e0, now)
	if err != nil || !s.Equal(s0) || !e.Equal(e0) {
		t.Fatalf("api custom range = %s ~ %s, err=%v", s, e, err)
	}
	// 只给一端 → 报错
	if _, _, err := ComputeTimeRange(TypeAPISens, &s0, nil, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("partial range should fail: %v", err)
	}
	// 倒置 → 报错
	if _, _, err := ComputeTimeRange(TypeAPIRisk, &e0, &s0, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("reversed range should fail: %v", err)
	}
	// 超 366 天 → 报错
	far := s0.AddDate(1, 0, 2)
	if _, _, err := ComputeTimeRange(TypeAPIAsset, &s0, &far, now); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf(">366d range should fail: %v", err)
	}
}

// ---------- 词表中文名 ----------

func TestAPIVocabNames(t *testing.T) {
	if got := AssetStatusName("ZOMBIE"); got != "僵尸" {
		t.Fatalf("asset status = %q", got)
	}
	if got := FindingStatusName("FALSE_POSITIVE"); got != "误报" {
		t.Fatalf("finding status = %q", got)
	}
	if got := WeaknessStatusName("TO_FIX"); got != "待整改" {
		t.Fatalf("weakness status = %q", got)
	}
	if got := SensitiveDataTypeName("id_card"); got != "身份证号" {
		t.Fatalf("sensitive type = %q", got)
	}
	// 未知词原样返回
	if got := AssetStatusName("X"); got != "X" {
		t.Fatalf("unknown asset status = %q", got)
	}
}

// ---------- 结论与建议（确定性） ----------

func apiSampleAsset() *APIReportData {
	return &APIReportData{
		ReportType: TypeAPIAsset,
		Asset: &APIAssetReport{
			TotalEndpoints: 100, NewEndpoints: 12, Confirmed: 30,
			Zombie: 2, Deprecated: 5, ShadowOpen: 3,
			StatusDist: []KV{{Key: "DISCOVERED", Value: 60}, {Key: "CONFIRMED", Value: 30}},
		},
	}
}

func apiSampleRisk() *APIReportData {
	return &APIReportData{
		ReportType: TypeAPIRisk,
		Risk: &APIRiskReport{
			NewFindings: 20, ClosedFindings: 4, OpenFindings: 16,
			TypeDist:     []KV{{Key: "SHADOW", Value: 10}, {Key: "BOLA", Value: 6}},
			SeverityDist: []KV{{Key: "HIGH", Value: 8}},
			TopEndpoints: []APIRiskEndpoint{{Method: "GET", Path: "/api/pay/{id}", Findings: 9, High: 5}},
			TopSubjects:  []APIRiskSubject{{SubjectType: "IP", SubjectID: "abcdef123456…", Findings: 7}},
		},
	}
}

func apiSampleWeakness() *APIReportData {
	due := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	return &APIReportData{
		ReportType: TypeAPIWeak,
		Weakness: &APIWeaknessReport{
			NewInRange: 6, FixedInRange: 2, OverdueOpen: 3,
			RetestPass: 1, RetestFail: 1,
			StatusDist:   []KV{{Key: "TO_FIX", Value: 4}, {Key: "FIXED", Value: 2}},
			SeverityDist: []KV{{Key: "HIGH", Value: 3}},
			OverdueList:  []APIWeaknessItem{{Name: "未认证敏感接口", Code: "UNAUTHENTICATED_SENSITIVE_API", Severity: "HIGH", Status: "TO_FIX", Owner: "zhangsan", DueDate: &due}},
		},
	}
}

func apiSampleSensitive() *APIReportData {
	return &APIReportData{
		ReportType: TypeAPISens,
		Sensitive: &APISensitiveReport{
			TotalFields: 40, NewInRange: 9,
			TypeDist:     []KV{{Key: "phone", Value: 18}, {Key: "id_card", Value: 12}},
			TopEndpoints: []APISensitiveEndpoint{{Method: "POST", Path: "/api/user/profile", Fields: 8, Types: 3}},
			DailyNew:     []Point{{Time: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC), Value: 5}},
		},
	}
}

func TestBuildAPIConclusionsDeterministic(t *testing.T) {
	samples := map[string]*APIReportData{
		TypeAPIAsset: apiSampleAsset(),
		TypeAPIRisk:  apiSampleRisk(),
		TypeAPIWeak:  apiSampleWeakness(),
		TypeAPISens:  apiSampleSensitive(),
	}
	for typ, d := range samples {
		c1 := BuildAPIConclusions(d)
		c2 := BuildAPIConclusions(d)
		if len(c1) == 0 {
			t.Fatalf("%s conclusions empty", typ)
		}
		if len(c1) != len(c2) {
			t.Fatalf("%s conclusions not deterministic", typ)
		}
		for i := range c1 {
			if c1[i] != c2[i] {
				t.Fatalf("%s conclusions differ at %d", typ, i)
			}
		}
	}
}

func TestBuildAPIConclusionsContent(t *testing.T) {
	asset := strings.Join(BuildAPIConclusions(apiSampleAsset()), "\n")
	for _, m := range []string{"共发现API端点100个", "报告期内新增12个", "确认率为30.0%", "3条未关闭的Shadow", "2个僵尸端点"} {
		if !strings.Contains(asset, m) {
			t.Fatalf("asset conclusions missing %q:\n%s", m, asset)
		}
	}

	risk := strings.Join(BuildAPIConclusions(apiSampleRisk()), "\n")
	for _, m := range []string{"新增API运行时发现20条", "关闭4条", "当前未关闭16条", "SHADOW为报告期内最主要的发现类型", "GET /api/pay/{id}"} {
		if !strings.Contains(risk, m) {
			t.Fatalf("risk conclusions missing %q:\n%s", m, risk)
		}
	}

	weak := strings.Join(BuildAPIConclusions(apiSampleWeakness()), "\n")
	for _, m := range []string{"累计API弱点6个", "新派生6个、完成整改2个", "3个弱点已超过整改期限", "复测2次（通过1次、失败1次）"} {
		if !strings.Contains(weak, m) {
			t.Fatalf("weakness conclusions missing %q:\n%s", m, weak)
		}
	}

	sens := strings.Join(BuildAPIConclusions(apiSampleSensitive()), "\n")
	for _, m := range []string{"累计识别API敏感字段40个", "新识别9个", "手机号码为占比最高的敏感数据类型", "POST /api/user/profile"} {
		if !strings.Contains(sens, m) {
			t.Fatalf("sensitive conclusions missing %q:\n%s", m, sens)
		}
	}
}

func TestBuildAPIConclusionsEmpty(t *testing.T) {
	// 空数据态：各类型均应给出兜底结论而非空切片
	for _, d := range []*APIReportData{
		{ReportType: TypeAPIAsset, Asset: &APIAssetReport{}},
		{ReportType: TypeAPIRisk, Risk: &APIRiskReport{}},
		{ReportType: TypeAPIWeak, Weakness: &APIWeaknessReport{}},
		{ReportType: TypeAPISens, Sensitive: &APISensitiveReport{}},
	} {
		if c := BuildAPIConclusions(d); len(c) == 0 {
			t.Fatalf("%s empty-data conclusions empty", d.ReportType)
		}
		// 空数据态建议兜底
		if s := BuildAPISuggestions(d); len(s) == 0 {
			t.Fatalf("%s empty-data suggestions empty", d.ReportType)
		}
	}
	// 未知类型 → nil
	if c := BuildAPIConclusions(&APIReportData{ReportType: "X"}); c != nil {
		t.Fatalf("unknown type conclusions = %v", c)
	}
}

func TestBuildAPISuggestionsRules(t *testing.T) {
	// 资产：确认率 <50% + Shadow + 僵尸 → 三条定向建议
	asset := strings.Join(BuildAPISuggestions(apiSampleAsset()), "\n")
	for _, m := range []string{"确认率仅为30.0%", "3条未关闭的Shadow", "2个僵尸端点"} {
		if !strings.Contains(asset, m) {
			t.Fatalf("asset suggestions missing %q:\n%s", m, asset)
		}
	}
	// 风险：关闭率 4/20=20% <50% → 积压建议；高危端点定向建议
	risk := strings.Join(BuildAPISuggestions(apiSampleRisk()), "\n")
	for _, m := range []string{"关闭率仅为20.0%", "高危及以上发现5条"} {
		if !strings.Contains(risk, m) {
			t.Fatalf("risk suggestions missing %q:\n%s", m, risk)
		}
	}
	// 弱点：超期 + 复测失败
	weak := strings.Join(BuildAPISuggestions(apiSampleWeakness()), "\n")
	for _, m := range []string{"3个超期未闭环弱点", "复测失败1次"} {
		if !strings.Contains(weak, m) {
			t.Fatalf("weakness suggestions missing %q:\n%s", m, weak)
		}
	}
	// 敏感：Top 清单 + 新增复核
	sens := strings.Join(BuildAPISuggestions(apiSampleSensitive()), "\n")
	for _, m := range []string{"脱敏规则覆盖情况", "新识别敏感字段9个"} {
		if !strings.Contains(sens, m) {
			t.Fatalf("sensitive suggestions missing %q:\n%s", m, sens)
		}
	}
	// 全部良好 → 默认建议
	def := BuildAPISuggestions(&APIReportData{ReportType: TypeAPIAsset, Asset: &APIAssetReport{TotalEndpoints: 10, Confirmed: 10}})
	if len(def) != 1 || !strings.Contains(def[0], "态势良好") {
		t.Fatalf("default api suggestion wrong: %v", def)
	}
}

// ---------- HTML 渲染 ----------

func TestRenderAPIHTMLContent(t *testing.T) {
	d := apiSampleAsset()
	d.RangeStart = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	d.RangeEnd = time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	d.GeneratedAt = time.Now().UTC()
	d.Asset.NewList = []APIEndpointDigest{{
		Method: "GET", Path: "/api/order/{id}", Status: "DISCOVERED", Hits: 42,
		FirstSeen: time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC),
		LastSeen:  time.Date(2026, 7, 19, 9, 0, 0, 0, time.UTC),
	}}
	d.Conclusions = BuildAPIConclusions(d)
	d.Suggestions = BuildAPISuggestions(d)
	html, err := RenderAPIHTML(BuiltinTemplate(), d, "JZ-202607-0002", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := string(html)
	for _, m := range []string{
		"API资产周报", "资产总览", "端点总数", "资产状态分布", "已发现",
		"新增端点清单", "/api/order/{id}", "Shadow端点清单", "结论和建议",
	} {
		if !strings.Contains(out, m) {
			t.Fatalf("asset html missing %q", m)
		}
	}
}

func TestRenderAPIHTMLEscapesInjection(t *testing.T) {
	d := apiSampleRisk()
	d.RangeStart = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	d.RangeEnd = time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	d.GeneratedAt = time.Now().UTC()
	d.Risk.TopEndpoints[0].Path = `<script>alert("xss")</script>`
	d.Conclusions = BuildAPIConclusions(d)
	d.Suggestions = BuildAPISuggestions(d)
	tpl := BuiltinTemplate()
	tpl.CompanyName = `</div><script>evil()</script>`
	html, err := RenderAPIHTML(tpl, d, "JZ-202607-0003", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := string(html)
	if strings.Contains(out, `<script>alert("xss")</script>`) {
		t.Fatal("endpoint path script not escaped")
	}
	if strings.Contains(out, "<script>evil()</script>") {
		t.Fatal("company name script not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("expected escaped script tag in output")
	}
}

func TestRenderAPIHTMLNoExternalResources(t *testing.T) {
	for _, d := range []*APIReportData{apiSampleAsset(), apiSampleRisk(), apiSampleWeakness(), apiSampleSensitive()} {
		d.RangeStart = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
		d.RangeEnd = time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
		d.GeneratedAt = time.Now().UTC()
		d.Conclusions = BuildAPIConclusions(d)
		d.Suggestions = BuildAPISuggestions(d)
		html, err := RenderAPIHTML(BuiltinTemplate(), d, "JZ-202607-0004", nil)
		if err != nil {
			t.Fatalf("%s: %v", d.ReportType, err)
		}
		out := strings.ToLower(string(html))
		for _, bad := range []string{"http://", "https://", "<script", "<link", "@import", "url(", "src="} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s html must not contain external resource %q", d.ReportType, bad)
			}
		}
	}
}

func TestRenderAPIHTMLEmptyState(t *testing.T) {
	// 空数据态：各类型均应渲染空态文案而不报错
	empty := map[string]*APIReportData{
		TypeAPIAsset: {ReportType: TypeAPIAsset, Asset: &APIAssetReport{}},
		TypeAPIRisk:  {ReportType: TypeAPIRisk, Risk: &APIRiskReport{}},
		TypeAPIWeak:  {ReportType: TypeAPIWeak, Weakness: &APIWeaknessReport{}},
		TypeAPISens:  {ReportType: TypeAPISens, Sensitive: &APISensitiveReport{}},
	}
	want := map[string]string{
		TypeAPIAsset: "报告期内无新增端点。",
		TypeAPIRisk:  "报告期内无新增发现。",
		TypeAPIWeak:  "当前无超期未修弱点。",
		TypeAPISens:  "暂无敏感数据字段。",
	}
	for typ, d := range empty {
		d.RangeStart = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
		d.RangeEnd = time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
		d.GeneratedAt = time.Now().UTC()
		d.Conclusions = BuildAPIConclusions(d)
		d.Suggestions = BuildAPISuggestions(d)
		html, err := RenderAPIHTML(BuiltinTemplate(), d, "JZ-202607-0005", nil)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !strings.Contains(string(html), want[typ]) {
			t.Fatalf("%s html missing empty-state %q", typ, want[typ])
		}
	}
}

// ---------- PDF 渲染 ----------

func TestRenderAPIPDFASCIIFallback(t *testing.T) {
	// 字体文件缺失 → 降级 ASCII 摘要而非崩溃
	for _, d := range []*APIReportData{apiSampleAsset(), apiSampleRisk(), apiSampleWeakness(), apiSampleSensitive()} {
		d.RangeStart = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
		d.RangeEnd = time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
		d.GeneratedAt = time.Now().UTC()
		d.Conclusions = BuildAPIConclusions(d)
		d.Suggestions = BuildAPISuggestions(d)
		pdf, err := RenderAPIPDF(BuiltinTemplate(), d, "JZ-202607-0006", "/nonexistent/font.ttf", nil)
		if err != nil {
			t.Fatalf("%s: %v", d.ReportType, err)
		}
		if !strings.HasPrefix(string(pdf), "%PDF") {
			t.Fatalf("%s fallback output is not a PDF", d.ReportType)
		}
	}
}
