package reports

import (
	"bytes"
	"fmt"
	"os"

	"github.com/jung-kurt/gofpdf/v2"
)

// RenderAPIPDF 渲染 API 域 PDF 报告。
// 与 RenderPDF 同一纪律：fontPath 指向内嵌中文字体；文件缺失时降级为
// ASCII 摘要 PDF 并在页面注明；字体文件存在但解析失败时返回明确错误。
// charts 为各小节图表（PNG 嵌入）；nil 或字段为空时不插图（字体降级场景）。
func RenderAPIPDF(tpl *Template, data *APIReportData, reportNo, fontPath string, charts *APICharts) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("api report data is nil")
	}
	if charts == nil {
		charts = &APICharts{}
	}
	pdf := gofpdf.New(NormalizePageOrientation(data.PageOrientation), "mm", "A4", "")
	d := &pdfDoc{pdf: pdf}
	pageW, pageH := pdf.GetPageSize()
	d.pageW = pageW
	d.bottomTrigger = pageH - 20

	if fontPath != "" {
		fontBytes, err := os.ReadFile(fontPath)
		switch {
		case err != nil:
			// 字体文件缺失/不可读 → 降级 ASCII 摘要（不崩溃）
			d.cjk = false
		default:
			pdf.AddUTF8FontFromBytes(pdfFontFamily, "", fontBytes)
			pdf.SetFont(pdfFontFamily, "", 11)
			if err := pdf.Error(); err != nil {
				return nil, fmt.Errorf("%w: %v", errPDFFont, err)
			}
			d.cjk = true
		}
	}
	if !d.cjk {
		pdf.SetFont("helvetica", "", 11)
	}

	d.apiCoverPage(tpl, data, reportNo)
	if err := d.apiBodyPages(tpl, data, reportNo, charts); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := pdf.OutputAndClose(writerNoClose{&buf}); err != nil {
		return nil, fmt.Errorf("output api pdf: %w", err)
	}
	if buf.Len() > MaxReportFileSize {
		return nil, fmt.Errorf("api report pdf exceeds %d bytes limit", MaxReportFileSize)
	}
	return buf.Bytes(), nil
}

// apiCoverPage API 报告封面页。
func (d *pdfDoc) apiCoverPage(tpl *Template, data *APIReportData, reportNo string) {
	d.pdf.AddPage()
	if !d.cjk {
		d.pdf.SetFontSize(10)
		d.line("NOTE: CJK font unavailable. This PDF is an ASCII-only summary; please use the HTML export for the full report.")
		d.pdf.Ln(6)
	}
	d.pdf.SetFontSize(22)
	d.pdf.SetTextColor(31, 78, 121)
	d.boldCellFormat(0, 16, d.tr(tpl.LogoText), "", 1, "C", false)
	d.pdf.SetFontSize(18)
	d.boldCellFormat(0, 14, d.tr(tpl.ProductName+APIReportTypeName(data.ReportType)), "", 1, "C", false)
	d.pdf.SetFontSize(11)
	d.pdf.SetTextColor(30, 30, 30)
	d.boldCellFormat(0, 8, d.tr(tpl.CompanyName), "", 1, "C", false)
	d.boldCellFormat(0, 8, d.tr(fmt.Sprintf("报告周期：%s 至 %s（%s）",
		data.RangeStart.Format("2006-01-02"), data.RangeEnd.Format("2006-01-02"), APIReportTypeName(data.ReportType))), "", 1, "C", false)
	d.pdf.Ln(10)
	d.pdf.SetTextColor(31, 78, 121)
	d.boldCellFormat(0, 8, d.tr("报告编号："+reportNo), "", 1, "C", false)
	d.pdf.Ln(16)
	d.pdf.SetTextColor(30, 30, 30)
	d.boldCellFormat(0, 7, d.tr(fmt.Sprintf("编制：%s    审核：%s    生成时间：%s",
		orDash(tpl.PreparedBy), orDash(tpl.ReviewedBy), data.GeneratedAt.Format("2006-01-02 15:04"))), "", 1, "C", false)
	d.pdf.SetTextColor(0, 0, 0)
}

// apiBodyPages API 报告正文章节（按报告类型渲染对应小节）。
func (d *pdfDoc) apiBodyPages(tpl *Template, data *APIReportData, reportNo string, charts *APICharts) error {
	d.pdf.AddPage()
	if tpl.HeaderText != "" {
		d.pdf.SetFontSize(9)
		d.pdf.SetTextColor(80, 80, 80)
		d.pdf.CellFormat(0, 6, d.tr(tpl.HeaderText+"  "+reportNo), "", 1, "R", false, 0, "")
		d.pdf.SetFontSize(10)
		d.pdf.SetTextColor(0, 0, 0)
	}

	if tpl.Show(SectionPeriod) {
		d.title("一、报告周期")
		d.line(fmt.Sprintf("统计范围：%s 至 %s（UTC，左闭右开）",
			data.RangeStart.Format("2006-01-02 15:04"), data.RangeEnd.Format("2006-01-02 15:04")))
	}

	switch {
	case data.Asset != nil:
		if err := d.apiAssetPages(data.Asset, charts, NewAPIAttention(data)); err != nil {
			return err
		}
	case data.Risk != nil:
		if err := d.apiRiskPages(data.Risk, charts, NewAPIAttention(data)); err != nil {
			return err
		}
	case data.Weakness != nil:
		if err := d.apiWeaknessPages(data.Weakness, charts, NewAPIAttention(data)); err != nil {
			return err
		}
	case data.Sensitive != nil:
		if err := d.apiSensitivePages(data.Sensitive, charts); err != nil {
			return err
		}
	}

	if tpl.Show(SectionConclusions) {
		d.title("七、结论和建议")
		d.line("【结论】")
		for _, s := range data.Conclusions {
			d.line("· " + s)
		}
		d.line("【建议】")
		for _, s := range data.Suggestions {
			d.line("· " + s)
		}
	}

	if tpl.FooterText != "" {
		d.pdf.Ln(8)
		d.pdf.SetFontSize(9)
		d.pdf.SetTextColor(80, 80, 80)
		d.pdf.MultiCell(0, 5, d.tr(tpl.FooterText), "", "C", false)
	}
	return nil
}

// apiAssetPages API 资产周报正文。
func (d *pdfDoc) apiAssetPages(r *APIAssetReport, charts *APICharts, att *APIAttention) error {
	d.title("二、资产总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"端点总数", fmt.Sprint(r.TotalEndpoints)},
		{"报告期内新增", fmt.Sprint(r.NewEndpoints)},
		{"已确认端点", fmt.Sprint(r.Confirmed)},
		{"端点确认率", fmt.Sprintf("%.1f%%", confirmedRate(r.Confirmed, r.TotalEndpoints))},
		{"Shadow发现（未关闭）", fmt.Sprint(r.ShadowOpen)},
		{"僵尸端点", fmt.Sprint(r.Zombie)},
		{"已下线端点", fmt.Sprint(r.Deprecated)},
	}, []bool{false, false, false, false, att.ShadowOpen, att.Zombie, false})

	d.title("三、资产状态分布")
	if err := d.chart(charts.Dist1); err != nil {
		return err
	}
	var dist [][]string
	for _, kv := range r.StatusDist {
		dist = append(dist, []string{AssetStatusName(kv.Key), fmt.Sprint(kv.Value),
			fmt.Sprintf("%.1f%%", pct(kv.Value, r.TotalEndpoints))})
	}
	d.tableOrEmpty("暂无API端点资产。", []string{"资产状态", "端点数", "占比"}, dist)

	d.title("四、新增端点清单")
	var newRows [][]string
	for _, e := range r.NewList {
		newRows = append(newRows, []string{e.Method, e.Path, AssetStatusName(e.Status),
			fmt.Sprint(e.Hits), e.FirstSeen.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("报告期内无新增端点。", []string{"方法", "路径", "状态", "命中次数", "首次发现"}, newRows)

	d.title("五、Shadow端点清单")
	var shadowRows [][]string
	for _, e := range r.ShadowList {
		shadowRows = append(shadowRows, []string{e.Method, e.Path, AssetStatusName(e.Status),
			fmt.Sprint(e.Hits), e.LastSeen.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("当前无未关闭的Shadow发现。", []string{"方法", "路径", "状态", "命中次数", "最近出现"}, shadowRows)
	return nil
}

// apiRiskPages API 风险周报正文。
func (d *pdfDoc) apiRiskPages(r *APIRiskReport, charts *APICharts, att *APIAttention) error {
	d.title("二、风险总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"报告期内新增发现", fmt.Sprint(r.NewFindings)},
		{"报告期内关闭", fmt.Sprint(r.ClosedFindings)},
		{"当前未关闭", fmt.Sprint(r.OpenFindings)},
	}, []bool{false, false, att.OpenFindings})

	d.title("三、发现类型分布")
	if err := d.chart(charts.Dist1); err != nil {
		return err
	}
	d.tableOrEmpty("报告期内无新增发现。", []string{"发现类型", "数量", "占比"}, kvRows(findingTypeDisplayKVs(r.TypeDist), r.NewFindings))

	d.title("四、严重度分布")
	if err := d.chart(charts.Dist2); err != nil {
		return err
	}
	d.tableMarkedOrEmpty("报告期内无新增发现。", []string{"严重度", "数量", "占比"}, kvRows(severityDisplayKVs(r.SeverityDist), r.NewFindings), severityMarks(r.SeverityDist))

	d.title("五、风险端点 TOP10")
	var epRows [][]string
	for _, e := range r.TopEndpoints {
		epRows = append(epRows, []string{e.Method, e.Path, fmt.Sprint(e.Findings), fmt.Sprint(e.High)})
	}
	d.tableOrEmpty("报告期内无风险端点记录。", []string{"方法", "路径", "新增发现", "高危及以上"}, epRows)

	d.title("六、风险主体 TOP10")
	var subjRows [][]string
	for _, s := range r.TopSubjects {
		subjRows = append(subjRows, []string{s.SubjectType, s.SubjectID, fmt.Sprint(s.Findings)})
	}
	d.tableOrEmpty("报告期内无风险主体记录。", []string{"主体类型", "主体指纹", "新增发现"}, subjRows)
	return nil
}

// apiWeaknessPages API 弱点整改报告正文。
func (d *pdfDoc) apiWeaknessPages(r *APIWeaknessReport, charts *APICharts, att *APIAttention) error {
	d.title("二、整改总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"报告期内新派生弱点", fmt.Sprint(r.NewInRange)},
		{"报告期内完成整改", fmt.Sprint(r.FixedInRange)},
		{"超期未闭环", fmt.Sprint(r.OverdueOpen)},
		{"报告期内复测通过", fmt.Sprint(r.RetestPass)},
		{"报告期内复测失败", fmt.Sprint(r.RetestFail)},
	}, []bool{false, false, att.Overdue, false, att.RetestFail})

	d.title("三、弱点状态分布")
	if err := d.chart(charts.Dist1); err != nil {
		return err
	}
	var dist [][]string
	for _, kv := range r.StatusDist {
		dist = append(dist, []string{WeaknessStatusName(kv.Key), fmt.Sprint(kv.Value)})
	}
	d.tableOrEmpty("暂无API弱点记录。", []string{"状态", "数量"}, dist)

	d.title("四、未闭环弱点严重度分布")
	if err := d.chart(charts.Dist2); err != nil {
		return err
	}
	var sev [][]string
	for _, kv := range r.SeverityDist {
		sev = append(sev, []string{SeverityName(kv.Key), fmt.Sprint(kv.Value)})
	}
	d.tableMarkedOrEmpty("当前无未闭环弱点。", []string{"严重度", "数量"}, sev, severityMarks(r.SeverityDist))

	d.title("五、超期未修清单")
	var overdue [][]string
	for _, w := range r.OverdueList {
		due := "-"
		if w.DueDate != nil {
			due = w.DueDate.Format("2006-01-02")
		}
		overdue = append(overdue, []string{w.Name, w.Severity, WeaknessStatusName(w.Status), orDash(w.Owner), due})
	}
	d.tableOrEmpty("当前无超期未修弱点。", []string{"弱点", "严重度", "状态", "负责人", "整改期限"}, overdue)

	d.title("六、复测记录")
	var retest [][]string
	for _, it := range r.RetestList {
		result := "失败"
		if it.Action == "RETEST_PASS" {
			result = "通过"
		}
		retest = append(retest, []string{it.WeaknessName, result, it.Actor, it.CreatedAt.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("报告期内无复测记录。", []string{"弱点", "复测结果", "操作人", "时间"}, retest)
	return nil
}

// apiSensitivePages API 敏感数据报告正文。
func (d *pdfDoc) apiSensitivePages(r *APISensitiveReport, charts *APICharts) error {
	d.title("二、敏感数据总览")
	d.table([]string{"指标", "数值"}, [][]string{
		{"敏感字段总数", fmt.Sprint(r.TotalFields)},
		{"报告期内新识别", fmt.Sprint(r.NewInRange)},
	})

	d.title("三、敏感数据类型分布")
	if err := d.chart(charts.Dist1); err != nil {
		return err
	}
	var dist [][]string
	for _, kv := range r.TypeDist {
		dist = append(dist, []string{SensitiveDataTypeName(kv.Key), fmt.Sprint(kv.Value),
			fmt.Sprintf("%.1f%%", pct(kv.Value, r.TotalFields))})
	}
	d.tableOrEmpty("暂无敏感数据字段。", []string{"数据类型", "字段数", "占比"}, dist)

	d.title("四、涉敏端点 TOP10")
	var epRows [][]string
	for _, e := range r.TopEndpoints {
		epRows = append(epRows, []string{e.Method, e.Path, fmt.Sprint(e.Fields), fmt.Sprint(e.Types)})
	}
	d.tableOrEmpty("暂无涉敏端点。", []string{"方法", "路径", "敏感字段数", "涉及类型数"}, epRows)

	d.title("五、新增敏感字段趋势")
	if err := d.chart(charts.Trend); err != nil {
		return err
	}
	var trend [][]string
	for _, p := range r.DailyNew {
		trend = append(trend, []string{p.Time.Format("2006-01-02"), fmt.Sprint(p.Value)})
	}
	d.tableOrEmpty("报告期内无新识别敏感字段。", []string{"日期", "新识别字段数"}, trend)
	return nil
}
