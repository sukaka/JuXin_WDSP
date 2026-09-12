package reports

import (
	"fmt"
)

// API 域报告 Word 渲染：结构与 api_pdf.go 正文一致，图表以 PNG 图片嵌入。

// RenderAPIDOCX 渲染 API 域 Word 报告。
func RenderAPIDOCX(tpl *Template, data *APIReportData, reportNo string, charts *APICharts) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("api report data is nil")
	}
	if charts == nil {
		charts = &APICharts{}
	}
	d, err := newDocxDoc()
	if err != nil {
		return nil, err
	}
	defer d.cleanup()
	d.setOrientation(data.PageOrientation)

	d.apiCover(tpl, data, reportNo)
	d.apiBody(tpl, data, reportNo, charts)
	return d.output()
}

// apiCover API 报告封面（遵循 cover 章节开关）。
func (d *docxDoc) apiCover(tpl *Template, data *APIReportData, reportNo string) {
	if !tpl.Show(SectionCover) {
		return
	}
	_, err := d.doc.AddHeading(tpl.ProductName+APIReportTypeName(data.ReportType), 0)
	d.setErr(err)
	d.line(tpl.LogoText + "    " + tpl.CompanyName)
	d.line(fmt.Sprintf("报告周期：%s 至 %s（%s）",
		data.RangeStart.Format("2006-01-02"), data.RangeEnd.Format("2006-01-02"), APIReportTypeName(data.ReportType)))
	d.line("报告编号：" + reportNo)
	d.line(fmt.Sprintf("编制：%s    审核：%s    生成时间：%s",
		orDash(tpl.PreparedBy), orDash(tpl.ReviewedBy), data.GeneratedAt.Format("2006-01-02 15:04")))
	d.doc.AddPageBreak()
}

// apiBody API 报告正文（按报告类型渲染对应小节）。
func (d *docxDoc) apiBody(tpl *Template, data *APIReportData, reportNo string, charts *APICharts) {
	if tpl.HeaderText != "" {
		d.line(tpl.HeaderText + "  " + reportNo)
	}

	if tpl.Show(SectionPeriod) {
		d.heading("一、报告周期")
		d.line(fmt.Sprintf("统计范围：%s 至 %s（UTC，左闭右开）",
			data.RangeStart.Format("2006-01-02 15:04"), data.RangeEnd.Format("2006-01-02 15:04")))
	}

	switch {
	case data.Asset != nil:
		d.apiAssetPages(data.Asset, charts, NewAPIAttention(data))
	case data.Risk != nil:
		d.apiRiskPages(data.Risk, charts, NewAPIAttention(data))
	case data.Weakness != nil:
		d.apiWeaknessPages(data.Weakness, charts, NewAPIAttention(data))
	case data.Sensitive != nil:
		d.apiSensitivePages(data.Sensitive, charts)
	}

	if tpl.Show(SectionConclusions) {
		d.heading("七、结论和建议")
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
		d.line(tpl.FooterText)
	}
}

// apiAssetPages API 资产周报正文。
func (d *docxDoc) apiAssetPages(r *APIAssetReport, charts *APICharts, att *APIAttention) {
	d.heading("二、资产总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"端点总数", fmt.Sprint(r.TotalEndpoints)},
		{"报告期内新增", fmt.Sprint(r.NewEndpoints)},
		{"已确认端点", fmt.Sprint(r.Confirmed)},
		{"端点确认率", fmt.Sprintf("%.1f%%", confirmedRate(r.Confirmed, r.TotalEndpoints))},
		{"Shadow发现（未关闭）", fmt.Sprint(r.ShadowOpen)},
		{"僵尸端点", fmt.Sprint(r.Zombie)},
		{"已下线端点", fmt.Sprint(r.Deprecated)},
	}, []bool{false, false, false, false, att.ShadowOpen, att.Zombie, false})

	d.heading("三、资产状态分布")
	d.chart(charts.Dist1)
	var dist [][]string
	for _, kv := range r.StatusDist {
		dist = append(dist, []string{AssetStatusName(kv.Key), fmt.Sprint(kv.Value),
			fmt.Sprintf("%.1f%%", pct(kv.Value, r.TotalEndpoints))})
	}
	d.tableOrEmpty("暂无API端点资产。", []string{"资产状态", "端点数", "占比"}, dist)

	d.heading("四、新增端点清单")
	var newRows [][]string
	for _, e := range r.NewList {
		newRows = append(newRows, []string{e.Method, e.Path, AssetStatusName(e.Status),
			fmt.Sprint(e.Hits), e.FirstSeen.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("报告期内无新增端点。", []string{"方法", "路径", "状态", "命中次数", "首次发现"}, newRows)

	d.heading("五、Shadow端点清单")
	var shadowRows [][]string
	for _, e := range r.ShadowList {
		shadowRows = append(shadowRows, []string{e.Method, e.Path, AssetStatusName(e.Status),
			fmt.Sprint(e.Hits), e.LastSeen.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("当前无未关闭的Shadow发现。", []string{"方法", "路径", "状态", "命中次数", "最近出现"}, shadowRows)
}

// apiRiskPages API 风险周报正文。
func (d *docxDoc) apiRiskPages(r *APIRiskReport, charts *APICharts, att *APIAttention) {
	d.heading("二、风险总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"报告期内新增发现", fmt.Sprint(r.NewFindings)},
		{"报告期内关闭", fmt.Sprint(r.ClosedFindings)},
		{"当前未关闭", fmt.Sprint(r.OpenFindings)},
	}, []bool{false, false, att.OpenFindings})

	d.heading("三、发现类型分布")
	d.chart(charts.Dist1)
	d.tableOrEmpty("报告期内无新增发现。", []string{"发现类型", "数量", "占比"}, kvRows(findingTypeDisplayKVs(r.TypeDist), r.NewFindings))

	d.heading("四、严重度分布")
	d.chart(charts.Dist2)
	d.tableMarkedOrEmpty("报告期内无新增发现。", []string{"严重度", "数量", "占比"}, kvRows(severityDisplayKVs(r.SeverityDist), r.NewFindings), severityMarks(r.SeverityDist))

	d.heading("五、风险端点 TOP10")
	var epRows [][]string
	for _, e := range r.TopEndpoints {
		epRows = append(epRows, []string{e.Method, e.Path, fmt.Sprint(e.Findings), fmt.Sprint(e.High)})
	}
	d.tableOrEmpty("报告期内无风险端点记录。", []string{"方法", "路径", "新增发现", "高危及以上"}, epRows)

	d.heading("六、风险主体 TOP10")
	var subjRows [][]string
	for _, s := range r.TopSubjects {
		subjRows = append(subjRows, []string{s.SubjectType, s.SubjectID, fmt.Sprint(s.Findings)})
	}
	d.tableOrEmpty("报告期内无风险主体记录。", []string{"主体类型", "主体指纹", "新增发现"}, subjRows)
}

// apiWeaknessPages API 弱点整改报告正文。
func (d *docxDoc) apiWeaknessPages(r *APIWeaknessReport, charts *APICharts, att *APIAttention) {
	d.heading("二、整改总览")
	d.tableMarked([]string{"指标", "数值"}, [][]string{
		{"报告期内新派生弱点", fmt.Sprint(r.NewInRange)},
		{"报告期内完成整改", fmt.Sprint(r.FixedInRange)},
		{"超期未闭环", fmt.Sprint(r.OverdueOpen)},
		{"报告期内复测通过", fmt.Sprint(r.RetestPass)},
		{"报告期内复测失败", fmt.Sprint(r.RetestFail)},
	}, []bool{false, false, att.Overdue, false, att.RetestFail})

	d.heading("三、弱点状态分布")
	d.chart(charts.Dist1)
	var dist [][]string
	for _, kv := range r.StatusDist {
		dist = append(dist, []string{WeaknessStatusName(kv.Key), fmt.Sprint(kv.Value)})
	}
	d.tableOrEmpty("暂无API弱点记录。", []string{"状态", "数量"}, dist)

	d.heading("四、未闭环弱点严重度分布")
	d.chart(charts.Dist2)
	var sev [][]string
	for _, kv := range r.SeverityDist {
		sev = append(sev, []string{SeverityName(kv.Key), fmt.Sprint(kv.Value)})
	}
	d.tableMarkedOrEmpty("当前无未闭环弱点。", []string{"严重度", "数量"}, sev, severityMarks(r.SeverityDist))

	d.heading("五、超期未修清单")
	var overdue [][]string
	for _, w := range r.OverdueList {
		due := "-"
		if w.DueDate != nil {
			due = w.DueDate.Format("2006-01-02")
		}
		overdue = append(overdue, []string{w.Name, w.Severity, WeaknessStatusName(w.Status), orDash(w.Owner), due})
	}
	d.tableOrEmpty("当前无超期未修弱点。", []string{"弱点", "严重度", "状态", "负责人", "整改期限"}, overdue)

	d.heading("六、复测记录")
	var retest [][]string
	for _, it := range r.RetestList {
		result := "失败"
		if it.Action == "RETEST_PASS" {
			result = "通过"
		}
		retest = append(retest, []string{it.WeaknessName, result, it.Actor, it.CreatedAt.Format("2006-01-02 15:04")})
	}
	d.tableOrEmpty("报告期内无复测记录。", []string{"弱点", "复测结果", "操作人", "时间"}, retest)
}

// apiSensitivePages API 敏感数据报告正文。
func (d *docxDoc) apiSensitivePages(r *APISensitiveReport, charts *APICharts) {
	d.heading("二、敏感数据总览")
	d.table([]string{"指标", "数值"}, [][]string{
		{"敏感字段总数", fmt.Sprint(r.TotalFields)},
		{"报告期内新识别", fmt.Sprint(r.NewInRange)},
	})

	d.heading("三、敏感数据类型分布")
	d.chart(charts.Dist1)
	var dist [][]string
	for _, kv := range r.TypeDist {
		dist = append(dist, []string{SensitiveDataTypeName(kv.Key), fmt.Sprint(kv.Value),
			fmt.Sprintf("%.1f%%", pct(kv.Value, r.TotalFields))})
	}
	d.tableOrEmpty("暂无敏感数据字段。", []string{"数据类型", "字段数", "占比"}, dist)

	d.heading("四、涉敏端点 TOP10")
	var epRows [][]string
	for _, e := range r.TopEndpoints {
		epRows = append(epRows, []string{e.Method, e.Path, fmt.Sprint(e.Fields), fmt.Sprint(e.Types)})
	}
	d.tableOrEmpty("暂无涉敏端点。", []string{"方法", "路径", "敏感字段数", "涉及类型数"}, epRows)

	d.heading("五、新增敏感字段趋势")
	d.chart(charts.Trend)
	var trend [][]string
	for _, p := range r.DailyNew {
		trend = append(trend, []string{p.Time.Format("2006-01-02"), fmt.Sprint(p.Value)})
	}
	d.tableOrEmpty("报告期内无新识别敏感字段。", []string{"日期", "新识别字段数"}, trend)
}
