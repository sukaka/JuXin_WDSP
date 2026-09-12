package reports

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/gomutex/godocx"
	"github.com/gomutex/godocx/common/units"
	"github.com/gomutex/godocx/docx"
	"github.com/gomutex/godocx/wml/ctypes"
	"github.com/gomutex/godocx/wml/stypes"
)

// Word（docx）报告渲染：结构与 PDF 正文一致（21 节、章节开关、相同表格数据），
// 图表以 PNG 图片嵌入。Word 文档由查看端系统字体渲染中文，无需内嵌字体、
// 无降级路径。图片经临时文件中转（godocx AddPicture 仅接受文件路径），
// 渲染完成后立即清理。

// docxTableStyle 表格样式（godocx 内置模板提供）。
const docxTableStyle = "LightGrid-Accent1"

// docxDoc docx 绘制上下文。err 累积首个错误（绘制辅助函数不逐个返回错误）。
type docxDoc struct {
	doc    *docx.RootDoc
	tmp    []string // 临时图片文件
	err    error
	secNo  int // 章节序号（正文动态编号，仅展示章节递增）
	chartW units.Inch
	chartH units.Inch
}

// setOrientation 设置纸张方向与图表嵌入尺寸（A4 竖向 11906x16838 twips / 横向互换）。
func (d *docxDoc) setOrientation(orientation string) {
	d.chartW, d.chartH = units.Inch(6.0), units.Inch(2.8)
	if NormalizePageOrientation(orientation) != OrientationLandscape {
		return
	}
	d.chartW, d.chartH = units.Inch(8.2), units.Inch(8.2*420.0/900.0)
	body := d.doc.Document.Body
	if body == nil {
		return
	}
	if body.SectPr == nil {
		body.SectPr = ctypes.NewSectionProper()
	}
	w, h := uint64(16838), uint64(11906) // A4 横向 twips
	body.SectPr.PageSize = &ctypes.PageSize{Width: &w, Height: &h, Orient: stypes.PageOrientLandscape}
}

// RenderDOCX 渲染 Word 报告。
func RenderDOCX(tpl *Template, data *ReportData, reportNo string, charts *MainCharts) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("report data is nil")
	}
	tpl = tplForScope(tpl, data.ContentScope)
	if charts == nil {
		charts = &MainCharts{}
	}
	d, err := newDocxDoc()
	if err != nil {
		return nil, err
	}
	defer d.cleanup()
	d.setOrientation(data.PageOrientation)

	d.cover(tpl, data, reportNo)
	d.body(tpl, data, reportNo, charts)
	return d.output()
}

// newDocxDoc 创建 docx 绘制上下文。
func newDocxDoc() (*docxDoc, error) {
	doc, err := godocx.NewDocument()
	if err != nil {
		return nil, fmt.Errorf("create docx: %w", err)
	}
	return &docxDoc{doc: doc}, nil
}

// cleanup 关闭文档并清理临时图片文件。
func (d *docxDoc) cleanup() {
	_ = d.doc.Close()
	for _, p := range d.tmp {
		_ = os.Remove(p)
	}
}

// output 序列化文档并校验大小上限与累积错误。
func (d *docxDoc) output() ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	var buf bytes.Buffer
	if err := d.doc.Write(&buf); err != nil {
		return nil, fmt.Errorf("output docx: %w", err)
	}
	if buf.Len() > MaxReportFileSize {
		return nil, fmt.Errorf("report docx exceeds %d bytes limit", MaxReportFileSize)
	}
	return buf.Bytes(), nil
}

// setErr 记录首个错误。
func (d *docxDoc) setErr(err error) {
	if d.err == nil && err != nil {
		d.err = err
	}
}

// heading 章节标题。
func (d *docxDoc) heading(text string) {
	_, err := d.doc.AddHeading(text, 1)
	d.setErr(err)
}

// secHeading 章节标题（自动中文编号：一、二、三……，仅计入实际展示的章节）。
func (d *docxDoc) secHeading(text string) {
	d.secNo++
	d.heading(cnNumeral(d.secNo) + "、" + text)
}

// line 正文段落。
func (d *docxDoc) line(text string) {
	d.doc.AddParagraph(text)
}

// table 表格（表头加粗，单元格截断防超长）。
func (d *docxDoc) table(header []string, rows [][]string) {
	d.tableMarked(header, rows, nil)
}

// tableMarked 表格；marks 命中的数据行整行红色加粗（关注项高亮）。
func (d *docxDoc) tableMarked(header []string, rows [][]string, marks []bool) {
	if len(header) == 0 {
		return
	}
	t := d.doc.AddTable()
	t.Style(docxTableStyle)
	hr := t.AddRow()
	for _, h := range header {
		p := hr.AddCell().AddParagraph("")
		p.AddText(docxCellText(h, 40)).Bold(true)
	}
	for ri, row := range rows {
		r := t.AddRow()
		red := ri < len(marks) && marks[ri]
		for i := range header {
			v := ""
			if i < len(row) {
				v = row[i]
			}
			p := r.AddCell().AddParagraph("")
			run := p.AddText(docxCellText(v, 60))
			if red {
				run.Color(attentionColorHex).Bold(true)
			}
		}
	}
	d.doc.AddEmptyParagraph()
}

// tableOrEmpty 有数据画表格，无数据输出占位文案。
func (d *docxDoc) tableOrEmpty(empty string, header []string, rows [][]string) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.table(header, rows)
}

// tableMarkedOrEmpty tableOrEmpty 的标红变体（marks 命中行红色加粗）。
func (d *docxDoc) tableMarkedOrEmpty(empty string, header []string, rows [][]string, marks []bool) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.tableMarked(header, rows, marks)
}

// warnLine 关注项文本行（cond 为真时红色加粗）。
func (d *docxDoc) warnLine(cond bool, s string) {
	p := d.doc.AddParagraph("")
	run := p.AddText(s)
	if cond {
		run.Color(attentionColorHex).Bold(true)
	}
}

// chart 嵌入图表 PNG（经临时文件中转，渲染结束后清理）。
func (d *docxDoc) chart(img *ChartImage) {
	if img == nil || len(img.PNG) == 0 {
		return
	}
	f, err := os.CreateTemp("", "jz-report-chart-*.png")
	if err != nil {
		d.setErr(fmt.Errorf("create chart temp file: %w", err))
		return
	}
	d.tmp = append(d.tmp, f.Name())
	if _, err := f.Write(img.PNG); err != nil {
		_ = f.Close()
		d.setErr(fmt.Errorf("write chart temp file: %w", err))
		return
	}
	if err := f.Close(); err != nil {
		d.setErr(fmt.Errorf("close chart temp file: %w", err))
		return
	}
	_, err = d.doc.AddPicture(f.Name(), d.chartW, d.chartH)
	d.setErr(err)
}

// docxCellText 截断过长文本（Word 原生渲染中文，无需 ASCII 降级）。
func docxCellText(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = string(r[:max-1]) + "…"
	}
	return s
}

// cover 封面（遵循 cover 章节开关）。
func (d *docxDoc) cover(tpl *Template, data *ReportData, reportNo string) {
	if !tpl.Show(SectionCover) {
		return
	}
	_, err := d.doc.AddHeading(tpl.ProductName+" 安全报告", 0)
	d.setErr(err)
	d.line(tpl.LogoText + "    " + tpl.CompanyName)
	d.line(fmt.Sprintf("报告周期：%s 至 %s（%s）",
		data.RangeStart.Format("2006-01-02"), data.RangeEnd.Format("2006-01-02"), ReportTypeName(data.ReportType)))
	d.line("报告编号：" + reportNo)
	d.line(fmt.Sprintf("编制：%s    审核：%s    生成时间：%s",
		orDash(tpl.PreparedBy), orDash(tpl.ReviewedBy), data.GeneratedAt.Format("2006-01-02 15:04")))
	d.doc.AddPageBreak()
}

// body 正文章节（按固定顺序、遵循模板章节开关）。
func (d *docxDoc) body(tpl *Template, data *ReportData, reportNo string, charts *MainCharts) {
	att := NewAttention(data)
	if tpl.HeaderText != "" {
		d.line(tpl.HeaderText + "  " + reportNo)
	}

	if tpl.Show(SectionPeriod) {
		d.secHeading("报告周期")
		d.line(fmt.Sprintf("统计范围：%s 至 %s（UTC，左闭右开）；内容范围：%s",
			data.RangeStart.Format("2006-01-02 15:04"), data.RangeEnd.Format("2006-01-02 15:04"), ContentScopeName(data.ContentScope)))
	}

	if tpl.Show(SectionScope) {
		d.secHeading("报告范围")
		if data.ScopeAll {
			d.line("本报告覆盖全部受保护应用。")
		} else {
			d.line(fmt.Sprintf("本报告覆盖 %d 个应用。", len(data.Applications)))
		}
		if len(data.Applications) > 0 {
			if data.API != nil {
				rows := make([][]string, 0, len(data.Applications)+1)
				for _, a := range data.Applications {
					rows = append(rows, []string{a.Code, a.Name, fmt.Sprint(a.APIEndpoints)})
				}
				if len(data.Applications) > 1 {
					rows = append(rows, []string{"合计", "", fmt.Sprint(totalAPIEndpoints(data.Applications))})
				}
				d.table([]string{"应用编码", "应用名称", "API 端点数"}, rows)
			} else {
				rows := make([][]string, 0, len(data.Applications))
				for _, a := range data.Applications {
					rows = append(rows, []string{a.Code, a.Name})
				}
				d.table([]string{"应用编码", "应用名称"}, rows)
			}
		}
	}

	if tpl.Show(SectionSummary) {
		d.secHeading("管理摘要")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"总请求数", fmt.Sprint(data.TotalRequests)},
			{"安全事件总数", fmt.Sprint(data.EventsTotal)},
			{"阻断事件", fmt.Sprint(data.EventsBlocked)},
			{"高危及以上事件", fmt.Sprint(data.HighSeverity)},
			{"CC拦截", fmt.Sprint(data.CCRejected)},
			{"风险等级", RiskLevelName(data.RiskLevel)},
		}, []bool{false, false, false, att.HighSeverity, att.CCNoBlock, att.RiskHigh})
	}

	if tpl.Show(SectionComparison) {
		d.secHeading("环比对比")
		rows := BuildComparisonRows(data)
		if len(rows) == 0 {
			d.line("无上一周期对照数据。")
		} else {
			tableRows := make([][]string, 0, len(rows))
			for _, r := range rows {
				tableRows = append(tableRows, []string{r.Name, r.Current, r.Previous, r.Delta})
			}
			d.tableMarked([]string{"指标", "本期", "上期", "变化"}, tableRows, comparisonMarks(rows))
		}
	}

	if tpl.Show(SectionTraffic) {
		d.secHeading("请求流量")
		d.line(fmt.Sprintf("报告期内总请求数：%d", data.TotalRequests))
		d.chart(charts.Traffic)
		if rows := trendRows(data.RequestsTrend, 31); len(rows) > 0 {
			d.table([]string{"时间", "请求数"}, rows)
		}
	}

	if tpl.Show(SectionEventsOverview) {
		d.secHeading("安全事件总览")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"事件总数", fmt.Sprint(data.EventsTotal)},
			{"阻断（BLOCK）", fmt.Sprint(data.EventsBlocked)},
			{"观察（OBSERVE）", fmt.Sprint(data.EventsObserved)},
			{"阻断率", fmt.Sprintf("%.1f%%", pct(data.EventsBlocked, data.EventsTotal))},
		}, []bool{false, false, false, att.BlockRateLow})
	}

	if tpl.Show(SectionRiskLevel) {
		d.secHeading("风险等级")
		d.warnLine(att.RiskHigh, "本期综合风险等级："+RiskLevelName(data.RiskLevel))
		d.chart(charts.Severity)
		d.tableMarked([]string{"严重度", "事件数", "占比"}, kvRows(severityDisplayKVs(data.SeverityDist), data.EventsTotal), severityMarks(data.SeverityDist))
	}

	if tpl.Show(SectionAttackTypes) {
		d.secHeading("攻击类型分布")
		d.chart(charts.AttackTypes)
		var rows [][]string
		for _, kv := range data.AttackTypes {
			rows = append(rows, []string{AttackTypeName(kv.Key), fmt.Sprint(kv.Value),
				fmt.Sprintf("%.1f%%", pct(kv.Value, data.EventsTotal))})
		}
		d.tableOrEmpty("报告期内无攻击事件。", []string{"攻击类型", "事件数", "占比"}, rows)
	}

	if tpl.Show(SectionAttackTrend) {
		d.secHeading("攻击趋势")
		d.chart(charts.AttackTrend)
		d.tableOrEmpty("报告期内无攻击事件。", []string{"时间", "事件数"}, trendRows(data.AttackTrend, 62))
	}

	if tpl.Show(SectionAttackHours) {
		d.secHeading("攻击时段分布")
		d.chart(charts.AttackHours)
		if name, n := peakHour(data.AttackHours); n > 0 {
			d.line(fmt.Sprintf("攻击高峰时段：%s:00-%s:59（%d 起）。", name, name, n))
		} else {
			d.line("报告期内无攻击事件。")
		}
	}

	if tpl.Show(SectionSourceIPs) {
		d.secHeading("攻击源IP TOP10")
		d.chart(charts.SourceIPs)
		var rows [][]string
		for _, kv := range data.TopSourceIPs {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无攻击源记录。", []string{"源IP", "事件数"}, rows)
	}

	if tpl.Show(SectionSourceGeo) {
		d.secHeading("攻击源地区 TOP10")
		switch {
		case !data.GeoEnabled:
			d.line("GeoIP 数据未启用，无法统计地区分布（部署 geoip/country.mmdb 后可用）。")
		case len(data.SourceGeo) == 0:
			d.line("报告期内无攻击源记录。")
		default:
			d.chart(charts.SourceGeo)
			d.table([]string{"地区", "事件数", "占比"}, kvRows(data.SourceGeo, data.EventsTotal))
		}
	}

	if tpl.Show(SectionApplications) {
		d.secHeading("被攻击应用 TOP10")
		d.chart(charts.AttackedApps)
		var rows [][]string
		for _, kv := range data.AttackedApps {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无被攻击应用记录。", []string{"应用", "事件数"}, rows)
	}

	if tpl.Show(SectionTargetPaths) {
		d.secHeading("被攻击路径 TOP10")
		d.chart(charts.TargetPaths)
		var rows [][]string
		for _, kv := range data.TargetPaths {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无被攻击路径记录。", []string{"路径", "事件数"}, rows)
	}

	if tpl.Show(SectionRuleHits) {
		d.secHeading("命中规则 TOP10")
		var rows [][]string
		for _, r := range data.TopRules {
			rows = append(rows, []string{fmt.Sprint(r.RuleID), RuleDisplayName(r.RuleID, r.RuleName), fmt.Sprint(r.Hits)})
		}
		d.tableOrEmpty("报告期内无规则命中记录。", []string{"规则ID", "规则名称", "命中次数"}, rows)
	}

	if tpl.Show(SectionEventSamples) {
		d.secHeading("高危事件明细 TOP20")
		var rows [][]string
		var marks []bool
		for _, s := range data.EventSamples {
			rows = append(rows, []string{
				s.OccurredAt.Format("01-02 15:04"), s.ClientIP, s.AppName, s.Method, s.Path,
				AttackTypeName(s.AttackType), SeverityName(s.Severity), ActionName(s.Action),
			})
			marks = append(marks, severityAttention(s.Severity))
		}
		d.tableMarkedOrEmpty("报告期内无安全事件。", []string{"时间", "源IP", "应用", "方法", "路径", "类型", "严重度", "动作"}, rows, marks)
	}

	if tpl.Show(SectionCCProtection) {
		d.secHeading("CC防护")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"阈值触发次数", fmt.Sprint(data.CCExceeded)},
			{"拦截请求数", fmt.Sprint(data.CCRejected)},
			{"临时封禁创建数", fmt.Sprint(data.CCTempBlocks)},
		}, []bool{false, att.CCNoBlock, false})
	}

	if tpl.Show(SectionIPLists) {
		d.secHeading("黑白名单")
		d.table([]string{"指标", "数值"}, [][]string{
			{"白名单命中（放行）", fmt.Sprint(data.IPAllowHits)},
			{"黑名单命中（阻断）", fmt.Sprint(data.IPDenyHits)},
		})
	}

	if tpl.Show(SectionDisposition) {
		d.secHeading("事件处置")
		var rows [][]string
		for _, kv := range data.Dispositions {
			rows = append(rows, []string{DispositionName(kv.Key), fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无事件处置记录。", []string{"处置状态", "事件数"}, rows)
	}

	if tpl.Show(SectionFalsePositive) {
		d.secHeading("误报和例外")
		d.table([]string{"指标", "数值"}, [][]string{
			{"确认误报事件", fmt.Sprint(data.FalsePositives)},
			{"新增例外策略", fmt.Sprint(data.ExceptionsCreated)},
		})
	}

	if tpl.Show(SectionUpstreamHealth) {
		d.secHeading("源站健康")
		var rows [][]string
		var marks []bool
		for _, u := range data.Upstreams {
			checked := "-"
			if u.CheckedAt != nil {
				checked = u.CheckedAt.Format("2006-01-02 15:04")
			}
			rows = append(rows, []string{u.Name, u.Address, UpstreamStatusName(u.Status), checked})
			marks = append(marks, upstreamAttention(u.Status))
		}
		d.tableMarkedOrEmpty("无源站健康数据。", []string{"源站", "地址", "状态", "最近检查"}, rows, marks)
	}

	if tpl.Show(SectionCertificates) {
		d.secHeading("证书状态")
		var rows [][]string
		var marks []bool
		for _, c := range data.Certificates {
			exp, days := "-", "-"
			if c.NotAfter != nil {
				exp = c.NotAfter.Format("2006-01-02")
				days = fmt.Sprint(c.DaysRemaining)
			}
			rows = append(rows, []string{c.Name, c.CommonName, CertStatusName(c.Status), exp, days})
			marks = append(marks, c.NotAfter != nil && certAttention(c.DaysRemaining))
		}
		d.tableMarkedOrEmpty("无证书数据。", []string{"证书", "通用名", "状态", "到期时间", "剩余天数"}, rows, marks)
	}

	if tpl.Show(SectionPublishTasks) {
		d.secHeading("策略发布")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"发布任务总数", fmt.Sprint(data.Publish.Total)},
			{"成功", fmt.Sprint(data.Publish.Success)},
			{"失败", fmt.Sprint(data.Publish.Failed)},
			{"进行中", fmt.Sprint(data.Publish.Running)},
		}, []bool{false, false, att.PublishFailed, false})
		var rows [][]string
		for _, p := range data.Publish.Recent {
			rows = append(rows, []string{p.RequestedAt.Format("2006-01-02 15:04"), PublishTaskTypeName(p.TaskType), PublishStatusName(p.Status), p.Summary})
		}
		if len(rows) > 0 {
			d.table([]string{"时间", "类型", "状态", "摘要"}, rows)
		}
	}

	if tpl.Show(SectionSystemHealth) {
		d.secHeading("系统运行")
		var rows [][]string
		var marks []bool
		for _, cp := range data.Components {
			rows = append(rows, []string{cp.Component, ComponentStatusName(cp.Status), cp.Message, cp.TakenAt.Format("2006-01-02 15:04")})
			marks = append(marks, componentAttention(cp.Status))
		}
		d.tableMarkedOrEmpty("无系统运行数据。", []string{"组件", "状态", "说明", "快照时间"}, rows, marks)
	}

	// 下篇：API 安全部分（WDSP 且 API 动态防护开启时输出，约占报告内容 40%）
	if showAPIPart(tpl, data) {
		d.apiPartPages(tpl, data, charts)
	}

	if tpl.Show(SectionConclusions) {
		d.secHeading("结论和建议")
		if len(data.Conclusions) > 0 {
			d.line("【结论】")
			for _, s := range data.Conclusions {
				d.line("· " + s)
			}
		}
		if showAPIPart(tpl, data) && len(data.API.Conclusions) > 0 {
			d.line("【API 安全结论】")
			for _, s := range data.API.Conclusions {
				d.line("· " + s)
			}
		}
		if len(data.Suggestions) > 0 {
			d.line("【建议】")
			for _, s := range data.Suggestions {
				d.line("· " + s)
			}
		}
		if showAPIPart(tpl, data) && len(data.API.Suggestions) > 0 {
			d.line("【API 安全建议】")
			for _, s := range data.API.Suggestions {
				d.line("· " + s)
			}
		}
	}

	if tpl.FooterText != "" {
		d.line(tpl.FooterText)
	}
}

// apiPartPages 主报告 API 安全部分（资产/Shadow/风险/弱点/敏感，11 节）。
func (d *docxDoc) apiPartPages(tpl *Template, data *ReportData, charts *MainCharts) {
	api := data.API
	att := NewAPIAttention(api)
	ac := charts.API
	if ac == nil {
		ac = &CombinedAPICharts{}
	}

	// 篇章分隔页
	d.doc.AddPageBreak()
	if _, err := d.doc.AddHeading(apiPartDivider(data.ContentScope), 0); err != nil {
		d.setErr(err)
	}

	if tpl.Show(SectionAPIOverview) {
		d.secHeading("API 资产总览")
		if a := api.Asset; a != nil {
			d.tableMarked([]string{"指标", "数值"}, [][]string{
				{"端点总数", fmt.Sprint(a.TotalEndpoints)},
				{"报告期内新增", fmt.Sprint(a.NewEndpoints)},
				{"已确认端点", fmt.Sprint(a.Confirmed)},
				{"端点确认率", fmt.Sprintf("%.1f%%", confirmedRate(a.Confirmed, a.TotalEndpoints))},
				{"Shadow发现（未关闭）", fmt.Sprint(a.ShadowOpen)},
				{"僵尸端点", fmt.Sprint(a.Zombie)},
				{"已下线端点", fmt.Sprint(a.Deprecated)},
			}, []bool{false, false, false, false, att.ShadowOpen, att.Zombie, false})
			d.chart(ac.AssetStatus)
			var dist [][]string
			for _, kv := range a.StatusDist {
				dist = append(dist, []string{AssetStatusName(kv.Key), fmt.Sprint(kv.Value),
					fmt.Sprintf("%.1f%%", pct(kv.Value, a.TotalEndpoints))})
			}
			d.tableOrEmpty("暂无API端点资产。", []string{"资产状态", "端点数", "占比"}, dist)
		} else {
			d.line("暂无API端点资产。")
		}
	}

	if tpl.Show(SectionAPIAssetList) && api.AssetList != nil {
		d.secHeading("API 资产清单（全量）")
		note := fmt.Sprintf("共 %d 条 API 资产", api.AssetListTotal)
		if api.AssetListTotal > int64(len(api.AssetList)) {
			note += fmt.Sprintf("（显示前 %d 条，按命中次数排序）", len(api.AssetList))
		}
		d.line(note + "。")
		var rows [][]string
		var marks []bool
		for _, it := range api.AssetList {
			purpose := it.Purpose
			if purpose == "" {
				purpose = "未分类"
			}
			rows = append(rows, []string{it.Method, it.Path, purpose, AssetStatusName(it.Status), it.FlagLabel(), fmt.Sprint(it.Hits)})
			marks = append(marks, it.IsShadow || it.IsZombie)
		}
		d.tableMarkedOrEmpty("暂无API端点资产。", []string{"方法", "路径", "用途", "状态", "标记", "命中次数"}, rows, marks)
	}

	if tpl.Show(SectionAPINewEndpoints) {
		d.secHeading("新增 API 端点 TOP20")
		var rows [][]string
		if a := api.Asset; a != nil {
			for _, e := range a.NewList {
				rows = append(rows, []string{e.Method, e.Path, AssetStatusName(e.Status), fmt.Sprint(e.Hits), e.FirstSeen.Format("01-02 15:04")})
			}
		}
		d.tableOrEmpty("报告期内无新增端点。", []string{"方法", "路径", "状态", "命中次数", "首次发现"}, rows)
	}

	if tpl.Show(SectionAPIShadow) {
		d.secHeading("Shadow API 清单")
		var rows [][]string
		if a := api.Asset; a != nil {
			for _, e := range a.ShadowList {
				rows = append(rows, []string{e.Method, e.Path, AssetStatusName(e.Status), fmt.Sprint(e.Hits), e.LastSeen.Format("01-02 15:04")})
			}
		}
		d.tableOrEmpty("当前无未关闭的Shadow发现。", []string{"方法", "路径", "状态", "命中次数", "最近出现"}, rows)
	}

	if tpl.Show(SectionAPIRisk) {
		d.secHeading("API 风险发现")
		if r := api.Risk; r != nil {
			d.tableMarked([]string{"指标", "数值"}, [][]string{
				{"报告期内新增发现", fmt.Sprint(r.NewFindings)},
				{"报告期内关闭", fmt.Sprint(r.ClosedFindings)},
				{"当前未关闭", fmt.Sprint(r.OpenFindings)},
			}, []bool{false, false, att.OpenFindings})
		} else {
			d.line("报告期内无风险发现。")
		}
	}

	if tpl.Show(SectionAPIRiskDist) {
		d.secHeading("发现类型与严重度分布")
		if r := api.Risk; r != nil {
			d.chart(ac.RiskType)
			d.tableOrEmpty("报告期内无新增发现。", []string{"发现类型", "数量", "占比"}, kvRows(findingTypeDisplayKVs(r.TypeDist), r.NewFindings))
			d.chart(ac.RiskSev)
			d.tableMarkedOrEmpty("报告期内无新增发现。", []string{"严重度", "数量", "占比"}, kvRows(severityDisplayKVs(r.SeverityDist), r.NewFindings), severityMarks(r.SeverityDist))
		} else {
			d.line("报告期内无风险发现。")
		}
	}

	if tpl.Show(SectionAPIRiskTop) {
		d.secHeading("风险端点 TOP10")
		var rows [][]string
		if r := api.Risk; r != nil {
			for _, e := range r.TopEndpoints {
				rows = append(rows, []string{e.Method, e.Path, fmt.Sprint(e.Findings), fmt.Sprint(e.High)})
			}
		}
		d.tableOrEmpty("报告期内无风险端点记录。", []string{"方法", "路径", "新增发现", "高危及以上"}, rows)
	}

	if tpl.Show(SectionAPISubjects) {
		d.secHeading("风险主体 TOP10")
		var rows [][]string
		if r := api.Risk; r != nil {
			for _, s := range r.TopSubjects {
				rows = append(rows, []string{s.SubjectType, s.SubjectID, fmt.Sprint(s.Findings)})
			}
		}
		d.tableOrEmpty("报告期内无风险主体记录。", []string{"主体类型", "主体指纹", "新增发现"}, rows)
	}

	if tpl.Show(SectionAPIWeakness) {
		d.secHeading("API 弱点整改")
		if w := api.Weakness; w != nil {
			d.tableMarked([]string{"指标", "数值"}, [][]string{
				{"报告期内新派生弱点", fmt.Sprint(w.NewInRange)},
				{"报告期内完成整改", fmt.Sprint(w.FixedInRange)},
				{"超期未闭环", fmt.Sprint(w.OverdueOpen)},
				{"报告期内复测通过", fmt.Sprint(w.RetestPass)},
				{"报告期内复测失败", fmt.Sprint(w.RetestFail)},
			}, []bool{false, false, att.Overdue, false, att.RetestFail})
			d.chart(ac.WeakStatus)
			var dist [][]string
			for _, kv := range w.StatusDist {
				dist = append(dist, []string{WeaknessStatusName(kv.Key), fmt.Sprint(kv.Value)})
			}
			d.tableOrEmpty("暂无API弱点记录。", []string{"状态", "数量"}, dist)
		} else {
			d.line("暂无API弱点记录。")
		}
	}

	if tpl.Show(SectionAPIWeakOverdue) {
		d.secHeading("超期未修清单")
		var rows [][]string
		var marks []bool
		if w := api.Weakness; w != nil {
			for _, item := range w.OverdueList {
				due := "-"
				if item.DueDate != nil {
					due = item.DueDate.Format("2006-01-02")
				}
				rows = append(rows, []string{item.Name, SeverityName(item.Severity), WeaknessStatusName(item.Status), orDash(item.Owner), due})
				marks = append(marks, severityAttention(item.Severity))
			}
		}
		d.tableMarkedOrEmpty("当前无超期未修弱点。", []string{"弱点", "严重度", "状态", "负责人", "整改期限"}, rows, marks)
	}

	if tpl.Show(SectionAPISensitive) {
		d.secHeading("API 敏感数据")
		if s := api.Sensitive; s != nil {
			d.table([]string{"指标", "数值"}, [][]string{
				{"敏感字段总数", fmt.Sprint(s.TotalFields)},
				{"报告期内新识别", fmt.Sprint(s.NewInRange)},
			})
			d.chart(ac.SensType)
			var dist [][]string
			for _, kv := range s.TypeDist {
				dist = append(dist, []string{SensitiveDataTypeName(kv.Key), fmt.Sprint(kv.Value),
					fmt.Sprintf("%.1f%%", pct(kv.Value, s.TotalFields))})
			}
			d.tableOrEmpty("暂无敏感数据字段。", []string{"数据类型", "字段数", "占比"}, dist)
			d.chart(ac.SensTrend)
		} else {
			d.line("暂无敏感数据字段。")
		}
	}

	if tpl.Show(SectionAPISensitiveTop) {
		d.secHeading("涉敏端点 TOP10")
		var rows [][]string
		if s := api.Sensitive; s != nil {
			for _, e := range s.TopEndpoints {
				rows = append(rows, []string{e.Method, e.Path, fmt.Sprint(e.Fields), fmt.Sprint(e.Types)})
			}
		}
		d.tableOrEmpty("暂无涉敏端点。", []string{"方法", "路径", "敏感字段数", "涉及类型数"}, rows)
	}
}
