package reports

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/jung-kurt/gofpdf/v2"
)

// pdfFontFamily 内嵌中文字体族名。
const pdfFontFamily = "notocjk"

// pdfDoc PDF 绘制上下文。
type pdfDoc struct {
	pdf           *gofpdf.Fpdf
	cjk           bool // 中文字体是否可用
	imgSeq        int  // 图表图片序号（注册名去重）
	secNo         int  // 章节序号（正文动态编号，仅展示章节递增）
	pageW         float64
	bottomTrigger float64
}

// RenderPDF 渲染 PDF 报告。
//   - fontPath 指向内嵌中文字体（NotoSansCJKsc-VF.ttf）；文件缺失时降级为
//     ASCII 摘要 PDF 并在页面注明；字体文件存在但解析失败时返回明确错误。
//   - charts 为各章节图表（PNG 嵌入）；nil 或字段为空时不插图（字体降级场景）。
//   - data.PageOrientation 决定纸张方向（P 竖向 A4 / L 横向 A4），版宽与列宽随方向缩放。
func RenderPDF(tpl *Template, data *ReportData, reportNo, fontPath string, charts *MainCharts) ([]byte, error) {
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

	d.coverPage(tpl, data, reportNo)
	if err := d.bodyPages(tpl, data, reportNo, charts); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := pdf.OutputAndClose(writerNoClose{&buf}); err != nil {
		return nil, fmt.Errorf("output pdf: %w", err)
	}
	if buf.Len() > MaxReportFileSize {
		return nil, fmt.Errorf("report pdf exceeds %d bytes limit", MaxReportFileSize)
	}
	return buf.Bytes(), nil
}

// writerNoClose 适配 bytes.Buffer 到 io.WriteCloser。
type writerNoClose struct{ *bytes.Buffer }

func (writerNoClose) Close() error { return nil }

// tr 输出文本（CJK 不可用时剔除非 ASCII 字符）。
func (d *pdfDoc) tr(s string) string {
	if d.cjk {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf {
			return r
		}
		return -1
	}, s)
}

// cellText 截断过长文本（先按字符数粗截，再转码）。
func (d *pdfDoc) cellText(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = string(r[:max-1]) + "…"
	}
	return d.tr(s)
}

// cellTextW 按列宽（毫米）截断文本：超出时逐字缩短至放下并补省略号。
// PDF 自绘表格的 CellFormat 不换行不截断，按字符数估算在中文场景必然溢列，
// 必须按实际排版宽度截断。
func (d *pdfDoc) cellTextW(s string, max int, maxWidth float64) string {
	s = d.cellText(s, max)
	const ell = "…"
	if d.pdf.GetStringWidth(s) <= maxWidth {
		return s
	}
	r := []rune(s)
	for len(r) > 1 {
		r = r[:len(r)-1]
		if d.pdf.GetStringWidth(string(r)+ell) <= maxWidth {
			return string(r) + ell
		}
	}
	return ell
}

func (d *pdfDoc) title(s string) {
	d.ensureSpace(10)
	d.pdf.SetFontSize(14)
	d.pdf.SetTextColor(31, 78, 121)
	d.boldCellFormat(0, 10, d.tr(s), "", 1, "L", false)
	d.pdf.SetFontSize(10)
	d.pdf.SetTextColor(0, 0, 0)
}

// secTitle 章节标题（自动中文编号：一、二、三……，仅计入实际展示的章节）。
func (d *pdfDoc) secTitle(s string) {
	d.secNo++
	d.title(cnNumeral(d.secNo) + "、" + s)
}

// ensureSpace 版面不足 h 高度时先换页。
// 必须手动控页：gofpdf 自动分页会在行中间触发，双描文本（伪加粗）两笔会
// 被撕到两页/画回旧坐标，造成单元格孤行与空白大洞。
// 触发线为页高-20mm（竖向 A4=277mm，横向 A4=190mm），由 RenderPDF 按方向注入。
func (d *pdfDoc) ensureSpace(h float64) {
	trigger := d.bottomTrigger
	if trigger <= 0 {
		trigger = 277.0 // 默认竖向 A4（单测未注入时）
	}
	if d.pdf.GetY()+h > trigger {
		d.pdf.AddPage()
	}
}

// fauxBoldOffset 伪加粗双描水平偏移（毫米，随字号缩放）。
// NotoSansCJKsc 可变字体经 gofpdf 嵌入后只能取默认字重（细体观感偏淡），
// 以极小偏移双描模拟加粗，提升屏幕与打印可读性。
func fauxBoldOffset(fontSize float64) float64 {
	off := fontSize * 0.012
	if off < 0.08 {
		off = 0.08
	}
	return off
}

// boldCellFormat 双描绘制单元格文本（伪加粗）。参数语义同 gofpdf CellFormat；
// 居中对齐时向两侧对称偏移，左对齐时仅向右偏移。
func (d *pdfDoc) boldCellFormat(w, h float64, s, borderStr string, ln int, align string, fill bool) {
	ptSize, _ := d.pdf.GetFontSize()
	off := fauxBoldOffset(ptSize)
	x, y := d.pdf.GetX(), d.pdf.GetY()
	if align == "C" {
		d.pdf.SetXY(x-off/2, y)
		d.pdf.CellFormat(w, h, s, borderStr, 0, align, fill, 0, "")
		d.pdf.SetXY(x+off/2, y)
		d.pdf.CellFormat(w, h, s, borderStr, ln, align, fill, 0, "")
		return
	}
	d.pdf.CellFormat(w, h, s, borderStr, 0, align, fill, 0, "")
	d.pdf.SetXY(x+off, y)
	d.pdf.CellFormat(w, h, s, borderStr, ln, align, fill, 0, "")
}

func (d *pdfDoc) line(s string) {
	text := d.tr(s)
	// 仅单行可放下的文本做双描（换行文本二次绘制换行点可能错开，保持单描）
	if d.pdf.GetStringWidth(text) <= d.pageW-22 {
		d.ensureSpace(6)
		ptSize, _ := d.pdf.GetFontSize()
		off := fauxBoldOffset(ptSize)
		x, y := d.pdf.GetX(), d.pdf.GetY()
		d.pdf.MultiCell(0, 6, text, "", "L", false)
		y2 := d.pdf.GetY()
		d.pdf.SetXY(x+off, y)
		d.pdf.MultiCell(0, 6, text, "", "L", false)
		d.pdf.SetY(y2)
		return
	}
	d.pdf.MultiCell(0, 6, text, "", "L", false)
}

// table 自绘简单表格（等宽列）。
func (d *pdfDoc) table(header []string, rows [][]string) {
	d.tableMarked(header, rows, nil)
}

// tableMarked 自绘表格；marks 命中的数据行整行红色加粗（关注项高亮）。
func (d *pdfDoc) tableMarked(header []string, rows [][]string, marks []bool) {
	d.tableMarkedW(header, rows, marks, nil)
}

// tableMarkedW tableMarked 的自定义列宽版本（widths 元素和应等于 190；nil 或长度不符时等宽）。
func (d *pdfDoc) tableMarkedW(header []string, rows [][]string, marks []bool, widths []float64) {
	if len(header) == 0 {
		return
	}
	n := len(header)
	widths = d.normalizeColWidths(widths, n)
	// 手动控页：行高不足先换页并在续页重复表头（防自动分页撕裂双描行）
	drawHeader := func() {
		d.pdf.SetFillColor(240, 244, 248)
		for i, h := range header {
			d.boldCellFormat(widths[i], 7, d.cellTextW(h, 40, widths[i]-2), "1", 0, "L", true)
		}
		d.pdf.Ln(-1)
	}
	d.ensureSpace(7)
	drawHeader()
	for ri, row := range rows {
		if d.pdf.GetY()+7 > d.bottomTrigger {
			d.pdf.AddPage()
			drawHeader() // 续页重复表头
		}
		red := ri < len(marks) && marks[ri]
		if red {
			d.pdf.SetTextColor(216, 57, 49)
		}
		for i := 0; i < n; i++ {
			v := ""
			if i < len(row) {
				v = row[i]
			}
			d.boldCellFormat(widths[i], 7, d.cellTextW(v, 60, widths[i]-2), "1", 0, "L", false)
		}
		if red {
			d.pdf.SetTextColor(0, 0, 0)
		}
		d.pdf.Ln(-1)
	}
	d.pdf.Ln(4)
}

// normalizeColWidths 列宽归一化到实际版宽（预设按 190mm 竖向版宽给出，
// 横向时按比例放大；非法输入回退版宽等分）。
func (d *pdfDoc) normalizeColWidths(widths []float64, n int) []float64 {
	total := d.pageW - 20
	if total < 150 {
		total = 190.0
	}
	if len(widths) == n {
		sum := 0.0
		for _, w := range widths {
			sum += w
		}
		if sum > 150 {
			scale := total / 190.0
			out := make([]float64, n)
			for i, w := range widths {
				out[i] = w * scale
			}
			return out
		}
	}
	w := total / float64(n)
	out := make([]float64, n)
	for i := range out {
		out[i] = w
	}
	return out
}

// warnLine 关注项文本行（cond 为真时红色加粗——红色 + 双描）。
func (d *pdfDoc) warnLine(cond bool, s string) {
	if cond {
		d.pdf.SetTextColor(216, 57, 49)
	}
	d.line(s)
	if cond {
		d.pdf.SetTextColor(0, 0, 0)
	}
}

// coverPage 封面页。
func (d *pdfDoc) coverPage(tpl *Template, data *ReportData, reportNo string) {
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
	d.boldCellFormat(0, 14, d.tr(tpl.ProductName+" 安全报告"), "", 1, "C", false)
	d.pdf.SetFontSize(11)
	d.pdf.SetTextColor(30, 30, 30)
	d.boldCellFormat(0, 8, d.tr(tpl.CompanyName), "", 1, "C", false)
	d.boldCellFormat(0, 8, d.tr(fmt.Sprintf("报告周期：%s 至 %s（%s）",
		data.RangeStart.Format("2006-01-02"), data.RangeEnd.Format("2006-01-02"), ReportTypeName(data.ReportType))), "", 1, "C", false)
	d.pdf.Ln(10)
	d.pdf.SetTextColor(31, 78, 121)
	d.boldCellFormat(0, 8, d.tr("报告编号："+reportNo), "", 1, "C", false)
	d.pdf.Ln(16)
	d.pdf.SetTextColor(30, 30, 30)
	d.boldCellFormat(0, 7, d.tr(fmt.Sprintf("编制：%s    审核：%s    生成时间：%s",
		orDash(tpl.PreparedBy), orDash(tpl.ReviewedBy), data.GeneratedAt.Format("2006-01-02 15:04"))), "", 1, "C", false)
	d.pdf.SetTextColor(0, 0, 0)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// bodyPages 正文章节（按固定顺序、遵循模板章节开关）。
func (d *pdfDoc) bodyPages(tpl *Template, data *ReportData, reportNo string, charts *MainCharts) error {
	d.pdf.AddPage()
	att := NewAttention(data)
	if tpl.HeaderText != "" {
		d.pdf.SetFontSize(9)
		d.pdf.SetTextColor(80, 80, 80)
		d.pdf.CellFormat(0, 6, d.tr(tpl.HeaderText+"  "+reportNo), "", 1, "R", false, 0, "")
		d.pdf.SetFontSize(10)
		d.pdf.SetTextColor(0, 0, 0)
	}

	if tpl.Show(SectionPeriod) {
		d.secTitle("报告周期")
		d.line(fmt.Sprintf("统计范围：%s 至 %s（UTC，左闭右开）；内容范围：%s",
			data.RangeStart.Format("2006-01-02 15:04"), data.RangeEnd.Format("2006-01-02 15:04"), ContentScopeName(data.ContentScope)))
	}

	if tpl.Show(SectionScope) {
		d.secTitle("报告范围")
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
		d.secTitle("管理摘要")
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
		d.secTitle("环比对比")
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
		d.secTitle("请求流量")
		d.line(fmt.Sprintf("报告期内总请求数：%d", data.TotalRequests))
		if err := d.chart(charts.Traffic); err != nil {
			return err
		}
		rows := trendRows(data.RequestsTrend, 31)
		if len(rows) > 0 {
			d.table([]string{"时间", "请求数"}, rows)
		}
	}

	if tpl.Show(SectionEventsOverview) {
		d.secTitle("安全事件总览")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"事件总数", fmt.Sprint(data.EventsTotal)},
			{"阻断（BLOCK）", fmt.Sprint(data.EventsBlocked)},
			{"观察（OBSERVE）", fmt.Sprint(data.EventsObserved)},
			{"阻断率", fmt.Sprintf("%.1f%%", pct(data.EventsBlocked, data.EventsTotal))},
		}, []bool{false, false, false, att.BlockRateLow})
	}

	if tpl.Show(SectionRiskLevel) {
		d.secTitle("风险等级")
		d.warnLine(att.RiskHigh, "本期综合风险等级："+RiskLevelName(data.RiskLevel))
		if err := d.chart(charts.Severity); err != nil {
			return err
		}
		d.tableMarked([]string{"严重度", "事件数", "占比"}, kvRows(severityDisplayKVs(data.SeverityDist), data.EventsTotal), severityMarks(data.SeverityDist))
	}

	if tpl.Show(SectionAttackTypes) {
		d.secTitle("攻击类型分布")
		if err := d.chart(charts.AttackTypes); err != nil {
			return err
		}
		var rows [][]string
		for _, kv := range data.AttackTypes {
			rows = append(rows, []string{AttackTypeName(kv.Key), fmt.Sprint(kv.Value),
				fmt.Sprintf("%.1f%%", pct(kv.Value, data.EventsTotal))})
		}
		d.tableOrEmpty("报告期内无攻击事件。", []string{"攻击类型", "事件数", "占比"}, rows)
	}

	if tpl.Show(SectionAttackTrend) {
		d.secTitle("攻击趋势")
		if err := d.chart(charts.AttackTrend); err != nil {
			return err
		}
		d.tableOrEmpty("报告期内无攻击事件。", []string{"时间", "事件数"}, trendRows(data.AttackTrend, 62))
	}

	if tpl.Show(SectionAttackHours) {
		d.secTitle("攻击时段分布")
		if err := d.chart(charts.AttackHours); err != nil {
			return err
		}
		if name, n := peakHour(data.AttackHours); n > 0 {
			d.line(fmt.Sprintf("攻击高峰时段：%s:00-%s:59（%d 起）。", name, name, n))
		} else {
			d.line("报告期内无攻击事件。")
		}
	}

	if tpl.Show(SectionSourceIPs) {
		d.secTitle("攻击源IP TOP10")
		if err := d.chart(charts.SourceIPs); err != nil {
			return err
		}
		var rows [][]string
		for _, kv := range data.TopSourceIPs {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无攻击源记录。", []string{"源IP", "事件数"}, rows)
	}

	if tpl.Show(SectionSourceGeo) {
		d.secTitle("攻击源地区 TOP10")
		switch {
		case !data.GeoEnabled:
			d.line("GeoIP 数据未启用，无法统计地区分布（部署 geoip/country.mmdb 后可用）。")
		case len(data.SourceGeo) == 0:
			d.line("报告期内无攻击源记录。")
		default:
			if err := d.chart(charts.SourceGeo); err != nil {
				return err
			}
			d.table([]string{"地区", "事件数", "占比"}, kvRows(data.SourceGeo, data.EventsTotal))
		}
	}

	if tpl.Show(SectionApplications) {
		d.secTitle("被攻击应用 TOP10")
		if err := d.chart(charts.AttackedApps); err != nil {
			return err
		}
		var rows [][]string
		for _, kv := range data.AttackedApps {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无被攻击应用记录。", []string{"应用", "事件数"}, rows)
	}

	if tpl.Show(SectionTargetPaths) {
		d.secTitle("被攻击路径 TOP10")
		if err := d.chart(charts.TargetPaths); err != nil {
			return err
		}
		var rows [][]string
		for _, kv := range data.TargetPaths {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmptyW("报告期内无被攻击路径记录。", []string{"路径", "事件数"}, rows, []float64{155, 35})
	}

	if tpl.Show(SectionRuleHits) {
		d.secTitle("命中规则 TOP10")
		var rows [][]string
		for _, r := range data.TopRules {
			rows = append(rows, []string{fmt.Sprint(r.RuleID), RuleDisplayName(r.RuleID, r.RuleName), fmt.Sprint(r.Hits)})
		}
		d.tableOrEmptyW("报告期内无规则命中记录。", []string{"规则ID", "规则名称", "命中次数"}, rows, []float64{25, 130, 35})
	}

	if tpl.Show(SectionEventSamples) {
		d.secTitle("高危事件明细 TOP20")
		var rows [][]string
		var marks []bool
		for _, s := range data.EventSamples {
			rows = append(rows, []string{
				s.OccurredAt.Format("01-02 15:04"), s.ClientIP, s.AppName, s.Method, s.Path,
				AttackTypeName(s.AttackType), SeverityName(s.Severity), ActionName(s.Action),
			})
			marks = append(marks, severityAttention(s.Severity))
		}
		d.tableMarkedOrEmptyW("报告期内无安全事件。", []string{"时间", "源IP", "应用", "方法", "路径", "类型", "严重度", "动作"},
			rows, marks, []float64{28, 22, 22, 12, 61, 15, 15, 15})
	}

	if tpl.Show(SectionCCProtection) {
		d.secTitle("CC防护")
		d.tableMarked([]string{"指标", "数值"}, [][]string{
			{"阈值触发次数", fmt.Sprint(data.CCExceeded)},
			{"拦截请求数", fmt.Sprint(data.CCRejected)},
			{"临时封禁创建数", fmt.Sprint(data.CCTempBlocks)},
		}, []bool{false, att.CCNoBlock, false})
	}

	if tpl.Show(SectionIPLists) {
		d.secTitle("黑白名单")
		d.table([]string{"指标", "数值"}, [][]string{
			{"白名单命中（放行）", fmt.Sprint(data.IPAllowHits)},
			{"黑名单命中（阻断）", fmt.Sprint(data.IPDenyHits)},
		})
	}

	if tpl.Show(SectionDisposition) {
		d.secTitle("事件处置")
		var rows [][]string
		for _, kv := range data.Dispositions {
			rows = append(rows, []string{DispositionName(kv.Key), fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无事件处置记录。", []string{"处置状态", "事件数"}, rows)
	}

	if tpl.Show(SectionFalsePositive) {
		d.secTitle("误报和例外")
		d.table([]string{"指标", "数值"}, [][]string{
			{"确认误报事件", fmt.Sprint(data.FalsePositives)},
			{"新增例外策略", fmt.Sprint(data.ExceptionsCreated)},
		})
	}

	if tpl.Show(SectionUpstreamHealth) {
		d.secTitle("源站健康")
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
		d.secTitle("证书状态")
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
		d.secTitle("策略发布")
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
		d.secTitle("系统运行")
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
		if err := d.apiPartPages(tpl, data, charts); err != nil {
			return err
		}
	}

	if tpl.Show(SectionConclusions) {
		d.secTitle("结论和建议")
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
		d.pdf.Ln(8)
		d.pdf.SetFontSize(9)
		d.pdf.SetTextColor(80, 80, 80)
		d.pdf.MultiCell(0, 5, d.tr(tpl.FooterText), "", "C", false)
	}
	return nil
}

// apiPartPages 主报告 API 安全部分（资产/Shadow/风险/弱点/敏感，11 节）。
func (d *pdfDoc) apiPartPages(tpl *Template, data *ReportData, charts *MainCharts) error {
	api := data.API
	att := NewAPIAttention(api)
	ac := charts.API
	if ac == nil {
		ac = &CombinedAPICharts{}
	}

	// 篇章分隔页
	d.pdf.AddPage()
	d.pdf.SetFontSize(18)
	d.pdf.SetTextColor(31, 78, 121)
	d.boldCellFormat(0, 12, apiPartDivider(data.ContentScope), "", 1, "C", false)
	d.pdf.SetFontSize(10)
	d.pdf.SetTextColor(0, 0, 0)

	if tpl.Show(SectionAPIOverview) {
		d.secTitle("API 资产总览")
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
			if err := d.chart(ac.AssetStatus); err != nil {
				return err
			}
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
		d.secTitle("API 资产清单（全量）")
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
		d.tableMarkedOrEmptyW("暂无API端点资产。", []string{"方法", "路径", "用途", "状态", "标记", "命中次数"},
			rows, marks, []float64{16, 78, 30, 22, 22, 22})
	}

	if tpl.Show(SectionAPINewEndpoints) {
		d.secTitle("新增 API 端点 TOP20")
		var rows [][]string
		if a := api.Asset; a != nil {
			for _, e := range a.NewList {
				rows = append(rows, []string{e.Method, e.Path, AssetStatusName(e.Status), fmt.Sprint(e.Hits), e.FirstSeen.Format("01-02 15:04")})
			}
		}
		d.tableOrEmptyW("报告期内无新增端点。", []string{"方法", "路径", "状态", "命中次数", "首次发现"}, rows, []float64{18, 82, 25, 25, 40})
	}

	if tpl.Show(SectionAPIShadow) {
		d.secTitle("Shadow API 清单")
		var rows [][]string
		if a := api.Asset; a != nil {
			for _, e := range a.ShadowList {
				rows = append(rows, []string{e.Method, e.Path, AssetStatusName(e.Status), fmt.Sprint(e.Hits), e.LastSeen.Format("01-02 15:04")})
			}
		}
		d.tableOrEmptyW("当前无未关闭的Shadow发现。", []string{"方法", "路径", "状态", "命中次数", "最近出现"}, rows, []float64{18, 82, 25, 25, 40})
	}

	if tpl.Show(SectionAPIRisk) {
		d.secTitle("API 风险发现")
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
		d.secTitle("发现类型与严重度分布")
		if r := api.Risk; r != nil {
			if err := d.chart(ac.RiskType); err != nil {
				return err
			}
			d.tableOrEmpty("报告期内无新增发现。", []string{"发现类型", "数量", "占比"}, kvRows(findingTypeDisplayKVs(r.TypeDist), r.NewFindings))
			if err := d.chart(ac.RiskSev); err != nil {
				return err
			}
			d.tableMarkedOrEmpty("报告期内无新增发现。", []string{"严重度", "数量", "占比"}, kvRows(severityDisplayKVs(r.SeverityDist), r.NewFindings), severityMarks(r.SeverityDist))
		} else {
			d.line("报告期内无风险发现。")
		}
	}

	if tpl.Show(SectionAPIRiskTop) {
		d.secTitle("风险端点 TOP10")
		var rows [][]string
		if r := api.Risk; r != nil {
			for _, e := range r.TopEndpoints {
				rows = append(rows, []string{e.Method, e.Path, fmt.Sprint(e.Findings), fmt.Sprint(e.High)})
			}
		}
		d.tableOrEmptyW("报告期内无风险端点记录。", []string{"方法", "路径", "新增发现", "高危及以上"}, rows, []float64{18, 112, 30, 30})
	}

	if tpl.Show(SectionAPISubjects) {
		d.secTitle("风险主体 TOP10")
		var rows [][]string
		if r := api.Risk; r != nil {
			for _, s := range r.TopSubjects {
				rows = append(rows, []string{s.SubjectType, s.SubjectID, fmt.Sprint(s.Findings)})
			}
		}
		d.tableOrEmpty("报告期内无风险主体记录。", []string{"主体类型", "主体指纹", "新增发现"}, rows)
	}

	if tpl.Show(SectionAPIWeakness) {
		d.secTitle("API 弱点整改")
		if w := api.Weakness; w != nil {
			d.tableMarked([]string{"指标", "数值"}, [][]string{
				{"报告期内新派生弱点", fmt.Sprint(w.NewInRange)},
				{"报告期内完成整改", fmt.Sprint(w.FixedInRange)},
				{"超期未闭环", fmt.Sprint(w.OverdueOpen)},
				{"报告期内复测通过", fmt.Sprint(w.RetestPass)},
				{"报告期内复测失败", fmt.Sprint(w.RetestFail)},
			}, []bool{false, false, att.Overdue, false, att.RetestFail})
			if err := d.chart(ac.WeakStatus); err != nil {
				return err
			}
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
		d.secTitle("超期未修清单")
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
		d.tableMarkedOrEmptyW("当前无超期未修弱点。", []string{"弱点", "严重度", "状态", "负责人", "整改期限"}, rows, marks, []float64{70, 25, 30, 30, 35})
	}

	if tpl.Show(SectionAPISensitive) {
		d.secTitle("API 敏感数据")
		if s := api.Sensitive; s != nil {
			d.table([]string{"指标", "数值"}, [][]string{
				{"敏感字段总数", fmt.Sprint(s.TotalFields)},
				{"报告期内新识别", fmt.Sprint(s.NewInRange)},
			})
			if err := d.chart(ac.SensType); err != nil {
				return err
			}
			var dist [][]string
			for _, kv := range s.TypeDist {
				dist = append(dist, []string{SensitiveDataTypeName(kv.Key), fmt.Sprint(kv.Value),
					fmt.Sprintf("%.1f%%", pct(kv.Value, s.TotalFields))})
			}
			d.tableOrEmpty("暂无敏感数据字段。", []string{"数据类型", "字段数", "占比"}, dist)
			if err := d.chart(ac.SensTrend); err != nil {
				return err
			}
		} else {
			d.line("暂无敏感数据字段。")
		}
	}

	if tpl.Show(SectionAPISensitiveTop) {
		d.secTitle("涉敏端点 TOP10")
		var rows [][]string
		if s := api.Sensitive; s != nil {
			for _, e := range s.TopEndpoints {
				rows = append(rows, []string{e.Method, e.Path, fmt.Sprint(e.Fields), fmt.Sprint(e.Types)})
			}
		}
		d.tableOrEmptyW("暂无涉敏端点。", []string{"方法", "路径", "敏感字段数", "涉及类型数"}, rows, []float64{18, 112, 30, 30})
	}
	return nil
}

// tableOrEmpty 有数据画表格，无数据输出占位文案。
func (d *pdfDoc) tableOrEmpty(empty string, header []string, rows [][]string) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.table(header, rows)
}

// tableMarkedOrEmpty tableOrEmpty 的标红变体（marks 命中行红色加粗）。
func (d *pdfDoc) tableMarkedOrEmpty(empty string, header []string, rows [][]string, marks []bool) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.tableMarked(header, rows, marks)
}

// tableOrEmptyW 自定义列宽表格（无数据输出占位文案）。
func (d *pdfDoc) tableOrEmptyW(empty string, header []string, rows [][]string, widths []float64) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.tableMarkedW(header, rows, nil, widths)
}

// tableMarkedOrEmptyW 自定义列宽 + 标红行表格（无数据输出占位文案）。
func (d *pdfDoc) tableMarkedOrEmptyW(empty string, header []string, rows [][]string, marks []bool, widths []float64) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.tableMarkedW(header, rows, marks, widths)
}

// chartImageSizeMM 图表嵌入尺寸（900x420px 按版宽等比缩放）。
func (d *pdfDoc) chartImageSizeMM() (float64, float64) {
	w := d.pageW - 20
	if w < 150 {
		w = 190.0
	}
	return w, w * 420.0 / 900.0
}

// chart 嵌入图表 PNG（版宽 190mm 等比缩放；版面不足时先换页）。
func (d *pdfDoc) chart(img *ChartImage) error {
	if img == nil || len(img.PNG) == 0 {
		return nil
	}
	d.imgSeq++
	name := fmt.Sprintf("chart-%d", d.imgSeq)
	opt := gofpdf.ImageOptions{ImageType: "PNG"}
	info := d.pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(img.PNG))
	if info == nil {
		if err := d.pdf.Error(); err != nil {
			return fmt.Errorf("embed chart image: %w", err)
		}
		return fmt.Errorf("embed chart image: register failed")
	}
	// 版面不足整图高度时换页
	chartW, chartH := d.chartImageSizeMM()
	if d.pdf.GetY()+chartH > d.bottomTrigger {
		d.pdf.AddPage()
	}
	d.pdf.ImageOptions(name, d.pdf.GetX(), d.pdf.GetY(), chartW, chartH, false, opt, 0, "")
	d.pdf.SetY(d.pdf.GetY() + chartH + 4)
	return nil
}

// trendRows 趋势点转表格行（限制行数防超长）。
func trendRows(points []Point, limit int) [][]string {
	if len(points) == 0 {
		return nil
	}
	format := "2006-01-02 15:04"
	rows := make([][]string, 0, len(points))
	for i, p := range points {
		if i >= limit {
			rows = append(rows, []string{fmt.Sprintf("……（共%d个时间点）", len(points)), ""})
			break
		}
		rows = append(rows, []string{p.Time.Format(format), fmt.Sprint(p.Value)})
	}
	return rows
}

// kvRows 计数对转表格行（含占比）。
func kvRows(kvs []KV, total int64) [][]string {
	var rows [][]string
	for _, kv := range kvs {
		rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value), fmt.Sprintf("%.1f%%", pct(kv.Value, total))})
	}
	return rows
}
