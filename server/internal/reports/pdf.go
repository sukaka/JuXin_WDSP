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
	pdf *gofpdf.Fpdf
	cjk bool // 中文字体是否可用
}

// RenderPDF 渲染 PDF 报告。
//   - fontPath 指向内嵌中文字体（NotoSansCJKsc-VF.ttf）；文件缺失时降级为
//     ASCII 摘要 PDF 并在页面注明；字体文件存在但解析失败时返回明确错误。
func RenderPDF(tpl *Template, data *ReportData, reportNo, fontPath string) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("report data is nil")
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	d := &pdfDoc{pdf: pdf}

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
	d.bodyPages(tpl, data, reportNo)

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

// cellText 截断过长文本。
func (d *pdfDoc) cellText(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = string(r[:max-1]) + "…"
	}
	return d.tr(s)
}

func (d *pdfDoc) title(s string) {
	d.pdf.SetFontSize(14)
	d.pdf.SetTextColor(31, 78, 121)
	d.pdf.CellFormat(0, 10, d.tr(s), "", 1, "L", false, 0, "")
	d.pdf.SetFontSize(10)
	d.pdf.SetTextColor(30, 30, 30)
}

func (d *pdfDoc) line(s string) {
	d.pdf.MultiCell(0, 6, d.tr(s), "", "L", false)
}

// table 自绘简单表格（等宽列）。
func (d *pdfDoc) table(header []string, rows [][]string) {
	if len(header) == 0 {
		return
	}
	n := len(header)
	w := 190.0 / float64(n)
	d.pdf.SetFillColor(240, 244, 248)
	for _, h := range header {
		d.pdf.CellFormat(w, 7, d.cellText(h, 40), "1", 0, "L", true, 0, "")
	}
	d.pdf.Ln(-1)
	for _, row := range rows {
		for i := 0; i < n; i++ {
			v := ""
			if i < len(row) {
				v = row[i]
			}
			d.pdf.CellFormat(w, 7, d.cellText(v, 60), "1", 0, "L", false, 0, "")
		}
		d.pdf.Ln(-1)
	}
	d.pdf.Ln(4)
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
	d.pdf.CellFormat(0, 16, d.tr(tpl.LogoText), "", 1, "C", false, 0, "")
	d.pdf.SetFontSize(18)
	d.pdf.CellFormat(0, 14, d.tr(tpl.ProductName+" 安全报告"), "", 1, "C", false, 0, "")
	d.pdf.SetFontSize(11)
	d.pdf.SetTextColor(90, 90, 90)
	d.pdf.CellFormat(0, 8, d.tr(tpl.CompanyName), "", 1, "C", false, 0, "")
	d.pdf.CellFormat(0, 8, d.tr(fmt.Sprintf("报告周期：%s 至 %s（%s）",
		data.RangeStart.Format("2006-01-02"), data.RangeEnd.Format("2006-01-02"), data.ReportType)), "", 1, "C", false, 0, "")
	d.pdf.Ln(10)
	d.pdf.SetTextColor(31, 78, 121)
	d.pdf.CellFormat(0, 8, d.tr("报告编号："+reportNo), "", 1, "C", false, 0, "")
	d.pdf.Ln(16)
	d.pdf.SetTextColor(60, 60, 60)
	d.pdf.CellFormat(0, 7, d.tr(fmt.Sprintf("编制：%s    审核：%s    生成时间：%s",
		orDash(tpl.PreparedBy), orDash(tpl.ReviewedBy), data.GeneratedAt.Format("2006-01-02 15:04"))), "", 1, "C", false, 0, "")
	d.pdf.SetTextColor(30, 30, 30)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// bodyPages 正文章节（按固定顺序、遵循模板章节开关）。
func (d *pdfDoc) bodyPages(tpl *Template, data *ReportData, reportNo string) {
	d.pdf.AddPage()
	if tpl.HeaderText != "" {
		d.pdf.SetFontSize(9)
		d.pdf.SetTextColor(120, 120, 120)
		d.pdf.CellFormat(0, 6, d.tr(tpl.HeaderText+"  "+reportNo), "", 1, "R", false, 0, "")
		d.pdf.SetFontSize(10)
		d.pdf.SetTextColor(30, 30, 30)
	}

	if tpl.Show(SectionPeriod) {
		d.title("一、报告周期")
		d.line(fmt.Sprintf("统计范围：%s 至 %s（UTC，左闭右开）",
			data.RangeStart.Format("2006-01-02 15:04"), data.RangeEnd.Format("2006-01-02 15:04")))
	}

	if tpl.Show(SectionScope) {
		d.title("二、报告范围")
		if data.ScopeAll {
			d.line("本报告覆盖全部受保护应用。")
		} else {
			d.line(fmt.Sprintf("本报告覆盖 %d 个应用。", len(data.Applications)))
		}
		if len(data.Applications) > 0 {
			rows := make([][]string, 0, len(data.Applications))
			for _, a := range data.Applications {
				rows = append(rows, []string{a.Code, a.Name})
			}
			d.table([]string{"应用编码", "应用名称"}, rows)
		}
	}

	if tpl.Show(SectionSummary) {
		d.title("三、管理摘要")
		d.table([]string{"指标", "数值"}, [][]string{
			{"总请求数", fmt.Sprint(data.TotalRequests)},
			{"安全事件总数", fmt.Sprint(data.EventsTotal)},
			{"阻断事件", fmt.Sprint(data.EventsBlocked)},
			{"高危及以上事件", fmt.Sprint(data.HighSeverity)},
			{"CC拦截", fmt.Sprint(data.CCRejected)},
			{"风险等级", data.RiskLevel},
		})
	}

	if tpl.Show(SectionTraffic) {
		d.title("四、请求流量")
		d.line(fmt.Sprintf("报告期内总请求数：%d", data.TotalRequests))
		rows := trendRows(data.RequestsTrend, 31)
		if len(rows) > 0 {
			d.table([]string{"时间", "请求数"}, rows)
		}
	}

	if tpl.Show(SectionEventsOverview) {
		d.title("五、安全事件总览")
		d.table([]string{"指标", "数值"}, [][]string{
			{"事件总数", fmt.Sprint(data.EventsTotal)},
			{"阻断（BLOCK）", fmt.Sprint(data.EventsBlocked)},
			{"观察（OBSERVE）", fmt.Sprint(data.EventsObserved)},
			{"阻断率", fmt.Sprintf("%.1f%%", pct(data.EventsBlocked, data.EventsTotal))},
		})
	}

	if tpl.Show(SectionRiskLevel) {
		d.title("六、风险等级")
		d.line("本期综合风险等级：" + data.RiskLevel)
		d.table([]string{"严重度", "事件数", "占比"}, kvRows(data.SeverityDist, data.EventsTotal))
	}

	if tpl.Show(SectionAttackTypes) {
		d.title("七、攻击类型分布")
		var rows [][]string
		for _, kv := range data.AttackTypes {
			rows = append(rows, []string{AttackTypeName(kv.Key), fmt.Sprint(kv.Value),
				fmt.Sprintf("%.1f%%", pct(kv.Value, data.EventsTotal))})
		}
		d.tableOrEmpty("报告期内无攻击事件。", []string{"攻击类型", "事件数", "占比"}, rows)
	}

	if tpl.Show(SectionAttackTrend) {
		d.title("八、攻击趋势")
		d.tableOrEmpty("报告期内无攻击事件。", []string{"时间", "事件数"}, trendRows(data.AttackTrend, 62))
	}

	if tpl.Show(SectionSourceIPs) {
		d.title("九、攻击源IP TOP10")
		var rows [][]string
		for _, kv := range data.TopSourceIPs {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无攻击源记录。", []string{"源IP", "事件数"}, rows)
	}

	if tpl.Show(SectionApplications) {
		d.title("十、被攻击应用 TOP10")
		var rows [][]string
		for _, kv := range data.AttackedApps {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无被攻击应用记录。", []string{"应用", "事件数"}, rows)
	}

	if tpl.Show(SectionRuleHits) {
		d.title("十一、命中规则 TOP10")
		var rows [][]string
		for _, r := range data.TopRules {
			rows = append(rows, []string{fmt.Sprint(r.RuleID), r.RuleName, fmt.Sprint(r.Hits)})
		}
		d.tableOrEmpty("报告期内无规则命中记录。", []string{"规则ID", "规则名称", "命中次数"}, rows)
	}

	if tpl.Show(SectionCCProtection) {
		d.title("十二、CC防护")
		d.table([]string{"指标", "数值"}, [][]string{
			{"阈值触发次数", fmt.Sprint(data.CCExceeded)},
			{"拦截请求数", fmt.Sprint(data.CCRejected)},
			{"临时封禁创建数", fmt.Sprint(data.CCTempBlocks)},
		})
	}

	if tpl.Show(SectionIPLists) {
		d.title("十三、黑白名单")
		d.table([]string{"指标", "数值"}, [][]string{
			{"白名单命中（放行）", fmt.Sprint(data.IPAllowHits)},
			{"黑名单命中（阻断）", fmt.Sprint(data.IPDenyHits)},
		})
	}

	if tpl.Show(SectionDisposition) {
		d.title("十四、事件处置")
		var rows [][]string
		for _, kv := range data.Dispositions {
			rows = append(rows, []string{kv.Key, fmt.Sprint(kv.Value)})
		}
		d.tableOrEmpty("报告期内无事件处置记录。", []string{"处置状态", "事件数"}, rows)
	}

	if tpl.Show(SectionFalsePositive) {
		d.title("十五、误报和例外")
		d.table([]string{"指标", "数值"}, [][]string{
			{"确认误报事件", fmt.Sprint(data.FalsePositives)},
			{"新增例外策略", fmt.Sprint(data.ExceptionsCreated)},
		})
	}

	if tpl.Show(SectionUpstreamHealth) {
		d.title("十六、源站健康")
		var rows [][]string
		for _, u := range data.Upstreams {
			checked := "-"
			if u.CheckedAt != nil {
				checked = u.CheckedAt.Format("2006-01-02 15:04")
			}
			rows = append(rows, []string{u.Name, u.Address, u.Status, checked})
		}
		d.tableOrEmpty("无源站健康数据。", []string{"源站", "地址", "状态", "最近检查"}, rows)
	}

	if tpl.Show(SectionCertificates) {
		d.title("十七、证书状态")
		var rows [][]string
		for _, c := range data.Certificates {
			exp, days := "-", "-"
			if c.NotAfter != nil {
				exp = c.NotAfter.Format("2006-01-02")
				days = fmt.Sprint(c.DaysRemaining)
			}
			rows = append(rows, []string{c.Name, c.CommonName, c.Status, exp, days})
		}
		d.tableOrEmpty("无证书数据。", []string{"证书", "通用名", "状态", "到期时间", "剩余天数"}, rows)
	}

	if tpl.Show(SectionPublishTasks) {
		d.title("十八、策略发布")
		d.table([]string{"指标", "数值"}, [][]string{
			{"发布任务总数", fmt.Sprint(data.Publish.Total)},
			{"成功", fmt.Sprint(data.Publish.Success)},
			{"失败", fmt.Sprint(data.Publish.Failed)},
			{"进行中", fmt.Sprint(data.Publish.Running)},
		})
		var rows [][]string
		for _, p := range data.Publish.Recent {
			rows = append(rows, []string{p.RequestedAt.Format("2006-01-02 15:04"), p.TaskType, p.Status, p.Summary})
		}
		if len(rows) > 0 {
			d.table([]string{"时间", "类型", "状态", "摘要"}, rows)
		}
	}

	if tpl.Show(SectionSystemHealth) {
		d.title("十九、系统运行")
		var rows [][]string
		for _, cp := range data.Components {
			rows = append(rows, []string{cp.Component, cp.Status, cp.Message, cp.TakenAt.Format("2006-01-02 15:04")})
		}
		d.tableOrEmpty("无系统运行数据。", []string{"组件", "状态", "说明", "快照时间"}, rows)
	}

	if tpl.Show(SectionConclusions) {
		d.title("二十、结论和建议")
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
		d.pdf.SetTextColor(140, 140, 140)
		d.pdf.MultiCell(0, 5, d.tr(tpl.FooterText), "", "C", false)
	}
}

// tableOrEmpty 有数据画表格，无数据输出占位文案。
func (d *pdfDoc) tableOrEmpty(empty string, header []string, rows [][]string) {
	if len(rows) == 0 {
		d.line(empty)
		return
	}
	d.table(header, rows)
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
