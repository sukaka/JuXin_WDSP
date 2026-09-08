package reports

import (
	"bytes"
	"fmt"
	"html/template"
	"time"
)

// htmlTemplate 固定内置 HTML 报告模板。
// 模板本身为系统代码，用户可配置的模板字段（公司名/页眉页脚等）仅作为
// 数据传入并由 html/template 自动转义——不存在任意代码/脚本/外部请求执行面。
// 图表 SVG 为本包本地渲染产物（标签已消毒），经 chartSVG 以 template.HTML 注入。
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"attackName":     AttackTypeName,
	"pct":            pct,
	"chartSVG":       chartSVGHTML,
	"warn":           warnHTML,
	"sevAlert":       severityAttention,
	"certAlert":      certAttention,
	"upAlert":        upstreamAttention,
	"compAlert":      componentAttention,
	"reportType":     ReportTypeName,
	"severityName":   SeverityName,
	"riskName":       RiskLevelName,
	"dispName":       DispositionName,
	"upStatusName":   UpstreamStatusName,
	"certStatusName": CertStatusName,
	"pubType":        PublishTaskTypeName,
	"pubStatus":      PublishStatusName,
	"ruleDisplay":    RuleDisplayName,
	"actionName":     ActionName,
	"peakHourText":   peakHourText,
	"confirmedRate":  confirmedRate,
	"assetStatus":    AssetStatusName,
	"weakStatus":     WeaknessStatusName,
	"sensitiveType":  SensitiveDataTypeName,
	"findingType":    FindingTypeName,
	"apiDivider":     apiPartDivider,
	"scopeName":      ContentScopeName,
	"totalEndpoints": totalAPIEndpoints,
	"toneClass":      func(tone string) string { return map[string]string{"bad": "warn", "good": "good"}[tone] },
	"fmtDate":        func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"fmtTime":        func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
	"fmtTimePtr": func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format("2006-01-02 15:04")
	},
	"inc": func(i int) int { return i + 1 },
}).Parse(reportHTMLTpl))

// renderData 渲染上下文。
type renderData struct {
	Tpl         *Template
	Data        *ReportData
	ReportNo    string
	Charts      *MainCharts
	Att         *Attention
	APIAtt      *APIAttention
	CompRows    []ComparisonRow
	ShowAPIPart bool
	secNo       int
}

// SecNo 章节中文编号（模板方法，仅展示章节递增）。
func (r *renderData) SecNo() string {
	r.secNo++
	return cnNumeral(r.secNo)
}

// chartSVGHTML 输出图表内联 SVG（本包自渲染、标签已消毒的可信内容）。
func chartSVGHTML(img *ChartImage) template.HTML {
	if img == nil || img.SVG == "" {
		return ""
	}
	return template.HTML(`<div class="chart">` + img.SVG + `</div>`)
}

// warnHTML 关注项文本标红（内容先转义，仅包一层样式 span）。
func warnHTML(cond bool, s string) template.HTML {
	esc := template.HTMLEscapeString(s)
	if cond {
		return template.HTML(`<span class="warn">` + esc + `</span>`)
	}
	return template.HTML(esc)
}

// RenderHTML 渲染 HTML 报告（全部数据经 html/template 转义，CSS 内联，无外部资源）。
// charts 为 nil 时按无图表渲染（字体降级场景）。
func RenderHTML(tpl *Template, data *ReportData, reportNo string, charts *MainCharts) ([]byte, error) {
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
	if charts.API == nil {
		charts.API = &CombinedAPICharts{}
	}
	ctx := &renderData{Tpl: tpl, Data: data, ReportNo: reportNo, Charts: charts, Att: NewAttention(data), APIAtt: NewAPIAttention(data.API), CompRows: BuildComparisonRows(data), ShowAPIPart: showAPIPart(tpl, data)}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render html: %w", err)
	}
	if buf.Len() > MaxReportFileSize {
		return nil, fmt.Errorf("report html exceeds %d bytes limit", MaxReportFileSize)
	}
	return buf.Bytes(), nil
}

const reportHTMLTpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Tpl.ProductName}}安全报告 {{.ReportNo}}</title>
<style>
body{font-family:"Noto Sans CJK SC","PingFang SC","Microsoft YaHei",sans-serif;color:#1f2329;margin:0;background:#f5f6f7}
.page{max-width:880px;margin:0 auto;background:#fff;padding:48px 56px}
.hdr{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #1f4e79;padding-bottom:12px;margin-bottom:32px}
.hdr .logo{font-size:22px;font-weight:700;color:#1f4e79}
.hdr .meta{color:#646a73;font-size:12px;text-align:right}
.cover{text-align:center;padding:96px 0 64px}
.cover h1{font-size:30px;margin:16px 0 8px}
.cover .sub{color:#646a73;font-size:15px}
.cover .no{margin-top:32px;color:#1f4e79;font-size:14px}
.cover .sign{margin-top:64px;font-size:13px;color:#333;display:flex;justify-content:space-around}
h2{font-size:18px;color:#1f4e79;border-left:4px solid #1f4e79;padding-left:10px;margin-top:36px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th,td{border:1px solid #dee0e3;padding:6px 10px;text-align:left}
th{background:#f0f4f8}
.kv{color:#333;font-size:13px;line-height:1.9}
.chart{margin:16px 0;text-align:center}.chart svg{max-width:100%;height:auto}
.warn{color:#d83931;font-weight:700}
.good{color:#2ea44f;font-weight:700}
.part{page-break-before:always;text-align:center;font-size:22px;color:#1f4e79;font-weight:700;margin:56px 0 28px;padding-top:24px;border-top:2px solid #1f4e79}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;color:#fff;font-size:12px}
.risk-LOW{background:#2ea44f}.risk-MEDIUM{background:#d4a106}.risk-HIGH{background:#d83931}.risk-CRITICAL{background:#8b0000}
ul{line-height:1.9;font-size:13px}
.ftr{margin-top:48px;border-top:1px solid #dee0e3;padding-top:12px;color:#8f959e;font-size:12px;text-align:center}
</style>
</head>
<body>
<div class="page">
{{if .Tpl.HeaderText}}<div class="hdr"><div class="logo">{{.Tpl.HeaderText}}</div><div class="meta">{{.ReportNo}}</div></div>{{end}}

{{if .Tpl.Show "cover"}}
<div class="cover">
  <div class="logo" style="font-size:26px;color:#1f4e79">{{.Tpl.LogoText}}</div>
  <h1>{{.Tpl.ProductName}}安全报告</h1>
  <div class="sub">{{.Tpl.CompanyName}}</div>
  <div class="sub">报告周期：{{fmtDate .Data.RangeStart}} 至 {{fmtDate .Data.RangeEnd}}（{{reportType .Data.ReportType}}）</div>
  <div class="no">报告编号：{{.ReportNo}}</div>
  <div class="sign">
    <span>编制：{{if .Tpl.PreparedBy}}{{.Tpl.PreparedBy}}{{else}}-{{end}}</span>
    <span>审核：{{if .Tpl.ReviewedBy}}{{.Tpl.ReviewedBy}}{{else}}-{{end}}</span>
    <span>生成时间：{{fmtTime .Data.GeneratedAt}}</span>
  </div>
</div>
{{end}}

{{if .Tpl.Show "period"}}
<h2>{{.SecNo}}、报告周期</h2>
<div class="kv">统计范围：{{fmtTime .Data.RangeStart}} 至 {{fmtTime .Data.RangeEnd}}（UTC，左闭右开）；内容范围：{{scopeName .Data.ContentScope}}</div>
{{end}}

{{if .Tpl.Show "scope"}}
<h2>{{.SecNo}}、报告范围</h2>
{{if .Data.ScopeAll}}
<div class="kv">本报告覆盖全部受保护应用。</div>
{{else}}
<div class="kv">本报告覆盖以下 {{len .Data.Applications}} 个应用：</div>
{{end}}
{{if .Data.Applications}}
<table><tr><th>#</th><th>应用编码</th><th>应用名称</th>{{if .Data.API}}<th>API 端点数</th>{{end}}</tr>
{{range $i, $a := .Data.Applications}}<tr><td>{{inc $i}}</td><td>{{$a.Code}}</td><td>{{$a.Name}}</td>{{if $.Data.API}}<td>{{$a.APIEndpoints}}</td>{{end}}</tr>{{end}}
{{if .Data.API}}{{if gt (len .Data.Applications) 1}}<tr><td></td><td><b>合计</b></td><td></td><td><b>{{totalEndpoints .Data.Applications}}</b></td></tr>{{end}}{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "summary"}}
<h2>{{.SecNo}}、管理摘要</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>总请求数</td><td>{{.Data.TotalRequests}}</td></tr>
<tr><td>安全事件总数</td><td>{{.Data.EventsTotal}}</td></tr>
<tr><td>阻断事件</td><td>{{.Data.EventsBlocked}}</td></tr>
<tr><td>高危及以上事件</td><td>{{warn .Att.HighSeverity (printf "%d" .Data.HighSeverity)}}</td></tr>
<tr><td>CC拦截</td><td>{{warn .Att.CCNoBlock (printf "%d" .Data.CCRejected)}}</td></tr>
<tr><td>风险等级</td><td><span class="badge risk-{{.Data.RiskLevel}}">{{riskName .Data.RiskLevel}}</span></td></tr>
</table>
{{end}}

{{if .Tpl.Show "comparison"}}
<h2>{{.SecNo}}、环比对比</h2>
{{if .CompRows}}
<table><tr><th>指标</th><th>本期</th><th>上期</th><th>变化</th></tr>
{{range .CompRows}}<tr><td>{{.Name}}</td><td>{{.Current}}</td><td>{{.Previous}}</td><td class="{{toneClass .Tone}}">{{.Delta}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无上一周期对照数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "traffic"}}
<h2>{{.SecNo}}、请求流量</h2>
<div class="kv">报告期内总请求数：{{.Data.TotalRequests}}</div>
{{chartSVG .Charts.Traffic}}
{{if .Data.RequestsTrend}}
<table><tr><th>时间</th><th>请求数</th></tr>
{{range .Data.RequestsTrend}}<tr><td>{{fmtTime .Time}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "events_overview"}}
<h2>{{.SecNo}}、安全事件总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>事件总数</td><td>{{.Data.EventsTotal}}</td></tr>
<tr><td>阻断（BLOCK）</td><td>{{.Data.EventsBlocked}}</td></tr>
<tr><td>观察（OBSERVE）</td><td>{{.Data.EventsObserved}}</td></tr>
<tr><td>阻断率</td><td>{{warn .Att.BlockRateLow (printf "%.1f%%" (pct .Data.EventsBlocked .Data.EventsTotal))}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "risk_level"}}
<h2>{{.SecNo}}、风险等级</h2>
<div class="kv">本期综合风险等级：<span class="badge risk-{{.Data.RiskLevel}}">{{riskName .Data.RiskLevel}}</span></div>
{{chartSVG .Charts.Severity}}
{{if .Data.SeverityDist}}
<table><tr><th>严重度</th><th>事件数</th><th>占比</th></tr>
{{range .Data.SeverityDist}}<tr><td>{{warn (sevAlert .Key) (severityName .Key)}}</td><td>{{warn (sevAlert .Key) (printf "%d" .Value)}}</td><td>{{warn (sevAlert .Key) (printf "%.1f%%" (pct .Value $.Data.EventsTotal))}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "attack_types"}}
<h2>{{.SecNo}}、攻击类型分布</h2>
{{if .Data.AttackTypes}}
{{chartSVG .Charts.AttackTypes}}
<table><tr><th>攻击类型</th><th>事件数</th><th>占比</th></tr>
{{range .Data.AttackTypes}}<tr><td>{{attackName .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.EventsTotal)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "attack_trend"}}
<h2>{{.SecNo}}、攻击趋势</h2>
{{if .Data.AttackTrend}}
{{chartSVG .Charts.AttackTrend}}
<table><tr><th>时间</th><th>事件数</th></tr>
{{range .Data.AttackTrend}}<tr><td>{{fmtTime .Time}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "attack_hours"}}
<h2>{{.SecNo}}、攻击时段分布</h2>
{{chartSVG .Charts.AttackHours}}
{{if peakHourText .Data.AttackHours}}<div class="kv">{{peakHourText .Data.AttackHours}}</div>{{else}}<div class="kv">报告期内无攻击事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "source_ips"}}
<h2>{{.SecNo}}、攻击源IP TOP10</h2>
{{if .Data.TopSourceIPs}}
{{chartSVG .Charts.SourceIPs}}
<table><tr><th>#</th><th>源IP</th><th>事件数</th></tr>
{{range $i, $s := .Data.TopSourceIPs}}<tr><td>{{inc $i}}</td><td>{{$s.Key}}</td><td>{{$s.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击源记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "source_geo"}}
<h2>{{.SecNo}}、攻击源地区 TOP10</h2>
{{if not .Data.GeoEnabled}}
<div class="kv">GeoIP 数据未启用，无法统计地区分布（部署 geoip/country.mmdb 后可用）。</div>
{{else if .Data.SourceGeo}}
{{chartSVG .Charts.SourceGeo}}
<table><tr><th>地区</th><th>事件数</th><th>占比</th></tr>
{{range .Data.SourceGeo}}<tr><td>{{.Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.EventsTotal)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击源记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "applications"}}
<h2>{{.SecNo}}、被攻击应用 TOP10</h2>
{{if .Data.AttackedApps}}
{{chartSVG .Charts.AttackedApps}}
<table><tr><th>#</th><th>应用</th><th>事件数</th></tr>
{{range $i, $s := .Data.AttackedApps}}<tr><td>{{inc $i}}</td><td>{{$s.Key}}</td><td>{{$s.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无被攻击应用记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "target_paths"}}
<h2>{{.SecNo}}、被攻击路径 TOP10</h2>
{{if .Data.TargetPaths}}
{{chartSVG .Charts.TargetPaths}}
<table><tr><th>#</th><th>路径</th><th>事件数</th></tr>
{{range $i, $s := .Data.TargetPaths}}<tr><td>{{inc $i}}</td><td>{{$s.Key}}</td><td>{{$s.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无被攻击路径记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "rule_hits"}}
<h2>{{.SecNo}}、命中规则 TOP10</h2>
{{if .Data.TopRules}}
<table><tr><th>#</th><th>规则ID</th><th>规则名称</th><th>命中次数</th></tr>
{{range $i, $r := .Data.TopRules}}<tr><td>{{inc $i}}</td><td>{{$r.RuleID}}</td><td>{{ruleDisplay $r.RuleID $r.RuleName}}</td><td>{{$r.Hits}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无规则命中记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "event_samples"}}
<h2>{{.SecNo}}、高危事件明细 TOP20</h2>
{{if .Data.EventSamples}}
<table><tr><th>时间</th><th>源IP</th><th>应用</th><th>方法</th><th>路径</th><th>类型</th><th>严重度</th><th>动作</th></tr>
{{range .Data.EventSamples}}<tr><td>{{.OccurredAt.Format "01-02 15:04"}}</td><td>{{.ClientIP}}</td><td>{{.AppName}}</td><td>{{.Method}}</td><td>{{.Path}}</td><td>{{attackName .AttackType}}</td><td>{{warn (sevAlert .Severity) (severityName .Severity)}}</td><td>{{actionName .Action}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无安全事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "cc_protection"}}
<h2>{{.SecNo}}、CC防护</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>阈值触发次数</td><td>{{.Data.CCExceeded}}</td></tr>
<tr><td>拦截请求数</td><td>{{warn .Att.CCNoBlock (printf "%d" .Data.CCRejected)}}</td></tr>
<tr><td>临时封禁创建数</td><td>{{.Data.CCTempBlocks}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "ip_lists"}}
<h2>{{.SecNo}}、黑白名单</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>白名单命中（放行）</td><td>{{.Data.IPAllowHits}}</td></tr>
<tr><td>黑名单命中（阻断）</td><td>{{.Data.IPDenyHits}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "disposition"}}
<h2>{{.SecNo}}、事件处置</h2>
{{if .Data.Dispositions}}
<table><tr><th>处置状态</th><th>事件数</th></tr>
{{range .Data.Dispositions}}<tr><td>{{dispName .Key}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无事件处置记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "false_positives"}}
<h2>{{.SecNo}}、误报和例外</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>确认误报事件</td><td>{{.Data.FalsePositives}}</td></tr>
<tr><td>新增例外策略</td><td>{{.Data.ExceptionsCreated}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "upstream_health"}}
<h2>{{.SecNo}}、源站健康</h2>
{{if .Data.Upstreams}}
<table><tr><th>源站</th><th>地址</th><th>状态</th><th>最近检查时间</th></tr>
{{range .Data.Upstreams}}<tr><td>{{warn (upAlert .Status) .Name}}</td><td>{{.Address}}</td><td>{{warn (upAlert .Status) (upStatusName .Status)}}</td><td>{{fmtTimePtr .CheckedAt}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无源站健康数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "certificates"}}
<h2>{{.SecNo}}、证书状态</h2>
{{if .Data.Certificates}}
<table><tr><th>证书</th><th>通用名</th><th>状态</th><th>到期时间</th><th>剩余天数</th></tr>
{{range .Data.Certificates}}<tr><td>{{warn (certAlert .DaysRemaining) .Name}}</td><td>{{.CommonName}}</td><td>{{certStatusName .Status}}</td><td>{{fmtTimePtr .NotAfter}}</td><td>{{if .NotAfter}}{{warn (certAlert .DaysRemaining) (printf "%d" .DaysRemaining)}}{{else}}-{{end}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无证书数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "publish_tasks"}}
<h2>{{.SecNo}}、策略发布</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>发布任务总数</td><td>{{.Data.Publish.Total}}</td></tr>
<tr><td>成功</td><td>{{.Data.Publish.Success}}</td></tr>
<tr><td>失败</td><td>{{warn .Att.PublishFailed (printf "%d" .Data.Publish.Failed)}}</td></tr>
<tr><td>进行中</td><td>{{.Data.Publish.Running}}</td></tr>
</table>
{{if .Data.Publish.Recent}}
<table><tr><th>时间</th><th>类型</th><th>状态</th><th>摘要</th></tr>
{{range .Data.Publish.Recent}}<tr><td>{{fmtTime .RequestedAt}}</td><td>{{pubType .TaskType}}</td><td>{{pubStatus .Status}}</td><td>{{.Summary}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "system_health"}}
<h2>{{.SecNo}}、系统运行</h2>
{{if .Data.Components}}
<table><tr><th>组件</th><th>状态</th><th>说明</th><th>快照时间</th></tr>
{{range .Data.Components}}<tr><td>{{warn (compAlert .Status) .Component}}</td><td>{{warn (compAlert .Status) (upStatusName .Status)}}</td><td>{{.Message}}</td><td>{{fmtTime .TakenAt}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无系统运行数据。</div>{{end}}
{{end}}

{{if .ShowAPIPart}}
<div class="part">{{apiDivider .Data.ContentScope}}</div>

{{if .Tpl.Show "api_overview"}}
<h2>{{.SecNo}}、API 资产总览</h2>
{{if .Data.API.Asset}}
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>端点总数</td><td>{{.Data.API.Asset.TotalEndpoints}}</td></tr>
<tr><td>报告期内新增</td><td>{{.Data.API.Asset.NewEndpoints}}</td></tr>
<tr><td>已确认端点</td><td>{{.Data.API.Asset.Confirmed}}</td></tr>
<tr><td>端点确认率</td><td>{{printf "%.1f%%" (confirmedRate .Data.API.Asset.Confirmed .Data.API.Asset.TotalEndpoints)}}</td></tr>
<tr><td>Shadow发现（未关闭）</td><td>{{warn .APIAtt.ShadowOpen (printf "%d" .Data.API.Asset.ShadowOpen)}}</td></tr>
<tr><td>僵尸端点</td><td>{{warn .APIAtt.Zombie (printf "%d" .Data.API.Asset.Zombie)}}</td></tr>
<tr><td>已下线端点</td><td>{{.Data.API.Asset.Deprecated}}</td></tr>
</table>
{{chartSVG .Charts.API.AssetStatus}}
{{if .Data.API.Asset.StatusDist}}
<table><tr><th>资产状态</th><th>端点数</th><th>占比</th></tr>
{{range .Data.API.Asset.StatusDist}}<tr><td>{{assetStatus .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.API.Asset.TotalEndpoints)}}</td></tr>{{end}}
</table>
{{end}}
{{else}}<div class="kv">暂无API端点资产。</div>{{end}}
{{end}}

{{if .ShowAPIPart}}{{if .Data.API.AssetList}}
{{if .Tpl.Show "api_asset_list"}}
<h2>{{.SecNo}}、API 资产清单（全量）</h2>
<div class="kv">共 {{.Data.API.AssetListTotal}} 条 API 资产{{if gt .Data.API.AssetListTotal (len .Data.API.AssetList)}}（显示前 {{len .Data.API.AssetList}} 条，按命中次数排序）{{end}}。</div>
<table><tr><th>#</th><th>方法</th><th>路径</th><th>用途</th><th>状态</th><th>标记</th><th>命中次数</th></tr>
{{range $i, $it := .Data.API.AssetList}}<tr><td>{{inc $i}}</td><td>{{$it.Method}}</td><td>{{$it.Path}}</td><td>{{if $it.Purpose}}{{$it.Purpose}}{{else}}未分类{{end}}</td><td>{{assetStatus $it.Status}}</td><td>{{warn (or $it.IsShadow $it.IsZombie) $it.FlagLabel}}</td><td>{{$it.Hits}}</td></tr>{{end}}
</table>
{{end}}
{{end}}{{end}}

{{if .Tpl.Show "api_new_endpoints"}}
<h2>{{.SecNo}}、新增 API 端点 TOP20</h2>
{{if .Data.API.Asset}}{{if .Data.API.Asset.NewList}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>状态</th><th>命中次数</th><th>首次发现</th></tr>
{{range $i, $e := .Data.API.Asset.NewList}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{assetStatus $e.Status}}</td><td>{{$e.Hits}}</td><td>{{fmtTime $e.FirstSeen}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无新增端点。</div>{{end}}{{else}}<div class="kv">报告期内无新增端点。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_shadow"}}
<h2>{{.SecNo}}、Shadow API 清单</h2>
{{if .Data.API.Asset}}{{if .Data.API.Asset.ShadowList}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>状态</th><th>命中次数</th><th>最近出现</th></tr>
{{range $i, $e := .Data.API.Asset.ShadowList}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{assetStatus $e.Status}}</td><td>{{$e.Hits}}</td><td>{{fmtTime $e.LastSeen}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">当前无未关闭的Shadow发现。</div>{{end}}{{else}}<div class="kv">当前无未关闭的Shadow发现。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_risk"}}
<h2>{{.SecNo}}、API 风险发现</h2>
{{if .Data.API.Risk}}
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>报告期内新增发现</td><td>{{.Data.API.Risk.NewFindings}}</td></tr>
<tr><td>报告期内关闭</td><td>{{.Data.API.Risk.ClosedFindings}}</td></tr>
<tr><td>当前未关闭</td><td>{{warn .APIAtt.OpenFindings (printf "%d" .Data.API.Risk.OpenFindings)}}</td></tr>
</table>
{{else}}<div class="kv">报告期内无风险发现。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_risk_dist"}}
<h2>{{.SecNo}}、发现类型与严重度分布</h2>
{{if .Data.API.Risk}}
{{chartSVG .Charts.API.RiskType}}
{{if .Data.API.Risk.TypeDist}}
<table><tr><th>发现类型</th><th>数量</th><th>占比</th></tr>
{{range .Data.API.Risk.TypeDist}}<tr><td>{{findingType .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.API.Risk.NewFindings)}}</td></tr>{{end}}
</table>
{{end}}
{{chartSVG .Charts.API.RiskSev}}
{{if .Data.API.Risk.SeverityDist}}
<table><tr><th>严重度</th><th>数量</th><th>占比</th></tr>
{{range .Data.API.Risk.SeverityDist}}<tr><td>{{warn (sevAlert .Key) (severityName .Key)}}</td><td>{{warn (sevAlert .Key) (printf "%d" .Value)}}</td><td>{{warn (sevAlert .Key) (printf "%.1f%%" (pct .Value $.Data.API.Risk.NewFindings))}}</td></tr>{{end}}
</table>
{{end}}
{{else}}<div class="kv">报告期内无风险发现。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_risk_top"}}
<h2>{{.SecNo}}、风险端点 TOP10</h2>
{{if .Data.API.Risk}}{{if .Data.API.Risk.TopEndpoints}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>新增发现</th><th>高危及以上</th></tr>
{{range $i, $e := .Data.API.Risk.TopEndpoints}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{$e.Findings}}</td><td>{{$e.High}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无风险端点记录。</div>{{end}}{{else}}<div class="kv">报告期内无风险端点记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_subjects"}}
<h2>{{.SecNo}}、风险主体 TOP10</h2>
{{if .Data.API.Risk}}{{if .Data.API.Risk.TopSubjects}}
<table><tr><th>#</th><th>主体类型</th><th>主体指纹</th><th>新增发现</th></tr>
{{range $i, $s := .Data.API.Risk.TopSubjects}}<tr><td>{{inc $i}}</td><td>{{$s.SubjectType}}</td><td>{{$s.SubjectID}}</td><td>{{$s.Findings}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无风险主体记录。</div>{{end}}{{else}}<div class="kv">报告期内无风险主体记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_weakness"}}
<h2>{{.SecNo}}、API 弱点整改</h2>
{{if .Data.API.Weakness}}
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>报告期内新派生弱点</td><td>{{.Data.API.Weakness.NewInRange}}</td></tr>
<tr><td>报告期内完成整改</td><td>{{.Data.API.Weakness.FixedInRange}}</td></tr>
<tr><td>超期未闭环</td><td>{{warn .APIAtt.Overdue (printf "%d" .Data.API.Weakness.OverdueOpen)}}</td></tr>
<tr><td>报告期内复测通过</td><td>{{.Data.API.Weakness.RetestPass}}</td></tr>
<tr><td>报告期内复测失败</td><td>{{warn .APIAtt.RetestFail (printf "%d" .Data.API.Weakness.RetestFail)}}</td></tr>
</table>
{{chartSVG .Charts.API.WeakStatus}}
{{if .Data.API.Weakness.StatusDist}}
<table><tr><th>状态</th><th>数量</th></tr>
{{range .Data.API.Weakness.StatusDist}}<tr><td>{{weakStatus .Key}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{end}}
{{else}}<div class="kv">暂无API弱点记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_weak_overdue"}}
<h2>{{.SecNo}}、超期未修清单</h2>
{{if .Data.API.Weakness}}{{if .Data.API.Weakness.OverdueList}}
<table><tr><th>#</th><th>弱点</th><th>严重度</th><th>状态</th><th>负责人</th><th>整改期限</th></tr>
{{range $i, $w := .Data.API.Weakness.OverdueList}}<tr><td>{{inc $i}}</td><td>{{$w.Name}}</td><td>{{warn (sevAlert $w.Severity) (severityName $w.Severity)}}</td><td>{{weakStatus $w.Status}}</td><td>{{if $w.Owner}}{{$w.Owner}}{{else}}-{{end}}</td><td>{{fmtTimePtr $w.DueDate}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">当前无超期未修弱点。</div>{{end}}{{else}}<div class="kv">当前无超期未修弱点。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_sensitive"}}
<h2>{{.SecNo}}、API 敏感数据</h2>
{{if .Data.API.Sensitive}}
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>敏感字段总数</td><td>{{.Data.API.Sensitive.TotalFields}}</td></tr>
<tr><td>报告期内新识别</td><td>{{.Data.API.Sensitive.NewInRange}}</td></tr>
</table>
{{chartSVG .Charts.API.SensType}}
{{if .Data.API.Sensitive.TypeDist}}
<table><tr><th>数据类型</th><th>字段数</th><th>占比</th></tr>
{{range .Data.API.Sensitive.TypeDist}}<tr><td>{{sensitiveType .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.API.Sensitive.TotalFields)}}</td></tr>{{end}}
</table>
{{end}}
{{chartSVG .Charts.API.SensTrend}}
{{else}}<div class="kv">暂无敏感数据字段。</div>{{end}}
{{end}}

{{if .Tpl.Show "api_sensitive_top"}}
<h2>{{.SecNo}}、涉敏端点 TOP10</h2>
{{if .Data.API.Sensitive}}{{if .Data.API.Sensitive.TopEndpoints}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>敏感字段数</th><th>涉及类型数</th></tr>
{{range $i, $e := .Data.API.Sensitive.TopEndpoints}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{$e.Fields}}</td><td>{{$e.Types}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">暂无涉敏端点。</div>{{end}}{{else}}<div class="kv">暂无涉敏端点。</div>{{end}}
{{end}}
{{end}}

{{if .Tpl.Show "conclusions"}}
<h2>{{.SecNo}}、结论和建议</h2>
{{if .Data.Conclusions}}<h3 style="font-size:14px">结论</h3>
<ul>{{range .Data.Conclusions}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .ShowAPIPart}}{{if .Data.API.Conclusions}}
<h3 style="font-size:14px">API 安全结论</h3>
<ul>{{range .Data.API.Conclusions}}<li>{{.}}</li>{{end}}</ul>
{{end}}{{end}}
{{if .Data.Suggestions}}<h3 style="font-size:14px">建议</h3>
<ul>{{range .Data.Suggestions}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .ShowAPIPart}}{{if .Data.API.Suggestions}}
<h3 style="font-size:14px">API 安全建议</h3>
<ul>{{range .Data.API.Suggestions}}<li>{{.}}</li>{{end}}</ul>
{{end}}{{end}}
{{end}}

{{if .Tpl.FooterText}}<div class="ftr">{{.Tpl.FooterText}}</div>{{end}}
<div class="ftr">本报告由 {{.Tpl.ProductName}} 自动生成。报告编号：{{.ReportNo}}</div>
</div>
</body>
</html>
`
