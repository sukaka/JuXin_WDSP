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
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"attackName": AttackTypeName,
	"pct":        pct,
	"fmtDate":    func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"fmtTime":    func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
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
	Tpl      *Template
	Data     *ReportData
	ReportNo string
}

// RenderHTML 渲染 HTML 报告（全部数据经 html/template 转义，CSS 内联，无外部资源）。
func RenderHTML(tpl *Template, data *ReportData, reportNo string) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("report data is nil")
	}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, renderData{Tpl: tpl, Data: data, ReportNo: reportNo}); err != nil {
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
  <div class="sub">报告周期：{{fmtDate .Data.RangeStart}} 至 {{fmtDate .Data.RangeEnd}}（{{.Data.ReportType}}）</div>
  <div class="no">报告编号：{{.ReportNo}}</div>
  <div class="sign">
    <span>编制：{{if .Tpl.PreparedBy}}{{.Tpl.PreparedBy}}{{else}}-{{end}}</span>
    <span>审核：{{if .Tpl.ReviewedBy}}{{.Tpl.ReviewedBy}}{{else}}-{{end}}</span>
    <span>生成时间：{{fmtTime .Data.GeneratedAt}}</span>
  </div>
</div>
{{end}}

{{if .Tpl.Show "period"}}
<h2>一、报告周期</h2>
<div class="kv">统计范围：{{fmtTime .Data.RangeStart}} 至 {{fmtTime .Data.RangeEnd}}（UTC，左闭右开）</div>
{{end}}

{{if .Tpl.Show "scope"}}
<h2>二、报告范围</h2>
{{if .Data.ScopeAll}}
<div class="kv">本报告覆盖全部受保护应用。</div>
{{else}}
<div class="kv">本报告覆盖以下 {{len .Data.Applications}} 个应用：</div>
{{end}}
{{if .Data.Applications}}
<table><tr><th>#</th><th>应用编码</th><th>应用名称</th></tr>
{{range $i, $a := .Data.Applications}}<tr><td>{{inc $i}}</td><td>{{$a.Code}}</td><td>{{$a.Name}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "summary"}}
<h2>三、管理摘要</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>总请求数</td><td>{{.Data.TotalRequests}}</td></tr>
<tr><td>安全事件总数</td><td>{{.Data.EventsTotal}}</td></tr>
<tr><td>阻断事件</td><td>{{.Data.EventsBlocked}}</td></tr>
<tr><td>高危及以上事件</td><td>{{.Data.HighSeverity}}</td></tr>
<tr><td>CC拦截</td><td>{{.Data.CCRejected}}</td></tr>
<tr><td>风险等级</td><td><span class="badge risk-{{.Data.RiskLevel}}">{{.Data.RiskLevel}}</span></td></tr>
</table>
{{end}}

{{if .Tpl.Show "traffic"}}
<h2>四、请求流量</h2>
<div class="kv">报告期内总请求数：{{.Data.TotalRequests}}</div>
{{if .Data.RequestsTrend}}
<table><tr><th>时间</th><th>请求数</th></tr>
{{range .Data.RequestsTrend}}<tr><td>{{fmtTime .Time}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "events_overview"}}
<h2>五、安全事件总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>事件总数</td><td>{{.Data.EventsTotal}}</td></tr>
<tr><td>阻断（BLOCK）</td><td>{{.Data.EventsBlocked}}</td></tr>
<tr><td>观察（OBSERVE）</td><td>{{.Data.EventsObserved}}</td></tr>
<tr><td>阻断率</td><td>{{printf "%.1f%%" (pct .Data.EventsBlocked .Data.EventsTotal)}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "risk_level"}}
<h2>六、风险等级</h2>
<div class="kv">本期综合风险等级：<span class="badge risk-{{.Data.RiskLevel}}">{{.Data.RiskLevel}}</span></div>
{{if .Data.SeverityDist}}
<table><tr><th>严重度</th><th>事件数</th><th>占比</th></tr>
{{range .Data.SeverityDist}}<tr><td>{{.Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.EventsTotal)}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "attack_types"}}
<h2>七、攻击类型分布</h2>
{{if .Data.AttackTypes}}
<table><tr><th>攻击类型</th><th>事件数</th><th>占比</th></tr>
{{range .Data.AttackTypes}}<tr><td>{{attackName .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.EventsTotal)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "attack_trend"}}
<h2>八、攻击趋势</h2>
{{if .Data.AttackTrend}}
<table><tr><th>时间</th><th>事件数</th></tr>
{{range .Data.AttackTrend}}<tr><td>{{fmtTime .Time}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击事件。</div>{{end}}
{{end}}

{{if .Tpl.Show "source_ips"}}
<h2>九、攻击源IP TOP10</h2>
{{if .Data.TopSourceIPs}}
<table><tr><th>#</th><th>源IP</th><th>事件数</th></tr>
{{range $i, $s := .Data.TopSourceIPs}}<tr><td>{{inc $i}}</td><td>{{$s.Key}}</td><td>{{$s.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无攻击源记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "applications"}}
<h2>十、被攻击应用 TOP10</h2>
{{if .Data.AttackedApps}}
<table><tr><th>#</th><th>应用</th><th>事件数</th></tr>
{{range $i, $s := .Data.AttackedApps}}<tr><td>{{inc $i}}</td><td>{{$s.Key}}</td><td>{{$s.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无被攻击应用记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "rule_hits"}}
<h2>十一、命中规则 TOP10</h2>
{{if .Data.TopRules}}
<table><tr><th>#</th><th>规则ID</th><th>规则名称</th><th>命中次数</th></tr>
{{range $i, $r := .Data.TopRules}}<tr><td>{{inc $i}}</td><td>{{$r.RuleID}}</td><td>{{$r.RuleName}}</td><td>{{$r.Hits}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无规则命中记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "cc_protection"}}
<h2>十二、CC防护</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>阈值触发次数</td><td>{{.Data.CCExceeded}}</td></tr>
<tr><td>拦截请求数</td><td>{{.Data.CCRejected}}</td></tr>
<tr><td>临时封禁创建数</td><td>{{.Data.CCTempBlocks}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "ip_lists"}}
<h2>十三、黑白名单</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>白名单命中（放行）</td><td>{{.Data.IPAllowHits}}</td></tr>
<tr><td>黑名单命中（阻断）</td><td>{{.Data.IPDenyHits}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "disposition"}}
<h2>十四、事件处置</h2>
{{if .Data.Dispositions}}
<table><tr><th>处置状态</th><th>事件数</th></tr>
{{range .Data.Dispositions}}<tr><td>{{.Key}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无事件处置记录。</div>{{end}}
{{end}}

{{if .Tpl.Show "false_positives"}}
<h2>十五、误报和例外</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>确认误报事件</td><td>{{.Data.FalsePositives}}</td></tr>
<tr><td>新增例外策略</td><td>{{.Data.ExceptionsCreated}}</td></tr>
</table>
{{end}}

{{if .Tpl.Show "upstream_health"}}
<h2>十六、源站健康</h2>
{{if .Data.Upstreams}}
<table><tr><th>源站</th><th>地址</th><th>状态</th><th>最近检查时间</th></tr>
{{range .Data.Upstreams}}<tr><td>{{.Name}}</td><td>{{.Address}}</td><td>{{.Status}}</td><td>{{fmtTimePtr .CheckedAt}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无源站健康数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "certificates"}}
<h2>十七、证书状态</h2>
{{if .Data.Certificates}}
<table><tr><th>证书</th><th>通用名</th><th>状态</th><th>到期时间</th><th>剩余天数</th></tr>
{{range .Data.Certificates}}<tr><td>{{.Name}}</td><td>{{.CommonName}}</td><td>{{.Status}}</td><td>{{fmtTimePtr .NotAfter}}</td><td>{{if .NotAfter}}{{.DaysRemaining}}{{else}}-{{end}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无证书数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "publish_tasks"}}
<h2>十八、策略发布</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>发布任务总数</td><td>{{.Data.Publish.Total}}</td></tr>
<tr><td>成功</td><td>{{.Data.Publish.Success}}</td></tr>
<tr><td>失败</td><td>{{.Data.Publish.Failed}}</td></tr>
<tr><td>进行中</td><td>{{.Data.Publish.Running}}</td></tr>
</table>
{{if .Data.Publish.Recent}}
<table><tr><th>时间</th><th>类型</th><th>状态</th><th>摘要</th></tr>
{{range .Data.Publish.Recent}}<tr><td>{{fmtTime .RequestedAt}}</td><td>{{.TaskType}}</td><td>{{.Status}}</td><td>{{.Summary}}</td></tr>{{end}}
</table>
{{end}}
{{end}}

{{if .Tpl.Show "system_health"}}
<h2>十九、系统运行</h2>
{{if .Data.Components}}
<table><tr><th>组件</th><th>状态</th><th>说明</th><th>快照时间</th></tr>
{{range .Data.Components}}<tr><td>{{.Component}}</td><td>{{.Status}}</td><td>{{.Message}}</td><td>{{fmtTime .TakenAt}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">无系统运行数据。</div>{{end}}
{{end}}

{{if .Tpl.Show "conclusions"}}
<h2>二十、结论和建议</h2>
<h3 style="font-size:14px">结论</h3>
<ul>{{range .Data.Conclusions}}<li>{{.}}</li>{{end}}</ul>
<h3 style="font-size:14px">建议</h3>
<ul>{{range .Data.Suggestions}}<li>{{.}}</li>{{end}}</ul>
{{end}}

{{if .Tpl.FooterText}}<div class="ftr">{{.Tpl.FooterText}}</div>{{end}}
<div class="ftr">本报告由 {{.Tpl.ProductName}} 自动生成。报告编号：{{.ReportNo}}</div>
</div>
</body>
</html>
`
