package reports

import (
	"bytes"
	"fmt"
	"html/template"
	"time"
)

// apiHTMLTemplate API 域报告固定内置 HTML 模板。
// 与 WAF 域模板同一安全纪律：模板本身为系统代码，用户可配置的模板字段
// （公司名/页眉页脚等）与全部采集数据仅作为数据传入并由 html/template
// 自动转义——不存在任意代码/脚本/外部请求执行面；CSS 内联，无外部资源。
var apiHTMLTemplate = template.Must(template.New("api_report").Funcs(template.FuncMap{
	"pct":     pct,
	"fmtDate": func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
	"fmtTimePtr": func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format("2006-01-02 15:04")
	},
	"inc":           func(i int) int { return i + 1 },
	"assetStatus":   AssetStatusName,
	"weakStatus":    WeaknessStatusName,
	"sensitiveType": SensitiveDataTypeName,
	"apiTypeName":   APIReportTypeName,
	"confirmedRate": confirmedRate,
	"chartSVG":      chartSVGHTML,
	"warn":          warnHTML,
	"sevAlert":      severityAttention,
	"severityName":  SeverityName,
	"findingType":   FindingTypeName,
}).Parse(apiReportHTMLTpl))

// apiRenderData API 报告渲染上下文。
type apiRenderData struct {
	Tpl      *Template
	Data     *APIReportData
	ReportNo string
	Charts   *APICharts
	Att      *APIAttention
}

// RenderAPIHTML 渲染 API 域 HTML 报告。charts 为 nil 时按无图表渲染（字体降级场景）。
func RenderAPIHTML(tpl *Template, data *APIReportData, reportNo string, charts *APICharts) ([]byte, error) {
	if tpl == nil {
		tpl = BuiltinTemplate()
	}
	if data == nil {
		return nil, fmt.Errorf("api report data is nil")
	}
	if charts == nil {
		charts = &APICharts{}
	}
	ctx := apiRenderData{Tpl: tpl, Data: data, ReportNo: reportNo, Charts: charts, Att: NewAPIAttention(data)}
	var buf bytes.Buffer
	if err := apiHTMLTemplate.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render api html: %w", err)
	}
	if buf.Len() > MaxReportFileSize {
		return nil, fmt.Errorf("api report html exceeds %d bytes limit", MaxReportFileSize)
	}
	return buf.Bytes(), nil
}

const apiReportHTMLTpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Tpl.ProductName}}{{apiTypeName .Data.ReportType}} {{.ReportNo}}</title>
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
  <h1>{{.Tpl.ProductName}}{{apiTypeName .Data.ReportType}}</h1>
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

{{if .Data.Asset}}
<h2>二、资产总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>端点总数</td><td>{{.Data.Asset.TotalEndpoints}}</td></tr>
<tr><td>报告期内新增</td><td>{{.Data.Asset.NewEndpoints}}</td></tr>
<tr><td>已确认端点</td><td>{{.Data.Asset.Confirmed}}</td></tr>
<tr><td>端点确认率</td><td>{{printf "%.1f%%" (confirmedRate .Data.Asset.Confirmed .Data.Asset.TotalEndpoints)}}</td></tr>
<tr><td>Shadow发现（未关闭）</td><td>{{warn .Att.ShadowOpen (printf "%d" .Data.Asset.ShadowOpen)}}</td></tr>
<tr><td>僵尸端点</td><td>{{warn .Att.Zombie (printf "%d" .Data.Asset.Zombie)}}</td></tr>
<tr><td>已下线端点</td><td>{{.Data.Asset.Deprecated}}</td></tr>
</table>

<h2>三、资产状态分布</h2>
{{chartSVG .Charts.Dist1}}
{{if .Data.Asset.StatusDist}}
<table><tr><th>资产状态</th><th>端点数</th><th>占比</th></tr>
{{range .Data.Asset.StatusDist}}<tr><td>{{assetStatus .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.Asset.TotalEndpoints)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">暂无API端点资产。</div>{{end}}

<h2>四、新增端点清单</h2>
{{if .Data.Asset.NewList}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>状态</th><th>命中次数</th><th>首次发现</th></tr>
{{range $i, $e := .Data.Asset.NewList}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{assetStatus $e.Status}}</td><td>{{$e.Hits}}</td><td>{{fmtTime $e.FirstSeen}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无新增端点。</div>{{end}}

<h2>五、Shadow端点清单</h2>
{{if .Data.Asset.ShadowList}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>状态</th><th>命中次数</th><th>最近出现</th></tr>
{{range $i, $e := .Data.Asset.ShadowList}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{assetStatus $e.Status}}</td><td>{{$e.Hits}}</td><td>{{fmtTime $e.LastSeen}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">当前无未关闭的Shadow发现。</div>{{end}}
{{end}}

{{if .Data.Risk}}
<h2>二、风险总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>报告期内新增发现</td><td>{{.Data.Risk.NewFindings}}</td></tr>
<tr><td>报告期内关闭</td><td>{{.Data.Risk.ClosedFindings}}</td></tr>
<tr><td>当前未关闭</td><td>{{warn .Att.OpenFindings (printf "%d" .Data.Risk.OpenFindings)}}</td></tr>
</table>

<h2>三、发现类型分布</h2>
{{chartSVG .Charts.Dist1}}
{{if .Data.Risk.TypeDist}}
<table><tr><th>发现类型</th><th>数量</th><th>占比</th></tr>
{{range .Data.Risk.TypeDist}}<tr><td>{{findingType .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.Risk.NewFindings)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无新增发现。</div>{{end}}

<h2>四、严重度分布</h2>
{{chartSVG .Charts.Dist2}}
{{if .Data.Risk.SeverityDist}}
<table><tr><th>严重度</th><th>数量</th><th>占比</th></tr>
{{range .Data.Risk.SeverityDist}}<tr><td>{{warn (sevAlert .Key) (severityName .Key)}}</td><td>{{warn (sevAlert .Key) (printf "%d" .Value)}}</td><td>{{warn (sevAlert .Key) (printf "%.1f%%" (pct .Value $.Data.Risk.NewFindings))}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无新增发现。</div>{{end}}

<h2>五、风险端点 TOP10</h2>
{{if .Data.Risk.TopEndpoints}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>新增发现</th><th>高危及以上</th></tr>
{{range $i, $e := .Data.Risk.TopEndpoints}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{$e.Findings}}</td><td>{{$e.High}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无风险端点记录。</div>{{end}}

<h2>六、风险主体 TOP10</h2>
{{if .Data.Risk.TopSubjects}}
<table><tr><th>#</th><th>主体类型</th><th>主体指纹</th><th>新增发现</th></tr>
{{range $i, $s := .Data.Risk.TopSubjects}}<tr><td>{{inc $i}}</td><td>{{$s.SubjectType}}</td><td>{{$s.SubjectID}}</td><td>{{$s.Findings}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无风险主体记录。</div>{{end}}
{{end}}

{{if .Data.Weakness}}
<h2>二、整改总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>报告期内新派生弱点</td><td>{{.Data.Weakness.NewInRange}}</td></tr>
<tr><td>报告期内完成整改</td><td>{{.Data.Weakness.FixedInRange}}</td></tr>
<tr><td>超期未闭环</td><td>{{warn .Att.Overdue (printf "%d" .Data.Weakness.OverdueOpen)}}</td></tr>
<tr><td>报告期内复测通过</td><td>{{.Data.Weakness.RetestPass}}</td></tr>
<tr><td>报告期内复测失败</td><td>{{warn .Att.RetestFail (printf "%d" .Data.Weakness.RetestFail)}}</td></tr>
</table>

<h2>三、弱点状态分布</h2>
{{chartSVG .Charts.Dist1}}
{{if .Data.Weakness.StatusDist}}
<table><tr><th>状态</th><th>数量</th></tr>
{{range .Data.Weakness.StatusDist}}<tr><td>{{weakStatus .Key}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">暂无API弱点记录。</div>{{end}}

<h2>四、未闭环弱点严重度分布</h2>
{{chartSVG .Charts.Dist2}}
{{if .Data.Weakness.SeverityDist}}
<table><tr><th>严重度</th><th>数量</th></tr>
{{range .Data.Weakness.SeverityDist}}<tr><td>{{warn (sevAlert .Key) (severityName .Key)}}</td><td>{{warn (sevAlert .Key) (printf "%d" .Value)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">当前无未闭环弱点。</div>{{end}}

<h2>五、超期未修清单</h2>
{{if .Data.Weakness.OverdueList}}
<table><tr><th>#</th><th>弱点</th><th>严重度</th><th>状态</th><th>负责人</th><th>整改期限</th></tr>
{{range $i, $w := .Data.Weakness.OverdueList}}<tr><td>{{inc $i}}</td><td>{{$w.Name}}</td><td>{{$w.Severity}}</td><td>{{weakStatus $w.Status}}</td><td>{{if $w.Owner}}{{$w.Owner}}{{else}}-{{end}}</td><td>{{fmtTimePtr $w.DueDate}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">当前无超期未修弱点。</div>{{end}}

<h2>六、复测记录</h2>
{{if .Data.Weakness.RetestList}}
<table><tr><th>#</th><th>弱点</th><th>复测结果</th><th>操作人</th><th>时间</th></tr>
{{range $i, $r := .Data.Weakness.RetestList}}<tr><td>{{inc $i}}</td><td>{{$r.WeaknessName}}</td><td>{{if eq $r.Action "RETEST_PASS"}}通过{{else}}失败{{end}}</td><td>{{$r.Actor}}</td><td>{{fmtTime $r.CreatedAt}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无复测记录。</div>{{end}}
{{end}}

{{if .Data.Sensitive}}
<h2>二、敏感数据总览</h2>
<table>
<tr><th>指标</th><th>数值</th></tr>
<tr><td>敏感字段总数</td><td>{{.Data.Sensitive.TotalFields}}</td></tr>
<tr><td>报告期内新识别</td><td>{{.Data.Sensitive.NewInRange}}</td></tr>
</table>

<h2>三、敏感数据类型分布</h2>
{{chartSVG .Charts.Dist1}}
{{if .Data.Sensitive.TypeDist}}
<table><tr><th>数据类型</th><th>字段数</th><th>占比</th></tr>
{{range .Data.Sensitive.TypeDist}}<tr><td>{{sensitiveType .Key}}</td><td>{{.Value}}</td><td>{{printf "%.1f%%" (pct .Value $.Data.Sensitive.TotalFields)}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">暂无敏感数据字段。</div>{{end}}

<h2>四、涉敏端点 TOP10</h2>
{{if .Data.Sensitive.TopEndpoints}}
<table><tr><th>#</th><th>方法</th><th>路径</th><th>敏感字段数</th><th>涉及类型数</th></tr>
{{range $i, $e := .Data.Sensitive.TopEndpoints}}<tr><td>{{inc $i}}</td><td>{{$e.Method}}</td><td>{{$e.Path}}</td><td>{{$e.Fields}}</td><td>{{$e.Types}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">暂无涉敏端点。</div>{{end}}

<h2>五、新增敏感字段趋势</h2>
{{chartSVG .Charts.Trend}}
{{if .Data.Sensitive.DailyNew}}
<table><tr><th>日期</th><th>新识别字段数</th></tr>
{{range .Data.Sensitive.DailyNew}}<tr><td>{{fmtDate .Time}}</td><td>{{.Value}}</td></tr>{{end}}
</table>
{{else}}<div class="kv">报告期内无新识别敏感字段。</div>{{end}}
{{end}}

{{if .Tpl.Show "conclusions"}}
<h2>七、结论和建议</h2>
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
