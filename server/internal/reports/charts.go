package reports

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	charts "github.com/vicanso/go-charts/v2"
)

// 报告图表：生成阶段一次性渲染，HTML 报告内联 SVG，PDF/Word 嵌入 PNG 位图。
//
// 安全约束：
//   - go-chart 的 SVG 输出对文本不做转义（上游 vector_renderer.go 原样写入），
//     所有进入图表的标签（应用名等用户可控数据）必须经 sanitizeChartLabel 处理；
//   - 图表完全本地渲染，无脚本、无外部请求，与报告安全模型一致。
//
// 字体降级纪律（与 PDF 一致）：字体文件缺失/不可读 → 跳过全部图表（退化为
// 纯文字表格报告，记 warn 日志，不算失败）；字体存在但解析失败 → 返回
// errChartFont，任务记 FONT_UNAVAILABLE。

// chartFontFamily 图表中文字体族名（与 PDF 共用 NotoSansCJKsc-VF.ttf）。
const chartFontFamily = "notocjk"

// chartThemeName 报告图表主题（light 克隆，文字纯黑提升屏幕与打印可读性）。
const chartThemeName = "jzreport"

// chartTextColor 图表文字颜色（纯黑）。
var chartTextColor = charts.Color{R: 0, G: 0, B: 0, A: 255}

var chartThemeOnce sync.Once

// ensureChartTheme 注册报告图表主题（进程内一次）：light 配色 + 纯黑文字。
func ensureChartTheme() {
	chartThemeOnce.Do(func() {
		light := charts.NewTheme(charts.ThemeLight)
		series := make([]charts.Color, 0, 9)
		for i := 0; i < 9; i++ {
			series = append(series, light.GetSeriesColor(i))
		}
		charts.AddTheme(chartThemeName, charts.ThemeOption{
			IsDarkMode:         false,
			AxisStrokeColor:    light.GetAxisStrokeColor(),
			AxisSplitLineColor: light.GetAxisSplitLineColor(),
			BackgroundColor:    light.GetBackgroundColor(),
			TextColor:          chartTextColor,
			SeriesColors:       series,
		})
	})
}

// 图表画布尺寸（像素）。
const (
	chartWidth  = 900
	chartHeight = 420
)

// 图表文字字号。库默认 10~12px 在 PDF 190mm 版宽缩放下物理尺寸过小，
// 且 1px 笔画的抗锯齿边缘占主导导致视觉发灰——统一加大字号提升可读性。
const (
	chartTitleFontSize = 18.0
	chartAxisFontSize  = 14.0
	chartLabelFontSize = 13.0
)

// errChartFont 图表字体解析失败标记错误（映射 FONT_UNAVAILABLE 失败码）。
var errChartFont = errors.New("chart font unavailable")

// ChartImage 一张图表的两种渲染产物。
type ChartImage struct {
	SVG string // 内联 SVG（HTML 报告用，标签已消毒）
	PNG []byte // PNG 位图（PDF/Word 用）
}

// MainCharts 主报告图表集（字段为 nil 表示该图不渲染）。
type MainCharts struct {
	Traffic      *ChartImage        // 请求流量趋势（折线）
	AttackTrend  *ChartImage        // 攻击趋势（折线）
	AttackTypes  *ChartImage        // 攻击类型分布（饼图）
	Severity     *ChartImage        // 严重度分布（饼图）
	AttackHours  *ChartImage        // 攻击时段分布（柱状）
	SourceIPs    *ChartImage        // 攻击源IP TOP10（横向条形）
	SourceGeo    *ChartImage        // 攻击源地区分布（饼图）
	AttackedApps *ChartImage        // 被攻击应用 TOP10（横向条形）
	TargetPaths  *ChartImage        // 被攻击路径 TOP10（横向条形）
	API          *CombinedAPICharts // API 安全部分图表（data.API 非空时构建）
}

// CombinedAPICharts 主报告 API 安全部分图表集。
type CombinedAPICharts struct {
	AssetStatus *ChartImage // 资产状态分布（饼图）
	RiskType    *ChartImage // 发现类型分布（饼图）
	RiskSev     *ChartImage // 发现严重度分布（饼图）
	WeakStatus  *ChartImage // 弱点状态分布（饼图）
	SensType    *ChartImage // 敏感数据类型分布（饼图）
	SensTrend   *ChartImage // 敏感字段新增趋势（折线）
}

// buildCombinedAPICharts 构建主报告 API 安全部分图表。
func buildCombinedAPICharts(api *APIReportData, b *chartBuilder) (*CombinedAPICharts, error) {
	cc := &CombinedAPICharts{}
	if api == nil || !b.fontOK {
		return cc, nil
	}
	var err error
	if api.Asset != nil {
		if cc.AssetStatus, err = b.pie("API 资产状态分布", api.Asset.StatusDist, AssetStatusName); err != nil {
			return nil, err
		}
	}
	if api.Risk != nil {
		if cc.RiskType, err = b.pie("API 发现类型分布", api.Risk.TypeDist, FindingTypeName); err != nil {
			return nil, err
		}
		if cc.RiskSev, err = b.pie("API 发现严重度分布", api.Risk.SeverityDist, SeverityName); err != nil {
			return nil, err
		}
	}
	if api.Weakness != nil {
		if cc.WeakStatus, err = b.pie("API 弱点状态分布", api.Weakness.StatusDist, WeaknessStatusName); err != nil {
			return nil, err
		}
	}
	if api.Sensitive != nil {
		if cc.SensType, err = b.pie("敏感数据类型分布", api.Sensitive.TypeDist, SensitiveDataTypeName); err != nil {
			return nil, err
		}
		if cc.SensTrend, err = b.line("敏感字段新增趋势", api.Sensitive.DailyNew, "新增字段数"); err != nil {
			return nil, err
		}
	}
	return cc, nil
}

// APICharts API 域报告图表集（按报告类型填充，nil 表示该图不渲染）。
type APICharts struct {
	Dist1 *ChartImage // 分布图1：资产状态/发现类型/弱点状态/数据类型
	Dist2 *ChartImage // 分布图2：API_RISK、API_WEAK 的严重度分布
	Trend *ChartImage // 趋势图：API_SENS 按天新增（折线）
}

// chartBuilder 图表构建器（持有字体可用状态）。
type chartBuilder struct {
	fontOK bool
}

// newChartBuilder 加载图表字体。文件缺失 → 降级（fontOK=false，不报错）。
func newChartBuilder(fontPath string) (*chartBuilder, error) {
	b := &chartBuilder{}
	if fontPath == "" {
		return b, nil
	}
	data, err := os.ReadFile(fontPath)
	if err != nil {
		slog.Warn("chart font unavailable, charts skipped", "path", fontPath, "error", err)
		return b, nil
	}
	if err := charts.InstallFont(chartFontFamily, data); err != nil {
		return nil, fmt.Errorf("%w: %v", errChartFont, err)
	}
	ensureChartTheme()
	b.fontOK = true
	return b, nil
}

// BuildMainCharts 构建主报告图表集。data 为 nil 或字体不可用时返回空集合。
func BuildMainCharts(data *ReportData, fontPath string) (*MainCharts, error) {
	b, err := newChartBuilder(fontPath)
	if err != nil {
		return nil, err
	}
	mc := &MainCharts{}
	if data == nil || !b.fontOK {
		return mc, nil
	}
	renderers := []struct {
		dst **ChartImage
		fn  func() (*ChartImage, error)
	}{
		{&mc.Traffic, func() (*ChartImage, error) { return b.line("请求流量趋势", data.RequestsTrend, "请求数") }},
		{&mc.AttackTrend, func() (*ChartImage, error) { return b.line("攻击趋势", data.AttackTrend, "事件数") }},
		{&mc.AttackTypes, func() (*ChartImage, error) {
			return b.pie("攻击类型分布", data.AttackTypes, AttackTypeName)
		}},
		{&mc.Severity, func() (*ChartImage, error) { return b.pie("严重度分布", data.SeverityDist, SeverityName) }},
		{&mc.AttackHours, func() (*ChartImage, error) { return b.bar("攻击时段分布", data.AttackHours, nil) }},
		{&mc.SourceIPs, func() (*ChartImage, error) { return b.hbar("攻击源IP TOP10", data.TopSourceIPs, nil) }},
		{&mc.SourceGeo, func() (*ChartImage, error) { return b.pie("攻击源地区分布", data.SourceGeo, nil) }},
		{&mc.AttackedApps, func() (*ChartImage, error) {
			return b.hbar("被攻击应用 TOP10", data.AttackedApps, nil)
		}},
		{&mc.TargetPaths, func() (*ChartImage, error) {
			return b.hbar("被攻击路径 TOP10", data.TargetPaths, nil)
		}},
	}
	for _, r := range renderers {
		img, err := r.fn()
		if err != nil {
			return nil, err
		}
		*r.dst = img
	}
	if mc.API, err = buildCombinedAPICharts(data.API, b); err != nil {
		return nil, err
	}
	return mc, nil
}

// BuildAPICharts 构建 API 域报告图表集（按报告类型选择图表）。
func BuildAPICharts(data *APIReportData, fontPath string) (*APICharts, error) {
	b, err := newChartBuilder(fontPath)
	if err != nil {
		return nil, err
	}
	ac := &APICharts{}
	if data == nil || !b.fontOK {
		return ac, nil
	}
	switch data.ReportType {
	case TypeAPIAsset:
		if data.Asset != nil {
			ac.Dist1, err = b.pie("资产状态分布", data.Asset.StatusDist, AssetStatusName)
		}
	case TypeAPIRisk:
		if data.Risk != nil {
			if ac.Dist1, err = b.pie("发现类型分布", data.Risk.TypeDist, nil); err == nil {
				ac.Dist2, err = b.pie("严重度分布", data.Risk.SeverityDist, nil)
			}
		}
	case TypeAPIWeak:
		if data.Weakness != nil {
			if ac.Dist1, err = b.pie("弱点状态分布", data.Weakness.StatusDist, WeaknessStatusName); err == nil {
				ac.Dist2, err = b.pie("未闭环弱点严重度分布", data.Weakness.SeverityDist, nil)
			}
		}
	case TypeAPISens:
		if data.Sensitive != nil {
			if ac.Dist1, err = b.pie("数据类型分布", data.Sensitive.TypeDist, SensitiveDataTypeName); err == nil {
				ac.Trend, err = b.line("按天新增趋势", data.Sensitive.DailyNew, "新增字段数")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return ac, nil
}

// line 折线图（趋势）。points 为空返回 nil。
func (b *chartBuilder) line(title string, points []Point, seriesName string) (*ChartImage, error) {
	if !b.fontOK || len(points) == 0 {
		return nil, nil
	}
	format := trendLabelFormat(points)
	labels := make([]string, 0, len(points))
	values := make([]float64, 0, len(points))
	for _, p := range points {
		labels = append(labels, p.Time.UTC().Format(format))
		values = append(values, float64(p.Value))
	}
	opts := append(baseChartOpts(title),
		charts.XAxisOptionFunc(chartXAxis(labels)),
		charts.YAxisOptionFunc(chartYAxis(nil)),
		charts.LegendOptionFunc(chartLegend([]string{sanitizeChartLabel(seriesName)})),
	)
	return renderChartPair(func(extra charts.OptionFunc) (*charts.Painter, error) {
		return charts.LineRender([][]float64{values}, withOutputType(opts, extra)...)
	})
}

// pie 饼图（分布）。kvs 为空返回 nil；nameFn 为标签中文名映射（可 nil）。
// 不设图例：扇区标签已带「名称: 占比」，图例冗余且多类目时与标签/标题重叠。
func (b *chartBuilder) pie(title string, kvs []KV, nameFn func(string) string) (*ChartImage, error) {
	if !b.fontOK || len(kvs) == 0 {
		return nil, nil
	}
	labels := make([]string, 0, len(kvs))
	values := make([]float64, 0, len(kvs))
	for _, kv := range kvs {
		labels = append(labels, chartKVLabel(kv.Key, nameFn))
		values = append(values, float64(kv.Value))
	}
	opts := append(baseChartOpts(title),
		charts.LegendOptionFunc(charts.LegendOption{Show: charts.FalseFlag()}),
		pieSeriesLabelOption(labels),
	)
	return renderChartPair(func(extra charts.OptionFunc) (*charts.Painter, error) {
		return charts.PieRender(values, withOutputType(opts, extra)...)
	})
}

// hbar 横向条形图（TOP 榜）。kvs 为空返回 nil；输入按值降序，第一名在最上。
func (b *chartBuilder) hbar(title string, kvs []KV, nameFn func(string) string) (*ChartImage, error) {
	if !b.fontOK || len(kvs) == 0 {
		return nil, nil
	}
	labels := make([]string, 0, len(kvs))
	values := make([]float64, 0, len(kvs))
	for _, kv := range kvs {
		labels = append(labels, chartKVLabel(kv.Key, nameFn))
		values = append(values, float64(kv.Value))
	}
	opts := append(baseChartOpts(title),
		charts.YAxisOptionFunc(chartYAxis(labels)),
		charts.XAxisOptionFunc(chartXAxis(nil)),
	)
	return renderChartPair(func(extra charts.OptionFunc) (*charts.Painter, error) {
		return charts.HorizontalBarRender([][]float64{values}, withOutputType(opts, extra)...)
	})
}

// bar 柱状图（时段等序列分布）。kvs 为空返回 nil。
func (b *chartBuilder) bar(title string, kvs []KV, nameFn func(string) string) (*ChartImage, error) {
	if !b.fontOK || len(kvs) == 0 {
		return nil, nil
	}
	labels := make([]string, 0, len(kvs))
	values := make([]float64, 0, len(kvs))
	for _, kv := range kvs {
		labels = append(labels, chartKVLabel(kv.Key, nameFn))
		values = append(values, float64(kv.Value))
	}
	opts := append(baseChartOpts(title),
		charts.XAxisOptionFunc(chartXAxis(labels)),
		charts.YAxisOptionFunc(chartYAxis(nil)),
	)
	return renderChartPair(func(extra charts.OptionFunc) (*charts.Painter, error) {
		return charts.BarRender([][]float64{values}, withOutputType(opts, extra)...)
	})
}

// baseChartOpts 图表公共配置（尺寸/字体/标题/主题）。
func baseChartOpts(title string) []charts.OptionFunc {
	return []charts.OptionFunc{
		charts.WidthOptionFunc(chartWidth),
		charts.HeightOptionFunc(chartHeight),
		charts.FontFamilyOptionFunc(chartFontFamily),
		charts.TitleOptionFunc(charts.TitleOption{
			Text:      sanitizeChartLabel(title),
			FontSize:  chartTitleFontSize,
			FontColor: chartTextColor,
		}),
		charts.ThemeOptionFunc(chartThemeName),
	}
}

// chartXAxis X 轴配置（类目数据 + 字号纯黑）。
func chartXAxis(data []string) charts.XAxisOption {
	return charts.XAxisOption{Data: data, FontSize: chartAxisFontSize, FontColor: chartTextColor}
}

// chartYAxis Y 轴配置（字号纯黑）。
func chartYAxis(data []string) charts.YAxisOption {
	return charts.YAxisOption{Data: data, FontSize: chartAxisFontSize, FontColor: chartTextColor}
}

// chartLegend 图例配置（字号纯黑；Top 下移避开 18px 大标题，防重叠）。
func chartLegend(labels []string) charts.LegendOption {
	return charts.LegendOption{Data: labels, Top: "42", FontSize: chartAxisFontSize, FontColor: chartTextColor}
}

// pieSeriesLabelOption 饼图扇区名称与标签样式（不设图例，扇区标签由系列名驱动，
// 显示「名称: 占比」；字号+纯黑替代库默认 10px 灰色）。
func pieSeriesLabelOption(labels []string) charts.OptionFunc {
	return func(opt *charts.ChartOption) {
		for i := range opt.SeriesList {
			if i < len(labels) {
				opt.SeriesList[i].Name = labels[i]
			}
			opt.SeriesList[i].Label.Show = true
			opt.SeriesList[i].Label.FontSize = chartLabelFontSize
			opt.SeriesList[i].Label.Color = chartTextColor
		}
	}
}

// withOutputType 在公共配置后追加输出类型选项（不改动原切片）。
func withOutputType(opts []charts.OptionFunc, t charts.OptionFunc) []charts.OptionFunc {
	out := make([]charts.OptionFunc, 0, len(opts)+1)
	out = append(out, opts...)
	return append(out, t)
}

// renderChartPair 同一图表渲染 PNG + SVG 两份产物。
func renderChartPair(render func(extra charts.OptionFunc) (*charts.Painter, error)) (*ChartImage, error) {
	pngPainter, err := render(charts.PNGTypeOption())
	if err != nil {
		return nil, fmt.Errorf("render chart png: %w", err)
	}
	png, err := pngPainter.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode chart png: %w", err)
	}
	svgPainter, err := render(charts.SVGTypeOption())
	if err != nil {
		return nil, fmt.Errorf("render chart svg: %w", err)
	}
	svg, err := svgPainter.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode chart svg: %w", err)
	}
	return &ChartImage{SVG: string(svg), PNG: png}, nil
}

// trendLabelFormat 按相邻点间隔选择时间标签格式（≥1天按日期，否则按小时）。
func trendLabelFormat(points []Point) string {
	if len(points) >= 2 && points[1].Time.Sub(points[0].Time) >= 24*time.Hour {
		return "01-02"
	}
	return "01-02 15:04"
}

// chartKVLabel 生成图表类目标签（中文名映射 + 消毒）。
func chartKVLabel(key string, nameFn func(string) string) string {
	if nameFn != nil {
		key = nameFn(key)
	}
	return sanitizeChartLabel(key)
}

// chartLabelReplacer XML 元字符 → 全角等价字符（防 SVG 注入，保持中文语境可读）。
var chartLabelReplacer = strings.NewReplacer(
	"<", "＜",
	">", "＞",
	"&", "＆",
	`"`, "＂",
	"'", "＇",
)

// sanitizeChartLabel 消毒进入图表 SVG 的文本标签。
func sanitizeChartLabel(s string) string {
	return chartLabelReplacer.Replace(s)
}
