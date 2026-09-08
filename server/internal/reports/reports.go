// Package reports 阶段6报告系统：日报/周报/月报/自定义报告的数据采集、
// 确定性结论生成、HTML/PDF 渲染、异步任务调度与下载审计。
//
// 安全约束：
//   - 统计内容全部来自聚合表与原始事件表，禁止 Mock；
//   - 结论与建议由确定性模板规则生成，不使用任何 AI/随机判断；
//   - 报告模板字段仅作为数据渲染（固定 Go 模板），不得执行任意代码/脚本/外部请求；
//   - 报告文件名为 report-{id}.{ext}，存放于 GATEWAY_DATA_DIR/reports/，
//     下载前校验文件名、归属与 sha256 完整性；
//   - 报告中不包含未脱敏的攻击载荷（仅统计与规则元数据）。
package reports

import (
	"time"

	"github.com/google/uuid"
)

// 报告类型
const (
	TypeDaily   = "DAILY"
	TypeWeekly  = "WEEKLY"
	TypeMonthly = "MONTHLY"
	TypeCustom  = "CUSTOM"
)

// 任务状态机：PENDING → COLLECTING → AGGREGATING → RENDERING → SUCCESS / FAILED / CANCELLED
const (
	StatusPending     = "PENDING"
	StatusCollecting  = "COLLECTING"
	StatusAggregating = "AGGREGATING"
	StatusRendering   = "RENDERING"
	StatusSuccess     = "SUCCESS"
	StatusFailed      = "FAILED"
	StatusCancelled   = "CANCELLED"
)

// 导出文件格式
const (
	FormatHTML = "html"
	FormatPDF  = "pdf"
	FormatDOCX = "docx"
)

// 报告内容范围（报告类型固定 日/周/月/自定义，内容范围独立选择）。
// 空串为兼容值（历史任务），语义同 ScopeWAFAPI。
const (
	ScopeWAF    = "WAF"     // 仅 Web 应用防护（上篇）
	ScopeAPI    = "API"     // 仅 API 动态防护（下篇）
	ScopeWAFAPI = "WAF_API" // Web + API 全部（默认）
)

// validContentScope 校验内容范围。
func validContentScope(s string) bool {
	return s == "" || s == ScopeWAF || s == ScopeAPI || s == ScopeWAFAPI
}

// NormalizeContentScope 归一化内容范围（空串 → WAF_API）。
func NormalizeContentScope(s string) string {
	if s == "" {
		return ScopeWAFAPI
	}
	return s
}

// 纸张方向（PDF/Word 导出）。
const (
	OrientationPortrait  = "P" // 竖向（默认）
	OrientationLandscape = "L" // 横向
)

// validPageOrientation 校验纸张方向。
func validPageOrientation(s string) bool {
	return s == "" || s == OrientationPortrait || s == OrientationLandscape
}

// NormalizePageOrientation 归一化纸张方向（空串 → 竖向）。
func NormalizePageOrientation(s string) string {
	if s == OrientationLandscape {
		return OrientationLandscape
	}
	return OrientationPortrait
}

// ContentScopeIncludesAPI 内容范围是否包含 API 部分。
func ContentScopeIncludesAPI(s string) bool {
	return NormalizeContentScope(s) != ScopeWAF
}

// ContentScopeIncludesWeb 内容范围是否包含 Web 防护部分。
func ContentScopeIncludesWeb(s string) bool {
	return NormalizeContentScope(s) != ScopeAPI
}

// 限制
const (
	// MaxReportFileSize 报告文件大小上限（20MB）
	MaxReportFileSize = 20 << 20
	// GenerateTimeout 单份报告生成时长上限（5分钟）
	GenerateTimeout = 5 * time.Minute
	// MaxCustomRangeHours 自定义报告时间跨度上限（366天）
	MaxCustomRangeHours = 366 * 24
)

// 失败码（写入 report_jobs.failure_code）
const (
	FailCollect      = "COLLECT_FAILED"
	FailRender       = "RENDER_FAILED"
	FailWrite        = "WRITE_FAILED"
	FailFileTooLarge = "FILE_TOO_LARGE"
	FailTimeout      = "TIMEOUT"
	FailFont         = "FONT_UNAVAILABLE"
	FailTemplate     = "TEMPLATE_NOT_FOUND"
	FailInvalidState = "INVALID_STATE"
)

// 报告章节键（26节，sections JSONB 开关使用同一组键）
const (
	SectionCover          = "cover"           // 封面
	SectionPeriod         = "period"          // 报告周期
	SectionScope          = "scope"           // 报告范围
	SectionSummary        = "summary"         // 管理摘要
	SectionComparison     = "comparison"      // 环比对比
	SectionTraffic        = "traffic"         // 请求流量
	SectionEventsOverview = "events_overview" // 安全事件总览
	SectionRiskLevel      = "risk_level"      // 风险等级
	SectionAttackTypes    = "attack_types"    // 攻击类型分布
	SectionAttackTrend    = "attack_trend"    // 攻击趋势
	SectionAttackHours    = "attack_hours"    // 攻击时段分布
	SectionSourceIPs      = "source_ips"      // 攻击源IP
	SectionSourceGeo      = "source_geo"      // 攻击源地区
	SectionApplications   = "applications"    // 被攻击应用
	SectionTargetPaths    = "target_paths"    // 被攻击路径
	SectionRuleHits       = "rule_hits"       // 命中规则
	SectionEventSamples   = "event_samples"   // 高危事件明细
	SectionCCProtection   = "cc_protection"   // CC防护
	SectionIPLists        = "ip_lists"        // 黑白名单
	SectionDisposition    = "disposition"     // 事件处置
	SectionFalsePositive  = "false_positives" // 误报和例外
	SectionUpstreamHealth = "upstream_health" // 源站健康
	SectionCertificates   = "certificates"    // 证书状态
	SectionPublishTasks   = "publish_tasks"   // 策略发布
	SectionSystemHealth   = "system_health"   // 系统运行
	// API 安全部分（WDSP 且 API 动态防护开启时输出，约占报告内容 40%）
	SectionAPIOverview     = "api_overview"      // API 资产总览
	SectionAPIAssetList    = "api_asset_list"    // API 资产清单（全量，任务开启时输出）
	SectionAPINewEndpoints = "api_new_endpoints" // 新增 API 端点
	SectionAPIShadow       = "api_shadow"        // Shadow API 清单
	SectionAPIRisk         = "api_risk"          // API 风险发现
	SectionAPIRiskDist     = "api_risk_dist"     // 发现类型与严重度分布
	SectionAPIRiskTop      = "api_risk_top"      // 风险端点 TOP10
	SectionAPISubjects     = "api_subjects"      // 风险主体 TOP10
	SectionAPIWeakness     = "api_weakness"      // API 弱点整改
	SectionAPIWeakOverdue  = "api_weak_overdue"  // 超期未修清单
	SectionAPISensitive    = "api_sensitive"     // API 敏感数据
	SectionAPISensitiveTop = "api_sensitive_top" // 涉敏端点 TOP10
	SectionConclusions     = "conclusions"       // 结论和建议
)

// SectionKeys 全部章节键（固定顺序，渲染与校验共用）。
var SectionKeys = []string{
	SectionCover, SectionPeriod, SectionScope, SectionSummary, SectionComparison,
	SectionTraffic, SectionEventsOverview, SectionRiskLevel, SectionAttackTypes, SectionAttackTrend,
	SectionAttackHours, SectionSourceIPs, SectionSourceGeo, SectionApplications, SectionTargetPaths,
	SectionRuleHits, SectionEventSamples, SectionCCProtection,
	SectionIPLists, SectionDisposition, SectionFalsePositive, SectionUpstreamHealth,
	SectionCertificates, SectionPublishTasks, SectionSystemHealth,
	SectionAPIOverview, SectionAPIAssetList, SectionAPINewEndpoints, SectionAPIShadow, SectionAPIRisk, SectionAPIRiskDist,
	SectionAPIRiskTop, SectionAPISubjects, SectionAPIWeakness, SectionAPIWeakOverdue,
	SectionAPISensitive, SectionAPISensitiveTop, SectionConclusions,
}

// SectionTitles 章节键 → 中文标题。
var SectionTitles = map[string]string{
	SectionCover:           "封面",
	SectionPeriod:          "报告周期",
	SectionScope:           "报告范围",
	SectionSummary:         "管理摘要",
	SectionComparison:      "环比对比",
	SectionTraffic:         "请求流量",
	SectionEventsOverview:  "安全事件总览",
	SectionRiskLevel:       "风险等级",
	SectionAttackTypes:     "攻击类型分布",
	SectionAttackTrend:     "攻击趋势",
	SectionAttackHours:     "攻击时段分布",
	SectionSourceIPs:       "攻击源IP TOP10",
	SectionSourceGeo:       "攻击源地区 TOP10",
	SectionApplications:    "被攻击应用 TOP10",
	SectionTargetPaths:     "被攻击路径 TOP10",
	SectionRuleHits:        "命中规则 TOP10",
	SectionEventSamples:    "高危事件明细 TOP20",
	SectionCCProtection:    "CC防护",
	SectionIPLists:         "黑白名单",
	SectionDisposition:     "事件处置",
	SectionFalsePositive:   "误报和例外",
	SectionUpstreamHealth:  "源站健康",
	SectionCertificates:    "证书状态",
	SectionPublishTasks:    "策略发布",
	SectionSystemHealth:    "系统运行",
	SectionAPIOverview:     "API 资产总览",
	SectionAPIAssetList:    "API 资产清单（全量）",
	SectionAPINewEndpoints: "新增 API 端点 TOP20",
	SectionAPIShadow:       "Shadow API 清单",
	SectionAPIRisk:         "API 风险发现",
	SectionAPIRiskDist:     "发现类型与严重度分布",
	SectionAPIRiskTop:      "风险端点 TOP10",
	SectionAPISubjects:     "风险主体 TOP10",
	SectionAPIWeakness:     "API 弱点整改",
	SectionAPIWeakOverdue:  "超期未修清单",
	SectionAPISensitive:    "API 敏感数据",
	SectionAPISensitiveTop: "涉敏端点 TOP10",
	SectionConclusions:     "结论和建议",
}

// DefaultSections 默认章节开关（全部开启）。
func DefaultSections() map[string]bool {
	m := make(map[string]bool, len(SectionKeys))
	for _, k := range SectionKeys {
		m[k] = true
	}
	return m
}

// validSectionKey 校验章节键合法。
func validSectionKey(k string) bool {
	_, ok := SectionTitles[k]
	return ok
}

// Show 判断章节是否启用（未显式关闭即启用）。
func Show(sections map[string]bool, key string) bool {
	if sections == nil {
		return true
	}
	v, ok := sections[key]
	return !ok || v
}

// Template 报告模板。
type Template struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	IsBuiltin      bool            `json:"is_builtin"`
	CompanyName    string          `json:"company_name"`
	ProductName    string          `json:"product_name"`
	LogoText       string          `json:"logo_text"`
	HeaderText     string          `json:"header_text"`
	FooterText     string          `json:"footer_text"`
	ReportNoFormat string          `json:"report_no_format"`
	PreparedBy     string          `json:"prepared_by"`
	ReviewedBy     string          `json:"reviewed_by"`
	Description    string          `json:"description"`
	Sections       map[string]bool `json:"sections"`
	CreatedBy      *uuid.UUID      `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Version        int             `json:"version"`
}

// Show 判断模板中某章节是否启用。
func (t *Template) Show(key string) bool {
	return Show(t.Sections, key)
}

// apiPartSectionKeys API 安全部分章节键（下篇 12 节）。
var apiPartSectionKeys = []string{
	SectionAPIOverview, SectionAPIAssetList, SectionAPINewEndpoints, SectionAPIShadow, SectionAPIRisk, SectionAPIRiskDist,
	SectionAPIRiskTop, SectionAPISubjects, SectionAPIWeakness, SectionAPIWeakOverdue,
	SectionAPISensitive, SectionAPISensitiveTop,
}

// webContentSectionKeys Web 防护内容章节键（上篇；封面/周期/范围/结论为共用元章节，不在此列）。
var webContentSectionKeys = []string{
	SectionSummary, SectionComparison, SectionTraffic, SectionEventsOverview, SectionRiskLevel,
	SectionAttackTypes, SectionAttackTrend, SectionAttackHours, SectionSourceIPs, SectionSourceGeo,
	SectionApplications, SectionTargetPaths, SectionRuleHits, SectionEventSamples, SectionCCProtection,
	SectionIPLists, SectionDisposition, SectionFalsePositive, SectionUpstreamHealth, SectionCertificates,
	SectionPublishTasks, SectionSystemHealth,
}

// tplForScope 按内容范围裁剪模板章节开关：WAF 关闭 API 部分章节，API 关闭 Web 内容章节。
// 返回模板副本（不改原对象）；WAF_API 或兼容空值原样返回。
func tplForScope(tpl *Template, scope string) *Template {
	if tpl == nil {
		return nil
	}
	scope = NormalizeContentScope(scope)
	if scope == ScopeWAFAPI {
		return tpl
	}
	out := *tpl
	sections := DefaultSections()
	for k, v := range tpl.Sections {
		sections[k] = v
	}
	if scope == ScopeWAF {
		for _, k := range apiPartSectionKeys {
			sections[k] = false
		}
	} else { // ScopeAPI
		for _, k := range webContentSectionKeys {
			sections[k] = false
		}
	}
	out.Sections = sections
	return &out
}

// apiPartDivider 下篇分隔标题（API-only 报告不分上下篇）。
func apiPartDivider(scope string) string {
	if NormalizeContentScope(scope) == ScopeAPI {
		return "API 动态防护"
	}
	return "下篇：API 动态防护"
}

// showAPIPart 是否输出 API 部分（数据存在且至少一个 API 章节启用）。
func showAPIPart(tpl *Template, data *ReportData) bool {
	if data == nil || data.API == nil || tpl == nil {
		return false
	}
	for _, k := range apiPartSectionKeys {
		if tpl.Show(k) {
			return true
		}
	}
	return false
}

// Job 报告生成任务。
type Job struct {
	ID               uuid.UUID   `json:"id"`
	ReportType       string      `json:"report_type"`
	ContentScope     string      `json:"content_scope"` // WAF / API / WAF_API（空为兼容值 WAF_API）
	Start            time.Time   `json:"time_range_start"`
	End              time.Time   `json:"time_range_end"`
	ApplicationIDs   []uuid.UUID `json:"application_ids"`
	TemplateID       *uuid.UUID  `json:"template_id"`
	ScheduleID       *uuid.UUID  `json:"schedule_id"`        // 来源定时计划（NULL 为手工创建）
	IncludeAPIAssets bool        `json:"include_api_assets"` // 是否包含全量 API 资产清单
	PageOrientation  string      `json:"page_orientation"`   // P 竖向 / L 横向（PDF/Word）
	Status           string      `json:"status"`
	Progress         int         `json:"progress"`
	RequestedBy      *uuid.UUID  `json:"requested_by"`
	RequestedAt      time.Time   `json:"requested_at"`
	StartedAt        *time.Time  `json:"started_at"`
	FinishedAt       *time.Time  `json:"finished_at"`
	FileReference    string      `json:"file_reference"`
	FileHash         string      `json:"file_hash"`
	FileFormat       string      `json:"file_format"`
	FileSize         int64       `json:"file_size"`
	ReportNo         string      `json:"report_no"`
	FailureCode      string      `json:"failure_code"`
	FailureMessage   string      `json:"failure_message"`
	RequestID        string      `json:"request_id"`
}

// FileName 报告文件名（report-{id}.{ext}）。
func (j *Job) FileName() string {
	return ReportFileName(j.ID, j.FileFormat)
}

// validReportType 校验报告类型（含 API 域报告类型，词表见 api.go）。
func validReportType(t string) bool {
	switch t {
	case TypeDaily, TypeWeekly, TypeMonthly, TypeCustom:
		return true
	}
	return IsAPIReportType(t)
}

// validFormat 校验导出格式。
func validFormat(f string) bool {
	return f == FormatHTML || f == FormatPDF || f == FormatDOCX
}
