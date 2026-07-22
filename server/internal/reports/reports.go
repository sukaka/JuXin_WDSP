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
)

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

// 报告章节键（21节，sections JSONB 开关使用同一组键）
const (
	SectionCover          = "cover"           // 封面
	SectionPeriod         = "period"          // 报告周期
	SectionScope          = "scope"           // 报告范围
	SectionSummary        = "summary"         // 管理摘要
	SectionTraffic        = "traffic"         // 请求流量
	SectionEventsOverview = "events_overview" // 安全事件总览
	SectionRiskLevel      = "risk_level"      // 风险等级
	SectionAttackTypes    = "attack_types"    // 攻击类型分布
	SectionAttackTrend    = "attack_trend"    // 攻击趋势
	SectionSourceIPs      = "source_ips"      // 攻击源IP
	SectionApplications   = "applications"    // 被攻击应用
	SectionRuleHits       = "rule_hits"       // 命中规则
	SectionCCProtection   = "cc_protection"   // CC防护
	SectionIPLists        = "ip_lists"        // 黑白名单
	SectionDisposition    = "disposition"     // 事件处置
	SectionFalsePositive  = "false_positives" // 误报和例外
	SectionUpstreamHealth = "upstream_health" // 源站健康
	SectionCertificates   = "certificates"    // 证书状态
	SectionPublishTasks   = "publish_tasks"   // 策略发布
	SectionSystemHealth   = "system_health"   // 系统运行
	SectionConclusions    = "conclusions"     // 结论和建议
)

// SectionKeys 全部章节键（固定顺序，渲染与校验共用）。
var SectionKeys = []string{
	SectionCover, SectionPeriod, SectionScope, SectionSummary, SectionTraffic,
	SectionEventsOverview, SectionRiskLevel, SectionAttackTypes, SectionAttackTrend,
	SectionSourceIPs, SectionApplications, SectionRuleHits, SectionCCProtection,
	SectionIPLists, SectionDisposition, SectionFalsePositive, SectionUpstreamHealth,
	SectionCertificates, SectionPublishTasks, SectionSystemHealth, SectionConclusions,
}

// SectionTitles 章节键 → 中文标题。
var SectionTitles = map[string]string{
	SectionCover:          "封面",
	SectionPeriod:         "报告周期",
	SectionScope:          "报告范围",
	SectionSummary:        "管理摘要",
	SectionTraffic:        "请求流量",
	SectionEventsOverview: "安全事件总览",
	SectionRiskLevel:      "风险等级",
	SectionAttackTypes:    "攻击类型分布",
	SectionAttackTrend:    "攻击趋势",
	SectionSourceIPs:      "攻击源IP TOP10",
	SectionApplications:   "被攻击应用 TOP10",
	SectionRuleHits:       "命中规则 TOP10",
	SectionCCProtection:   "CC防护",
	SectionIPLists:        "黑白名单",
	SectionDisposition:    "事件处置",
	SectionFalsePositive:  "误报和例外",
	SectionUpstreamHealth: "源站健康",
	SectionCertificates:   "证书状态",
	SectionPublishTasks:   "策略发布",
	SectionSystemHealth:   "系统运行",
	SectionConclusions:    "结论和建议",
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

// Job 报告生成任务。
type Job struct {
	ID             uuid.UUID   `json:"id"`
	ReportType     string      `json:"report_type"`
	Start          time.Time   `json:"time_range_start"`
	End            time.Time   `json:"time_range_end"`
	ApplicationIDs []uuid.UUID `json:"application_ids"`
	TemplateID     *uuid.UUID  `json:"template_id"`
	Status         string      `json:"status"`
	Progress       int         `json:"progress"`
	RequestedBy    *uuid.UUID  `json:"requested_by"`
	RequestedAt    time.Time   `json:"requested_at"`
	StartedAt      *time.Time  `json:"started_at"`
	FinishedAt     *time.Time  `json:"finished_at"`
	FileReference  string      `json:"file_reference"`
	FileHash       string      `json:"file_hash"`
	FileFormat     string      `json:"file_format"`
	FileSize       int64       `json:"file_size"`
	ReportNo       string      `json:"report_no"`
	FailureCode    string      `json:"failure_code"`
	FailureMessage string      `json:"failure_message"`
	RequestID      string      `json:"request_id"`
}

// FileName 报告文件名（report-{id}.{ext}）。
func (j *Job) FileName() string {
	return ReportFileName(j.ID, j.FileFormat)
}

// validReportType 校验报告类型。
func validReportType(t string) bool {
	switch t {
	case TypeDaily, TypeWeekly, TypeMonthly, TypeCustom:
		return true
	}
	return false
}

// validFormat 校验导出格式。
func validFormat(f string) bool {
	return f == FormatHTML || f == FormatPDF
}
