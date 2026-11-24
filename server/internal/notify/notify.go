// Package notify 提供告警通知外发：企业微信/飞书/邮件/短信（二期）四渠道 + syslog 复用，
// 以及通知层风暴抑制（每渠道速率限制、同指纹静默、聚合摘要、恢复通知开关）。
//
// 架构沿用 syslogfw 范式：非阻塞 Enqueue（有界 channel，满则丢弃最旧）+
// 单协程 drain + 磁盘 spool（notify-spool.jsonl，上限 50MB）+ 10s 重放 + 配置热读
// （每批发送前重读渠道与抑制参数，CRUD 后最迟下一批生效）。
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 渠道类型。
const (
	TypeWecom  = "wecom"
	TypeFeishu = "feishu"
	TypeSMTP   = "smtp"
	TypeSyslog = "syslog"
	TypeSMS    = "sms"
)

// 告警级别（与 systemalerts 词表一致；INFO 低于 LOW，不参与 min_severity 选择）。
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// 告警状态（仅触发/恢复两类进入通知层）。
const (
	StatusOpen     = "OPEN"
	StatusResolved = "RESOLVED"
)

// severityRank 返回级别序（LOW<MEDIUM<HIGH<CRITICAL；INFO 与未知级别为 0，
// 任何 min_severity 都不会放行，避免来源不明的低级别事件刷屏）。
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// SeverityGte 判断事件级别是否达到渠道最低通知级别。
func SeverityGte(eventSeverity, minSeverity string) bool {
	return severityRank(eventSeverity) >= severityRank(minSeverity) && severityRank(eventSeverity) > 0
}

// Severities 是可配置的最低通知级别清单（notification-meta 接口契约）。
func Severities() []string {
	return []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// IsValidMinSeverity 校验 min_severity 词表。
func IsValidMinSeverity(s string) bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// IsValidType 校验渠道类型词表。
func IsValidType(t string) bool {
	switch t {
	case TypeWecom, TypeFeishu, TypeSMTP, TypeSyslog, TypeSMS:
		return true
	}
	return false
}

// Category 是告警类别（notification-meta 接口契约，固定 10 类）。
type Category struct {
	Code       string   `json:"code"`
	Name       string   `json:"name"`
	AlertTypes []string `json:"alert_types"`
}

// categories 是固定类别词表（顺序即接口返回顺序）。
var categories = []Category{
	{Code: "infrastructure", Name: "基础设施", AlertTypes: []string{
		"GATEWAY_DOWN", "MANAGEMENT_API_DOWN", "DATABASE_UNAVAILABLE", "VALKEY_UNAVAILABLE",
		"HA_VIP_FAULT", "HA_SPLIT_BRAIN", "NETWORK_APPLY_FAILED", "LINK_PAIR_DOWN", "LINK_PAIR_SUPPRESSED"}},
	{Code: "storage", Name: "存储容量", AlertTypes: []string{
		"DISK_SPACE_LOW", "DATABASE_CAPACITY_HIGH"}},
	{Code: "certificate", Name: "证书", AlertTypes: []string{
		"CERTIFICATE_EXPIRING", "CERTIFICATE_EXPIRED"}},
	{Code: "collection", Name: "采集健康", AlertTypes: []string{
		"EVENT_COLLECTOR_LAG", "EVENT_PARSE_FAILURE_RATE_HIGH", "SOURCE_UNHEALTHY", "APM_INGEST_LAG"}},
	{Code: "config_publish", Name: "配置发布", AlertTypes: []string{
		"CONFIG_PUBLISH_FAILED", "CONFIG_HASH_MISMATCH"}},
	{Code: "api_security", Name: "API安全", AlertTypes: []string{
		"API_CRITICAL_FINDING", "API_FINDING_SPIKE", "API_MASK_FAILURE"}},
	{Code: "ops", Name: "运维操作", AlertTypes: []string{
		"BACKUP_FAILED", "RESTORE_VALIDATION_FAILED", "REPORT_FAILED", "UPGRADE_FAILED", "AUDIT_INTEGRITY_FAILED",
		"BACKUP_VERIFY_FAILED", "RESTORE_CLEANUP_FAILED", "UPGRADE_ROLLBACK_FAILED", "UPGRADE_ROLLED_BACK"}},
	{Code: "security_events", Name: "安全事件", AlertTypes: []string{
		"SECURITY_EVENT_SPIKE", "LOGIN_BRUTE_FORCE", "CC_BAN_SPIKE"}},
	{Code: "apm", Name: "业务性能", AlertTypes: []string{
		"ENDPOINT_LATENCY_HIGH", "ENDPOINT_ERROR_RATE_HIGH", "APM_SLO_BREACH"}},
	{Code: "threat_intel", Name: "漏洞情报", AlertTypes: []string{
		"VULN_INTEL_NEW"}},
}

// Categories 返回固定类别词表（副本，防调用方修改）。
func Categories() []Category {
	out := make([]Category, len(categories))
	copy(out, categories)
	return out
}

// IsValidCategory 校验类别 code 词表。
func IsValidCategory(code string) bool {
	for _, c := range categories {
		if c.Code == code {
			return true
		}
	}
	return false
}

// CategoryOf 返回告警类型所属类别 code；未知类型返回空串。
func CategoryOf(alertType string) string {
	for _, c := range categories {
		for _, t := range c.AlertTypes {
			if t == alertType {
				return c.Code
			}
		}
	}
	return ""
}

// alertTypeNames 是告警类型中文名（通知文案与聚合摘要用）。
var alertTypeNames = map[string]string{
	"GATEWAY_DOWN":                  "网关离线",
	"MANAGEMENT_API_DOWN":           "管理API不可用",
	"DATABASE_UNAVAILABLE":          "数据库不可用",
	"VALKEY_UNAVAILABLE":            "Valkey不可用",
	"HA_VIP_FAULT":                  "主备VIP异常",
	"HA_SPLIT_BRAIN":                "主备双主脑裂",
	"NETWORK_APPLY_FAILED":          "网络配置执行失败",
	"LINK_PAIR_DOWN":                "端口联动触发",
	"LINK_PAIR_SUPPRESSED":          "端口联动抑制",
	"DISK_SPACE_LOW":                "磁盘空间不足",
	"DATABASE_CAPACITY_HIGH":        "数据库容量过高",
	"CERTIFICATE_EXPIRING":          "证书即将到期",
	"CERTIFICATE_EXPIRED":           "证书已过期",
	"EVENT_COLLECTOR_LAG":           "事件采集滞后",
	"EVENT_PARSE_FAILURE_RATE_HIGH": "事件解析失败率过高",
	"SOURCE_UNHEALTHY":              "源站健康异常",
	"CONFIG_PUBLISH_FAILED":         "配置发布失败",
	"CONFIG_HASH_MISMATCH":          "配置哈希不一致",
	"API_CRITICAL_FINDING":          "API高危风险发现",
	"API_FINDING_SPIKE":             "API风险发现激增",
	"API_MASK_FAILURE":              "API响应脱敏失败",
	"BACKUP_FAILED":                 "备份失败",
	"RESTORE_VALIDATION_FAILED":     "恢复验证失败",
	"REPORT_FAILED":                 "报告生成失败",
	"UPGRADE_FAILED":                "升级失败",
	"AUDIT_INTEGRITY_FAILED":        "审计完整性校验失败",
	"BACKUP_VERIFY_FAILED":          "备份验证失败",
	"RESTORE_CLEANUP_FAILED":        "恢复环境清理失败",
	"UPGRADE_ROLLBACK_FAILED":       "升级回滚失败",
	"UPGRADE_ROLLED_BACK":           "升级失败已自动回滚",
	"SECURITY_EVENT_SPIKE":          "安全事件激增",
	"LOGIN_BRUTE_FORCE":             "登录暴破锁定",
	"CC_BAN_SPIKE":                  "CC封禁激增",
	"VULN_INTEL_NEW":                "漏洞情报提醒",
}

// AlertTypeName 返回告警类型中文名；未知类型返回原 code。
func AlertTypeName(alertType string) string {
	if n, ok := alertTypeNames[alertType]; ok {
		return n
	}
	return alertType
}

// Event 是一条进入通知层的告警事件（由告警引擎闭包转换投递，值语义）。
type Event struct {
	AlertType  string    `json:"alert_type"`
	Severity   string    `json:"severity"`
	Component  string    `json:"component"`
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Status     string    `json:"status"` // OPEN=新触发 / RESOLVED=已恢复
	OccurredAt time.Time `json:"occurred_at"`
	// Summary 为 true 表示聚合摘要事件（AlertType 为空，Message 为汇总文案）。
	Summary bool `json:"summary,omitempty"`
}

// fingerprint 是同告警免打扰指纹（alert_type+component）。
func (e Event) fingerprint() string {
	return e.AlertType + "|" + e.Component
}

// Channel 是一条通知渠道（config 中的密值字段按用途分别为明文/密文/脱敏值，见 store.go）。
type Channel struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Enabled     bool                   `json:"enabled"`
	MinSeverity string                 `json:"min_severity"`
	Categories  []string               `json:"categories"`
	Config      map[string]interface{} `json:"config"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// subscribes 判断渠道是否订阅该事件（级别达标 且 类别为空=全部 或 含事件类别）。
func (c *Channel) subscribes(ev Event) bool {
	if !c.Enabled {
		return false
	}
	if !SeverityGte(ev.Severity, c.MinSeverity) {
		return false
	}
	if len(c.Categories) == 0 {
		return true
	}
	code := CategoryOf(ev.AlertType)
	if code == "" {
		return false
	}
	for _, sub := range c.Categories {
		if sub == code {
			return true
		}
	}
	return false
}

// ---------- 消息渲染 ----------

// shanghai 是通知文案时区（容器可能无 tzdata，Asia/Shanghai 加载失败回退固定 +8）。
var shanghai = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("Asia/Shanghai", 8*3600)
	}
	return loc
}()

// Message 是渲染后的通知内容：Text 为纯文本（邮件/syslog/摘要），
// Markdown 为企业微信格式；飞书 post 富文本由 sender 按 Text 行构建。
type Message struct {
	Subject  string
	Text     string
	Markdown string
}

// renderMessage 把事件渲染为通知文案（中文，含级别/类型中文名/组件/标题/详情/时间）。
func renderMessage(ev Event) Message {
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	ts := occurred.In(shanghai).Format("2006-01-02 15:04:05")

	if ev.Summary {
		subject := "【九章WAF告警摘要】" + ev.Title
		text := fmt.Sprintf("%s\n详情：%s\n时间：%s（Asia/Shanghai）", ev.Title, ev.Message, ts)
		md := fmt.Sprintf("**%s**\n> 详情：%s\n> 时间：%s", subject, ev.Message, ts)
		return Message{Subject: subject, Text: text, Markdown: md}
	}

	statusCN := "新触发"
	if ev.Status == StatusResolved {
		statusCN = "已恢复"
	}
	subject := fmt.Sprintf("【九章WAF告警】%s", ev.Title)
	if ev.Status == StatusResolved {
		subject = fmt.Sprintf("【九章WAF恢复】%s", ev.Title)
	}
	typeCN := AlertTypeName(ev.AlertType)
	text := fmt.Sprintf(
		"级别：%s\n类型：%s（%s）\n组件：%s\n标题：%s\n状态：%s\n详情：%s\n时间：%s（Asia/Shanghai）",
		ev.Severity, typeCN, ev.AlertType, ev.Component, ev.Title, statusCN, ev.Message, ts)

	// 企业微信 markdown 字体颜色：高危以上橙红，恢复绿色，其余灰色
	color := "comment"
	switch {
	case ev.Status == StatusResolved:
		color = "info"
	case severityRank(ev.Severity) >= severityRank(SeverityHigh):
		color = "warning"
	}
	md := fmt.Sprintf(
		"**%s**\n> 级别：<font color=\"%s\">%s</font>\n> 类型：%s（%s）\n> 组件：%s\n> 状态：%s\n> 详情：%s\n> 时间：%s",
		subject, color, ev.Severity, typeCN, ev.AlertType, ev.Component, statusCN, ev.Message, ts)
	return Message{Subject: subject, Text: text, Markdown: md}
}
