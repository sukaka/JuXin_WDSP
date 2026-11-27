// Package blockpages 实现自定义拦截页面模板库、不可变修订版本历史、安全净化渲染与全局/应用/场景绑定管理。
package blockpages

import (
	"time"

	"github.com/google/uuid"
)

// 编辑模式常量。
const (
	EditorModeVisual = "VISUAL"
	EditorModeHTML   = "HTML"
)

// 拦截场景常量（绑定表与网关运行时冻结词表）。
const (
	SceneDefault       = "DEFAULT"
	SceneWAF           = "WAF"
	SceneAccessControl = "ACCESS_CONTROL"
	SceneRateLimit     = "RATE_LIMIT"
)

// 内置视觉皮肤主题常量。
const (
	ThemeClassicDark    = "classic_dark"
	ThemeCleanLight     = "clean_light"
	ThemeEnterpriseBlue = "enterprise_blue"
	ThemeAlertRed       = "alert_red"
	ThemeAmberLimit     = "amber_limit"
)

// 硬上限常量（管理面与网关侧保持同口径）。
const (
	MaxNameRunes         = 128
	MaxDescriptionRunes  = 512
	MaxChangeNoteRunes   = 512
	MaxHTMLBytes         = 65536 // 64 KiB
	MaxJSONCodeBytes     = 128
	MaxJSONMessageBytes  = 512
	MaxTemplatesTotal    = 100
	MaxRequestBodyBytes  = 256 * 1024
	DefaultPage          = 1
	DefaultPageSize      = 20
	MaxPageSize          = 100
	MaxVisualTextRunes   = 1024
	MaxVisualShortRunes  = 160
	MaxLogoURLBytes      = 512
)

// FieldError 字段级参数校验错误（与项目其余模块同构）。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// VisualConfig 可视化配置模式的结构化字段。
type VisualConfig struct {
	Badge          string `json:"badge"`
	Title          string `json:"title"`
	Subtitle       string `json:"subtitle,omitempty"`
	Description    string `json:"description"`
	ContactInfo    string `json:"contact_info,omitempty"`
	BrandName      string `json:"brand_name,omitempty"`
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	BgColor        string `json:"bg_color,omitempty"`
	CardColor      string `json:"card_color,omitempty"`
	TextColor      string `json:"text_color,omitempty"`
	ShowRequestID  bool   `json:"show_request_id"`
	ShowTimestamp  bool   `json:"show_timestamp"`
	ShowClientIP   bool   `json:"show_client_ip"`
	ShowDomain     bool   `json:"show_domain"`
	ShowStatusCode bool   `json:"show_status_code"`
	ShowRetryAfter bool   `json:"show_retry_after,omitempty"`
	FooterText     string `json:"footer_text,omitempty"`
}

// BlockPage 自定义拦截页面模板（当前最新版本视图）。
type BlockPage struct {
	ID           uuid.UUID    `json:"id"`
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	EditorMode   string       `json:"editor_mode"`
	Theme        string       `json:"theme"`
	VisualConfig VisualConfig `json:"visual_config"`
	HTMLContent  string       `json:"html_content"`
	RenderedHTML string       `json:"rendered_html"`
	StatusCode   int          `json:"status_code"`
	JSONCode     string       `json:"json_code"`
	JSONMessage  string       `json:"json_message"`
	Version      int          `json:"version"`
	IsBuiltin    bool         `json:"is_builtin"`
	BindingCount int          `json:"binding_count"`
	CreatedBy    string       `json:"created_by"`
	UpdatedBy    string       `json:"updated_by"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// BlockPageVersion 不可变修订版本历史条目。
type BlockPageVersion struct {
	ID           uuid.UUID    `json:"id"`
	BlockPageID  uuid.UUID    `json:"block_page_id"`
	Version      int          `json:"version"`
	EditorMode   string       `json:"editor_mode"`
	Theme        string       `json:"theme"`
	VisualConfig VisualConfig `json:"visual_config"`
	HTMLContent  string       `json:"html_content"`
	RenderedHTML string       `json:"rendered_html"`
	StatusCode   int          `json:"status_code"`
	JSONCode     string       `json:"json_code"`
	JSONMessage  string       `json:"json_message"`
	ChangeNote   string       `json:"change_note"`
	CreatedBy    string       `json:"created_by"`
	CreatedAt    time.Time    `json:"created_at"`
}

// BlockPageBinding 生效绑定条目（全局或应用 × 场景）。
type BlockPageBinding struct {
	ID                     uuid.UUID  `json:"id"`
	ApplicationID          *uuid.UUID `json:"application_id"`
	ApplicationCode        string     `json:"application_code,omitempty"`
	ApplicationName        string     `json:"application_name,omitempty"`
	Scene                  string     `json:"scene"`
	BlockPageID            uuid.UUID  `json:"block_page_id"`
	BlockPageName          string     `json:"block_page_name"`
	BlockPageLatestVersion int        `json:"block_page_latest_version"`
	PinnedVersion          *int       `json:"pinned_version"`
	EffectiveVersion       int        `json:"effective_version"`
	Enabled                bool       `json:"enabled"`
	UpdatedBy              string     `json:"updated_by"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// ListFilter 模板分页查询过滤条件。
type ListFilter struct {
	Keyword    string
	EditorMode string
	Page       int
	PageSize   int
}

// BindingFilter 生效绑定查询过滤条件。
type BindingFilter struct {
	ApplicationID *uuid.UUID
	GlobalOnly    bool
	Scene         string
}

// CreateInput 新建拦截页模板输入。
type CreateInput struct {
	Name         string
	Description  string
	EditorMode   string
	Theme        string
	VisualConfig VisualConfig
	HTMLContent  string
	RenderedHTML string
	StatusCode   int
	JSONCode     string
	JSONMessage  string
	ChangeNote   string
	CreatedBy    string
}

// UpdateInput 更新拦截页模板输入（追加新修订版本）。
type UpdateInput struct {
	ID              uuid.UUID
	ExpectedVersion int
	Name            string
	Description     string
	EditorMode      string
	Theme           string
	VisualConfig    VisualConfig
	HTMLContent     string
	RenderedHTML    string
	StatusCode      int
	JSONCode        string
	JSONMessage     string
	ChangeNote      string
	UpdatedBy       string
}

// RollbackInput 回滚拦截页到指定历史版本（追加为 version+1）。
type RollbackInput struct {
	ID              uuid.UUID
	ExpectedVersion int
	TargetVersion   int
	ChangeNote      string
	UpdatedBy       string
}

// UpsertBindingInput 创建或更新生效绑定输入。
type UpsertBindingInput struct {
	ApplicationID *uuid.UUID
	Scene         string
	BlockPageID   uuid.UUID
	PinnedVersion *int
	Enabled       bool
	UpdatedBy     string
}

// ThemePreset 描述前端可选的内置主题元信息。
type ThemePreset struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	BgColor      string `json:"bg_color"`
	CardColor    string `json:"card_color"`
	PrimaryColor string `json:"primary_color"`
	TextColor    string `json:"text_color"`
}

// PlaceholderInfo 描述可用的运行时动态占位变量。
type PlaceholderInfo struct {
	Token       string `json:"token"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Example     string `json:"example"`
}

// SceneInfo 描述可绑定的拦截场景。
type SceneInfo struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// BuiltinThemes 返回全部可视化预设皮肤元信息。
func BuiltinThemes() []ThemePreset {
	return []ThemePreset{
		{
			Key:          ThemeClassicDark,
			Label:        "经典深空暗色",
			Description:  "深蓝暗色高对比卡片，稳重专业",
			BgColor:      "#1b2431",
			CardColor:    "#232f42",
			PrimaryColor: "#e06c75",
			TextColor:    "#e6e9ef",
		},
		{
			Key:          ThemeCleanLight,
			Label:        "极简企业浅色",
			Description:  "明净留白卡片风格，适合品牌化对外站点",
			BgColor:      "#f3f5f9",
			CardColor:    "#ffffff",
			PrimaryColor: "#1d4ed8",
			TextColor:    "#1f2937",
		},
		{
			Key:          ThemeEnterpriseBlue,
			Label:        "政企蓝盾风格",
			Description:  "庄重深蓝顶栏与清晰公告区，适合政企机构",
			BgColor:      "#edf2f7",
			CardColor:    "#ffffff",
			PrimaryColor: "#0f2d52",
			TextColor:    "#1a202c",
		},
		{
			Key:          ThemeAlertRed,
			Label:        "高危安全警示",
			Description:  "强对比赤红警戒条，突出恶意攻击拦截",
			BgColor:      "#181216",
			CardColor:    "#241a20",
			PrimaryColor: "#dc2626",
			TextColor:    "#f5e9ec",
		},
		{
			Key:          ThemeAmberLimit,
			Label:        "温和限流提示",
			Description:  "柔和琥珀色卡片，专为 CC 限速 429 场景设计",
			BgColor:      "#fffbeb",
			CardColor:    "#ffffff",
			PrimaryColor: "#d97706",
			TextColor:    "#451a03",
		},
	}
}

// SupportedPlaceholders 返回支持的运行时动态占位变量清单。
func SupportedPlaceholders() []PlaceholderInfo {
	return []PlaceholderInfo{
		{Token: "{{request_id}}", Label: "请求编号", Description: "本次拦截唯一追踪 ID（与 X-Jiuzhang-Request-ID 一致）", Example: "req-8f2a9c41-0b7e"},
		{Token: "{{time}}", Label: "发生时间（UTC）", Description: "拦截发生的 UTC 时间", Example: "2026-11-26 15:30:00 UTC"},
		{Token: "{{time_local}}", Label: "发生时间（东八区）", Description: "拦截发生的北京时间（UTC+8）", Example: "2026-11-26 23:30:00 +0800"},
		{Token: "{{client_ip}}", Label: "客户端真实 IP", Description: "经可信代理识别后的真实客户端 IP", Example: "203.0.113.42"},
		{Token: "{{domain}}", Label: "访问站点域名", Description: "被拦截请求的 Host 域名", Example: "shop.example.com"},
		{Token: "{{path}}", Label: "请求路径", Description: "被拦截请求的 URL 路径（自动截断与转义）", Example: "/api/v1/orders"},
		{Token: "{{status_code}}", Label: "状态码", Description: "本次拦截返回的 HTTP 状态码", Example: "403"},
		{Token: "{{scene}}", Label: "场景标识", Description: "拦截场景编码（WAF / ACCESS_CONTROL / RATE_LIMIT）", Example: "WAF"},
		{Token: "{{scene_label}}", Label: "场景名称", Description: "拦截场景中文名称", Example: "WAF 安全拦截"},
		{Token: "{{app_code}}", Label: "应用编码", Description: "被保护应用的唯一编码", Example: "shop-web"},
		{Token: "{{retry_after}}", Label: "重试等待（秒）", Description: "429 限速场景建议客户端重试等待秒数", Example: "60"},
		{Token: "{{message}}", Label: "补充说明", Description: "L7 规则等附加拦截提示文案（自动转义）", Example: "当前请求触发访问控制规则"},
	}
}

// SupportedScenes 返回全部可绑定的拦截场景元信息。
func SupportedScenes() []SceneInfo {
	return []SceneInfo{
		{Key: SceneDefault, Label: "通用默认", Description: "未单独配置具体拦截场景时的统一兜底页面"},
		{Key: SceneWAF, Label: "WAF 攻击拦截", Description: "Coraza/CRS 规则拦截与 API 策略通用 403 阻断"},
		{Key: SceneAccessControl, Label: "访问控制与封禁", Description: "IP 黑名单、人工/自动临时封禁、身份封禁、风险策略 403 与 L7 阻止"},
		{Key: SceneRateLimit, Label: "CC 与频率限制", Description: "CC 频率限制、授权配额限速、风险策略 429 与 API 限速"},
	}
}

// ValidEditorMode 校验编辑模式。
func ValidEditorMode(m string) bool {
	return m == EditorModeVisual || m == EditorModeHTML
}

// ValidScene 校验拦截场景。
func ValidScene(s string) bool {
	switch s {
	case SceneDefault, SceneWAF, SceneAccessControl, SceneRateLimit:
		return true
	default:
		return false
	}
}

// ValidTheme 校验视觉主题。
func ValidTheme(t string) bool {
	switch t {
	case ThemeClassicDark, ThemeCleanLight, ThemeEnterpriseBlue, ThemeAlertRed, ThemeAmberLimit:
		return true
	default:
		return false
	}
}

// SceneLabel 返回拦截场景中文标签。
func SceneLabel(scene string) string {
	switch scene {
	case SceneWAF:
		return "WAF 安全拦截"
	case SceneAccessControl:
		return "访问控制拦截"
	case SceneRateLimit:
		return "频率限制拦截"
	default:
		return "安全拦截"
	}
}
