// render.go 可视化拦截页渲染器、参数校验与预览占位符替换。
package blockpages

import (
	"fmt"
	stdhtml "html"
	"regexp"
	"strings"
	"unicode/utf8"
)

var jsonCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// themePalette 定义各视觉主题的默认调色板与样式变体。
type themePalette struct {
	Bg          string
	Card        string
	Border      string
	Accent      string
	BadgeBg     string
	BadgeBorder string
	BadgeText   string
	TitleText   string
	SubText     string
	BodyText    string
	MetaBg      string
	MetaBorder  string
	MetaLabel   string
	MetaVal     string
	BrandText   string
	TopBar      bool
	HeaderBand  bool
	Shadow      string
}

var themePalettes = map[string]themePalette{
	ThemeClassicDark: {
		Bg: "#1b2431", Card: "#232f42", Border: "#33415c", Accent: "#e06c75",
		BadgeBg: "rgba(224,108,117,0.16)", BadgeBorder: "rgba(224,108,117,0.42)", BadgeText: "#e06c75",
		TitleText: "#f0f3f8", SubText: "#7c8aa5", BodyText: "#9aa7bd",
		MetaBg: "#1b2431", MetaBorder: "#2c3a52", MetaLabel: "#7c8aa5", MetaVal: "#c3cede",
		BrandText: "#5a6a86", Shadow: "0 12px 36px rgba(0,0,0,0.35)",
	},
	ThemeCleanLight: {
		Bg: "#f3f5f9", Card: "#ffffff", Border: "#e5e7eb", Accent: "#1d4ed8",
		BadgeBg: "#eff6ff", BadgeBorder: "#bfdbfe", BadgeText: "#1d4ed8",
		TitleText: "#111827", SubText: "#6b7280", BodyText: "#4b5563",
		MetaBg: "#f8fafc", MetaBorder: "#e2e8f0", MetaLabel: "#64748b", MetaVal: "#0f172a",
		BrandText: "#94a3b8", Shadow: "0 10px 30px rgba(15,23,42,0.08)",
	},
	ThemeEnterpriseBlue: {
		Bg: "#edf2f7", Card: "#ffffff", Border: "#cbd5e1", Accent: "#0f2d52",
		BadgeBg: "rgba(255,255,255,0.16)", BadgeBorder: "rgba(255,255,255,0.35)", BadgeText: "#ffffff",
		TitleText: "#0f172a", SubText: "#475569", BodyText: "#334155",
		MetaBg: "#f8fafc", MetaBorder: "#cbd5e1", MetaLabel: "#64748b", MetaVal: "#0f172a",
		BrandText: "#64748b", HeaderBand: true, Shadow: "0 12px 32px rgba(15,45,82,0.12)",
	},
	ThemeAlertRed: {
		Bg: "#181216", Card: "#241a20", Border: "#5c2832", Accent: "#dc2626",
		BadgeBg: "rgba(220,38,38,0.18)", BadgeBorder: "rgba(248,113,113,0.45)", BadgeText: "#f87171",
		TitleText: "#fff1f2", SubText: "#fda4af", BodyText: "#d6bbc1",
		MetaBg: "#181216", MetaBorder: "#452129", MetaLabel: "#a8868e", MetaVal: "#fde8ec",
		BrandText: "#7a5b62", TopBar: true, Shadow: "0 14px 40px rgba(0,0,0,0.45)",
	},
	ThemeAmberLimit: {
		Bg: "#fffbeb", Card: "#ffffff", Border: "#fde68a", Accent: "#d97706",
		BadgeBg: "#fef3c7", BadgeBorder: "#fcd34d", BadgeText: "#b45309",
		TitleText: "#78350f", SubText: "#b45309", BodyText: "#713f12",
		MetaBg: "#fffbeb", MetaBorder: "#fde68a", MetaLabel: "#92400e", MetaVal: "#451a03",
		BrandText: "#b45309", TopBar: true, Shadow: "0 10px 28px rgba(217,119,6,0.10)",
	},
}

// DefaultVisualConfig 返回新模板的默认可视化配置。
func DefaultVisualConfig() VisualConfig {
	return VisualConfig{
		Badge:          "安全拦截",
		Title:          "请求已被安全策略阻断",
		Subtitle:       "Security Policy Enforcement",
		Description:    "您发起的请求触发了本站的安全防护策略，已被拦截。如果您认为这是误判，请记录下方信息并联系系统管理员处理。",
		ContactInfo:    "请联系您的系统管理员，并提供请求编号与发生时间，以便快速定位和处理。",
		BrandName:      "九章WEB应用智能防护系统",
		ShowRequestID:  true,
		ShowTimestamp:  true,
		ShowClientIP:   true,
		ShowDomain:     true,
		ShowStatusCode: true,
	}
}

// RenderVisualHTML 将可视化配置与所选主题编译为完整、确定性、安全的 HTML 文档（保留运行时占位符）。
func RenderVisualHTML(theme string, vc VisualConfig) string {
	p, ok := themePalettes[theme]
	if !ok {
		p = themePalettes[ThemeClassicDark]
	}
	if IsValidHexColor(vc.BgColor) {
		p.Bg = strings.TrimSpace(vc.BgColor)
	}
	if IsValidHexColor(vc.CardColor) {
		p.Card = strings.TrimSpace(vc.CardColor)
	}
	if IsValidHexColor(vc.PrimaryColor) {
		p.Accent = strings.TrimSpace(vc.PrimaryColor)
		if !p.HeaderBand {
			p.BadgeText = p.Accent
			p.BadgeBorder = p.Accent
		}
	}
	if IsValidHexColor(vc.TextColor) {
		p.TitleText = strings.TrimSpace(vc.TextColor)
		p.BodyText = strings.TrimSpace(vc.TextColor)
	}

	badge := strings.TrimSpace(vc.Badge)
	if badge == "" {
		badge = "安全拦截"
	}
	title := strings.TrimSpace(vc.Title)
	if title == "" {
		title = "请求已被安全策略阻断"
	}
	desc := strings.TrimSpace(vc.Description)
	if desc == "" {
		desc = "您发起的请求触发了本站的安全防护策略，已被拦截。"
	}

	var topBorderCSS string
	if p.TopBar {
		topBorderCSS = fmt.Sprintf("border-top:4px solid %s;", p.Accent)
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>`)
	b.WriteString(stdhtml.EscapeString(title))
	b.WriteString(`</title><style>`)
	b.WriteString(`*{margin:0;padding:0;box-sizing:border-box;}`)
	fmt.Fprintf(&b, `body{font-family:"PingFang SC","Microsoft YaHei","Helvetica Neue",Arial,sans-serif;background:%s;color:%s;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}`, p.Bg, p.BodyText)
	if p.HeaderBand {
		fmt.Fprintf(&b, `.bp-card{max-width:600px;width:100%%;background:%s;border:1px solid %s;border-radius:10px;overflow:hidden;box-shadow:%s;}`, p.Card, p.Border, p.Shadow)
		fmt.Fprintf(&b, `.bp-band{background:%s;color:#ffffff;padding:20px 32px;display:flex;align-items:center;justify-content:space-between;gap:12px;}`, p.Accent)
		b.WriteString(`.bp-body{padding:32px 32px 28px;}`)
	} else {
		fmt.Fprintf(&b, `.bp-card{max-width:580px;width:100%%;background:%s;border:1px solid %s;%sborder-radius:10px;padding:38px 36px;box-shadow:%s;}`, p.Card, p.Border, topBorderCSS, p.Shadow)
		b.WriteString(`.bp-body{}`)
	}
	fmt.Fprintf(&b, `.bp-badge{display:inline-block;background:%s;color:%s;border:1px solid %s;border-radius:4px;font-size:12px;font-weight:600;padding:4px 12px;letter-spacing:1px;}`, p.BadgeBg, p.BadgeText, p.BadgeBorder)
	b.WriteString(`.bp-head-row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;}`)
	b.WriteString(`.bp-logo{max-height:36px;max-width:160px;object-fit:contain;}`)
	fmt.Fprintf(&b, `h1{font-size:22px;font-weight:600;margin-bottom:8px;color:%s;line-height:1.35;}`, p.TitleText)
	fmt.Fprintf(&b, `.bp-sub{font-size:13px;color:%s;margin-bottom:14px;}`, p.SubText)
	fmt.Fprintf(&b, `.bp-desc{font-size:14px;line-height:1.8;color:%s;margin-bottom:24px;white-space:pre-line;}`, p.BodyText)
	fmt.Fprintf(&b, `.bp-meta{background:%s;border:1px solid %s;border-radius:6px;padding:14px 18px;font-size:13px;margin-bottom:22px;}`, p.MetaBg, p.MetaBorder)
	b.WriteString(`.bp-row{display:flex;justify-content:space-between;gap:16px;padding:5px 0;word-break:break-all;}`)
	fmt.Fprintf(&b, `.bp-label{color:%s;flex-shrink:0;}`, p.MetaLabel)
	fmt.Fprintf(&b, `.bp-val{color:%s;font-family:"SF Mono",Menlo,Consolas,monospace;text-align:right;}`, p.MetaVal)
	fmt.Fprintf(&b, `.bp-contact{font-size:13px;color:%s;line-height:1.7;border-top:1px solid %s;padding-top:16px;white-space:pre-line;}`, p.SubText, p.MetaBorder)
	fmt.Fprintf(&b, `.bp-brand{margin-top:22px;font-size:12px;color:%s;text-align:center;letter-spacing:1.5px;}`, p.BrandText)
	fmt.Fprintf(&b, `.bp-footer{margin-top:10px;font-size:12px;color:%s;text-align:center;}`, p.SubText)
	b.WriteString(`</style></head><body><div class="bp-card">`)

	safeLogo, hasLogo := SanitizeImageSrc(vc.LogoURL)

	if p.HeaderBand {
		b.WriteString(`<div class="bp-band"><div class="bp-badge">`)
		b.WriteString(stdhtml.EscapeString(badge))
		b.WriteString(`</div>`)
		if hasLogo {
			fmt.Fprintf(&b, `<img class="bp-logo" src="%s" alt="Logo">`, stdhtml.EscapeString(safeLogo))
		} else if bn := strings.TrimSpace(vc.BrandName); bn != "" {
			fmt.Fprintf(&b, `<span style="font-size:13px;opacity:0.9;">%s</span>`, stdhtml.EscapeString(bn))
		}
		b.WriteString(`</div><div class="bp-body">`)
	} else {
		b.WriteString(`<div class="bp-body"><div class="bp-head-row"><div class="bp-badge">`)
		b.WriteString(stdhtml.EscapeString(badge))
		b.WriteString(`</div>`)
		if hasLogo {
			fmt.Fprintf(&b, `<img class="bp-logo" src="%s" alt="Logo">`, stdhtml.EscapeString(safeLogo))
		}
		b.WriteString(`</div>`)
	}

	fmt.Fprintf(&b, `<h1>%s</h1>`, stdhtml.EscapeString(title))
	if sub := strings.TrimSpace(vc.Subtitle); sub != "" {
		fmt.Fprintf(&b, `<div class="bp-sub">%s</div>`, stdhtml.EscapeString(sub))
	}
	fmt.Fprintf(&b, `<p class="bp-desc">%s</p>`, stdhtml.EscapeString(desc))

	var metaRows []struct{ Label, Token string }
	if vc.ShowRequestID {
		metaRows = append(metaRows, struct{ Label, Token string }{"请求编号", "{{request_id}}"})
	}
	if vc.ShowTimestamp {
		metaRows = append(metaRows, struct{ Label, Token string }{"发生时间", "{{time}}"})
	}
	if vc.ShowClientIP {
		metaRows = append(metaRows, struct{ Label, Token string }{"客户端 IP", "{{client_ip}}"})
	}
	if vc.ShowDomain {
		metaRows = append(metaRows, struct{ Label, Token string }{"访问站点", "{{domain}}"})
	}
	if vc.ShowStatusCode {
		metaRows = append(metaRows, struct{ Label, Token string }{"状态码", "{{status_code}}"})
	}
	if vc.ShowRetryAfter {
		metaRows = append(metaRows, struct{ Label, Token string }{"建议等待（秒）", "{{retry_after}}"})
	}
	if len(metaRows) > 0 {
		b.WriteString(`<div class="bp-meta">`)
		for _, row := range metaRows {
			fmt.Fprintf(&b, `<div class="bp-row"><span class="bp-label">%s</span><span class="bp-val">%s</span></div>`,
				stdhtml.EscapeString(row.Label), row.Token)
		}
		b.WriteString(`</div>`)
	}

	if contact := strings.TrimSpace(vc.ContactInfo); contact != "" {
		fmt.Fprintf(&b, `<p class="bp-contact">%s</p>`, stdhtml.EscapeString(contact))
	}
	if footer := strings.TrimSpace(vc.FooterText); footer != "" {
		fmt.Fprintf(&b, `<div class="bp-footer">%s</div>`, stdhtml.EscapeString(footer))
	}
	if brand := strings.TrimSpace(vc.BrandName); brand != "" {
		fmt.Fprintf(&b, `<div class="bp-brand">%s</div>`, stdhtml.EscapeString(brand))
	}
	b.WriteString(`</div></div></body></html>`)
	return b.String()
}

// PlaceholderValues 用于管理面实时预览或网关运行时替换动态变量。
type PlaceholderValues struct {
	RequestID  string
	TimeUTC    string
	TimeLocal  string
	ClientIP   string
	Domain     string
	Path       string
	StatusCode string
	Scene      string
	SceneLabel string
	AppCode    string
	RetryAfter string
	Message    string
}

// SubstitutePlaceholders 将白名单占位符替换为经 HTML 转义后的真实值（无模板执行，零 SSTI 风险）。
func SubstitutePlaceholders(tmpl string, v PlaceholderValues) string {
	pathVal := v.Path
	if len(pathVal) > 256 {
		pathVal = pathVal[:256] + "..."
	}
	rep := strings.NewReplacer(
		"{{request_id}}", stdhtml.EscapeString(v.RequestID),
		"{{time}}", stdhtml.EscapeString(v.TimeUTC),
		"{{time_local}}", stdhtml.EscapeString(v.TimeLocal),
		"{{client_ip}}", stdhtml.EscapeString(v.ClientIP),
		"{{domain}}", stdhtml.EscapeString(v.Domain),
		"{{path}}", stdhtml.EscapeString(pathVal),
		"{{status_code}}", stdhtml.EscapeString(v.StatusCode),
		"{{scene}}", stdhtml.EscapeString(v.Scene),
		"{{scene_label}}", stdhtml.EscapeString(v.SceneLabel),
		"{{app_code}}", stdhtml.EscapeString(v.AppCode),
		"{{retry_after}}", stdhtml.EscapeString(v.RetryAfter),
		"{{message}}", stdhtml.EscapeString(v.Message),
	)
	return rep.Replace(tmpl)
}

// CompileInput 编译并校验一份拦截页配置（Create / Update / Preview 共用）。
type CompileInput struct {
	Name         string
	CheckName    bool
	Description  string
	EditorMode   string
	Theme        string
	VisualConfig VisualConfig
	HTMLContent  string
	StatusCode   int
	JSONCode     string
	JSONMessage  string
	ChangeNote   string
}

// CompileOutput 编译结果：可直接入库和下发网关的净化后 HTML 与告警列表。
type CompileOutput struct {
	Theme        string
	RenderedHTML string
	Warnings     []string
}

// CompileAndValidate 统一校验拦截页配置并编译生成安全的最终 HTML。
func CompileAndValidate(in CompileInput) (CompileOutput, []FieldError) {
	var errs []FieldError

	if in.CheckName {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			errs = append(errs, FieldError{Field: "name", Message: "模板名称不能为空"})
		} else if utf8.RuneCountInString(name) > MaxNameRunes {
			errs = append(errs, FieldError{Field: "name", Message: fmt.Sprintf("模板名称长度不能超过 %d 个字符", MaxNameRunes)})
		}
	}
	if utf8.RuneCountInString(in.Description) > MaxDescriptionRunes {
		errs = append(errs, FieldError{Field: "description", Message: fmt.Sprintf("描述长度不能超过 %d 个字符", MaxDescriptionRunes)})
	}
	if utf8.RuneCountInString(in.ChangeNote) > MaxChangeNoteRunes {
		errs = append(errs, FieldError{Field: "change_note", Message: fmt.Sprintf("版本变更说明不能超过 %d 个字符", MaxChangeNoteRunes)})
	}
	if !ValidEditorMode(in.EditorMode) {
		errs = append(errs, FieldError{Field: "editor_mode", Message: "编辑模式仅支持 VISUAL 或 HTML"})
	}
	theme := strings.TrimSpace(in.Theme)
	if theme == "" {
		theme = ThemeClassicDark
	}
	if !ValidTheme(theme) {
		errs = append(errs, FieldError{Field: "theme", Message: "不支持的主题风格"})
	}
	if in.StatusCode != 0 && (in.StatusCode < 400 || in.StatusCode > 599) {
		errs = append(errs, FieldError{Field: "status_code", Message: "响应状态码须为 0（沿用拦截码）或 400~599"})
	}
	if len(in.JSONCode) > MaxJSONCodeBytes {
		errs = append(errs, FieldError{Field: "json_code", Message: fmt.Sprintf("JSON 错误码不能超过 %d 字节", MaxJSONCodeBytes)})
	} else if in.JSONCode != "" && !jsonCodePattern.MatchString(in.JSONCode) {
		errs = append(errs, FieldError{Field: "json_code", Message: "JSON 错误码仅允许字母、数字及 _ . -"})
	}
	if len(in.JSONMessage) > MaxJSONMessageBytes {
		errs = append(errs, FieldError{Field: "json_message", Message: fmt.Sprintf("JSON 提示文案不能超过 %d 字节", MaxJSONMessageBytes)})
	}

	var out CompileOutput
	out.Theme = theme

	switch in.EditorMode {
	case EditorModeVisual:
		errs = append(errs, validateVisualConfig(in.VisualConfig)...)
		if len(errs) == 0 {
			rendered := RenderVisualHTML(theme, in.VisualConfig)
			if len(rendered) > MaxHTMLBytes {
				errs = append(errs, FieldError{Field: "visual_config", Message: fmt.Sprintf("生成的页面体积超出上限（%d 字节）", MaxHTMLBytes)})
			} else {
				out.RenderedHTML = rendered
			}
		}
	case EditorModeHTML:
		raw := strings.TrimSpace(in.HTMLContent)
		if raw == "" {
			errs = append(errs, FieldError{Field: "html_content", Message: "HTML 源码模式下页面内容不能为空"})
		} else if len(raw) > MaxHTMLBytes {
			errs = append(errs, FieldError{Field: "html_content", Message: fmt.Sprintf("HTML 内容超过上限 %d 字节（当前 %d 字节）", MaxHTMLBytes, len(raw))})
		} else {
			san := SanitizeHTML(raw)
			if strings.TrimSpace(san.HTML) == "" {
				errs = append(errs, FieldError{Field: "html_content", Message: "净化后无有效可渲染内容，请检查 HTML 标签是否合规"})
			} else if len(san.HTML) > MaxHTMLBytes {
				errs = append(errs, FieldError{Field: "html_content", Message: fmt.Sprintf("净化后 HTML 体积超过上限 %d 字节", MaxHTMLBytes)})
			} else {
				out.RenderedHTML = san.HTML
				out.Warnings = san.Warnings
			}
		}
	}

	return out, errs
}

func validateVisualConfig(vc VisualConfig) []FieldError {
	var errs []FieldError
	if strings.TrimSpace(vc.Title) == "" {
		errs = append(errs, FieldError{Field: "visual_config.title", Message: "页面主标题不能为空"})
	}
	checkLen := func(field, val string, max int) {
		if utf8.RuneCountInString(val) > max {
			errs = append(errs, FieldError{Field: field, Message: fmt.Sprintf("长度不能超过 %d 个字符", max)})
		}
	}
	checkLen("visual_config.badge", vc.Badge, 64)
	checkLen("visual_config.title", vc.Title, MaxVisualShortRunes)
	checkLen("visual_config.subtitle", vc.Subtitle, MaxVisualShortRunes)
	checkLen("visual_config.description", vc.Description, MaxVisualTextRunes)
	checkLen("visual_config.contact_info", vc.ContactInfo, MaxVisualTextRunes)
	checkLen("visual_config.brand_name", vc.BrandName, MaxVisualShortRunes)
	checkLen("visual_config.footer_text", vc.FooterText, MaxVisualTextRunes)

	if u := strings.TrimSpace(vc.LogoURL); u != "" {
		if len(u) > MaxLogoURLBytes {
			errs = append(errs, FieldError{Field: "visual_config.logo_url", Message: fmt.Sprintf("Logo 地址不能超过 %d 字节", MaxLogoURLBytes)})
		} else if _, ok := SanitizeImageSrc(u); !ok {
			errs = append(errs, FieldError{Field: "visual_config.logo_url", Message: "Logo 地址仅支持 https/http/相对路径或安全图片 Base64"})
		}
	}
	checkColor := func(field, c string) {
		if strings.TrimSpace(c) != "" && !IsValidHexColor(c) {
			errs = append(errs, FieldError{Field: field, Message: "颜色值格式非法，需为 #RGB 或 #RRGGBB"})
		}
	}
	checkColor("visual_config.primary_color", vc.PrimaryColor)
	checkColor("visual_config.bg_color", vc.BgColor)
	checkColor("visual_config.card_color", vc.CardColor)
	checkColor("visual_config.text_color", vc.TextColor)
	return errs
}
