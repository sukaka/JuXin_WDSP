// sanitize.go 自定义拦截页面 HTML/CSS 安全净化器：
//   - 允许标准 HTML 排版标签、内联 <style>、class/id/style 与安全静态 SVG 图标；
//   - 彻底剔除 <script>、<iframe>、<object>、<embed>、<form>、<meta http-equiv>、SVG SMIL 动画等危险子树；
//   - 剥离全部 on* 事件属性与 javascript:/vbscript:/data:(非安全光栅图) URL；
//   - 净化 <style> 与 style="..." 中的 @import、expression()、behavior、-moz-binding 与外部 url()；
//   - 与 gateway/modules/jiuzhang_guard/blockpages_sanitize.go 保持同口径纵深防御。
package blockpages

import (
	"fmt"
	stdhtml "html"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// droppedSubtreeTags 连同标签内部全部文本/子节点整棵丢弃的高危标签。
var droppedSubtreeTags = map[string]bool{
	"script":           true,
	"iframe":           true,
	"frame":            true,
	"frameset":         true,
	"object":           true,
	"embed":            true,
	"applet":           true,
	"base":             true,
	"form":             true,
	"input":            true,
	"button":           true,
	"textarea":         true,
	"select":           true,
	"option":           true,
	"link":             true,
	"audio":            true,
	"video":            true,
	"source":           true,
	"track":            true,
	"canvas":           true,
	"math":             true,
	"template":         true,
	"portal":           true,
	"foreignobject":    true,
	"animate":          true,
	"set":              true,
	"animatemotion":    true,
	"animatetransform": true,
	"mpath":            true,
	"noscript":         true,
}

// allowedHTMLTags 放行的安全 HTML 与静态 SVG 标签白名单。
var allowedHTMLTags = map[string]bool{
	"html": true, "head": true, "title": true, "body": true, "meta": true, "style": true,
	"div": true, "span": true, "section": true, "article": true, "header": true, "footer": true,
	"main": true, "aside": true, "nav": true, "p": true, "br": true, "hr": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"blockquote": true, "pre": true, "code": true, "strong": true, "b": true, "em": true,
	"i": true, "u": true, "s": true, "small": true, "mark": true, "sub": true, "sup": true,
	"ul": true, "ol": true, "li": true, "dl": true, "dt": true, "dd": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true, "th": true, "td": true, "caption": true,
	"figure": true, "figcaption": true, "details": true, "summary": true,
	"a": true, "img": true,
	// 安全静态 SVG 矢量子集（用于盾牌/图标装饰）
	"svg": true, "g": true, "path": true, "circle": true, "ellipse": true, "rect": true,
	"line": true, "polyline": true, "polygon": true, "defs": true, "lineargradient": true,
	"radialgradient": true, "stop": true, "desc": true,
}

// voidHTMLTags HTML5 全量空元素（无闭合标签，也不得触发 dropDepth 吞没后续节点）。
var voidHTMLTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

// globalSafeAttrs 全局放行的安全属性（严格白名单，拒绝全部 on* 与未知属性）。
var globalSafeAttrs = map[string]bool{
	"class": true, "id": true, "lang": true, "dir": true, "title": true,
	"role": true, "aria-label": true, "aria-hidden": true, "style": true,
}

// svgSafeAttrs 静态 SVG 呈现属性白名单。
var svgSafeAttrs = map[string]bool{
	"viewbox": true, "xmlns": true, "width": true, "height": true,
	"fill": true, "stroke": true, "stroke-width": true, "stroke-linecap": true,
	"stroke-linejoin": true, "stroke-dasharray": true, "stroke-opacity": true,
	"fill-opacity": true, "fill-rule": true, "clip-rule": true, "opacity": true,
	"d": true, "cx": true, "cy": true, "r": true, "rx": true, "ry": true,
	"x": true, "y": true, "x1": true, "y1": true, "x2": true, "y2": true,
	"points": true, "transform": true, "offset": true, "stop-color": true,
	"stop-opacity": true, "gradientunits": true, "preserveaspectratio": true,
}

// svgCaseMap 还原 SVG 区分大小写的标准属性名（HTML tokenizer 会全部小写）。
var svgCaseMap = map[string]string{
	"viewbox":             "viewBox",
	"gradientunits":       "gradientUnits",
	"preserveaspectratio": "preserveAspectRatio",
}

// svgTagSet 判定是否属于 SVG 标签集。
var svgTagSet = map[string]bool{
	"svg": true, "g": true, "path": true, "circle": true, "ellipse": true, "rect": true,
	"line": true, "polyline": true, "polygon": true, "defs": true, "lineargradient": true,
	"radialgradient": true, "stop": true, "desc": true,
}

var (
	reCSSComment      = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reCSSUnclosedComm = regexp.MustCompile(`(?s)/\*.*$`)
	reCSSHexEscape    = regexp.MustCompile(`\\([0-9A-Fa-f]{1,6})[ \t\r\n\f]?`)
	reCSSCharEscape   = regexp.MustCompile(`\\([A-Za-z0-9@()/:<>{}_!-])`)
	reCSSAtImport     = regexp.MustCompile(`(?i)@(?:import|charset|namespace)\b[^;{}]*(?:;|$)`)
	reCSSDangerousFn  = regexp.MustCompile(`(?i)(?:expression|javascript|vbscript|-moz-binding|behavior)\s*(?:\(|:)[^;{}]*`)
	reCSSImageSet     = regexp.MustCompile(`(?i)(?:-webkit-)?image-set\s*\([^)]*\)`)
	reCSSURL          = regexp.MustCompile(`(?i)url\s*\(([^)]*)\)`)
	reCSSScriptTag    = regexp.MustCompile(`(?is)<\s*script\b.*?(?:</\s*script\s*>|$)`)
	reCSSClosingStyle = regexp.MustCompile(`(?i)</\s*style`)
	reSafeFragmentID  = regexp.MustCompile(`^#[A-Za-z0-9_-]{1,64}$`)
	reHexColor        = regexp.MustCompile(`^#[0-9A-Fa-f]{3}([0-9A-Fa-f]{3})?$`)
	reDataImageRaster = regexp.MustCompile(`(?i)^data:image/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=\s]+$`)
	reControlOrSpace  = regexp.MustCompile(`[\x00-\x20]+`)
)

// SanitizeResult 返回净化后的安全 HTML 及被过滤项告警（用于管理面提示）。
type SanitizeResult struct {
	HTML     string
	Warnings []string
}

// SanitizeHTML 基于 WHATWG HTML5 DOM 树解析器按安全白名单净化自定义拦截页 HTML 与内联 CSS：
//   - 使用 golang.org/x/net/html 树解析器而非扁平 Tokenizer，严格区分 HTML 与 SVG/MathML 命名空间；
//   - 严禁 SVG 命名空间内的 <style> / 非纯图形标签，根除 <svg><style> mXSS；
//   - 按树节点直接跳过 droppedSubtreeTags，避免 <input>/<link> 等 void 标签破坏后续文档。
func SanitizeHTML(in string) SanitizeResult {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return SanitizeResult{}
	}
	var (
		b           strings.Builder
		warnings    []string
		warned      = map[string]bool{}
		hasHTMLRoot bool
	)
	addWarn := func(msg string) {
		if !warned[msg] && len(warnings) < 20 {
			warned[msg] = true
			warnings = append(warnings, msg)
		}
	}

	b.Grow(len(in))
	lowerHead := strings.ToLower(trimmed)
	isFullDoc := strings.HasPrefix(lowerHead, "<!doctype") || strings.HasPrefix(lowerHead, "<html")

	var roots []*xhtml.Node
	if isFullDoc {
		doc, err := xhtml.Parse(strings.NewReader(in))
		if err != nil {
			addWarn("HTML 文档解析失败，已拒绝渲染")
			return SanitizeResult{Warnings: warnings}
		}
		hasHTMLRoot = true
		for c := doc.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == xhtml.ElementNode && strings.EqualFold(c.Data, "html") {
				roots = append(roots, c)
			}
		}
	} else {
		ctxNode := &xhtml.Node{Type: xhtml.ElementNode, DataAtom: atom.Body, Data: "body"}
		nodes, err := xhtml.ParseFragment(strings.NewReader(in), ctxNode)
		if err != nil {
			addWarn("HTML 片段解析失败，已拒绝渲染")
			return SanitizeResult{Warnings: warnings}
		}
		roots = nodes
	}

	var walk func(n *xhtml.Node, inSVG bool)
	walk = func(n *xhtml.Node, inSVG bool) {
		switch n.Type {
		case xhtml.DocumentNode:
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, inSVG)
			}
		case xhtml.TextNode:
			b.WriteString(stdhtml.EscapeString(n.Data))
		case xhtml.ElementNode:
			name := strings.ToLower(n.Data)
			nodeInSVG := inSVG || n.Namespace == "svg" || name == "svg"

			// MathML 命名空间整棵丢弃
			if n.Namespace == "math" {
				addWarn(fmt.Sprintf("已移除不安全标签 <%s>", name))
				return
			}
			// 高危标签整棵子树丢弃（DOM 树下 void 标签无子节点，不会吞掉兄弟节点）
			if droppedSubtreeTags[name] {
				addWarn(fmt.Sprintf("已移除不安全标签 <%s>", name))
				return
			}
			// SVG 外来命名空间：严格仅允许静态安全 SVG 矢量子集，严禁 <style>/<a>/<img> 等引发 mXSS 的标签
			if nodeInSVG {
				if name == "style" {
					addWarn("已移除 SVG 内的不安全标签 <style>")
					return
				}
				if !svgTagSet[name] {
					addWarn(fmt.Sprintf("已过滤 SVG 内未在白名单内的标签 <%s>", name))
					return
				}
				attrs := collectSafeDOMAttrs(n.Attr)
				safeAttrs := filterTagAttrs(name, attrs, addWarn)
				tagName := restoreSVGTagName(name)
				if n.FirstChild == nil {
					writeOpenTag(&b, tagName, safeAttrs, true)
					return
				}
				writeOpenTag(&b, tagName, safeAttrs, false)
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, true)
				}
				b.WriteString("</")
				b.WriteString(tagName)
				b.WriteByte('>')
				return
			}

			// HTML 命名空间：不在白名单内则剥离外壳（保留合法文本子内容，与原策略一致）
			if !allowedHTMLTags[name] || svgTagSet[name] {
				addWarn(fmt.Sprintf("已过滤未在白名单内的标签 <%s>", name))
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, false)
				}
				return
			}

			// HTML <style>：仅收集直接文本节点并经 CSS 净化器处理，严禁嵌套子元素
			if name == "style" {
				var rawCSS strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == xhtml.TextNode {
						rawCSS.WriteString(c.Data)
					}
				}
				cleaned, cssWarn := SanitizeCSS(rawCSS.String())
				for _, w := range cssWarn {
					addWarn(w)
				}
				b.WriteString("<style>")
				b.WriteString(cleaned)
				b.WriteString("</style>")
				return
			}

			attrs := collectSafeDOMAttrs(n.Attr)
			// <meta> 仅放行 charset 与 viewport，禁止 http-equiv 等重定向指令
			if name == "meta" {
				safeMeta, ok := filterMetaAttrs(attrs)
				if !ok {
					addWarn("已移除不安全的 <meta> 标签（仅允许 charset 与 viewport）")
					return
				}
				writeOpenTag(&b, "meta", safeMeta, false)
				return
			}

			safeAttrs := filterTagAttrs(name, attrs, addWarn)
			if voidHTMLTags[name] {
				writeOpenTag(&b, name, safeAttrs, false)
				return
			}
			writeOpenTag(&b, name, safeAttrs, false)
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, false)
			}
			b.WriteString("</")
			b.WriteString(name)
			b.WriteByte('>')
		default:
			// 注释与 DOCTYPE 丢弃（根节点为 <html> 时由输出统一补标准 <!DOCTYPE html>）
		}
	}

	for _, r := range roots {
		walk(r, false)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return SanitizeResult{Warnings: warnings}
	}
	if hasHTMLRoot {
		out = "<!DOCTYPE html>\n" + out
	}
	return SanitizeResult{HTML: out, Warnings: warnings}
}

// collectSafeDOMAttrs 仅收集无外来命名空间的属性（拒绝 xlink:href 等命名空间属性）。
func collectSafeDOMAttrs(raw []xhtml.Attribute) [][2]string {
	if len(raw) == 0 {
		return nil
	}
	attrs := make([][2]string, 0, len(raw))
	for _, a := range raw {
		if a.Namespace != "" {
			continue
		}
		attrs = append(attrs, [2]string{strings.ToLower(a.Key), a.Val})
	}
	return attrs
}

func restoreSVGTagName(name string) string {
	switch name {
	case "lineargradient":
		return "linearGradient"
	case "radialgradient":
		return "radialGradient"
	default:
		return name
	}
}

func writeOpenTag(b *strings.Builder, name string, attrs [][2]string, selfClose bool) {
	b.WriteByte('<')
	b.WriteString(name)
	for _, kv := range attrs {
		b.WriteByte(' ')
		b.WriteString(kv[0])
		b.WriteString(`="`)
		b.WriteString(stdhtml.EscapeString(kv[1]))
		b.WriteByte('"')
	}
	if selfClose {
		b.WriteString("/>")
	} else {
		b.WriteByte('>')
	}
}

func filterMetaAttrs(attrs [][2]string) ([][2]string, bool) {
	var charset, nameVal, contentVal string
	for _, kv := range attrs {
		switch kv[0] {
		case "charset":
			charset = strings.TrimSpace(kv[1])
		case "name":
			nameVal = strings.ToLower(strings.TrimSpace(kv[1]))
		case "content":
			contentVal = strings.TrimSpace(kv[1])
		case "http-equiv":
			return nil, false
		}
	}
	if strings.EqualFold(charset, "utf-8") {
		return [][2]string{{"charset", "UTF-8"}}, true
	}
	if nameVal == "viewport" && contentVal != "" && len(contentVal) <= 128 {
		return [][2]string{{"name", "viewport"}, {"content", contentVal}}, true
	}
	return nil, false
}

func filterTagAttrs(tag string, attrs [][2]string, addWarn func(string)) [][2]string {
	out := make([][2]string, 0, len(attrs))
	hasTargetBlank := false
	hasRel := false

	for _, kv := range attrs {
		k, v := kv[0], kv[1]
		if strings.HasPrefix(k, "on") {
			addWarn(fmt.Sprintf("已移除事件属性 %s", k))
			continue
		}
		if k == "style" {
			cleaned, warn := SanitizeCSS(v)
			for _, w := range warn {
				addWarn(w)
			}
			if cleaned != "" {
				out = append(out, [2]string{"style", cleaned})
			}
			continue
		}
		if globalSafeAttrs[k] {
			out = append(out, [2]string{k, v})
			continue
		}

		switch tag {
		case "a":
			switch k {
			case "href":
				if clean, ok := SanitizeHref(v); ok {
					out = append(out, [2]string{"href", clean})
				} else {
					addWarn("已移除不安全的链接 href（仅支持 http/https/mailto/相对路径）")
				}
			case "target":
				tv := strings.TrimSpace(v)
				if tv == "_blank" || tv == "_self" {
					out = append(out, [2]string{"target", tv})
					if tv == "_blank" {
						hasTargetBlank = true
					}
				}
			case "rel":
				hasRel = true
				out = append(out, [2]string{"rel", "noopener noreferrer"})
			default:
				addWarn(fmt.Sprintf("已过滤不支持的属性 %s", k))
			}
		case "img":
			switch k {
			case "src":
				if clean, ok := SanitizeImageSrc(v); ok {
					out = append(out, [2]string{"src", clean})
				} else {
					addWarn("已移除不安全的图片 src（仅支持 https/http/相对路径或 PNG/JPEG/WebP/GIF Base64）")
				}
			case "alt", "width", "height":
				out = append(out, [2]string{k, v})
			case "loading":
				if v == "lazy" || v == "eager" {
					out = append(out, [2]string{"loading", v})
				}
			default:
				addWarn(fmt.Sprintf("已过滤不支持的属性 %s", k))
			}
		case "td", "th":
			if k == "colspan" || k == "rowspan" || k == "scope" {
				out = append(out, [2]string{k, v})
			}
		default:
			if svgTagSet[tag] && svgSafeAttrs[k] {
				attrName := k
				if mapped, ok := svgCaseMap[k]; ok {
					attrName = mapped
				}
				if k == "xmlns" && strings.TrimSpace(v) != "http://www.w3.org/2000/svg" {
					continue
				}
				out = append(out, [2]string{attrName, v})
			} else {
				addWarn(fmt.Sprintf("已过滤不支持的属性 %s", k))
			}
		}
	}

	if tag == "a" && hasTargetBlank && !hasRel {
		out = append(out, [2]string{"rel", "noopener noreferrer"})
	}
	return out
}

// SanitizeHref 校验并净化 <a href> 链接协议。
func SanitizeHref(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	collapsed := strings.ToLower(reControlOrSpace.ReplaceAllString(trimmed, ""))
	if strings.HasPrefix(collapsed, "http://") ||
		strings.HasPrefix(collapsed, "https://") ||
		strings.HasPrefix(collapsed, "mailto:") ||
		strings.HasPrefix(collapsed, "#") ||
		(strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//")) {
		return trimmed, true
	}
	return "", false
}

// SanitizeImageSrc 校验并净化 <img src> 与可视化 Logo URL。
func SanitizeImageSrc(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > MaxHTMLBytes {
		return "", false
	}
	collapsed := strings.ToLower(reControlOrSpace.ReplaceAllString(trimmed, ""))
	if strings.HasPrefix(collapsed, "https://") ||
		strings.HasPrefix(collapsed, "http://") ||
		(strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//")) {
		return trimmed, true
	}
	if reDataImageRaster.MatchString(trimmed) {
		return trimmed, true
	}
	return "", false
}

// decodeCSSEscapes 解码 CSS 十六进制转义（\69、\000072 ）与安全单字符转义（\u、\@ 等），
// 防止通过 @\69mport、u\72l(...)、expr\65ssion(...) 绕过关键字与函数拦截。
func decodeCSSEscapes(s string) string {
	s = reCSSHexEscape.ReplaceAllStringFunc(s, func(match string) string {
		sub := reCSSHexEscape.FindStringSubmatch(match)
		if len(sub) < 2 {
			return ""
		}
		cp, err := strconv.ParseUint(sub[1], 16, 32)
		if err != nil || cp == 0 || cp > utf8.MaxRune || (cp >= 0xD800 && cp <= 0xDFFF) {
			return ""
		}
		return string(rune(cp))
	})
	s = reCSSCharEscape.ReplaceAllString(s, "$1")
	return s
}

// SanitizeCSS 净化 <style> 块与内联 style 属性：迭代解码转义、剥离注释、禁止 '<' 逃逸、
// 拦截 @import / expression() / javascript:/vbscript:/behavior / image-set() 与外部 url()。
func SanitizeCSS(raw string) (string, []string) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	var (
		warnings []string
		warned   = map[string]bool{}
	)
	addWarn := func(msg string) {
		if !warned[msg] {
			warned[msg] = true
			warnings = append(warnings, msg)
		}
	}

	s := strings.ReplaceAll(raw, "\x00", "")
	for iter := 0; iter < 8; iter++ {
		prev := s
		// 1. 剥离注释（含未闭合注释）
		s = reCSSComment.ReplaceAllString(s, "")
		s = reCSSUnclosedComm.ReplaceAllString(s, "")
		// 2. 解码 CSS 转义以暴露混淆后的 @import/url()/expression/</style
		s = decodeCSSEscapes(s)
		// 3. 彻底消除内嵌 <script>、</style> 重组与任意原始 '<' 字符，杜绝样式块跳出逃逸
		if reCSSScriptTag.MatchString(s) {
			s = reCSSScriptTag.ReplaceAllString(s, "")
			addWarn("已移除 CSS 中的非法脚本片段")
		}
		for reCSSClosingStyle.MatchString(s) {
			s = reCSSClosingStyle.ReplaceAllString(s, "")
			addWarn("已移除 CSS 中的非法闭合标签")
		}
		if strings.ContainsRune(s, '<') {
			s = strings.ReplaceAll(s, "<", "")
			addWarn("已移除 CSS 中的非法 '<' 字符")
		}
		// 4. 拦截 @import / @charset / @namespace
		if reCSSAtImport.MatchString(s) {
			s = reCSSAtImport.ReplaceAllString(s, "")
			addWarn("已移除 CSS 外部导入指令（@import）")
		}
		// 5. 拦截 expression()/javascript:/vbscript:/behavior:/-moz-binding:
		if reCSSDangerousFn.MatchString(s) {
			s = reCSSDangerousFn.ReplaceAllString(s, "none")
			addWarn("已移除 CSS 中的危险表达式（expression/javascript/behavior）")
		}
		// 6. 拦截 image-set() / -webkit-image-set() 外部资源加载
		if reCSSImageSet.MatchString(s) {
			s = reCSSImageSet.ReplaceAllString(s, "none")
			addWarn("已移除 CSS 中的 image-set() 外部资源引用")
		}
		// 7. 拦截 url(...) 外部资源引用（仅放行站内安全 SVG 渐变引用 url(#id)）
		urlBlocked := false
		s = reCSSURL.ReplaceAllStringFunc(s, func(match string) string {
			sub := reCSSURL.FindStringSubmatch(match)
			if len(sub) >= 2 {
				inner := strings.TrimSpace(strings.Trim(strings.TrimSpace(sub[1]), `"'`))
				if reSafeFragmentID.MatchString(inner) {
					return fmt.Sprintf("url(%s)", inner)
				}
			}
			urlBlocked = true
			return "none"
		})
		if urlBlocked {
			addWarn("已移除 CSS 中的外部 url() 资源引用")
		}
		if s == prev {
			break
		}
	}
	return strings.TrimSpace(s), warnings
}

// IsValidHexColor 判断是否为合法的 #RGB 或 #RRGGBB 颜色值。
func IsValidHexColor(c string) bool {
	return reHexColor.MatchString(strings.TrimSpace(c))
}
