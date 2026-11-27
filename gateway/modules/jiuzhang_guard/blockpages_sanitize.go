// blockpages_sanitize.go 网关装配期自定义拦截页 HTML/CSS 纵深防御净化器：
// 与管理面 server/internal/blockpages/sanitize.go 保持同口径，即使配置 JSON 绕过管理面
// 直接下发，网关装配期仍会严格剔除 <script>、<iframe>、<form>、on* 事件属性、
// javascript:/vbscript: 链接与 CSS @import/expression()/外部 url()，同时保留 <style>、
// class、style 与安全静态 SVG 图标。
package jiuzhang_guard

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

var richDroppedSubtreeTags = map[string]bool{
	"script": true, "iframe": true, "frame": true, "frameset": true,
	"object": true, "embed": true, "applet": true, "base": true,
	"form": true, "input": true, "button": true, "textarea": true,
	"select": true, "option": true, "link": true, "audio": true,
	"video": true, "source": true, "track": true, "canvas": true,
	"math": true, "template": true, "portal": true, "foreignobject": true,
	"animate": true, "set": true, "animatemotion": true,
	"animatetransform": true, "mpath": true, "noscript": true,
}

var richAllowedHTMLTags = map[string]bool{
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
	"svg": true, "g": true, "path": true, "circle": true, "ellipse": true, "rect": true,
	"line": true, "polyline": true, "polygon": true, "defs": true, "lineargradient": true,
	"radialgradient": true, "stop": true, "desc": true,
}

var richVoidHTMLTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

var richGlobalSafeAttrs = map[string]bool{
	"class": true, "id": true, "lang": true, "dir": true, "title": true,
	"role": true, "aria-label": true, "aria-hidden": true, "style": true,
}

var richSVGSafeAttrs = map[string]bool{
	"viewbox": true, "xmlns": true, "width": true, "height": true,
	"fill": true, "stroke": true, "stroke-width": true, "stroke-linecap": true,
	"stroke-linejoin": true, "stroke-dasharray": true, "stroke-opacity": true,
	"fill-opacity": true, "fill-rule": true, "clip-rule": true, "opacity": true,
	"d": true, "cx": true, "cy": true, "r": true, "rx": true, "ry": true,
	"x": true, "y": true, "x1": true, "y1": true, "x2": true, "y2": true,
	"points": true, "transform": true, "offset": true, "stop-color": true,
	"stop-opacity": true, "gradientunits": true, "preserveaspectratio": true,
}

var richSVGCaseMap = map[string]string{
	"viewbox":             "viewBox",
	"gradientunits":       "gradientUnits",
	"preserveaspectratio": "preserveAspectRatio",
}

var richSVGTagSet = map[string]bool{
	"svg": true, "g": true, "path": true, "circle": true, "ellipse": true, "rect": true,
	"line": true, "polyline": true, "polygon": true, "defs": true, "lineargradient": true,
	"radialgradient": true, "stop": true, "desc": true,
}

var (
	reGuardCSSComment      = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reGuardCSSUnclosedComm = regexp.MustCompile(`(?s)/\*.*$`)
	reGuardCSSHexEscape    = regexp.MustCompile(`\\([0-9A-Fa-f]{1,6})[ \t\r\n\f]?`)
	reGuardCSSCharEscape   = regexp.MustCompile(`\\([A-Za-z0-9@()/:<>{}_!-])`)
	reGuardCSSAtImport     = regexp.MustCompile(`(?i)@(?:import|charset|namespace)\b[^;{}]*(?:;|$)`)
	reGuardCSSDangerousFn  = regexp.MustCompile(`(?i)(?:expression|javascript|vbscript|-moz-binding|behavior)\s*(?:\(|:)[^;{}]*`)
	reGuardCSSImageSet     = regexp.MustCompile(`(?i)(?:-webkit-)?image-set\s*\([^)]*\)`)
	reGuardCSSURL          = regexp.MustCompile(`(?i)url\s*\(([^)]*)\)`)
	reGuardCSSScriptTag    = regexp.MustCompile(`(?is)<\s*script\b.*?(?:</\s*script\s*>|$)`)
	reGuardCSSClosingStyle = regexp.MustCompile(`(?i)</\s*style`)
	reGuardSafeFragmentID  = regexp.MustCompile(`^#[A-Za-z0-9_-]{1,64}$`)
	reGuardDataImageRaster = regexp.MustCompile(`(?i)^data:image/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=\s]+$`)
	reGuardControlOrSpace  = regexp.MustCompile(`[\x00-\x20]+`)
)

// sanitizeRichBlockHTML 基于 WHATWG HTML5 DOM 树解析器做网关装配期纵深防御净化，
// 与管理面 server/internal/blockpages/sanitize.go 保持同口径：
// 严格隔离 SVG/MathML 命名空间（严禁 <svg><style> mXSS），按树跳过高危子树避免 void 标签吞页。
func sanitizeRichBlockHTML(in string) string {
	trimmed := strings.TrimSpace(in)
	if trimmed == "" {
		return ""
	}
	var (
		b           strings.Builder
		hasHTMLRoot bool
	)
	b.Grow(len(in))
	lowerHead := strings.ToLower(trimmed)
	isFullDoc := strings.HasPrefix(lowerHead, "<!doctype") || strings.HasPrefix(lowerHead, "<html")

	var roots []*xhtml.Node
	if isFullDoc {
		doc, err := xhtml.Parse(strings.NewReader(in))
		if err != nil {
			return ""
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
			return ""
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
			if n.Namespace == "math" || richDroppedSubtreeTags[name] {
				return
			}
			if nodeInSVG {
				if name == "style" || !richSVGTagSet[name] {
					return
				}
				attrs := collectSafeGuardDOMAttrs(n.Attr)
				safeAttrs := filterRichTagAttrs(name, attrs)
				tagName := restoreRichSVGTagName(name)
				if n.FirstChild == nil {
					writeRichOpenTag(&b, tagName, safeAttrs, true)
					return
				}
				writeRichOpenTag(&b, tagName, safeAttrs, false)
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, true)
				}
				b.WriteString("</")
				b.WriteString(tagName)
				b.WriteByte('>')
				return
			}
			if !richAllowedHTMLTags[name] || richSVGTagSet[name] {
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, false)
				}
				return
			}
			if name == "style" {
				var rawCSS strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == xhtml.TextNode {
						rawCSS.WriteString(c.Data)
					}
				}
				b.WriteString("<style>")
				b.WriteString(sanitizeRichCSS(rawCSS.String()))
				b.WriteString("</style>")
				return
			}
			attrs := collectSafeGuardDOMAttrs(n.Attr)
			if name == "meta" {
				safeMeta, ok := filterRichMetaAttrs(attrs)
				if !ok {
					return
				}
				writeRichOpenTag(&b, "meta", safeMeta, false)
				return
			}
			safeAttrs := filterRichTagAttrs(name, attrs)
			if richVoidHTMLTags[name] {
				writeRichOpenTag(&b, name, safeAttrs, false)
				return
			}
			writeRichOpenTag(&b, name, safeAttrs, false)
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, false)
			}
			b.WriteString("</")
			b.WriteString(name)
			b.WriteByte('>')
		default:
			// 注释/DOCTYPE 丢弃
		}
	}

	for _, r := range roots {
		walk(r, false)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return ""
	}
	if hasHTMLRoot {
		out = "<!DOCTYPE html>\n" + out
	}
	return out
}

func collectSafeGuardDOMAttrs(raw []xhtml.Attribute) [][2]string {
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

func restoreRichSVGTagName(name string) string {
	switch name {
	case "lineargradient":
		return "linearGradient"
	case "radialgradient":
		return "radialGradient"
	default:
		return name
	}
}

func writeRichOpenTag(b *strings.Builder, name string, attrs [][2]string, selfClose bool) {
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

func filterRichMetaAttrs(attrs [][2]string) ([][2]string, bool) {
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

func filterRichTagAttrs(tag string, attrs [][2]string) [][2]string {
	out := make([][2]string, 0, len(attrs))
	hasTargetBlank := false
	hasRel := false

	for _, kv := range attrs {
		k, v := kv[0], kv[1]
		if strings.HasPrefix(k, "on") {
			continue
		}
		if k == "style" {
			if cleaned := sanitizeRichCSS(v); cleaned != "" {
				out = append(out, [2]string{"style", cleaned})
			}
			continue
		}
		if richGlobalSafeAttrs[k] {
			out = append(out, [2]string{k, v})
			continue
		}
		switch tag {
		case "a":
			switch k {
			case "href":
				if clean, ok := sanitizeRichHref(v); ok {
					out = append(out, [2]string{"href", clean})
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
			}
		case "img":
			switch k {
			case "src":
				if clean, ok := sanitizeRichImageSrc(v); ok {
					out = append(out, [2]string{"src", clean})
				}
			case "alt", "width", "height":
				out = append(out, [2]string{k, v})
			case "loading":
				if v == "lazy" || v == "eager" {
					out = append(out, [2]string{"loading", v})
				}
			}
		case "td", "th":
			if k == "colspan" || k == "rowspan" || k == "scope" {
				out = append(out, [2]string{k, v})
			}
		default:
			if richSVGTagSet[tag] && richSVGSafeAttrs[k] {
				attrName := k
				if mapped, ok := richSVGCaseMap[k]; ok {
					attrName = mapped
				}
				if k == "xmlns" && strings.TrimSpace(v) != "http://www.w3.org/2000/svg" {
					continue
				}
				out = append(out, [2]string{attrName, v})
			}
		}
	}
	if tag == "a" && hasTargetBlank && !hasRel {
		out = append(out, [2]string{"rel", "noopener noreferrer"})
	}
	return out
}

func sanitizeRichHref(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	collapsed := strings.ToLower(reGuardControlOrSpace.ReplaceAllString(trimmed, ""))
	if strings.HasPrefix(collapsed, "http://") ||
		strings.HasPrefix(collapsed, "https://") ||
		strings.HasPrefix(collapsed, "mailto:") ||
		strings.HasPrefix(collapsed, "#") ||
		(strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//")) {
		return trimmed, true
	}
	return "", false
}

func sanitizeRichImageSrc(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxBlockPageHTMLBytes {
		return "", false
	}
	collapsed := strings.ToLower(reGuardControlOrSpace.ReplaceAllString(trimmed, ""))
	if strings.HasPrefix(collapsed, "https://") ||
		strings.HasPrefix(collapsed, "http://") ||
		(strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "//")) {
		return trimmed, true
	}
	if reGuardDataImageRaster.MatchString(trimmed) {
		return trimmed, true
	}
	return "", false
}

func decodeGuardCSSEscapes(s string) string {
	s = reGuardCSSHexEscape.ReplaceAllStringFunc(s, func(match string) string {
		sub := reGuardCSSHexEscape.FindStringSubmatch(match)
		if len(sub) < 2 {
			return ""
		}
		cp, err := strconv.ParseUint(sub[1], 16, 32)
		if err != nil || cp == 0 || cp > utf8.MaxRune || (cp >= 0xD800 && cp <= 0xDFFF) {
			return ""
		}
		return string(rune(cp))
	})
	s = reGuardCSSCharEscape.ReplaceAllString(s, "$1")
	return s
}

func sanitizeRichCSS(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	s := strings.ReplaceAll(raw, "\x00", "")
	for iter := 0; iter < 8; iter++ {
		prev := s
		s = reGuardCSSComment.ReplaceAllString(s, "")
		s = reGuardCSSUnclosedComm.ReplaceAllString(s, "")
		s = decodeGuardCSSEscapes(s)
		s = reGuardCSSScriptTag.ReplaceAllString(s, "")
		for reGuardCSSClosingStyle.MatchString(s) {
			s = reGuardCSSClosingStyle.ReplaceAllString(s, "")
		}
		s = strings.ReplaceAll(s, "<", "")
		s = reGuardCSSAtImport.ReplaceAllString(s, "")
		s = reGuardCSSDangerousFn.ReplaceAllString(s, "none")
		s = reGuardCSSImageSet.ReplaceAllString(s, "none")
		s = reGuardCSSURL.ReplaceAllStringFunc(s, func(match string) string {
			sub := reGuardCSSURL.FindStringSubmatch(match)
			if len(sub) >= 2 {
				inner := strings.TrimSpace(strings.Trim(strings.TrimSpace(sub[1]), `"'`))
				if reGuardSafeFragmentID.MatchString(inner) {
					return fmt.Sprintf("url(%s)", inner)
				}
			}
			return "none"
		})
		if s == prev {
			break
		}
	}
	return strings.TrimSpace(s)
}
