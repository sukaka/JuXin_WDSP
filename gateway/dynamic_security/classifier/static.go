// static.go 静态资源路径与响应 MIME 统一判定规则。
//
// 供在线网关（jiuzhang_guard）、旁路镜像（mirrorcap）、服务端采集器（apiruntime）、
// 分布式 Agent 资产联动（agents）与 Kafka 数据流投影（apidataflow）共用，确保全链路
// 对图片、前端脚本/样式、字体、音视频、静态压缩包/安装包等非 API 资源的判定口径一致。
//
// 原则：
//   - 仅影响 API 资产发现与识别，绝不跳过 WAF、访问控制、下载合规或安全告警；
//   - 仅对读方法（GET/HEAD/OPTIONS/空）应用静态后缀与静态前缀排除，写方法（POST/PUT/PATCH/DELETE）不误伤；
//   - 明确不将 .json/.xml/.do/.action/.php/.jsp/.asp/.aspx/.cgi/.ashx/.svc 视为静态后缀；
//   - 动态导出接口（如 GET /api/v1/orders/export 返回 Content-Disposition 附件）路径不含静态后缀，
//     仍按 FILE_DOWNLOAD API 识别与保护。
package classifier

import (
	"mime"
	"path"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// defaultStaticAssetExtensions 默认静态资源扩展名清单（有序、小写带点）。
var defaultStaticAssetExtensions = []string{
	// 图片 / 图标
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif", ".tif", ".tiff", ".cur",
	// 前端脚本 / 样式 / 映射 / WebAssembly
	".js", ".mjs", ".cjs", ".css", ".less", ".scss", ".sass", ".map", ".wasm",
	// 字体
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	// 音视频 / 流媒体切片
	".mp3", ".mp4", ".webm", ".ogg", ".wav", ".flac", ".m4a", ".aac", ".avi", ".mov", ".mkv", ".m3u8", ".ts",
	// 压缩包 / 归档 / 磁盘镜像 / 客户端安装包
	".tar.gz", ".tar.bz2", ".tar.xz",
	".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".bz2", ".xz", ".zst",
	".iso", ".dmg", ".pkg", ".exe", ".msi", ".apk", ".ipa", ".deb", ".rpm",
	// 静态文档（直链下载；动态导出接口路径一般不含这些扩展名）
	".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	// 常见前端静态页面扩展名
	".html", ".htm", ".shtml",
}

// defaultStaticCompoundExtensions 需要优先于单扩展名检查的复合扩展名。
var defaultStaticCompoundExtensions = []string{
	".tar.gz", ".tar.bz2", ".tar.xz", ".js.map", ".css.map",
}

// defaultStaticExtSet 默认静态扩展名只读查找表。
var defaultStaticExtSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(defaultStaticAssetExtensions)+2)
	for _, ext := range defaultStaticAssetExtensions {
		m[ext] = struct{}{}
	}
	m[".js.map"] = struct{}{}
	m[".css.map"] = struct{}{}
	return m
}()

// defaultStaticWellKnownPaths 常见静态元信息文件（不将通用 .txt/.xml 拉黑，避免误杀接口）。
var defaultStaticWellKnownPaths = map[string]struct{}{
	"/robots.txt":            {},
	"/ads.txt":               {},
	"/app-ads.txt":           {},
	"/humans.txt":            {},
	"/security.txt":          {},
	"/sitemap.xml":           {},
	"/sitemap_index.xml":     {},
	"/browserconfig.xml":     {},
	"/crossdomain.xml":       {},
	"/manifest.webmanifest":  {},
	"/site.webmanifest":      {},
	"/favicon.ico":           {},
	"/apple-touch-icon.png":  {},
	"/service-worker.js":     {},
}

// StaticFilterConfig 可配置的静态资源排除规则（供管理面系统设置传入）。
type StaticFilterConfig struct {
	// ExcludeExtensions 归一化后的静态扩展名（小写带前导 '.'，支持复合后缀如 .tar.gz）。
	ExcludeExtensions []string
	// UseCustomExtensions 为 true 时仅使用 ExcludeExtensions（允许用户删减默认后缀）；
	// 为 false 且 ExcludeExtensions 为空时使用内置默认清单。
	UseCustomExtensions bool
	// ExcludePathPrefixes 自定义静态排除路径前缀（段前缀匹配，如 /astro、/_next/static）。
	ExcludePathPrefixes []string
	// IncludePathPrefixes 强制保留（不排除）白名单路径前缀，优先级高于静态扩展名与排除前缀。
	IncludePathPrefixes []string
}

// DefaultStaticAssetExtensions 返回内置默认静态扩展名副本（有序、小写带点）。
func DefaultStaticAssetExtensions() []string {
	out := make([]string, len(defaultStaticAssetExtensions))
	copy(out, defaultStaticAssetExtensions)
	return out
}

// DefaultStaticFilter 返回内置默认静态过滤配置。
func DefaultStaticFilter() StaticFilterConfig {
	return StaticFilterConfig{
		ExcludeExtensions: DefaultStaticAssetExtensions(),
	}
}

// NormalizeExtension 将扩展名规范化为小写带前导点（如 "PNG" -> ".png"、"tar.gz" -> ".tar.gz"）。
// 不合法时返回空串。
func NormalizeExtension(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*")
	}
	if !strings.HasPrefix(s, ".") {
		s = "." + s
	}
	if len(s) < 2 || len(s) > 24 {
		return ""
	}
	body := s[1:]
	if strings.HasPrefix(body, ".") || strings.HasSuffix(body, ".") || strings.Contains(body, "..") {
		return ""
	}
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' {
			continue
		}
		return ""
	}
	return s
}

// NormalizePathPrefix 将路径前缀规范化为以 '/' 开头、非根去尾斜杠的形式（如 "astro/" -> "/astro"）。
// 不合法（空或含空白/控制字符）时返回空串。
func NormalizePathPrefix(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 256 {
		return ""
	}
	if strings.ContainsAny(s, " \t\r\n?#\x00") {
		return ""
	}
	cp := normalizer.CanonicalPath(s)
	if cp != "/" {
		cp = strings.TrimSuffix(cp, "/")
	}
	return cp
}

// IsStaticAssetPath 使用内置默认规则判定请求路径是否为静态资源（仅对 GET/HEAD/OPTIONS/空方法生效）。
func IsStaticAssetPath(method, rawPath string) bool {
	matched, _ := DefaultStaticFilter().MatchStaticPath(method, rawPath)
	return matched
}

// MatchesIncludePrefix 判断路径是否命中强制保留白名单前缀（大小写不敏感段前缀匹配）。
func (c StaticFilterConfig) MatchesIncludePrefix(rawPath string) bool {
	if len(c.IncludePathPrefixes) == 0 {
		return false
	}
	lowerPath := strings.ToLower(normalizer.CanonicalPath(rawPath))
	for _, rawPref := range c.IncludePathPrefixes {
		pref := strings.ToLower(NormalizePathPrefix(rawPref))
		if pref == "" {
			continue
		}
		if normalizer.PrefixSegmentMatch(pref, lowerPath) {
			return true
		}
	}
	return false
}

// MatchStaticPath 判定 (method, rawPath) 是否命中静态资源/自定义排除路径规则。
// 返回是否命中以及命中原因（如 "static_extension:.png"、"exclude_path_prefix:/astro"、"static_well_known"）。
func (c StaticFilterConfig) MatchStaticPath(method, rawPath string) (bool, string) {
	if strings.TrimSpace(rawPath) == "" {
		return false, ""
	}
	if c.MatchesIncludePrefix(rawPath) {
		return false, ""
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m != "" && m != "GET" && m != "HEAD" && m != "OPTIONS" {
		return false, ""
	}

	cp := normalizer.CanonicalPath(rawPath)
	lowerPath := strings.ToLower(cp)

	// 1. 自定义排除路径前缀（段前缀匹配，避免 /astro 误伤 /astrology）
	for _, rawPref := range c.ExcludePathPrefixes {
		pref := strings.ToLower(NormalizePathPrefix(rawPref))
		if pref == "" {
			continue
		}
		if normalizer.PrefixSegmentMatch(pref, lowerPath) {
			return true, "exclude_path_prefix:" + pref
		}
	}

	// 2. 常见静态元信息路径与 /.well-known/ 目录
	trimmed := lowerPath
	if trimmed != "/" {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if _, ok := defaultStaticWellKnownPaths[trimmed]; ok {
		return true, "static_well_known"
	}
	if normalizer.PrefixSegmentMatch("/.well-known", lowerPath) {
		return true, "static_well_known"
	}

	// 3. 路径末段静态扩展名检查
	base := path.Base(trimmed)
	if base == "" || base == "." || base == "/" {
		return false, ""
	}
	// 忽略路径模板占位符末段（如 /{id}、/{uuid}）
	if strings.HasPrefix(base, "{") && strings.HasSuffix(base, "}") {
		return false, ""
	}

	extSet := c.extensionSet()
	if len(extSet) == 0 {
		return false, ""
	}
	// 先检查复合扩展名（如 .tar.gz、.js.map）
	for _, compound := range defaultStaticCompoundExtensions {
		if len(base) > len(compound) && strings.HasSuffix(base, compound) {
			if _, ok := extSet[compound]; ok {
				return true, "static_extension:" + compound
			}
		}
	}
	// 支持用户自定义的复合扩展名（含 2 个点）
	if c.UseCustomExtensions || len(c.ExcludeExtensions) > 0 {
		for ext := range extSet {
			if strings.Count(ext, ".") >= 2 && len(base) > len(ext) && strings.HasSuffix(base, ext) {
				return true, "static_extension:" + ext
			}
		}
	}
	// 单扩展名检查
	if dot := strings.LastIndex(base, "."); dot > 0 && dot < len(base)-1 {
		ext := base[dot:]
		if _, ok := extSet[ext]; ok {
			return true, "static_extension:" + ext
		}
	}
	return false, ""
}

func (c StaticFilterConfig) extensionSet() map[string]struct{} {
	if !c.UseCustomExtensions && len(c.ExcludeExtensions) == 0 {
		return defaultStaticExtSet
	}
	m := make(map[string]struct{}, len(c.ExcludeExtensions))
	for _, raw := range c.ExcludeExtensions {
		if norm := NormalizeExtension(raw); norm != "" {
			m[norm] = struct{}{}
		}
	}
	return m
}

// staticResponseMIMEs 明确属于静态资源的精确响应 MIME 集合。
var staticResponseMIMEs = map[string]struct{}{
	"text/css":                       {},
	"text/javascript":                {},
	"application/javascript":         {},
	"application/x-javascript":       {},
	"application/ecmascript":         {},
	"text/ecmascript":                {},
	"application/wasm":               {},
	"application/font-woff":          {},
	"application/font-woff2":         {},
	"application/x-font-woff":        {},
	"application/x-font-ttf":         {},
	"application/x-font-otf":         {},
	"application/vnd.ms-fontobject":  {},
	"application/zip":                {},
	"application/x-zip-compressed":   {},
	"application/gzip":               {},
	"application/x-gzip":             {},
	"application/x-tar":              {},
	"application/x-rar-compressed":   {},
	"application/vnd.rar":            {},
	"application/x-7z-compressed":    {},
	"application/x-bzip2":            {},
	"application/x-xz":               {},
	"application/zstd":               {},
	"application/pdf":                {},
	"application/x-shockwave-flash":  {},
	"application/vnd.apple.mpegurl":  {},
	"application/x-mpegurl":          {},
	"text/cache-manifest":            {},
	"text/vtt":                       {},
}

func parsePrimaryMediaType(contentType string) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
	}
	return strings.ToLower(mt)
}

// IsStaticResponseContentType 判定响应 Content-Type 是否明确为图片/脚本/样式/字体/音视频/压缩包等静态资源。
func IsStaticResponseContentType(contentType string) bool {
	mt := parsePrimaryMediaType(contentType)
	if mt == "" {
		return false
	}
	if strings.HasPrefix(mt, "image/") ||
		strings.HasPrefix(mt, "font/") ||
		strings.HasPrefix(mt, "audio/") ||
		strings.HasPrefix(mt, "video/") {
		return true
	}
	_, ok := staticResponseMIMEs[mt]
	return ok
}

// IsHTMLResponseContentType 判定响应 Content-Type 是否为 HTML 网页。
func IsHTMLResponseContentType(contentType string) bool {
	mt := parsePrimaryMediaType(contentType)
	return mt == "text/html" || mt == "application/xhtml+xml"
}

// IsJSONResponseContentType 判定响应 Content-Type 是否为 JSON 族。
func IsJSONResponseContentType(contentType string) bool {
	mt := parsePrimaryMediaType(contentType)
	return mt == "application/json" || mt == "text/json" ||
		(strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// IsXMLAPIResponseContentType 判定响应 Content-Type 是否为 XML/SOAP 接口响应（排除 image/svg+xml 和 application/xhtml+xml）。
func IsXMLAPIResponseContentType(contentType string) bool {
	mt := parsePrimaryMediaType(contentType)
	if mt == "" || mt == "image/svg+xml" || mt == "application/xhtml+xml" {
		return false
	}
	if mt == "application/xml" || mt == "text/xml" || mt == "application/soap+xml" {
		return true
	}
	return strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+xml")
}

// IsEventStreamResponseContentType 判定响应 Content-Type 是否为 SSE（text/event-stream）。
func IsEventStreamResponseContentType(contentType string) bool {
	return parsePrimaryMediaType(contentType) == "text/event-stream"
}
