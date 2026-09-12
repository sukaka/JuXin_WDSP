package reports

import "os"

// FontFileName PDF 内嵌中文字体文件名（Noto Sans CJK SC 可变 TTF，OFL 1.1）。
// 说明：gofpdf v2.17.3 不支持 CFF 格式 OTF，故使用同仓库可变 TTF。
const FontFileName = "NotoSansCJKsc-VF.ttf"

// DefaultFontPath 解析内嵌中文字体路径。
// 优先 REPORT_FONT_PATH 环境变量；其后按常见工作目录候选查找。
// 找不到时返回默认候选路径（PDF 渲染将降级为 ASCII 摘要页，而非崩溃）。
func DefaultFontPath() string {
	if p := os.Getenv("REPORT_FONT_PATH"); p != "" {
		return p
	}
	candidates := []string{
		"assets/fonts/" + FontFileName,
		"server/assets/fonts/" + FontFileName,
		"/app/assets/fonts/" + FontFileName,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}
