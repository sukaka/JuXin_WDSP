package reports

import (
	"os"
	"strings"
	"testing"

	"github.com/jung-kurt/gofpdf/v2"
)

// mustReadTestFont 读取测试字体文件内容。
func mustReadTestFont(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(testFontPath(t))
	if err != nil {
		t.Fatalf("read font: %v", err)
	}
	return data
}

// TestCellTextWFitsWidth 按列宽截断：任意长文本截断后排版宽度不得超列宽（防溢列重叠）。
func TestCellTextWFitsWidth(t *testing.T) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	fontBytes := mustReadTestFont(t)
	pdf.AddUTF8FontFromBytes(pdfFontFamily, "", fontBytes)
	pdf.SetFont(pdfFontFamily, "", 10)
	d := &pdfDoc{pdf: pdf, cjk: true}

	long := "【XSS跨站脚本】NoScript XSS InjectionChecker: HTML Injection"
	for _, w := range []float64{20, 40, 63.3, 128} {
		got := d.cellTextW(long, 60, w)
		if width := pdf.GetStringWidth(got); width > w+0.01 {
			t.Fatalf("truncated text width %.2f exceeds %.2f: %q", width, w, got)
		}
	}
	// 短文本不截断
	short := "命中次数"
	if got := d.cellTextW(short, 60, 40); got != short {
		t.Fatalf("short text should pass through: %q", got)
	}
	// 超长文本带省略号
	got := d.cellTextW(long, 60, 40)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated text should end with ellipsis: %q", got)
	}
}

// TestNormalizeColWidths 列宽归一化（按版宽缩放）。
func TestNormalizeColWidths(t *testing.T) {
	d := &pdfDoc{pdf: gofpdf.New("P", "mm", "A4", "")}
	d.pageW = 210 // 竖向版宽 190，缩放比 1
	// 合法自定义列宽原样
	w := d.normalizeColWidths([]float64{25, 130, 35}, 3)
	if w[0] != 25 || w[1] != 130 || w[2] != 35 {
		t.Fatalf("custom widths: %v", w)
	}
	// 横向版宽 277，按比例放大
	d.pageW = 297
	wL := d.normalizeColWidths([]float64{25, 130, 35}, 3)
	if wL[1] < 130*1.4 {
		t.Fatalf("landscape widths should scale up: %v", wL)
	}
	// nil/长度不符/和异常 → 等宽（竖向 190/3）
	d.pageW = 210
	for _, bad := range [][]float64{nil, {1, 2}, {10, 10, 10}} {
		w := d.normalizeColWidths(bad, 3)
		for _, v := range w {
			if v < 63 || v > 64 {
				t.Fatalf("bad widths %v should fall back to equal: %v", bad, w)
			}
		}
	}
}
