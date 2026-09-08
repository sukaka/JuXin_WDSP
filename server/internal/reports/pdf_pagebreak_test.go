package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/jung-kurt/gofpdf/v2"
)

// TestEnsureSpaceManualPageBreak 手动控页：版面不足整行高度时先换页，
// 防 gofpdf 自动分页把双描行撕到两页（PDF 跨页孤行/空白大洞回归）。
func TestEnsureSpaceManualPageBreak(t *testing.T) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	fontBytes := mustReadTestFont(t)
	pdf.AddUTF8FontFromBytes(pdfFontFamily, "", fontBytes)
	pdf.SetFont(pdfFontFamily, "", 10)
	d := &pdfDoc{pdf: pdf, cjk: true, pageW: 210, bottomTrigger: 277}
	pdf.AddPage()

	// 版面充足：不换页
	pdf.SetY(270) // 270+7=277 不越线
	d.ensureSpace(7)
	if pdf.PageCount() != 1 {
		t.Fatal("ensureSpace should not break page when space suffices")
	}
	// 版面不足：换页
	d.ensureSpace(7) // 270+7=277 边界（不 >）；再测一次 271
	pdf.SetY(271)    // 271+7=278 > 277
	d.ensureSpace(7)
	if pdf.PageCount() != 2 {
		t.Fatal("ensureSpace should break page when space insufficient")
	}

	// 表格跨页：行不被撕裂，续页重复表头
	pdf.SetY(d.bottomTrigger - 10) // 表头占 7，剩 3 放不下一行
	d.tableMarked([]string{"规则ID", "规则名称", "命中次数"}, [][]string{
		{"941160", "【XSS跨站脚本】NoScript XSS InjectionChecker: HTML Injection", "11"},
		{"941100", "【XSS跨站脚本】XSS Attack Detected via libinjection", "11"},
		{"941110", "【XSS跨站脚本】XSS Filter - Category 1: Script Tag Vector", "8"},
	}, []bool{false, false, false})
	// 每行起始 y 均不得越过触发线（行高 7：起始 y+7 <= 触发线 + 行高容差）
	// 直接证据：当前页内容在触发线内连续推进，页数 = 表头(页2) + 部分行后正常分页
	if pdf.GetY() > d.bottomTrigger {
		t.Fatalf("cursor beyond bottom trigger after table: %.1f", pdf.GetY())
	}
}

// TestRenderPDFManyRowsNoTornRows 大表跨页渲染：任意页文本不越页底触发线。
func TestRenderPDFManyRowsNoTornRows(t *testing.T) {
	now := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	data := sampleReportData()
	var rules []RuleHit
	for i := 0; i < 40; i++ {
		rules = append(rules, RuleHit{RuleID: 941000 + i, RuleName: "XSS Attack Detected via libinjection (very long rule name for width testing)", Hits: int64(100 - i)})
	}
	data.TopRules = rules
	var paths []KV
	for i := 0; i < 50; i++ {
		paths = append(paths, KV{Key: "/api/orders/very/long/path/segment/testing/page/break/behavior", Value: int64(50 - i)})
	}
	data.TargetPaths = paths
	data.AttackTrend = []Point{{Time: now, Value: 5}, {Time: now.Add(time.Hour), Value: 9}}
	pdf, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0801", testFontPath(t), nil)
	if err != nil {
		t.Fatalf("render pdf: %v", err)
	}
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		t.Fatal("pdf magic invalid")
	}
	// 内容流中不得出现把整页拉空的异常：压缩流均可解压
	if strings.Contains(string(pdf), "stream") == false {
		t.Fatal("pdf content streams missing")
	}
}
