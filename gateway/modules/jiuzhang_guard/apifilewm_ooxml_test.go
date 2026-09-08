// apifilewm_ooxml_test.go OOXML 下载水印端到端（W14-GW / P2-01 全格式扩展）：
// docx 下载注入水印部件并可正常开包、Content-Length 修正、扩展名双重一致门禁、
// 损坏 ZIP FAIL_OPEN 直通、未白名单零行为。
package jiuzhang_guard

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

const ooxmlDocxMIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

// newOOXMLWatermarkTestGuard 构造启用 OOXML 水印的测试 Guard（白名单含 docx MIME）。
func newOOXMLWatermarkTestGuard(t *testing.T, mode string, contentTypes []string) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	cfg, err := response.NewFileWatermarkConfig(true, "wm ip={ip} d={domain}", contentTypes, "")
	if err != nil {
		t.Fatalf("new watermark config: %v", err)
	}
	g.apiFileWatermark = cfg
	return g, logPath
}

// buildE2EDocx 构造最小 docx 形态 ZIP 下载体（无 custom.xml）。
func buildE2EDocx(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entries := []struct{ name, content string }{
		{"[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>订单导出</w:t></w:r></w:p></w:body></w:document>`},
	}
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}
		if _, err := io.WriteString(w, e.content); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// ooxmlDownloadNext 构造返回 docx 下载响应的下游处理器。
func ooxmlDownloadNext(t *testing.T, filename string, body []byte) nextFunc {
	t.Helper()
	return nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", ooxmlDocxMIME)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return nil
	})
}

// docx 下载：水印部件注入（开包验证完整性与水印内容）、Content-Length 修正、
// 事件产 file.watermark_applied 明细（与水印 v1 同键，证据不含水印内容）。
func TestServeNext_OOXMLWatermarkDocxDownload(t *testing.T) {
	g, logPath := newOOXMLWatermarkTestGuard(t, "OBSERVE", []string{"text/plain", ooxmlDocxMIME})

	src := buildE2EDocx(t)
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-ooxml-1"), ooxmlDownloadNext(t, "orders.docx", src)); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	// 开包完整性 + 水印部件 + 原文档保留
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("watermarked body must be valid zip: %v", err)
	}
	var customProps, document string
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s (crc): %v", f.Name, err)
		}
		switch f.Name {
		case "docProps/custom.xml":
			customProps = string(raw)
		case "word/document.xml":
			document = string(raw)
		}
	}
	if !strings.Contains(customProps, `name="jiuzhang-watermark"`) ||
		!strings.Contains(customProps, "wm ip=203.0.113.9 d=shop.example.com") {
		t.Fatalf("watermark part missing/wrong: %s", customProps)
	}
	if !strings.Contains(document, "订单导出") {
		t.Fatal("document content must be preserved")
	}
	if len(body) == len(src) {
		t.Fatal("body must change after watermark injection")
	}
	// Content-Length 修正
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("content-length = %q, want %d", cl, len(body))
	}
	// 事件：file.watermark_applied（与水印 v1 同键），证据不含水印内容
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	var found bool
	for _, d := range recs[0].Details {
		if d.RuleID != "file.watermark_applied" {
			continue
		}
		found = true
		if d.Category != "INFO" || d.Severity != "INFO" {
			t.Fatalf("discipline broken: %s/%s", d.Category, d.Severity)
		}
		if d.Evidence["filename"] != "orders.docx" || d.Evidence["mime"] != ooxmlDocxMIME {
			t.Fatalf("evidence = %+v", d.Evidence)
		}
		for k, v := range d.Evidence {
			if strings.Contains(v, "203.0.113.9") || strings.Contains(v, "wm ip=") {
				t.Fatalf("evidence must not contain watermark content: %s=%s", k, v)
			}
		}
	}
	if !found {
		t.Fatalf("file.watermark_applied missing: %+v", recs[0].Details)
	}
}

// 扩展名双重一致门禁：MIME 白名单命中但 filename 扩展名不符 → 不加（防伪造扩展名）。
func TestServeNext_OOXMLWatermarkExtensionGate(t *testing.T) {
	g, logPath := newOOXMLWatermarkTestGuard(t, "OBSERVE", []string{ooxmlDocxMIME})

	src := buildE2EDocx(t)
	rec := httptest.NewRecorder()
	// filename 为 .txt 但 Content-Type 为 docx MIME：扩展名不符跳过
	if err := g.serveNext(rec, wmDownloadRequest("req-ooxml-2"), ooxmlDownloadNext(t, "orders.txt", src)); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !bytes.Equal(body, src) {
		t.Fatal("extension mismatch must pass through unmodified")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("extension mismatch must not watermark")
		}
	}
	// xlsx 扩展名 + docx MIME 同样跳过（MIME 与扩展名必须一致）
	rec2 := httptest.NewRecorder()
	if err := g.serveNext(rec2, wmDownloadRequest("req-ooxml-3"), ooxmlDownloadNext(t, "orders.xlsx", src)); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body2, _ := io.ReadAll(rec2.Result().Body)
	if !bytes.Equal(body2, src) {
		t.Fatal("mismatched ooxml extension must pass through unmodified")
	}
}

// 损坏 ZIP 下载：FAIL_OPEN 直通原响应（不告警内容、不产水印明细）。
func TestServeNext_OOXMLWatermarkCorruptFailOpen(t *testing.T) {
	g, logPath := newOOXMLWatermarkTestGuard(t, "OBSERVE", []string{ooxmlDocxMIME})

	corrupt := []byte("PK\x03\x04 broken zip payload not parseable")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-ooxml-4"), ooxmlDownloadNext(t, "broken.docx", corrupt)); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !bytes.Equal(body, corrupt) {
		t.Fatal("corrupt zip must fail open with original delivered")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "file.watermark_applied" {
			t.Fatal("corrupt zip must not produce watermark detail")
		}
	}
}
