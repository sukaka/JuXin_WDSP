// watermark_ooxml_test.go OOXML 下载水印测试（W14-GW / P2-01 全格式扩展）：
// 注入后可正常开包（zip 完整性 + XML 良构）、水印内容正确、条目顺序/压缩方法保留、
// 幂等跳过、护栏直通（超大/损坏/加密）、配置白名单扩展。
package response

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// ooxmlTestEntry 测试包条目。
type ooxmlTestEntry struct {
	name    string
	method  uint16
	content string
}

// buildTestOOXML 构造最小 docx 形态 ZIP 包（条目顺序固定）。
func buildTestOOXML(t *testing.T, entries []ooxmlTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			t.Fatalf("create entry %s: %v", e.name, err)
		}
		if _, err := io.WriteString(w, e.content); err != nil {
			t.Fatalf("write entry %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// docxWithoutCustomProps 无 custom.xml 的最小 docx 包。
func docxWithoutCustomProps(t *testing.T) []byte {
	t.Helper()
	return buildTestOOXML(t, []ooxmlTestEntry{
		{ooxmlContentTypesPart, zip.Deflate, `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`},
		{ooxmlRelsPart, zip.Store, `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", zip.Deflate, `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>机密报表</w:t></w:r></w:p></w:body></w:document>`},
	})
}

// docxWithCustomProps 已有 custom.xml（含一个既有自定义属性）的 docx 包。
func docxWithCustomProps(t *testing.T) []byte {
	t.Helper()
	return buildTestOOXML(t, []ooxmlTestEntry{
		{ooxmlContentTypesPart, zip.Deflate, `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>`},
		{ooxmlRelsPart, zip.Store, `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/></Relationships>`},
		{"word/document.xml", zip.Deflate, `<?xml version="1.0"?><w:document/>`},
		{ooxmlCustomPropsPart, zip.Deflate, `<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="owner"><vt:lpwstr>ops</vt:lpwstr></property></Properties>`},
	})
}

// readZipEntries 开包读取全部条目（完整性断言：CRC 校验在读路径执行）；
// 返回按物理顺序的 名→（方法，内容）。
func readZipEntries(t *testing.T, body []byte) ([]string, map[string]uint16, map[string]string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("repackaged body must be a valid zip: %v", err)
	}
	order := []string{}
	methods := map[string]uint16{}
	contents := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		raw, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read entry %s (crc): %v", f.Name, err)
		}
		order = append(order, f.Name)
		methods[f.Name] = f.Method
		contents[f.Name] = string(raw)
	}
	return order, methods, contents
}

// assertWellFormedXML XML 良构断言（解析至 EOF）。
func assertWellFormedXML(t *testing.T, name, data string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(data))
	for {
		if _, err := dec.Token(); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("%s must be well-formed xml: %v", name, err)
		}
	}
}

// 无 custom.xml 的包：新建部件 + 三处登记同步、条目顺序保留（原条目为前缀、新部件包尾）、
// 压缩方法保留、水印文本正确、全程良构。
func TestApplyOOXMLWatermarkNewCustomProps(t *testing.T) {
	src := docxWithoutCustomProps(t)
	out, applied, err := applyOOXMLFileWatermark(src, "wm ip=203.0.113.9 id=auth:abc")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("must apply on clean docx")
	}
	order, methods, contents := readZipEntries(t, out)
	// 条目顺序：原三条为前缀，新部件在包尾
	wantPrefix := []string{ooxmlContentTypesPart, ooxmlRelsPart, "word/document.xml"}
	if len(order) != 4 || strings.Join(order[:3], ",") != strings.Join(wantPrefix, ",") || order[3] != ooxmlCustomPropsPart {
		t.Fatalf("entry order = %v", order)
	}
	// 压缩方法保留
	if methods[ooxmlContentTypesPart] != zip.Deflate || methods[ooxmlRelsPart] != zip.Store || methods["word/document.xml"] != zip.Deflate {
		t.Fatalf("methods not preserved: %+v", methods)
	}
	// 登记同步：Override + Relationship（rId2 = 现存 rId1 最大值 +1）
	if !strings.Contains(contents[ooxmlContentTypesPart], `/docProps/custom.xml`) ||
		!strings.Contains(contents[ooxmlContentTypesPart], `custom-properties+xml`) {
		t.Fatalf("content types registration missing: %s", contents[ooxmlContentTypesPart])
	}
	if !strings.Contains(contents[ooxmlRelsPart], `Id="rId2"`) ||
		!strings.Contains(contents[ooxmlRelsPart], `relationships/custom-properties`) {
		t.Fatalf("rels registration missing: %s", contents[ooxmlRelsPart])
	}
	// 水印部件：文本正确、命名空间声明完整、良构
	cp := contents[ooxmlCustomPropsPart]
	if !strings.Contains(cp, `name="jiuzhang-watermark"`) || !strings.Contains(cp, `pid="2"`) {
		t.Fatalf("watermark property missing: %s", cp)
	}
	if !strings.Contains(cp, "wm ip=203.0.113.9 id=auth:abc") {
		t.Fatalf("watermark text missing: %s", cp)
	}
	if !strings.Contains(cp, `xmlns:vt=`) || !strings.Contains(cp, `</Properties>`) {
		t.Fatalf("custom props part malformed: %s", cp)
	}
	assertWellFormedXML(t, ooxmlCustomPropsPart, cp)
	assertWellFormedXML(t, ooxmlContentTypesPart, contents[ooxmlContentTypesPart])
	assertWellFormedXML(t, ooxmlRelsPart, contents[ooxmlRelsPart])
	// 原文档内容不变
	if !strings.Contains(contents["word/document.xml"], "机密报表") {
		t.Fatal("document content must be preserved")
	}
}

// 已有 custom.xml 的包：属性注入（pid 取最大值 +1）、登记部件内容不改动、
// 幂等锚点命中二次跳过。
func TestApplyOOXMLWatermarkExistingCustomProps(t *testing.T) {
	src := docxWithCustomProps(t)
	out, applied, err := applyOOXMLFileWatermark(src, "wm d=shop.example.com")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("must apply")
	}
	order, _, contents := readZipEntries(t, out)
	if len(order) != 4 || order[3] != ooxmlCustomPropsPart {
		t.Fatalf("no new part expected: %v", order)
	}
	cp := contents[ooxmlCustomPropsPart]
	// 既有属性保留 + 新属性 pid=3（现存最大 2 +1）
	if !strings.Contains(cp, `name="owner"`) || !strings.Contains(cp, `name="jiuzhang-watermark"`) || !strings.Contains(cp, `pid="3"`) {
		t.Fatalf("property injection wrong: %s", cp)
	}
	assertWellFormedXML(t, ooxmlCustomPropsPart, cp)
	// 幂等：二次注入跳过（锚点已存在）
	out2, applied2, err := applyOOXMLFileWatermark(out, "wm other")
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if applied2 || !bytes.Equal(out2, out) {
		t.Fatalf("idempotent skip expected: applied=%v", applied2)
	}
}

// XML 转义：水印文本含特殊字符时属性部件仍良构且内容可还原。
func TestApplyOOXMLWatermarkEscapesText(t *testing.T) {
	out, applied, err := applyOOXMLFileWatermark(docxWithoutCustomProps(t), `wm <tag> & "quote"`)
	if err != nil || !applied {
		t.Fatalf("apply: %v/%v", err, applied)
	}
	_, _, contents := readZipEntries(t, out)
	cp := contents[ooxmlCustomPropsPart]
	if strings.Contains(cp, `<tag>`) {
		t.Fatalf("text must be escaped: %s", cp)
	}
	if !strings.Contains(cp, `&lt;tag&gt; &amp; &#34;quote&#34;`) {
		t.Fatalf("escaped text missing: %s", cp)
	}
	assertWellFormedXML(t, ooxmlCustomPropsPart, cp)
}

// 护栏直通：超大（>32MiB）静默跳过；损坏 ZIP 与加密包返回错误（调用方 FAIL_OPEN）。
func TestApplyOOXMLWatermarkGuards(t *testing.T) {
	// 超大：applied=false, err=nil（预期体量形态，不告警）
	big := make([]byte, maxOOXMLWatermarkBytes+1)
	out, applied, err := applyOOXMLFileWatermark(big, "wm")
	if err != nil || applied || !bytes.Equal(out, big) {
		t.Fatalf("oversize must pass through silently: applied=%v err=%v", applied, err)
	}
	// 损坏 ZIP：返回错误
	if _, _, err := applyOOXMLFileWatermark([]byte("not a zip at all"), "wm"); err == nil {
		t.Fatal("corrupt zip must return error")
	}
	// 加密包（EncryptedPackage 部件）：返回错误
	enc := buildTestOOXML(t, []ooxmlTestEntry{
		{ooxmlEncryptedPackagePart, zip.Store, "ole-stream"},
		{"EncryptionInfo", zip.Store, "info"},
	})
	if _, _, err := applyOOXMLFileWatermark(enc, "wm"); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted package must return error: %v", err)
	}
	// 缺登记锚点（无 [Content_Types].xml 且无既有 custom.xml）：返回错误
	broken := buildTestOOXML(t, []ooxmlTestEntry{
		{"word/document.xml", zip.Deflate, "<w:document/>"},
	})
	if _, _, err := applyOOXMLFileWatermark(broken, "wm"); err == nil {
		t.Fatal("package without registration anchors must return error")
	}
	// 空体：静默跳过
	if _, applied, err := applyOOXMLFileWatermark(nil, "wm"); err != nil || applied {
		t.Fatalf("empty body must skip: %v/%v", applied, err)
	}
}

// ApplyFileWatermark 集成：OOXML MIME 走 ZIP 注入；配置白名单扩展三个 OOXML MIME
// （其余二进制类型仍显式拒绝）；类型不在白名单跳过。
func TestApplyFileWatermarkOOXMLIntegration(t *testing.T) {
	const docxMIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	cfg, err := NewFileWatermarkConfig(true, "wm {ip}", []string{"text/plain", docxMIME}, "")
	if err != nil {
		t.Fatalf("ooxml mime must be accepted: %v", err)
	}
	if !cfg.AllowsContentType(docxMIME + "; charset=utf-8") {
		t.Fatal("ooxml mime must be allowed (params stripped)")
	}
	out, applied, err := ApplyFileWatermark(docxWithoutCustomProps(t), docxMIME, cfg, "wm ip=1.2.3.4")
	if err != nil || !applied {
		t.Fatalf("apply ooxml: %v/%v", err, applied)
	}
	_, _, contents := readZipEntries(t, out)
	if !strings.Contains(contents[ooxmlCustomPropsPart], "wm ip=1.2.3.4") {
		t.Fatalf("watermark missing: %s", contents[ooxmlCustomPropsPart])
	}
	// 类型不在白名单：跳过
	if _, applied, err := ApplyFileWatermark(docxWithoutCustomProps(t), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", cfg, "wm"); err != nil || applied {
		t.Fatalf("non-whitelisted ooxml type must skip: %v/%v", applied, err)
	}
	// 三个 OOXML MIME 全部可配置；其余二进制类型仍拒绝
	for _, mt := range []string{
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	} {
		if _, err := NewFileWatermarkConfig(true, "wm", []string{mt}, ""); err != nil {
			t.Fatalf("%s must be accepted: %v", mt, err)
		}
	}
	if _, err := NewFileWatermarkConfig(true, "wm", []string{"application/pdf"}, ""); err == nil {
		t.Fatal("application/pdf must still be rejected")
	}
	// 扩展名映射
	if OOXMLWatermarkExtension(docxMIME) != "docx" || OOXMLWatermarkExtension("text/plain") != "" {
		t.Fatal("extension mapping wrong")
	}
}

// 解压护栏（zip bomb 放大形态）：单条目解压超 64MiB 返回错误 FAIL_OPEN——
// 返回原文不嵌水印；全零条目压缩后包体极小（仍过 32MiB 包体护栏），
// 验证护栏按真实解压量判定而非压缩包体。
func TestApplyOOXMLWatermarkEntryInflateGuard(t *testing.T) {
	big := string(make([]byte, maxOOXMLWatermarkEntryBytes+1))
	src := buildTestOOXML(t, []ooxmlTestEntry{
		{ooxmlContentTypesPart, zip.Deflate, `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`},
		{ooxmlRelsPart, zip.Store, `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", zip.Deflate, big},
	})
	if len(src) > maxOOXMLWatermarkBytes {
		t.Fatalf("precondition: compressed package must stay under package guard, got %d", len(src))
	}
	out, applied, err := applyOOXMLFileWatermark(src, "wm")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized inflated entry must fail: %v", err)
	}
	if applied || !bytes.Equal(out, src) {
		t.Fatalf("fail-open must return original body unwatermarked: applied=%v", applied)
	}
}

// 解压护栏：多条目各自低于单条目上限（48MiB < 64MiB）、累计解压 144MiB 超 128MiB
// 护栏，同样返回错误 FAIL_OPEN 不嵌水印。
func TestApplyOOXMLWatermarkCumulativeInflateGuard(t *testing.T) {
	zeros := string(make([]byte, 48<<20))
	src := buildTestOOXML(t, []ooxmlTestEntry{
		{ooxmlContentTypesPart, zip.Deflate, `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`},
		{ooxmlRelsPart, zip.Store, `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", zip.Deflate, zeros},
		{"word/comments.xml", zip.Deflate, zeros},
		{"word/endnotes.xml", zip.Deflate, zeros},
	})
	out, applied, err := applyOOXMLFileWatermark(src, "wm")
	if err == nil || !strings.Contains(err.Error(), "inflated size") {
		t.Fatalf("cumulative inflated guard must fail: %v", err)
	}
	if applied || !bytes.Equal(out, src) {
		t.Fatalf("fail-open must return original body unwatermarked: applied=%v", applied)
	}
}
