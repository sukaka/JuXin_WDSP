// watermark_ooxml.go OOXML（docx/xlsx/pptx）下载水印（W14-GW / P2-01 全格式水印扩展）：
// 与水印 v1 共用配置与开关（content_types 白名单扩展三个 OOXML MIME），
// 仅依赖 Go 标准库 archive/zip（不引新媒体处理依赖）。
//
// 注入方式（选不破坏包结构的形态）：OOXML 即 ZIP 容器（OPC），水印写入
// docProps/custom.xml 自定义属性部件——Office 原生属性面板可读，取证提取无需解析
// 文档主体；部件已存在时按 custom-properties 架构追加 <property>（pid 取现存最大值 +1），
// 不存在时新建部件并同步登记 [Content_Types].xml Override 与 _rels/.rels Relationship
// （OPC 合规登记，缺登记部件属非法包，Office 可能拒开——三处同步登记缺一不可）。
// 不选「新建 jiuzhang-watermark.xml 独立部件」：自定义部件同样要求 [Content_Types].xml
// 与 .rels 登记且属性面板不可见，custom.xml 一处修改取证价值更高。
//
// 重打包纪律：逐条目按原顺序复制、保留原压缩方法（store/deflate）与修改时间等元数据；
// Go 标准库不暴露原 deflate 压缩级别，重压缩按标准库默认级别（v1 如实声明此字节级差异；
// 条目内容与包结构语义不变）。CRC/大小由 zip.Writer 重算。
// 新部件（含被修改的登记部件）追加至包尾，OPC 不依赖部件物理顺序。
//
// FAIL_OPEN 直通（与水印 v1 同一纪律）：ZIP 损坏/加密（OLE 复合文档或 EncryptedPackage
// 部件/条目加密标志）/结构缺登记锚点返回错误，由调用方告警后直通原响应；
// 重打包条目解压超每条目/累计双护栏（zip bomb 放大形态）同样返回错误 FAIL_OPEN；
// 超大（>32MiB 护栏）属预期体量形态，静默跳过不加（与空体/非白名单同一纪律，防日志刷屏）。
package response

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// maxOOXMLWatermarkBytes OOXML 水印体量护栏（32 MiB）：超限静默跳过（预期形态不告警）。
const maxOOXMLWatermarkBytes = 32 << 20

// maxOOXMLMetaPartBytes 登记/属性部件读取上限（[Content_Types].xml、.rels、custom.xml
// 均为小元数据部件；超限按异常处理返回错误，防畸形包撑内存）。
const maxOOXMLMetaPartBytes = 4 << 20

// maxOOXMLWatermarkEntryBytes 重打包单条目解压上限（64 MiB）：压缩包 32 MiB 护栏下，
// 正常 OOXML 部件（媒体近乎不可压、文档主体 deflate 率有限）单条目解压量远低于此；
// 超限即 zip bomb 放大形态，返回错误 FAIL_OPEN 直通原文不嵌水印（调用方 Warn）。
const maxOOXMLWatermarkEntryBytes = 64 << 20

// maxOOXMLWatermarkInflateBytes 重打包累计解压上限（128 MiB，包体护栏的 4 倍）：
// 正常文档整体解压量与包体同量级（媒体占比高且不可压），累计超限即异常放大形态，
// 同样返回错误 FAIL_OPEN 直通不嵌水印（登记部件另受 maxOOXMLMetaPartBytes 约束，不计入）。
const maxOOXMLWatermarkInflateBytes = 128 << 20

// ooxmlWatermarkExtensions OOXML 水印支持的 Content-Type 主类型 → 下载文件扩展名。
// 下载侧命中须 MIME 白名单与 filename 扩展名双重一致（防伪造扩展名绕过/误标）。
var ooxmlWatermarkExtensions = map[string]string{
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   "docx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         "xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
}

// OOXMLWatermarkExtension 返回 OOXML 水印类型对应的文件扩展名；非 OOXML 水印类型返回空串。
func OOXMLWatermarkExtension(mediaType string) string {
	return ooxmlWatermarkExtensions[strings.ToLower(strings.TrimSpace(mediaType))]
}

// OOXML 部件路径与登记锚点常量。
const (
	ooxmlContentTypesPart = "[Content_Types].xml"
	ooxmlRelsPart         = "_rels/.rels"
	ooxmlCustomPropsPart  = "docProps/custom.xml"
	// ooxmlEncryptedPackagePart 敏捷加密包标志部件（加密文档不解、不改写）
	ooxmlEncryptedPackagePart = "EncryptedPackage"
)

// 水印自定义属性名（幂等锚点：已存在即跳过，不重复注入）。
const ooxmlWatermarkPropName = "jiuzhang-watermark"

// 水印属性/登记片段模板（custom-properties 架构；fmtid 为架构固定 GUID）。
const (
	ooxmlPropFmt = `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="%d" name="` + ooxmlWatermarkPropName + `"><vt:lpwstr>%s</vt:lpwstr></property>`

	ooxmlCustomPropsHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">`
	ooxmlCustomPropsFooter = `</Properties>`

	ooxmlCustomPropsOverride = `<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>`
	ooxmlCustomPropsRelFmt   = `<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>`
)

var (
	reOOXMLPropPID = regexp.MustCompile(`pid="(\d+)"`)
	reOOXMLRelID   = regexp.MustCompile(`Id="rId(\d+)"`)
)

// applyOOXMLFileWatermark 对完整捕获的 OOXML 下载体注入水印部件并重打包。
// 返回改写后体、是否已加水印、错误；护栏跳过（超大/已注入）applied=false、err=nil；
// 损坏/加密/结构异常返回错误（调用方 FAIL_OPEN 直通）。
func applyOOXMLFileWatermark(body []byte, text string) ([]byte, bool, error) {
	if len(body) == 0 || len(body) > maxOOXMLWatermarkBytes {
		return body, false, nil // 超大护栏：预期体量形态，静默直通（见文件头注释）
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		// OLE 复合文档（旧版 .doc/.xls 与加密文档同为 D0CF 魔数）在此失败
		return body, false, fmt.Errorf("read ooxml zip package: %w", err)
	}

	// 部件索引与加密/幂等判定
	var customProps *zip.File
	for _, f := range zr.File {
		if f.Name == ooxmlEncryptedPackagePart {
			return body, false, fmt.Errorf("ooxml package encrypted (EncryptedPackage part present)")
		}
		if f.Flags&0x1 != 0 {
			return body, false, fmt.Errorf("ooxml zip entry %q encrypted", f.Name)
		}
		if f.Name == ooxmlCustomPropsPart {
			customProps = f
		}
	}

	// 改写计划：默认原样复制；命中登记/属性部件时替换内容
	replacements := map[string][]byte{}
	propXML := ""
	if customProps != nil {
		raw, err := readOOXMLPart(customProps)
		if err != nil {
			return body, false, fmt.Errorf("read %s: %w", ooxmlCustomPropsPart, err)
		}
		if strings.Contains(raw, `name="`+ooxmlWatermarkPropName+`"`) {
			return body, false, nil // 已注入：幂等跳过（不覆盖既有水印，与 JSON 键存在跳过同一纪律）
		}
		propXML = raw
	} else {
		// 新建 custom.xml：三处登记同步（[Content_Types].xml Override + .rels Relationship）
		ct := findOOXMLPart(zr, ooxmlContentTypesPart)
		rels := findOOXMLPart(zr, ooxmlRelsPart)
		if ct == nil || rels == nil {
			return body, false, fmt.Errorf("ooxml package missing %s or %s", ooxmlContentTypesPart, ooxmlRelsPart)
		}
		ctRaw, err := readOOXMLPart(ct)
		if err != nil {
			return body, false, fmt.Errorf("read %s: %w", ooxmlContentTypesPart, err)
		}
		ctNew, err := insertBeforeCloseTag(ctRaw, "</Types>", ooxmlCustomPropsOverride)
		if err != nil {
			return body, false, fmt.Errorf("register watermark in %s: %w", ooxmlContentTypesPart, err)
		}
		replacements[ooxmlContentTypesPart] = ctNew
		relsRaw, err := readOOXMLPart(rels)
		if err != nil {
			return body, false, fmt.Errorf("read %s: %w", ooxmlRelsPart, err)
		}
		relsNew, err := insertBeforeCloseTag(relsRaw, "</Relationships>",
			fmt.Sprintf(ooxmlCustomPropsRelFmt, nextOOXMLRelID(relsRaw)))
		if err != nil {
			return body, false, fmt.Errorf("register watermark in %s: %w", ooxmlRelsPart, err)
		}
		replacements[ooxmlRelsPart] = relsNew
		propXML = ooxmlCustomPropsHeader + ooxmlCustomPropsFooter
	}

	// 注入水印属性（pid 取现存最大值 +1；水印文本 XML 转义）
	escaped := escapeOOXMLText(text)
	pid := nextOOXMLPropPID(propXML)
	propXMLNew, err := insertBeforeCloseTag(propXML, "</Properties>", fmt.Sprintf(ooxmlPropFmt, pid, escaped))
	if err != nil {
		return body, false, fmt.Errorf("inject watermark property: %w", err)
	}
	replacements[ooxmlCustomPropsPart] = propXMLNew

	// 重打包：原顺序复制（保留压缩方法与元数据），命中计划的部件替换内容，
	// 新建部件追加至包尾（OPC 不依赖部件物理顺序）；
	// 普通条目解压按每条目/累计双上限护栏防 zip bomb 放大（超限 FAIL_OPEN）
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	customPropsWritten := false
	var inflatedTotal int64
	for _, f := range zr.File {
		content, replaced := replacements[f.Name]
		if !replaced {
			entry, err := readOOXMLEntry(f)
			if err != nil {
				return body, false, fmt.Errorf("read zip entry %q: %w", f.Name, err)
			}
			inflatedTotal += int64(len(entry))
			if inflatedTotal > maxOOXMLWatermarkInflateBytes {
				return body, false, fmt.Errorf("ooxml package inflated size %d exceeds guard %d", inflatedTotal, maxOOXMLWatermarkInflateBytes)
			}
			content = entry
		}
		if f.Name == ooxmlCustomPropsPart {
			customPropsWritten = true
		}
		if err := writeOOXMLEntry(zw, f, content); err != nil {
			return body, false, fmt.Errorf("rewrite zip entry %q: %w", f.Name, err)
		}
	}
	if !customPropsWritten {
		// 新建 custom.xml 部件（deflate；小部件压缩语义无关紧要）
		if err := writeOOXMLNewEntry(zw, ooxmlCustomPropsPart, replacements[ooxmlCustomPropsPart]); err != nil {
			return body, false, fmt.Errorf("add %s: %w", ooxmlCustomPropsPart, err)
		}
	}
	if err := zw.Close(); err != nil {
		return body, false, fmt.Errorf("close ooxml repackage: %w", err)
	}
	return buf.Bytes(), true, nil
}

// findOOXMLPart 按名查找包内部件（未找到返回 nil）。
func findOOXMLPart(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// readOOXMLPart 读取元数据部件全文（上限 maxOOXMLMetaPartBytes，超限报错）。
func readOOXMLPart(f *zip.File) (string, error) {
	if f.UncompressedSize64 > maxOOXMLMetaPartBytes {
		return "", fmt.Errorf("part %q too large (%d bytes)", f.Name, f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(io.LimitReader(rc, maxOOXMLMetaPartBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxOOXMLMetaPartBytes {
		return "", fmt.Errorf("part %q too large (%d bytes)", f.Name, len(raw))
	}
	return string(raw), nil
}

// readOOXMLEntry 读取重打包普通条目内容（上限 maxOOXMLWatermarkEntryBytes，超限报错）：
// 头部声明大小预检 + LimitReader 实读双保险（声明值可被伪造，实读截断为最终防线）。
func readOOXMLEntry(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > maxOOXMLWatermarkEntryBytes {
		return nil, fmt.Errorf("entry %q too large (%d bytes)", f.Name, f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	content, err := io.ReadAll(io.LimitReader(rc, maxOOXMLWatermarkEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxOOXMLWatermarkEntryBytes {
		return nil, fmt.Errorf("entry %q too large (%d bytes)", f.Name, len(content))
	}
	return content, nil
}

// insertBeforeCloseTag 在最后一个闭合标签前插入片段；锚点缺失返回错误（结构异常 FAIL_OPEN）。
func insertBeforeCloseTag(data, closeTag, fragment string) ([]byte, error) {
	i := strings.LastIndex(data, closeTag)
	if i < 0 {
		return nil, fmt.Errorf("close tag %s not found", closeTag)
	}
	out := make([]byte, 0, len(data)+len(fragment))
	out = append(out, data[:i]...)
	out = append(out, fragment...)
	out = append(out, data[i:]...)
	return out, nil
}

// nextOOXMLPropPID 取现存 pid 最大值 +1（custom-properties 架构要求 pid 唯一且 ≥2）。
func nextOOXMLPropPID(props string) int {
	max := 1
	for _, m := range reOOXMLPropPID.FindAllStringSubmatch(props, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && n > max {
			max = n
		}
	}
	return max + 1
}

// nextOOXMLRelID 取现存 rIdN 最大值 +1（.rels 关系 Id 唯一约定）。
func nextOOXMLRelID(rels string) string {
	max := 0
	for _, m := range reOOXMLRelID.FindAllStringSubmatch(rels, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && n > max {
			max = n
		}
	}
	return "rId" + strconv.Itoa(max+1)
}

// escapeOOXMLText 水印文本 XML 转义（属性值进入 vt:lpwstr 元素内容）。
func escapeOOXMLText(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// writeOOXMLEntry 复制条目并重写内容：保留原名/压缩方法/修改时间/扩展属性等元数据
// （CRC 与大小由 zip.Writer 重算；deflate 级别标准库不暴露原值，按默认级别重压缩）。
func writeOOXMLEntry(zw *zip.Writer, f *zip.File, content []byte) error {
	nh := &zip.FileHeader{
		Name:          f.Name,
		Method:        f.Method,
		Modified:      f.Modified,
		Extra:         f.Extra,
		ExternalAttrs: f.ExternalAttrs,
		NonUTF8:       f.NonUTF8,
	}
	w, err := zw.CreateHeader(nh)
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}

// writeOOXMLNewEntry 新建部件（deflate 压缩）。
func writeOOXMLNewEntry(zw *zip.Writer, name string, content []byte) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}
