// file_watermark_ooxml_test.go OOXML 水印白名单扩展下发单测（W14-GW / P2-01 全格式扩展，
// 纯函数不依赖数据库）：三个 OOXML MIME 接受、其余二进制类型仍显式拒绝。
package guardconfig

import (
	"testing"
)

// TestParseFileWatermarkSettingsOOXML 三个 OOXML MIME（docx/xlsx/pptx）进入白名单；
// 与文本族混配保序去重；其余二进制类型（pdf/zip/旧版 OLE doc）仍显式拒绝。
func TestParseFileWatermarkSettingsOOXML(t *testing.T) {
	base := map[string]string{
		"api_file_watermark_enabled":  "true",
		"api_file_watermark_template": "wm {ip}",
	}
	// 三个 OOXML MIME 全接受（大小写/空白归一）
	kv := map[string]string{}
	for k, v := range base {
		kv[k] = v
	}
	kv["api_file_watermark_content_types"] = "text/plain," +
		" application/vnd.openxmlformats-officedocument.wordprocessingml.document ," +
		"Application/Vnd.Openxmlformats-Officedocument.Spreadsheetml.Sheet," +
		"application/vnd.openxmlformats-officedocument.presentationml.presentation"
	wm, err := parseFileWatermarkSettings(kv)
	if err != nil {
		t.Fatalf("ooxml mimes must be accepted: %v", err)
	}
	if wm == nil || len(wm.ContentTypes) != 4 ||
		wm.ContentTypes[1] != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
		wm.ContentTypes[2] != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" ||
		wm.ContentTypes[3] != "application/vnd.openxmlformats-officedocument.presentationml.presentation" {
		t.Fatalf("wm = %+v", wm)
	}
	// 其余二进制类型仍拒绝（逐项）
	for _, bad := range []string{
		"application/pdf",
		"application/zip",
		"application/msword", // 旧版 OLE 复合文档不在 OOXML 范围
		"image/png",
	} {
		kv := map[string]string{}
		for k, v := range base {
			kv[k] = v
		}
		kv["api_file_watermark_content_types"] = bad
		if _, err := parseFileWatermarkSettings(kv); err == nil {
			t.Fatalf("%s must still be rejected", bad)
		}
	}
}
