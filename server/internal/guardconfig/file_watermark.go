// file_watermark.go 文件下载水印下发（W12-GW 交付文本族 v1；W14-GW 扩展 OOXML 族）：
// system_settings gateway_runtime 组 api_file_watermark_* 键 → GuardConfig.APIFileWatermark：
//
//	api_file_watermark_enabled       true/false（缺省 false 不下发，网关零行为变化）
//	api_file_watermark_template      水印文本模板（{ip}/{identity}/{time}/{domain} 占位）
//	api_file_watermark_content_types 逗号分隔 Content-Type 白名单（缺省网关默认表
//	                                 text/plain,text/csv,application/json,text/markdown；
//	                                 W14-GW 起另接受三个 OOXML MIME：docx/xlsx/pptx）
//	api_file_watermark_json_key      JSON 顶层水印字段名（缺省 "_wm" 由网关侧兜底）
//
// 校验失败如实报错（中止发布），不静默回退——避免管理面显示与网关行为不一致。
// 网关侧对应实现：gateway dynamic_security/response/watermark.go（同一校验口径）。
package guardconfig

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 文件水印设置护栏（与网关 response.NewFileWatermarkConfig 同一口径）。
const (
	maxFileWatermarkTemplateLen = 256
	maxFileWatermarkTypes       = 32
	maxFileWatermarkTypeLen     = 100
	maxFileWatermarkJSONKeyLen  = 64
)

// ooxmlWatermarkMIMETypes OOXML 水印支持的三个 MIME（W14-GW；与网关
// response.ooxmlWatermarkExtensions 键集同一口径）。
var ooxmlWatermarkMIMETypes = map[string]bool{
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
}

// parseFileWatermarkSettings 解析 api_file_watermark_* 键组（纯函数，可测）。
// 未配置/未启用返回 nil（不下发，网关响应侧零行为变化）；
// enabled=true 时模板必填、禁控制字符——模板进入单行注释/JSON 字段值，
// 换行等控制字符会破坏单行语义并向文件注入额外内容。
func parseFileWatermarkSettings(kv map[string]string) (*gatewayconfig.GuardFileWatermark, error) {
	enabled, err := parseFileWatermarkEnabled(kv["api_file_watermark_enabled"])
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	tmpl := strings.TrimSpace(kv["api_file_watermark_template"])
	if tmpl == "" {
		return nil, fmt.Errorf("gateway_runtime.api_file_watermark_template 启用水印时必填")
	}
	if utf8.RuneCountInString(tmpl) > maxFileWatermarkTemplateLen {
		return nil, fmt.Errorf("gateway_runtime.api_file_watermark_template 长度超过 %d", maxFileWatermarkTemplateLen)
	}
	if hasFileWatermarkControlChar(tmpl) {
		return nil, fmt.Errorf("gateway_runtime.api_file_watermark_template 不允许控制字符（含换行）")
	}
	wm := &gatewayconfig.GuardFileWatermark{Enabled: true, TextTemplate: tmpl}
	// Content-Type 白名单（逗号分隔；缺省/空 = 网关默认表，逐项 trim 小写、去空去重）
	if raw := strings.TrimSpace(kv["api_file_watermark_content_types"]); raw != "" {
		seen := map[string]bool{}
		for _, p := range strings.Split(raw, ",") {
			mt := strings.ToLower(strings.TrimSpace(p))
			if mt == "" || seen[mt] {
				continue
			}
			if len(mt) > maxFileWatermarkTypeLen || !strings.Contains(mt, "/") {
				return nil, fmt.Errorf("gateway_runtime.api_file_watermark_content_types 非法取值 %q", p)
			}
			// 能力边界：文本族与 application/json + 三个 OOXML MIME（W14-GW；
			// 其余类型需媒体库；显式拒绝不静默跳过）
			if mt != "application/json" && !strings.HasPrefix(mt, "text/") && !ooxmlWatermarkMIMETypes[mt] {
				return nil, fmt.Errorf("gateway_runtime.api_file_watermark_content_types 取值 %q 超出支持范围（仅 text/*、application/json 与 OOXML docx/xlsx/pptx）", p)
			}
			seen[mt] = true
			wm.ContentTypes = append(wm.ContentTypes, mt)
			if len(wm.ContentTypes) > maxFileWatermarkTypes {
				return nil, fmt.Errorf("gateway_runtime.api_file_watermark_content_types 条数超过 %d", maxFileWatermarkTypes)
			}
		}
		if len(wm.ContentTypes) == 0 {
			return nil, fmt.Errorf("gateway_runtime.api_file_watermark_content_types 全部为空项")
		}
	}
	// JSON 顶层水印字段名（缺省 "_wm" 由网关侧兜底；禁控制字符——键名进入 JSON 重编码）
	if raw := strings.TrimSpace(kv["api_file_watermark_json_key"]); raw != "" {
		if utf8.RuneCountInString(raw) > maxFileWatermarkJSONKeyLen {
			return nil, fmt.Errorf("gateway_runtime.api_file_watermark_json_key 长度超过 %d", maxFileWatermarkJSONKeyLen)
		}
		if hasFileWatermarkControlChar(raw) {
			return nil, fmt.Errorf("gateway_runtime.api_file_watermark_json_key 不允许控制字符")
		}
		wm.JSONKey = raw
	}
	return wm, nil
}

// parseFileWatermarkEnabled 解析 enabled 键（仅 true/false；缺省/空 = false）。
func parseFileWatermarkEnabled(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("gateway_runtime.api_file_watermark_enabled 非法取值 %q（仅支持 true|false）", raw)
	}
}

// hasFileWatermarkControlChar 控制字符（含换行/制表/DEL）判定。
func hasFileWatermarkControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
