// blockresponse.go 自定义 429/阻断响应页面（阶段5 §5.1；发布通道下发 block_response 段，
// 全产品形态能力不受 WDSP 门控）：
//   - nil 或全空 = 内置默认模板（渲染与历史版本逐字节一致）；
//   - 装配期校验大小硬上限（fail-closed 拒绝加载，不静默截断；
//     与发布侧 gatewayconfig/block_response.go、settings.settingStringMaxLen 同口径）；
//   - HTML 正文白名单式净化（防注入 XSS）：仅放行少量排版标签且剥离全部属性，
//     其余标签/注释/DOCTYPE 丢弃，文本整串转义；标题与 JSON 文案保留原文，渲染时转义。
package jiuzhang_guard

import (
	"fmt"
	stdhtml "html"
	"regexp"
	"strings"

	xhtml "golang.org/x/net/html"
)

// block_response 段大小硬上限（字节；与发布侧 gatewayconfig 同口径）。
const (
	maxBlockResponseTitleBytes   = 128
	maxBlockResponseBodyBytes    = 4096
	maxBlockResponseJSONCode     = 128
	maxBlockResponseJSONMsgBytes = 512
)

// blockResponseCodePattern JSON 错误码字符集（与发布侧同口径）。
var blockResponseCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// blockResponseJSON 自定义 429/阻断响应（发布通道下发 block_response 段）。
// json tag 为跨分片契约，不得改动。
type blockResponseJSON struct {
	HTMLTitle   string `json:"html_title,omitempty"`   // HTML 页面标题（渲染时整串转义）
	HTMLBody    string `json:"html_body,omitempty"`    // HTML 页面正文（受限 HTML，装配期净化）
	JSONCode    string `json:"json_code,omitempty"`    // JSON 错误响应 error 错误码
	JSONMessage string `json:"json_message,omitempty"` // JSON 错误响应 message 文案
}

// compiledBlockResponse 装配期编译产物：body 已白名单净化；title/code/message
// 保留原文（渲染时转义/经 JSON 编码）。
type compiledBlockResponse struct {
	title       string
	body        string
	jsonCode    string
	jsonMessage string
}

// validateBlockResponse 校验 block_response 段大小上限与错误码字符集（装配期调用，
// 非法配置拒绝加载——fail-closed，与 license_max_qps 负数拒绝同一纪律）。
func validateBlockResponse(cfg *blockResponseJSON) error {
	if cfg == nil {
		return nil
	}
	if len(cfg.HTMLTitle) > maxBlockResponseTitleBytes {
		return fmt.Errorf("block_response.html_title 超过上限 %d 字节：%d", maxBlockResponseTitleBytes, len(cfg.HTMLTitle))
	}
	if len(cfg.HTMLBody) > maxBlockResponseBodyBytes {
		return fmt.Errorf("block_response.html_body 超过上限 %d 字节：%d", maxBlockResponseBodyBytes, len(cfg.HTMLBody))
	}
	if len(cfg.JSONCode) > maxBlockResponseJSONCode {
		return fmt.Errorf("block_response.json_code 超过上限 %d 字节：%d", maxBlockResponseJSONCode, len(cfg.JSONCode))
	}
	if cfg.JSONCode != "" && !blockResponseCodePattern.MatchString(cfg.JSONCode) {
		return fmt.Errorf("block_response.json_code 非法取值（仅允许字母数字与 _ . -）")
	}
	if len(cfg.JSONMessage) > maxBlockResponseJSONMsgBytes {
		return fmt.Errorf("block_response.json_message 超过上限 %d 字节：%d", maxBlockResponseJSONMsgBytes, len(cfg.JSONMessage))
	}
	return nil
}

// compileBlockResponse 装配期编译：校验 + 正文白名单净化；nil 或全空返回 nil（未配置，
// 渲染走内置默认模板）。
func compileBlockResponse(cfg *blockResponseJSON) (*compiledBlockResponse, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := validateBlockResponse(cfg); err != nil {
		return nil, err
	}
	if cfg.HTMLTitle == "" && cfg.HTMLBody == "" && cfg.JSONCode == "" && cfg.JSONMessage == "" {
		return nil, nil
	}
	return &compiledBlockResponse{
		title:       cfg.HTMLTitle,
		body:        sanitizeBlockHTML(cfg.HTMLBody),
		jsonCode:    cfg.JSONCode,
		jsonMessage: cfg.JSONMessage,
	}, nil
}

// blockBodyAllowedTags HTML 正文白名单标签（纯排版语义，无脚本/嵌入/表单能力；
// 一律剥离属性——on* 事件、style、href 等攻击面整体移除）。
var blockBodyAllowedTags = map[string]bool{
	"p": true, "br": true, "hr": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"strong": true, "b": true, "em": true, "i": true, "u": true,
	"ul": true, "ol": true, "li": true,
	"div": true, "span": true,
}

// sanitizeBlockHTML 白名单式净化 HTML 正文：放行白名单标签（无属性），文本经
// 整串转义，其余标签/注释/DOCTYPE 一律丢弃（script/style 等标签连同其文本内容
// 只以转义文本形式残留，绝不形成可执行标记）。解析失败返回已净化前缀（安全侧）。
func sanitizeBlockHTML(in string) string {
	if in == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(in))
	tz := xhtml.NewTokenizer(strings.NewReader(in))
	for {
		switch tz.Next() {
		case xhtml.ErrorToken:
			return b.String()
		case xhtml.TextToken:
			b.WriteString(stdhtml.EscapeString(string(tz.Text())))
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			rawName, _ := tz.TagName()
			name := string(rawName)
			if blockBodyAllowedTags[name] {
				b.WriteByte('<')
				b.WriteString(name)
				b.WriteByte('>')
			}
		case xhtml.EndTagToken:
			rawName, _ := tz.TagName()
			name := string(rawName)
			if blockBodyAllowedTags[name] {
				b.WriteString("</")
				b.WriteString(name)
				b.WriteByte('>')
			}
		default:
			// 注释 / DOCTYPE：丢弃
		}
	}
}
