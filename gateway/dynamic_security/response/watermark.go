// watermark.go 文件下载水印（W12-GW 交付文本族 v1；W14-GW 扩展 OOXML 族）：
// 文本族下载响应（Content-Disposition 下载观测命中 + Content-Type 白名单 +
// identity 编码完整捕获体，命中条件由挂点侧判定）在文件尾追加不可见水印标记；
// JSON 族在顶层加 "_wm" 字段（键名可配置）。水印内容含 IP/Identity/Domain/Time
// 占位变量（由挂点侧注入渲染），用于外发文件泄露溯源。
//
// 能力范围（不引媒体处理依赖）：
//   - 文本族（text/plain、text/csv、text/markdown）与 application/json（W12 v1）；
//   - OOXML 族 docx/xlsx/pptx（W14-GW：archive/zip 标准库读写 ZIP 容器，
//     水印注入 docProps/custom.xml 自定义属性部件并重打包，见 watermark_ooxml.go）。
//
// 追加方式按类型选取不破坏语法/解析的形态：
//   - text/plain：追加 "# " 注释行（纯文本无语法约束，# 为通用注释约定）；
//   - text/markdown、text/html：追加 HTML 注释行 <!-- ... -->（渲染不可见，不破坏文档结构）；
//   - text/csv：RFC 4180 无注释语法，追加 "# " 开头的单字段末行——文件仍可正常解析，
//     常见解析器（pandas comment='#' 等）可跳过；严格逐行消费者会多读一条单字段记录，
//     属 v1 已知边界（选择可读标记优先于零宽隐写，便于取证提取）；
//   - application/json：顶层对象加水印字段；顶层非对象或键已存在时跳过不改写
//     （不覆盖既有数据）；重编码经 UseNumber 保留数字字面量、SetEscapeHTML(false)，
//     键按字典序输出（与 ApplyJSON 同一编码纪律，存在键序/空白字节漂移）；
//   - OOXML 族：docProps/custom.xml 自定义属性部件注入（OPC 合规三处登记，
//     部件幂等锚点存在时跳过不重复注入）。
//
// 配置校验仅接受 text/*、application/json 与三个 OOXML MIME（其余类型需媒体库，
// 配置期显式拒绝，不静默跳过）。
//
// 失败纪律：解析/改写失败返回错误，由调用方 FAIL_OPEN 直通原响应（水印为审计能力，
// 不阻断业务，也不随 api_response_fail_policy 升级为抑制）。
package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"
)

// DefaultFileWatermarkContentTypes 文件水印默认 Content-Type 白名单（配置缺省/空时生效）。
var DefaultFileWatermarkContentTypes = []string{
	"text/plain", "text/csv", "application/json", "text/markdown",
}

// DefaultFileWatermarkJSONKey JSON 顶层水印字段缺省键名。
const DefaultFileWatermarkJSONKey = "_wm"

// 文件水印配置护栏（防误配）。
const (
	maxFileWatermarkTemplateLen = 256
	maxFileWatermarkTypes       = 32
	maxFileWatermarkTypeLen     = 100
	maxFileWatermarkJSONKeyLen  = 64
)

// FileWatermarkConfig 文件水印 v1 配置（发布通道下发 api_file_watermark 段）。
type FileWatermarkConfig struct {
	Enabled      bool
	TextTemplate string   // 水印文本模板，支持 {ip}/{identity}/{time}/{domain} 占位
	ContentTypes []string // 媒体类型白名单（小写主类型；空 = DefaultFileWatermarkContentTypes）
	JSONKey      string   // JSON 顶层水印字段名（空 = DefaultFileWatermarkJSONKey）

	typeSet map[string]bool // ContentTypes 归一化集合（编译期构造，运行期 O(1) 判定）
}

// WatermarkVars 水印占位变量（挂点侧注入：真实客户端 IP/身份指纹/请求时间/域名）。
type WatermarkVars struct {
	IP       string // {ip} 真实客户端 IP（入口中间件识别结果）
	Identity string // {identity} 身份指纹（仅凭据派生；匿名为空串）
	Time     string // {time} 请求时间（RFC3339 UTC）
	Domain   string // {domain} 请求域名（去端口小写）
}

// NewFileWatermarkConfig 解析并校验文件水印配置（配置错误显式返回，不静默吞错）。
// enabled=false 时只做归一化不强校验（未启用不生效，网关零行为变化）；
// enabled=true 时模板必填、禁控制字符——模板进入单行注释/JSON 字段值，
// 换行等控制字符会破坏单行语义并向文件注入额外内容。
func NewFileWatermarkConfig(enabled bool, textTemplate string, contentTypes []string, jsonKey string) (*FileWatermarkConfig, error) {
	cfg := &FileWatermarkConfig{Enabled: enabled, TextTemplate: strings.TrimSpace(textTemplate)}
	if !enabled {
		return cfg, nil
	}
	if cfg.TextTemplate == "" {
		return nil, fmt.Errorf("api_file_watermark: text_template required when enabled")
	}
	if utf8.RuneCountInString(cfg.TextTemplate) > maxFileWatermarkTemplateLen {
		return nil, fmt.Errorf("api_file_watermark: text_template must be <= %d chars", maxFileWatermarkTemplateLen)
	}
	if hasFileWatermarkControlChar(cfg.TextTemplate) {
		return nil, fmt.Errorf("api_file_watermark: text_template must not contain control characters")
	}
	// Content-Type 白名单：缺省/空用默认表；逐项 trim 小写、去空去重，防误配上限
	types := contentTypes
	if len(types) == 0 {
		types = DefaultFileWatermarkContentTypes
	}
	if len(types) > maxFileWatermarkTypes {
		return nil, fmt.Errorf("api_file_watermark: content_types too many (%d > %d)", len(types), maxFileWatermarkTypes)
	}
	cfg.typeSet = make(map[string]bool, len(types))
	for _, ct := range types {
		mt := strings.ToLower(strings.TrimSpace(ct))
		if mt == "" {
			continue
		}
		if len(mt) > maxFileWatermarkTypeLen || !strings.Contains(mt, "/") {
			return nil, fmt.Errorf("api_file_watermark: bad content_type %q", ct)
		}
		// 能力边界：文本族（text/*）、application/json 与三个 OOXML MIME
		// （docx/xlsx/pptx，ZIP 容器由标准库读写）；其余类型需媒体库，配置期显式拒绝
		if mt != "application/json" && !strings.HasPrefix(mt, "text/") && OOXMLWatermarkExtension(mt) == "" {
			return nil, fmt.Errorf("api_file_watermark: content_type %q not supported (only text/*, application/json and OOXML docx/xlsx/pptx)", ct)
		}
		if cfg.typeSet[mt] {
			continue
		}
		cfg.typeSet[mt] = true
		cfg.ContentTypes = append(cfg.ContentTypes, mt)
	}
	if len(cfg.ContentTypes) == 0 {
		return nil, fmt.Errorf("api_file_watermark: content_types all empty")
	}
	// JSON 键名：缺省 "_wm"；禁控制字符（键名进入 JSON 重编码）
	key := strings.TrimSpace(jsonKey)
	if key == "" {
		key = DefaultFileWatermarkJSONKey
	}
	if utf8.RuneCountInString(key) > maxFileWatermarkJSONKeyLen {
		return nil, fmt.Errorf("api_file_watermark: json_key must be <= %d chars", maxFileWatermarkJSONKeyLen)
	}
	if hasFileWatermarkControlChar(key) {
		return nil, fmt.Errorf("api_file_watermark: json_key must not contain control characters")
	}
	cfg.JSONKey = key
	return cfg, nil
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

// fileWatermarkMediaType Content-Type 主类型归一（剥离 charset 等参数，小写；
// 解析失败降级为 ';' 前缀小写，与 parser.splitMediaType 同一纪律）。
func fileWatermarkMediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	return strings.ToLower(mt)
}

// AllowsContentType 判定 Content-Type 是否在白名单（按主类型比对）。
func (c *FileWatermarkConfig) AllowsContentType(contentType string) bool {
	if c == nil || !c.Enabled {
		return false
	}
	return c.typeSet[fileWatermarkMediaType(contentType)]
}

// RenderFileWatermark 渲染水印文本：{ip}/{identity}/{time}/{domain} 占位替换；
// 未知占位符原样保留（配置作者可见，不静默吞掉）；占位值为空（如匿名无身份）替换为空串。
func RenderFileWatermark(template string, vars WatermarkVars) string {
	return strings.NewReplacer(
		"{ip}", vars.IP,
		"{identity}", vars.Identity,
		"{time}", vars.Time,
		"{domain}", vars.Domain,
	).Replace(template)
}

// ApplyFileWatermark 对完整捕获的下载响应体加水印；返回改写后体、是否已加水印、错误。
// 不加的情形（applied=false, err=nil）：未启用 / 水印文本为空 / 类型不在白名单 /
// 空体 / JSON 顶层非对象 / JSON 水印键已存在 / OOXML 超 32MiB 护栏或已注入。
// JSON 解析失败、OOXML 包损坏/加密/结构异常返回 err（调用方 FAIL_OPEN 直通）。
func ApplyFileWatermark(body []byte, contentType string, cfg *FileWatermarkConfig, text string) ([]byte, bool, error) {
	if cfg == nil || !cfg.Enabled || text == "" || len(body) == 0 || !cfg.AllowsContentType(contentType) {
		return body, false, nil
	}
	mt := fileWatermarkMediaType(contentType)
	switch {
	case mt == "application/json":
		return applyJSONFileWatermark(body, cfg.JSONKey, text)
	case OOXMLWatermarkExtension(mt) != "":
		// OOXML 族（W14-GW）：docProps/custom.xml 自定义属性部件注入 + 重打包
		return applyOOXMLFileWatermark(body, text)
	case mt == "text/markdown" || mt == "text/html":
		// HTML 注释行：渲染不可见，不破坏文档结构
		return appendFileWatermarkLine(body, "<!-- "+text+" -->"), true, nil
	default:
		// text/plain、text/csv 及其余白名单文本类型："# " 注释行（各类型取舍见文件头注释）
		return appendFileWatermarkLine(body, "# "+text), true, nil
	}
}

// appendFileWatermarkLine 文件尾追加水印注释行（体不以换行结尾时先补一个换行）。
func appendFileWatermarkLine(body []byte, line string) []byte {
	out := make([]byte, 0, len(body)+len(line)+1)
	out = append(out, body...)
	if !bytes.HasSuffix(body, []byte("\n")) {
		out = append(out, '\n')
	}
	return append(out, line...)
}

// applyJSONFileWatermark JSON 顶层对象加水印字段：顶层非对象或键已存在跳过不改写
// （不覆盖既有数据）；UseNumber 保留数字字面量，SetEscapeHTML(false) 减小字节漂移
// （与 ApplyJSON 同一编码纪律）。尾随数据与解析失败同口径返回错误（重编码只输出
// 第一个值，尾随字节会被静默丢弃；调用方 FAIL_OPEN 直通原响应）。
func applyJSONFileWatermark(body []byte, key, text string) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return body, false, fmt.Errorf("decode download json: %w", err)
	}
	if err := ensureSingleJSONValue(dec); err != nil {
		return body, false, fmt.Errorf("decode download json: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return body, false, nil // 顶层数组/标量：无处加字段，跳过（v1 纪律）
	}
	if _, exists := obj[key]; exists {
		return body, false, nil // 键已存在：不覆盖既有数据
	}
	obj[key] = text
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return body, false, fmt.Errorf("re-encode download json: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true, nil
}
