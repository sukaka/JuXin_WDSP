// API 流量响应捕获与脱敏改写支撑（WDSP / 阶段8 响应侧）。
//
// 设计约束：
//   - 仅 API 流量包装捕获（api_dynamic_protection 开启且判为 API）；非 API 流量零包装零开销；
//   - 可安全重编码的响应（JSON 族或缺省 Content-Type、identity/gzip/br 编码、非升级/非 SSE）缓冲完整响应，
//     待响应相位与脱敏执行后一次性写回（含 Content-Length 修正）；配置 response_body 规则时，
//     完整 XML/text/plain 同样缓冲供值级检测，检测只观测不改写；
//   - 文件水印/签名启用时，候选文本族 + 携带 Content-Disposition 的下载响应同样进入缓冲；
//     include_inline_html=true 时仅额外缓冲 2xx、无下载头的 text/html 响应，其他网页仍直通
//     （水印/签名需完整体重写；SSE 永不缓冲；候选超限/编码不可处理一律 FAIL_OPEN 直通 + Warn）；
//   - 文件合规下载方向规则存在时，携带 Content-Disposition 的下载响应进入缓冲
//     （合规评估与 PROTECT 阻断抑制的前提——已直通外发的响应无法撤回；同样 FAIL_OPEN 直通 + Warn）；
//   - 流式/WebSocket/未启用值级检测的显式非 JSON 类型直通不缓冲（避免长连接挂死与内存失控）；
//     SSE 不整流缓冲，由通用 response_body writer 按单事件检测，MCP 活跃时仍由专用 writer 独占；
//   - 缓冲超 api_response_capture_max_bytes：
//     FAIL_OPEN（默认）→ 转直通溢出（spill），已缓冲字节连同后续完整外发，原响应不截断，zap Warn；
//     FAIL_CLOSED 且端点有命中规则 → 丢弃字节（discarded），最终以 500 空明细响应抑制
//     （原始响应一字节不外发，防未脱敏数据泄露）；
//   - gzip/br 原压缩字节保留在捕获器中；完整缓冲后有界解码供检测与改写，未改写逐字节交付原体，
//     改写后按原编码重压缩。非法或解压超限时 FAIL_OPEN 原压缩字节直通 + Warn，
//     FAIL_CLOSED 且端点有规则则抑制；多重/未知编码仍按不可处理响应处理；
//   - 缓冲模式声明 Trailer（公告头或 TrailerPrefix 键）的响应不强制 Content-Length：
//     net/http 仅在分块编码下外发 Trailer，强制长度会让 Trailer 值静默丢失而公告头照发
//     （语义漂移）；写回侧移除 Content-Length 改由分块编码保留 Trailer 语义（见 writeBufferedResponse）；
//   - 任何失败不得 panic、不得静默（Warn 必带 endpoint_key 与 request_id）。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"go.uber.org/zap"
)

// 响应捕获上限默认值与硬上限（防内存误配）。
const (
	defaultAPIResponseCaptureMaxBytes = 1 << 20  // 1 MiB（api_response_capture_max_bytes 缺省值）
	maxAPIResponseCaptureMaxBytes     = 16 << 20 // 16 MiB 配置硬上限
)

// gRPC 帧校验配置硬上限（W14-GW / P2-05；防内存误配）。
const maxAPIGRPCMaxFrameBytes = 64 << 20 // 64 MiB

// 响应侧处理失败策略（api_response_fail_policy）。
const (
	apiFailOpen   = "FAIL_OPEN"
	apiFailClosed = "FAIL_CLOSED"
)

// 捕获模式。
const (
	captureUndecided   = iota
	captureBuffered    // 缓冲（可安全重编码），完成后一次性写回
	capturePassthrough // 直通（流式/非 JSON/不支持编码 FAIL_OPEN）
	captureDiscarded   // FAIL_CLOSED 抑制：字节丢弃，最终 500 空明细响应
)

// apiResponseCapture API 流量响应捕获 writer（并发模型与请求处理一致：单请求单 goroutine 顺序写）。
type apiResponseCapture struct {
	base         http.ResponseWriter
	maxBytes     int
	failClosed   bool
	hasMaskRules bool
	// downloadTypes 下载改写候选 Content-Type 判定（水印白名单或签名文本族能力，挂点侧合并注入；
	// nil = 无下载改写能力启用，捕获行为与历史版本一致）
	downloadTypes     func(string) bool
	downloadCandidate bool // decide 判定：本响应为水印/签名候选文本族下载（缓冲依据之一）
	// downloadHold 文件合规下载方向规则存在：携带 Content-Disposition 的下载响应进入缓冲
	// （W13-GW / P2-03：合规评估与 PROTECT 阻断抑制的前提——已直通外发的响应无法撤回）
	downloadHold       bool
	inlineHTML         bool // 显式启用的内联 HTML 水印候选（仅 2xx + text/html + 无下载头）
	responseBodyValues bool // response_body 值级规则启用时允许完整 XML/text/plain 缓冲
	logger             *zap.Logger
	endpointKey        string
	requestID          string

	status          int
	mode            int
	contentEncoding string
	body            bytes.Buffer // 源站原始体（spill 后保留前缀供错误签名扫描）
	spilled         bool         // 缓冲超限已转直通（原响应完整外发）
	bytesStreamed   int64        // 直通/溢出已外发字节数
	hijacked        bool
	warnedSkip      bool // 跳过原因 Warn 已发（每次请求最多一条）
}

func newAPIResponseCapture(w http.ResponseWriter, maxBytes int, failClosed, hasMaskRules bool, downloadTypes func(string) bool, downloadHold bool, endpointKey, requestID string, logger *zap.Logger) *apiResponseCapture {
	if maxBytes <= 0 {
		maxBytes = defaultAPIResponseCaptureMaxBytes
	}
	return &apiResponseCapture{
		base: w, maxBytes: maxBytes, failClosed: failClosed, hasMaskRules: hasMaskRules,
		downloadTypes: downloadTypes, downloadHold: downloadHold,
		endpointKey: endpointKey, requestID: requestID, logger: logger,
	}
}

// Header 透传底层头表（处理器写头直接落底层，保证缓冲模式扣留状态行期间头仍生效）。
func (c *apiResponseCapture) Header() http.Header { return c.base.Header() }

// WriteHeader 捕获状态码并按响应头决定捕获模式（直通模式立即透传，缓冲/抑制模式扣留状态行）。
func (c *apiResponseCapture) WriteHeader(code int) {
	// Informational responses are provisional and may be followed by the final
	// response status. Forward each one before a final status is captured.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if c.status == 0 {
			c.base.WriteHeader(code)
		}
		return
	}
	if c.status != 0 {
		return // 与 net/http 一致：忽略重复 WriteHeader
	}
	c.status = code
	c.decide()
	if c.mode == capturePassthrough {
		c.base.WriteHeader(code)
	}
}

// decide 在首个 WriteHeader 时按头判定捕获模式。
func (c *apiResponseCapture) decide() {
	h := c.base.Header()
	if c.status == http.StatusSwitchingProtocols || h.Get("Upgrade") != "" {
		c.mode = capturePassthrough // WebSocket 升级：不缓冲
		return
	}
	// 文件下载候选（W12-GW 水印 / W13-GW 签名与合规）：携带 Content-Disposition（下载语义）+
	// 非 SSE——水印/签名候选按 Content-Type 判定（改写需完整体），合规挂留不限类型
	// （评估只需头元数据，但 PROTECT 阻断抑制要求字节未外发）；SSE 长连接永不缓冲（防挂死）
	isDownload := h.Get("Content-Disposition") != "" &&
		!strings.Contains(strings.ToLower(h.Get("Content-Type")), "text/event-stream")
	c.downloadCandidate = isDownload && c.downloadTypes != nil && c.downloadTypes(h.Get("Content-Type"))
	complianceHold := isDownload && c.downloadHold
	c.inlineHTML = c.inlineHTML && c.status >= 200 && c.status <= 299 &&
		h.Get("Content-Disposition") == "" && response.IsHTMLMediaType(h.Get("Content-Type"))
	encoding, supported := apiResponseContentEncoding(h)
	if !supported {
		if c.failClosed && c.hasMaskRules {
			c.mode = captureDiscarded
			c.warnSkip("unsupported content-encoding, response suppressed by fail-closed policy")
		} else {
			if c.hasMaskRules {
				c.warnSkip("unsupported content-encoding, mask transform skipped (fail-open)")
			} else if c.downloadCandidate {
				c.warnSkip("unsupported content-encoding, file download rewrite skipped (fail-open)")
			} else if c.inlineHTML {
				c.warnSkip("unsupported content-encoding, inline html watermark skipped (fail-open)")
			} else if complianceHold {
				c.warnSkip("unsupported content-encoding, file compliance download check degraded (fail-open)")
			}
			c.mode = capturePassthrough
		}
		return
	}
	c.contentEncoding = encoding
	ct := h.Get("Content-Type")
	if ct == "" || response.IsJSONMediaType(ct) {
		c.mode = captureBuffered // JSON 族或缺省类型：缓冲（缺省类型在响应相位嗅探后决定是否解析）
		return
	}
	if c.responseBodyValues && responseBodyValueMediaType(ct) {
		c.mode = captureBuffered // 配置 response_body 规则的完整 XML/text/plain：缓冲供值级检测
		return
	}
	if c.downloadCandidate || c.inlineHTML || complianceHold {
		c.mode = captureBuffered // 下载候选（水印/签名改写或合规评估/抑制）：缓冲（需完整体或字节未外发）
		return
	}
	c.mode = capturePassthrough // 显式非 JSON（含 SSE text/event-stream）：直通
}

func responseBodyValueMediaType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if mediaType == "text/plain" {
		return true
	}
	return mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml")
}

// Write 捕获响应体；缓冲模式在上限内累积，超限按失败策略转溢出直通或抑制。
func (c *apiResponseCapture) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.WriteHeader(http.StatusOK)
	}
	switch c.mode {
	case capturePassthrough:
		n, err := c.base.Write(p)
		c.bytesStreamed += int64(n)
		return n, err
	case captureDiscarded:
		return len(p), nil // 丢弃但向处理器报告成功（最终统一 500 抑制）
	default: // captureBuffered
		if c.body.Len()+len(p) <= c.maxBytes {
			c.body.Write(p)
			return len(p), nil
		}
		if c.failClosed && c.hasMaskRules {
			// 超限且不可放行未检查响应：转抑制（已缓冲字节一并丢弃，未外发一字节）
			c.mode = captureDiscarded
			c.body.Reset()
			c.warnSkip("response body exceeds capture limit, suppressed by fail-closed policy")
			return len(p), nil
		}
		// FAIL_OPEN 溢出：转直通，已缓冲前缀 + 当前块完整外发（原响应不截断）
		c.mode = capturePassthrough
		c.spilled = true
		c.base.WriteHeader(c.status)
		warnSpill := func() {
			if c.hasMaskRules {
				c.warnSkip("response body exceeds capture limit, mask transform skipped (fail-open)")
			} else if c.downloadCandidate {
				c.warnSkip("response body exceeds capture limit, file download rewrite skipped (fail-open)")
			} else if c.inlineHTML {
				c.warnSkip("response body exceeds capture limit, inline html watermark skipped (fail-open)")
			} else if c.downloadHold {
				// 合规下载挂留超限：已缓冲前缀连同后续字节直通外发，PROTECT 阻断无法执行——
				// 诚实降级（不静默），挂点侧据终态补记 file.download_block_unavailable
				c.warnSkip("response body exceeds capture limit, file compliance download check degraded (fail-open)")
			}
		}
		n1, err1 := c.base.Write(c.body.Bytes())
		c.bytesStreamed += int64(n1)
		if err1 != nil {
			warnSpill()
			return 0, err1
		}
		n2, err2 := c.base.Write(p)
		c.bytesStreamed += int64(n2)
		warnSpill()
		if err2 != nil {
			return n2, err2
		}
		return len(p), nil
	}
}

// Flush 透传底层 Flusher；缓冲未溢出的响应扣留 Flush（完成后一次性写回，防提前提交状态行）。
func (c *apiResponseCapture) Flush() {
	if c.hijacked {
		return
	}
	if c.status == 0 {
		c.WriteHeader(http.StatusOK)
	}
	if c.mode == captureBuffered && !c.spilled {
		return
	}
	if f, ok := c.base.(http.Flusher); ok {
		f.Flush()
		return
	}
	_ = http.NewResponseController(c.base).Flush()
}

// Unwrap 返回底层 writer（http.ResponseController 依赖）。
func (c *apiResponseCapture) Unwrap() http.ResponseWriter { return c.base }

// Hijack 透传连接劫持（WebSocket 升级需要；支持底层直接 Hijacker 与 Unwrap 链）。
// 劫持后响应脱离捕获：存在命中规则时只能 fail-open 并 Warn（无法向已劫持连接注入封闭响应）。
func (c *apiResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	var (
		conn net.Conn
		rw   *bufio.ReadWriter
		err  error
	)
	if h, ok := c.base.(http.Hijacker); ok {
		conn, rw, err = h.Hijack()
	} else {
		conn, rw, err = http.NewResponseController(c.base).Hijack()
	}
	if err == nil {
		c.hijacked = true
		if c.hasMaskRules {
			c.warnSkip("connection hijacked, mask transform unavailable (fail-open)")
		}
	}
	return conn, rw, err
}

// warnSkip 跳过/抑制原因告警（每请求一次，必带端点与请求 ID）。
func (c *apiResponseCapture) warnSkip(msg string) {
	if c.warnedSkip || c.logger == nil {
		return
	}
	c.warnedSkip = true
	c.logger.Warn("api response capture: "+msg,
		zap.String("endpoint_key", c.endpointKey),
		zap.String("request_id", c.requestID))
}

// 捕获终态（下游处理器返回后由挂点读取）。
const (
	outcomeBuffered  = iota // 完整缓冲，未外发（可执行响应相位与脱敏后写回）
	outcomeStreamed         // 已直通外发（含溢出 spill），仅状态/头/大小可用
	outcomeDiscarded        // FAIL_CLOSED 抑制，未外发（挂点写 500 空明细响应）
	outcomeHijacked         // 连接被劫持，脱离捕获
)

// outcome 返回捕获终态；status 归一（处理器未显式写状态码视为 200）。
func (c *apiResponseCapture) outcome() (status int, kind int) {
	status = c.status
	if status == 0 {
		status = http.StatusOK
	}
	switch {
	case c.hijacked:
		return status, outcomeHijacked
	case c.mode == captureDiscarded:
		return status, outcomeDiscarded
	case c.mode == captureBuffered && !c.spilled:
		return status, outcomeBuffered
	default:
		return status, outcomeStreamed
	}
}

// redactResponseHeaders 响应头快照（脱敏：set-cookie 等仅标记存在；值截断 256，头数封顶 64）。
func redactResponseHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	n := 0
	for k, vs := range h {
		if n >= 64 {
			break
		}
		lk := strings.ToLower(k)
		switch lk {
		case "set-cookie", "www-authenticate", "proxy-authenticate":
			out[lk] = "[redacted]"
		default:
			if len(vs) > 0 {
				v := vs[0]
				if len(v) > 256 {
					v = v[:256]
				}
				out[lk] = v
			}
		}
		n++
	}
	return out
}

// responseFailClosed 响应侧失败策略是否为 FAIL_CLOSED（缺省 FAIL_OPEN）。
func (g *Guard) responseFailClosed() bool {
	return g.APIResponseFailPolicy == apiFailClosed
}

// resolvedResponseFailPolicy 生效的失败策略（日志用；缺省 FAIL_OPEN）。
func (g *Guard) resolvedResponseFailPolicy() string {
	if g.APIResponseFailPolicy == "" {
		return apiFailOpen
	}
	return g.APIResponseFailPolicy
}

// responseCaptureMax 响应捕获上限（0/未配置用默认值兜底）。
func (g *Guard) responseCaptureMax() int {
	if g.APIResponseCaptureMaxBytes > 0 {
		return g.APIResponseCaptureMaxBytes
	}
	return defaultAPIResponseCaptureMaxBytes
}

// compileAPIMaskRules 编译 api_mask_rules：逐条校验并按 endpoint_key 归组（配置错误显式返回，不静默）。
func compileAPIMaskRules(in []maskRuleJSON) (map[string][]response.MaskRule, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > response.MaxRules {
		return nil, fmt.Errorf("api_mask_rules: too many rules (%d > %d)", len(in), response.MaxRules)
	}
	out := make(map[string][]response.MaskRule, len(in))
	for i, r := range in {
		rule, err := response.ParseMaskRule(r.EndpointKey, r.FieldPath, r.DataType, r.Algorithm, r.Params)
		if err != nil {
			return nil, fmt.Errorf("api_mask_rules[%d]: %w", i, err)
		}
		out[rule.EndpointKey] = append(out[rule.EndpointKey], rule)
	}
	return out, nil
}
