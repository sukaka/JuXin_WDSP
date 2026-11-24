// Package classifier API 流量识别（多信号置信度，不单独依赖 /api/ 前缀）。
package classifier

import (
	"math"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 识别结果四级标签（任务书 §8.2）。
const (
	LevelConfirmedAPI = "CONFIRMED_API" // 多路独立强信号（score ≥ 0.75）
	LevelProbableAPI  = "PROBABLE_API"  // 达到既有 IsAPI 判定线（0.35 ≤ score < 0.75）
	LevelPossibleAPI  = "POSSIBLE_API"  // 仅有单路弱信号（0.15 ≤ score < 0.35）
	LevelNonAPI       = "NON_API"       // score < 0.15
)

// 四级标签阈值：probableThreshold 与既有 IsAPI 判定线一致，
// 保证 IsAPI ==（Level 为 CONFIRMED_API 或 PROBABLE_API），旧消费方零变化。
const (
	confirmedThreshold = 0.75
	probableThreshold  = 0.35
	possibleThreshold  = 0.15
)

// Result API 识别结果。
type Result struct {
	IsAPI      bool
	Confidence float64 // 0..1
	Signals    []string
	// Level §8.2 四级识别标签（IsAPI 兼容口径见上方常量注释）。
	Level string
	// Confidence100 §8.2 的 0-100 置信度：由 Confidence（0..1，score 已封顶 1）
	// 四舍五入 ×100 换算，二者同源同分、仅量纲不同。
	Confidence100 int
}

// ResponseEvidence 响应侧可见性证据。nil 或截断/流式响应不参与分类调整。
type ResponseEvidence struct {
	Status             int
	ContentType        string
	ContentDisposition string
	Truncated          bool
	Streamed           bool
}

// Classify 基于请求侧解析结果打分。
func Classify(p *parser.Parsed) Result {
	if p == nil {
		return Result{Level: LevelNonAPI}
	}
	// 静态资源路径快筛：仅读方法且非结构性协议时，图片/脚本/样式/字体/音视频/压缩包等
	// 直接归类为 NON_API（避免路径碰巧含 /v1/ 或带 Accept 头被误判为 API）。
	if !hasStructuralAPISignal(p) && IsStaticAssetPath(p.Method, p.RawPath) {
		return Result{
			IsAPI:         false,
			Confidence:    0,
			Signals:       []string{"static_asset_path"},
			Level:         LevelNonAPI,
			Confidence100: 0,
		}
	}
	var score float64
	var signals []string
	add := func(s string, w float64) {
		signals = append(signals, s)
		score += w
	}
	ct := strings.ToLower(p.ContentType)
	if strings.Contains(ct, "application/json") || p.IsJSON {
		add("content_type_json", 0.35)
	}
	if strings.Contains(ct, "application/xml") || strings.Contains(ct, "soap") {
		add("content_type_xml", 0.25)
	}
	path := strings.ToLower(p.RawPath)
	if strings.Contains(path, "/graphql") {
		add("graphql_path", 0.4)
	}
	// /api/ is a signal but not sole rule
	if strings.HasPrefix(path, "/api/") || strings.Contains(path, "/api/") {
		add("api_prefix", 0.15)
	}
	// versioned REST
	if strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") {
		add("versioned_path", 0.2)
	}
	// JSON body fields strongly suggest API
	if len(p.JSONFields) > 0 {
		add("json_fields", 0.25)
	}
	// Accept header
	if acc, ok := p.Headers["accept"]; ok && strings.Contains(strings.ToLower(acc), "application/json") {
		add("accept_json", 0.15)
	}
	// API 认证头（Authorization / X-API-Key；不同于浏览器自动携带的 Cookie，不单独过 0.35 线，
	// 配合 /api/ 或 /v1/ 等弱信号可可靠识别 204/无体 REST 接口）
	if p.Headers["authorization"] != "" || p.Headers["x-api-key"] != "" {
		add("auth_header", 0.20)
	}
	// method write with JSON
	if (p.Method == "POST" || p.Method == "PUT" || p.Method == "PATCH") && p.IsJSON {
		add("write_json", 0.1)
	}
	if score > 1 {
		score = 1
	}
	return Result{
		IsAPI:         score >= probableThreshold,
		Confidence:    score,
		Signals:       signals,
		Level:         classificationLevel(score),
		Confidence100: int(math.Round(score * 100)),
	}
}

// ClassifyWithResponse 在请求侧评分基础上纳入完整可见响应证据。响应缺失、
// 截断或流式直通不代表非 API，保持请求侧结论；静态 MIME 与成功 HTML 压低非结构性流量；
// 成功 JSON/XML/SSE 或动态路径附件下载提升 API 置信度（避免 404/5xx JSON 错误页洗白噪声路径）。
func ClassifyWithResponse(p *parser.Parsed, resp *ResponseEvidence) Result {
	result := Classify(p)
	if p == nil || resp == nil || resp.Truncated || resp.Streamed {
		return result
	}
	structural := hasStructuralAPISignal(p)
	staticPath := !structural && IsStaticAssetPath(p.Method, p.RawPath)
	if staticPath {
		return Result{
			IsAPI:         false,
			Confidence:    0,
			Signals:       []string{"static_asset_path"},
			Level:         LevelNonAPI,
			Confidence100: 0,
		}
	}
	successStatus := resp.Status == 0 || (resp.Status >= 200 && resp.Status < 400)
	dynamicAttachment := successStatus && hasAttachmentDisposition(resp.ContentDisposition)
	if !structural && !dynamicAttachment && IsStaticResponseContentType(resp.ContentType) {
		signals := append([]string(nil), result.Signals...)
		signals = append(signals, "response_static_mime")
		return Result{
			IsAPI:         false,
			Confidence:    0,
			Signals:       signals,
			Level:         LevelNonAPI,
			Confidence100: 0,
		}
	}

	score := result.Confidence
	signals := append([]string(nil), result.Signals...)
	add := func(s string, w float64) {
		signals = append(signals, s)
		score += w
	}
	if successStatus {
		if IsJSONResponseContentType(resp.ContentType) {
			add("response_json", 0.35)
		} else if IsXMLAPIResponseContentType(resp.ContentType) {
			add("response_xml", 0.25)
		} else if IsEventStreamResponseContentType(resp.ContentType) {
			add("response_sse", 0.35)
		} else if dynamicAttachment {
			add("response_attachment", 0.35)
		}
	}
	if resp.Status >= 200 && resp.Status < 300 && IsHTMLResponseContentType(resp.ContentType) && !structural {
		add("response_html", -0.35)
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return Result{
		IsAPI:         score >= probableThreshold,
		Confidence:    score,
		Signals:       signals,
		Level:         classificationLevel(score),
		Confidence100: int(math.Round(score * 100)),
	}
}

func hasAttachmentDisposition(cd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cd))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "attachment") &&
		(strings.Contains(lower, "filename=") || strings.Contains(lower, "filename*="))
}

func hasStructuralAPISignal(p *parser.Parsed) bool {
	ct := strings.ToLower(p.ContentType)
	path := strings.ToLower(p.RawPath)
	return strings.Contains(path, "/graphql") || strings.Contains(ct, "soap") ||
		strings.Contains(ct, "xml") || strings.Contains(ct, "grpc")
}

// classificationLevel score → §8.2 四级标签。
func classificationLevel(score float64) string {
	switch {
	case score >= confirmedThreshold:
		return LevelConfirmedAPI
	case score >= probableThreshold:
		return LevelProbableAPI
	case score >= possibleThreshold:
		return LevelPossibleAPI
	default:
		return LevelNonAPI
	}
}
