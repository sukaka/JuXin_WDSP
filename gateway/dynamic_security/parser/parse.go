// Package parser 在 ParseLimits 下一次解析请求（Query/头/JSON/表单/XML/multipart/GraphQL），供 Web 与 API 检测共享。
package parser

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// 写入 RequestContext.Extensions 的扩展键（键集合固定，禁止无界动态膨胀；值均已脱敏）。
const (
	ExtFormFields           = "req.form_fields"
	ExtXMLFields            = "req.xml_fields"
	ExtMultipartParts       = "req.multipart_parts"
	ExtHasFiles             = "req.has_files"
	ExtGraphQLOperation     = "req.graphql_operation"
	ExtGraphQLOperationName = "req.graphql_operation_name"
	ExtGraphQLVariables     = "req.graphql_variables"
	ExtMultipartCapped      = "req.multipart_capped"
	ExtXMLTruncated         = "req.xml_truncated"
	ExtXMLDTDBlocked        = "req.xml_dtd_blocked"
)

// Parsed 一次解析结果（不含明文密钥；字段名与粗类型供学习/偏离使用）。
type Parsed struct {
	Method         string
	RawPath        string
	NormalizedPath string
	Query          map[string]string
	Headers        map[string]string // 已脱敏（authorization/cookie 仅标记存在）
	ContentType    string
	JSONFields     map[string]string // path -> type: string|number|bool|object|array|null
	FormFields     map[string]string // urlencoded 表单字段名 -> type: string|number|bool
	XMLFields      map[string]string // XML 元素路径 -> 叶子类型: string|number|bool
	MultipartParts []PartMeta        // multipart part 元数据（按出现顺序；文件内容不落内存）
	HasFiles       bool              // multipart 中含文件 part
	// GraphQL 识别（application/graphql 原始查询，或 /graphql 路径 + JSON body 含 query 字段）
	GraphQLOperation     string   // query|mutation|subscription|unknown
	GraphQLOperationName string   // operationName（缺省时从查询文本推断）
	GraphQLVariables     []string // variables 顶层键名（排序，不存值）
	FieldCount           int
	BodySize             int
	BodyHash             string
	BodyTruncated        bool
	FieldCapped          bool
	MultipartCapped      bool // part 元数据数超 MaxFileMetaCount，已截断
	XMLTruncated         bool // 元素嵌套超 MaxXMLDepth，已停止解析
	XMLDTDBlocked        bool // 遇 DOCTYPE 拒绝解析（XXE 防御：禁止 DTD/实体展开）
	IsJSON               bool
}

// ParseRequest 解析 HTTP 请求并填充 RequestContext 的请求侧字段。
func ParseRequest(r *http.Request, ctx *dsctx.RequestContext) (*Parsed, error) {
	if r == nil {
		return nil, nil
	}
	limits := dsctx.DefaultParseLimits()
	if ctx != nil {
		limits = ctx.Limits
	}
	p := &Parsed{
		Method:         strings.ToUpper(r.Method),
		RawPath:        r.URL.Path,
		NormalizedPath: normalizer.NormalizePath(r.URL.Path),
		Query:          map[string]string{},
		Headers:        map[string]string{},
		JSONFields:     map[string]string{},
		FormFields:     map[string]string{},
		XMLFields:      map[string]string{},
		ContentType:    r.Header.Get("Content-Type"),
	}
	// Query
	for k, vs := range r.URL.Query() {
		if p.FieldCount >= limits.MaxFieldCount {
			p.FieldCapped = true
			break
		}
		if len(vs) > 0 {
			p.Query[k] = vs[0]
			p.FieldCount++
		}
	}
	// Headers (minimize secrets)
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" || lk == "x-api-key" {
			p.Headers[lk] = "[redacted]"
			continue
		}
		if len(vs) > 0 {
			p.Headers[lk] = vs[0]
		}
	}

	// Body
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		mediaType, params := splitMediaType(p.ContentType)
		if mediaType == "multipart/form-data" && params["boundary"] != "" {
			// multipart 流式解析：文件内容不落内存，仅计 part 元数据与大小
			p.parseMultipart(r.Body, params["boundary"], limits)
		} else {
			limit := int64(limits.MaxBodyParseBytes) + 1
			if limit < 2 {
				limit = 2
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, limit))
			if err != nil && err != io.EOF {
				return p, err
			}
			_ = r.Body.Close()
			if len(raw) > limits.MaxBodyParseBytes {
				p.BodyTruncated = true
				sample := limits.MaxBodySampleBytes
				if sample <= 0 {
					sample = limits.MaxBodyParseBytes
				}
				if sample > len(raw) {
					sample = len(raw)
				}
				// keep only sample for type sniffing; do not full-parse oversized bodies
				raw = raw[:sample]
			}
			p.BodySize = len(raw)
			p.BodyHash = shortHash(raw)
			ct := strings.ToLower(p.ContentType)
			isJSONBody := strings.Contains(ct, "application/json") || looksLikeJSON(raw)
			switch {
			case p.BodyTruncated:
				// truncated: skip full field walk to avoid partial schema pollution
				if isJSONBody {
					p.IsJSON = true
				}
			case mediaType == "application/graphql":
				// 原始 GraphQL 查询文档（优先于 JSON 嗅探："{" 开头的查询不是 JSON）
				p.extractGraphQLQuery(string(raw))
			case isJSONBody:
				p.IsJSON = true
				extractJSONFields(raw, "", p, limits)
				p.extractGraphQLJSON(raw)
			case mediaType == "application/x-www-form-urlencoded":
				p.extractFormFields(raw, limits)
			case isXMLMediaType(mediaType):
				p.extractXMLFields(raw, limits)
			}
		}
	}

	if ctx != nil {
		ctx.HTTPMethod = p.Method
		ctx.RawPath = p.RawPath
		ctx.NormalizedPath = p.NormalizedPath
		ctx.RequestContentType = p.ContentType
		ctx.RequestBodySize = int64(p.BodySize)
		ctx.RequestBodyHash = p.BodyHash
		ctx.BodyTruncated = p.BodyTruncated
		ctx.FieldCountCapped = p.FieldCapped
		// 解析产物经 Extensions 写入（键固定，值已脱敏；见 Ext* 常量）
		if len(p.FormFields) > 0 {
			ctx.SetExtension(ExtFormFields, p.FormFields)
		}
		if len(p.XMLFields) > 0 {
			ctx.SetExtension(ExtXMLFields, p.XMLFields)
		}
		if len(p.MultipartParts) > 0 {
			ctx.SetExtension(ExtMultipartParts, p.MultipartParts)
		}
		if p.HasFiles {
			ctx.SetExtension(ExtHasFiles, true)
		}
		if p.GraphQLOperation != "" {
			ctx.SetExtension(ExtGraphQLOperation, p.GraphQLOperation)
		}
		if p.GraphQLOperationName != "" {
			ctx.SetExtension(ExtGraphQLOperationName, p.GraphQLOperationName)
		}
		if len(p.GraphQLVariables) > 0 {
			ctx.SetExtension(ExtGraphQLVariables, p.GraphQLVariables)
		}
		if p.MultipartCapped {
			ctx.SetExtension(ExtMultipartCapped, true)
		}
		if p.XMLTruncated {
			ctx.SetExtension(ExtXMLTruncated, true)
		}
		if p.XMLDTDBlocked {
			ctx.SetExtension(ExtXMLDTDBlocked, true)
		}
		if id := r.Header.Get("X-Request-Id"); id != "" && ctx.RequestID == "" {
			ctx.RequestID = id
		}
		if ctx.RequestID == "" {
			if id := r.Header.Get("X-Jiuzhang-Request-ID"); id != "" {
				ctx.RequestID = id
			}
		}
	}
	return p, nil
}

func looksLikeJSON(b []byte) bool {
	s := strings.TrimSpace(string(b))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func extractJSONFields(raw []byte, prefix string, p *Parsed, limits dsctx.ParseLimits) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	walkJSON(v, prefix, 0, p, limits)
}

func walkJSON(v any, path string, depth int, p *Parsed, limits dsctx.ParseLimits) {
	if depth > limits.MaxJSONDepth {
		return
	}
	if p.FieldCount >= limits.MaxFieldCount {
		p.FieldCapped = true
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if path != "" {
			p.JSONFields[path] = "object"
			p.FieldCount++
		}
		for k, child := range t {
			if p.FieldCount >= limits.MaxFieldCount {
				p.FieldCapped = true
				return
			}
			np := k
			if path != "" {
				np = path + "." + k
			}
			walkJSON(child, np, depth+1, p, limits)
		}
	case []any:
		p.JSONFields[path] = "array"
		p.FieldCount++
		if len(t) > 0 {
			walkJSON(t[0], path+"[]", depth+1, p, limits)
		}
	case string:
		p.JSONFields[path] = "string"
		p.FieldCount++
	case float64:
		p.JSONFields[path] = "number"
		p.FieldCount++
	case bool:
		p.JSONFields[path] = "bool"
		p.FieldCount++
	case nil:
		p.JSONFields[path] = "null"
		p.FieldCount++
	default:
		p.JSONFields[path] = "unknown"
		p.FieldCount++
	}
}

func shortHash(b []byte) string {
	// FNV-1a 64 for lightweight body fingerprint (not crypto)
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return formatHex(h)
}

func formatHex(h uint64) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		buf[i] = hexdigits[h&0xf]
		h >>= 4
	}
	return string(buf)
}

// splitMediaType 拆分 Content-Type 主类型与参数；头部畸形时降级为 ';' 前缀（小写）。
func splitMediaType(ct string) (string, map[string]string) {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])), nil
	}
	return mt, params
}

// isXMLMediaType 匹配 application/xml、text/xml 及 +xml 后缀类型（如 application/soap+xml）。
func isXMLMediaType(mt string) bool {
	return mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml")
}
