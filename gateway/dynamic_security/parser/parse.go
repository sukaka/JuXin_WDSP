// Package parser 在 ParseLimits 下一次解析请求（Query/头/JSON 字段），供 Web 与 API 检测共享。
package parser

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
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
	FieldCount     int
	BodySize       int
	BodyHash       string
	BodyTruncated  bool
	FieldCapped    bool
	IsJSON         bool
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
		if !p.BodyTruncated && (strings.Contains(ct, "application/json") || looksLikeJSON(raw)) {
			p.IsJSON = true
			extractJSONFields(raw, "", p, limits)
		} else if p.BodyTruncated && (strings.Contains(ct, "application/json") || looksLikeJSON(raw)) {
			p.IsJSON = true
			// truncated: skip full field walk to avoid partial schema pollution
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
