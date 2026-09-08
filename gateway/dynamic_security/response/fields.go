package response

import (
	"bytes"
	"encoding/json"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// IsJSONMediaType 判定 Content-Type 是否 JSON 族（application/json 及 +json 后缀）。
func IsJSONMediaType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// IsJSONContentType 判定响应体是否按 JSON 处理：
// JSON 族 Content-Type 直接认定；Content-Type 缺失时按首非空白字符嗅探（{ 或 [）；
// 其余显式非 JSON 类型不解析（跳过）。
func IsJSONContentType(ct string, body []byte) bool {
	if IsJSONMediaType(ct) {
		return true
	}
	if strings.TrimSpace(ct) == "" {
		trimmed := bytes.TrimSpace(body)
		return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
	}
	return false
}

// ParseJSON 在解析上限内一次解码响应 JSON 并提取字段路径 → 类型
// （string|number|bool|object|array|null；路径约定与 WalkJSONFields 一致）。
// 同时返回解码根值供调用方复用做窄提取（任务书原则 2.1：同一响应体不得重复解析——
// 如响应相位 LLM 观测补全直接消费根值）；isJSON=false 表示解析失败（调用方按非 JSON 跳过）。
func ParseJSON(body []byte, limits dsctx.ParseLimits) (map[string]string, any, bool) {
	if limits.MaxJSONDepth <= 0 {
		limits = dsctx.DefaultParseLimits()
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // 保留数字字面量，避免 float64 精度与记数法漂移
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, false
	}
	fields := make(map[string]string, 16)
	count := 0
	walkJSONFields(v, "", 0, fields, &count, limits)
	return fields, v, true
}

// WalkJSONFields 在解析上限内提取响应 JSON 字段路径 → 类型（string|number|bool|object|array|null）。
// 路径约定与请求侧 parser 一致：数组元素路径以 "[]" 结尾且仅下钻首个元素
// （路径集合天然有界，脱敏执行由 Transformer 遍历全部元素）。
// 返回 isJSON=false 表示解析失败（调用方按非 JSON 跳过）。
// 仅需字段表时使用本封装；还需复用解码根值（免二次解析）时改用 ParseJSON。
func WalkJSONFields(body []byte, limits dsctx.ParseLimits) (map[string]string, bool) {
	fields, _, ok := ParseJSON(body, limits)
	return fields, ok
}

func walkJSONFields(v any, path string, depth int, fields map[string]string, count *int, limits dsctx.ParseLimits) {
	if depth > limits.MaxJSONDepth || *count >= limits.MaxFieldCount {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if path != "" {
			fields[path] = "object"
			*count++
		}
		for k, child := range t {
			if *count >= limits.MaxFieldCount {
				return
			}
			np := k
			if path != "" {
				np = path + "." + k
			}
			walkJSONFields(child, np, depth+1, fields, count, limits)
		}
	case []any:
		fields[path] = "array"
		*count++
		if len(t) > 0 {
			walkJSONFields(t[0], path+"[]", depth+1, fields, count, limits)
		}
	case string:
		fields[path] = "string"
		*count++
	case json.Number:
		fields[path] = "number"
		*count++
	case bool:
		fields[path] = "bool"
		*count++
	case nil:
		fields[path] = "null"
		*count++
	default:
		fields[path] = "unknown"
		*count++
	}
}
