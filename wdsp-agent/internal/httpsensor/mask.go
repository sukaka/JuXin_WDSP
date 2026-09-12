// 脱敏（Phase 3 契约 §5：离主机前 Agent 侧强制执行）。
//
// 无旁路证明：所有 HTTP 记录唯一构造出口为 conn.emit → buildMessage，
// headers/URI query/表单 Body/JSON Body/multipart 字段全部经本包函数脱敏后
// 才写入 events.HTTPRecord；transport/agent 发送路径不接触未脱敏数据。
package httpsensor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// maskValue 脱敏占位值（契约 §5）。
const maskValue = "********"

// maskHeaders 对 Header map 就地应用脱敏规则（大小写不敏感；headers 已为小写键）。
// NONE=不动 | MASK=替换 | HASH=sha256:<hex 前16位> | DROP=整行删除。
// 返回实际脱敏的字段数（masked 指标，P1-03 §5.7）。
func maskHeaders(headers map[string]string, rule config.MaskRule) int {
	if rule.Mode == config.MaskModeNone || len(rule.Names) == 0 {
		return 0
	}
	names := lowerSet(rule.Names)
	masked := 0
	for k, v := range headers {
		if _, hit := names[k]; !hit {
			continue
		}
		masked++
		switch rule.Mode {
		case config.MaskModeDrop:
			delete(headers, k)
		case config.MaskModeHash:
			headers[k] = hashValue(v)
		default: // MASK
			headers[k] = maskValue
		}
	}
	return masked
}

// maskQueryString 对 query/form 字符串（k=v&k=v）按参数名脱敏（大小写不敏感）。
// 保持原有分隔与顺序；DROP 删除该段。返回脱敏后字符串与实际脱敏的参数数。
func maskQueryString(qs string, rule config.MaskRule) (string, int) {
	if rule.Mode == config.MaskModeNone || qs == "" || len(rule.Names) == 0 {
		return qs, 0
	}
	names := lowerSet(rule.Names)
	segs := strings.Split(qs, "&")
	out := segs[:0]
	masked := 0
	for _, seg := range segs {
		k := seg
		v := ""
		if i := strings.IndexByte(seg, '='); i >= 0 {
			k, v = seg[:i], seg[i+1:]
		}
		if _, hit := names[strings.ToLower(k)]; !hit {
			out = append(out, seg)
			continue
		}
		masked++
		switch rule.Mode {
		case config.MaskModeDrop:
			continue // 段删除
		case config.MaskModeHash:
			out = append(out, k+"="+hashValue(v))
		default: // MASK
			out = append(out, k+"="+maskValue)
		}
	}
	return strings.Join(out, "&"), masked
}

// maskURI 对请求 URI 的 query 部分脱敏（路径不动）。返回脱敏后 URI 与脱敏参数数。
func maskURI(uri string, rule config.MaskRule) (string, int) {
	i := strings.IndexByte(uri, '?')
	if i < 0 {
		return uri, 0
	}
	qs, n := maskQueryString(uri[i+1:], rule)
	return uri[:i+1] + qs, n
}

// maskBodyParams 对 Body 按内容类型做一级参数脱敏（契约 §5）：
//   - application/x-www-form-urlencoded → 同 query 规则；
//   - application/json → 一级字段（嵌套不递归，Phase 3 限制）；
//   - 其他类型不动。
func maskBodyParams(body, mediaType string, rule config.MaskRule) (string, int) {
	if rule.Mode == config.MaskModeNone || body == "" || len(rule.Names) == 0 {
		return body, 0
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return maskQueryString(body, rule)
	case "application/json":
		return maskJSONFirstLevel(body, rule)
	}
	return body, 0
}

// maskJSONFirstLevel JSON 对象一级字段脱敏；非合法 JSON 对象原样返回。
// 返回脱敏后字符串与实际脱敏的字段数。
func maskJSONFirstLevel(body string, rule config.MaskRule) (string, int) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil || obj == nil {
		return body, 0
	}
	names := lowerSet(rule.Names)
	masked := 0
	for k, v := range obj {
		if _, hit := names[strings.ToLower(k)]; !hit {
			continue
		}
		masked++
		switch rule.Mode {
		case config.MaskModeDrop:
			delete(obj, k)
		case config.MaskModeHash:
			obj[k] = hashValue(jsonValueString(v))
		default: // MASK
			obj[k] = maskValue
		}
	}
	if masked == 0 {
		return body, 0
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body, 0
	}
	return string(out), masked
}

// maskParamValue 单个参数值按名脱敏（multipart 字段用）。masked=true 表示命中规则。
func maskParamValue(name, value string, rule config.MaskRule) (string, bool) {
	if rule.Mode == config.MaskModeNone || len(rule.Names) == 0 {
		return value, false
	}
	if _, hit := lowerSet(rule.Names)[strings.ToLower(name)]; !hit {
		return value, false
	}
	switch rule.Mode {
	case config.MaskModeDrop:
		return "", true
	case config.MaskModeHash:
		return hashValue(value), true
	default:
		return maskValue, true
	}
}

// hashValue HASH 模式：sha256:<hex 前16位>（契约 §5）。
func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// jsonValueString JSON 值转字符串（HASH 输入）：字符串原样，其余按 JSON 序列化。
func jsonValueString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// lowerSet 名字集合转小写 set（匹配大小写不敏感，契约 §5）。
func lowerSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}
