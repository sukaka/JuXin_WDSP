// spec_har.go HAR 1.1 / 1.2（.har / .json）规范导入解析。
// 从 log.entries[].request 提取去重后的端点及参数结构（QUERY / HEADER / BODY）；
// 安全底线：落库前严格剥离所有请求值、Cookie、Authorization 凭据值与完整响应体，
// 仅保留脱敏后的端点与参数名/类型骨架，绝不把抓包凭据或业务 PII 写入 spec_json。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// harNoiseHeaders 浏览器/传输层通用头（不作为业务 API 参数提取；值本身绝不留存）。
var harNoiseHeaders = map[string]bool{
	"host": true, "connection": true, "keep-alive": true,
	"content-length": true, "content-type": true,
	"accept": true, "accept-encoding": true, "accept-language": true,
	"user-agent": true, "origin": true, "referer": true,
	"cache-control": true, "pragma": true, "cookie": true,
	"dnt": true, "upgrade-insecure-requests": true,
	"priority": true, "te": true, "if-none-match": true, "if-modified-since": true,
}

// ParseHAR 解析 HAR 1.1 / 1.2 文档，返回脱敏后的规范化文档与去重排序的操作清单。
func ParseHAR(doc map[string]any) (map[string]any, []SpecOperation, error) {
	logObj, ok := doc["log"].(map[string]any)
	if !ok || logObj == nil {
		return nil, nil, fmt.Errorf("%w: 缺少 log 对象", ErrSpecInvalidHAR)
	}
	entries, ok := logObj["entries"].([]any)
	if !ok || len(entries) == 0 {
		return nil, nil, fmt.Errorf("%w: log.entries 为空", ErrSpecInvalidHAR)
	}

	ops := make([]SpecOperation, 0, len(entries))
	for _, entryRaw := range entries {
		entry, ok := entryRaw.(map[string]any)
		if !ok {
			continue
		}
		req, ok := entry["request"].(map[string]any)
		if !ok {
			continue
		}
		method, _ := req["method"].(string)
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" || len(method) > 16 {
			continue
		}
		rawURL, _ := req["url"].(string)
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil {
			continue
		}
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}

		params := []SpecParam{}
		// 1. queryString 数组 + URL 查询串（仅取参数名，丢弃参数值）
		if qs, ok := req["queryString"].([]any); ok {
			for _, qRaw := range qs {
				if qm, ok := qRaw.(map[string]any); ok {
					if name, _ := qm["name"].(string); strings.TrimSpace(name) != "" {
						params = append(params, SpecParam{Name: strings.TrimSpace(name), In: "QUERY", Type: "string"})
					}
				}
			}
		}
		for qName := range u.Query() {
			if strings.TrimSpace(qName) != "" {
				params = append(params, SpecParam{Name: strings.TrimSpace(qName), In: "QUERY", Type: "string"})
			}
		}

		// 2. headers（跳过 HTTP/2 伪头与浏览器传输噪声头，仅取头名，丢弃值）
		if headers, ok := req["headers"].([]any); ok {
			for _, hRaw := range headers {
				hm, ok := hRaw.(map[string]any)
				if !ok {
					continue
				}
				name, _ := hm["name"].(string)
				name = strings.TrimSpace(name)
				lower := strings.ToLower(name)
				if name == "" || strings.HasPrefix(name, ":") || harNoiseHeaders[lower] || strings.HasPrefix(lower, "sec-") {
					continue
				}
				params = append(params, SpecParam{Name: name, In: "HEADER", Type: "string"})
			}
		}

		// 3. postData（仅提取字段名与推断类型，绝不留存字段值或原始文本）
		if pd, ok := req["postData"].(map[string]any); ok {
			if pdParams, ok := pd["params"].([]any); ok {
				for _, ppRaw := range pdParams {
					if ppm, ok := ppRaw.(map[string]any); ok {
						if name, _ := ppm["name"].(string); strings.TrimSpace(name) != "" {
							params = append(params, SpecParam{Name: strings.TrimSpace(name), In: "BODY", Type: "string"})
						}
					}
				}
			}
			if text, _ := pd["text"].(string); strings.TrimSpace(text) != "" {
				var obj map[string]any
				if err := json.Unmarshal([]byte(text), &obj); err == nil && obj != nil {
					for k, v := range obj {
						params = append(params, SpecParam{Name: k, In: "BODY", Type: jsonValueType(v)})
					}
				}
			}
		}

		ops = append(ops, SpecOperation{
			Method: method,
			Path:   p,
			Key:    method + " " + p,
			Params: params,
		})
	}

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, nil, fmt.Errorf("%w: 未在 log.entries 中找到有效的 HTTP 请求", ErrSpecInvalidHAR)
	}

	title := extractHARTitle(logObj)
	// 落库仅保留脱敏后的操作骨架，剥离原始请求值/凭据/响应体
	normalized := map[string]any{
		"x-wdsp-spec-format": SpecFormatHAR,
		"har_version":        stringOrEmpty(logObj["version"]),
		"operations":         ops,
	}
	if title != "" {
		normalized["info"] = map[string]any{"title": title}
	}
	return normalized, ops, nil
}

func extractHARTitle(logObj map[string]any) string {
	if pages, ok := logObj["pages"].([]any); ok && len(pages) > 0 {
		if p0, ok := pages[0].(map[string]any); ok {
			if t := strings.TrimSpace(stringOrEmpty(p0["title"])); t != "" {
				return t
			}
		}
	}
	if creator, ok := logObj["creator"].(map[string]any); ok {
		if n := strings.TrimSpace(stringOrEmpty(creator["name"])); n != "" {
			return n + "-har"
		}
	}
	return ""
}

func stringOrEmpty(v any) string {
	s, _ := v.(string)
	return s
}

// parseStoredHAROperations 从已落库的脱敏 HAR 骨架文档还原操作列表（跨版本对比/审计用）。
func parseStoredHAROperations(doc map[string]any) ([]SpecOperation, error) {
	if _, hasLog := doc["log"]; hasLog {
		_, ops, err := ParseHAR(doc)
		return ops, err
	}
	rawOps, ok := doc["operations"]
	if !ok {
		return nil, fmt.Errorf("%w: 已存 HAR 规范缺少 operations", ErrSpecInvalidHAR)
	}
	b, err := json.Marshal(rawOps)
	if err != nil {
		return nil, err
	}
	var ops []SpecOperation
	if err := json.Unmarshal(b, &ops); err != nil {
		return nil, fmt.Errorf("%w: 已存 HAR operations 解析失败: %v", ErrSpecInvalidHAR, err)
	}
	return sortAndDedupeSpecOps(ops), nil
}
