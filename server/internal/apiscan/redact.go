// redact.go 扫描证据脱敏与截断（安全红线：所有请求/响应样本脱敏落库，
// 与 apiruntime/findings.go 脱敏纪律同一标准）：
//   - 凭据类请求头（authorization/cookie/x-api-key 等）值一律替换 [redacted]；
//   - 响应样本截断（默认 2KB，保留前缀 + 截断标记）；
//   - 敏感类探针（SENSITIVE_EXPOSURE/BOLA_COMPARE）不落响应原文，证据只落
//     字段名/状态码/响应体哈希前缀。
package apiscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Redacted 脱敏占位符（凭据值替换）。
const Redacted = "[redacted]"

// 样本截断上限（字节）。
const (
	maxRequestSample  = 2048
	maxResponseSample = 2048
	// 敏感探针响应体读取上限（判定用，不落库）。
	maxResponseBodyRead = 64 * 1024
)

// sensitiveHeaders 凭据类请求头词表（小写比较；值替换 [redacted]）。
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-jiuzhang-scan":     true, // 隔离签名头值同样不落库（防伪造面收敛）
}

// redactHeaderValue 凭据头值脱敏。
func redactHeaderValue(name, value string) string {
	if sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))] {
		return Redacted
	}
	return value
}

// truncateSample 截断样本（保留前缀，追加截断标记）。
func truncateSample(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("...[truncated %d bytes]", len(s)-max)
}

// buildRequestSample 构造脱敏请求样本（请求行 + 脱敏头，不含 body——v1 探针均不带凭据 body）。
func buildRequestSample(req *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.URL.Host)
	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range req.Header[name] {
			fmt.Fprintf(&b, "%s: %s\r\n", name, redactHeaderValue(name, v))
		}
	}
	return truncateSample(b.String(), maxRequestSample)
}

// buildResponseSample 构造脱敏响应样本（状态行 + 截断体；body 原始读取，
// 调用方须确认该探针允许落体——敏感类探针不得调用本函数落体）。
func buildResponseSample(status int, body []byte) string {
	return truncateSample(fmt.Sprintf("HTTP %d\r\n\r\n%s", status, body), maxResponseSample)
}

// bodyDigest 响应体哈希前缀证据（不落原文时的可核对指纹）。
func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}

// sensitiveFieldNames 敏感字段名词表（SENSITIVE_EXPOSURE 探针判定 JSON 键名；
// 保守小词表，只落命中的字段名不落值）。
var sensitiveFieldNames = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true,
	"token": true, "access_token": true, "refresh_token": true, "api_key": true, "apikey": true,
	"private_key": true, "credential": true, "credentials": true,
	"id_card": true, "idcard": true, "id_number": true, "ssn": true,
	"bank_card": true, "card_number": true, "cvv": true,
	"phone": true, "mobile": true, "email": true,
}

// scanSensitiveFields 扫描 JSON 响应体中的敏感字段名（仅一级与嵌套对象的键名；
// 返回排序去重的命中清单，不落任何值）。
func scanSensitiveFields(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	found := map[string]bool{}
	walkJSONKeys(v, found)
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// walkJSONKeys 递归遍历 JSON 键名，命中敏感词表即记录。
func walkJSONKeys(v any, found map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			if sensitiveFieldNames[strings.ToLower(k)] {
				found[strings.ToLower(k)] = true
			}
			walkJSONKeys(sub, found)
		}
	case []any:
		for _, sub := range t {
			walkJSONKeys(sub, found)
		}
	}
}
