// Package classifier API 流量识别（多信号置信度，不单独依赖 /api/ 前缀）。
package classifier

import (
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// Result API 识别结果。
type Result struct {
	IsAPI      bool
	Confidence float64 // 0..1
	Signals    []string
}

// Classify 基于解析结果打分。
func Classify(p *parser.Parsed) Result {
	if p == nil {
		return Result{}
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
	// method write with JSON
	if (p.Method == "POST" || p.Method == "PUT" || p.Method == "PATCH") && p.IsJSON {
		add("write_json", 0.1)
	}
	if score > 1 {
		score = 1
	}
	return Result{
		IsAPI:      score >= 0.35,
		Confidence: score,
		Signals:    signals,
	}
}
