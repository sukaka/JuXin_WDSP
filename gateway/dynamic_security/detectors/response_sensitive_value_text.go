package detectors

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

const maxResponseBodyXMLPathLen = 512

// ResponseBodyValueScanner 在同一条响应或 SSE 流上复用值级匹配预算。
type ResponseBodyValueScanner struct {
	scanner responseSensitiveValueScanner
}

// NewResponseBodyValueScanner 构造响应值扫描器；同一实例可跨多个 SSE 事件累计预算。
func NewResponseBodyValueScanner(ctx *dsctx.RequestContext, rules []CompiledSensitiveValueRule, limits dsctx.ParseLimits) *ResponseBodyValueScanner {
	defaults := dsctx.DefaultParseLimits()
	if limits.MaxJSONDepth <= 0 {
		limits.MaxJSONDepth = defaults.MaxJSONDepth
	}
	if limits.MaxXMLDepth <= 0 {
		limits.MaxXMLDepth = defaults.MaxXMLDepth
	}
	if limits.MaxFieldCount <= 0 {
		limits.MaxFieldCount = defaults.MaxFieldCount
	}
	return &ResponseBodyValueScanner{scanner: responseSensitiveValueScanner{ctx: ctx, rules: rules, limits: limits}}
}

func (s *ResponseBodyValueScanner) ScanJSON(body []byte, prefix string) string {
	if s == nil || s.scanner.ctx == nil || !hasResponseSensitiveValueLocation(s.scanner.rules) {
		return ""
	}
	if !utf8.Valid(body) {
		return "INVALID_UTF8"
	}
	_, root, ok := response.ParseJSON(body, s.scanner.limits)
	if !ok {
		return "INVALID_JSON"
	}
	s.scanner.walk(root, prefix, 0)
	if s.scanner.scans >= maxSensitiveValueScans {
		return "SCAN_BUDGET_EXCEEDED"
	}
	if s.scanner.matches >= maxSensitiveMatches {
		return "MATCH_BUDGET_EXCEEDED"
	}
	return ""
}

func (s *ResponseBodyValueScanner) ScanText(body []byte, prefix string) string {
	if s == nil || s.scanner.ctx == nil || !hasResponseSensitiveValueLocation(s.scanner.rules) {
		return ""
	}
	if !utf8.Valid(body) {
		return "INVALID_UTF8"
	}
	if prefix == "" {
		prefix = "text."
	}
	lines := strings.Split(string(body), "\n")
	for i, line := range lines {
		value := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if value == "" {
			continue
		}
		if s.scanner.fields >= s.scanner.limits.MaxFieldCount {
			return "FIELD_BUDGET_EXCEEDED"
		}
		s.scanner.fields++
		path := fmt.Sprintf("%sline[%d]", prefix, i+1)
		if reason := s.scanValue(path, value); reason != "" {
			return reason
		}
	}
	return ""
}

func (s *ResponseBodyValueScanner) ScanXML(body []byte) string {
	if s == nil || s.scanner.ctx == nil || !hasResponseSensitiveValueLocation(s.scanner.rules) {
		return ""
	}
	if !utf8.Valid(body) {
		return "INVALID_UTF8"
	}
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	decoder := xml.NewDecoder(bytes.NewReader(body))
	stack := make([]string, 0, 8)
	rootSeen, rootClosed := false, false
	nodes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || len(stack) != 0 {
				return "INVALID_XML"
			}
			return ""
		}
		if err != nil {
			return "INVALID_XML"
		}
		nodes++
		if nodes > s.scanner.limits.MaxFieldCount {
			return "FIELD_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(value))), "DOCTYPE") {
				return "DTD_FORBIDDEN"
			}
			return "UNSUPPORTED_XML_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return "UNSUPPORTED_XML_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			if rootClosed {
				return "INVALID_XML"
			}
			if len(stack) >= s.scanner.limits.MaxXMLDepth {
				return "XML_DEPTH_EXCEEDED"
			}
			stack = append(stack, value.Name.Local)
			rootSeen = true
			path := strings.Join(stack, ".")
			if len(path) > maxResponseBodyXMLPathLen {
				return "XML_PATH_TOO_LONG"
			}
			for _, attribute := range value.Attr {
				field := path + ".@" + attribute.Name.Local
				if len(field) > maxResponseBodyXMLPathLen {
					return "XML_PATH_TOO_LONG"
				}
				if reason := s.scanValue(field, attribute.Value); reason != "" {
					return reason
				}
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return "INVALID_XML"
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootClosed = true
			}
		case xml.CharData:
			text := strings.TrimSpace(string(value))
			if text == "" {
				continue
			}
			if rootClosed || len(stack) == 0 {
				return "INVALID_XML"
			}
			if reason := s.scanValue(strings.Join(stack, "."), text); reason != "" {
				return reason
			}
		}
	}
}

func (s *ResponseBodyValueScanner) scanValue(path, value string) string {
	if s.scanner.matches >= maxSensitiveMatches {
		return "MATCH_BUDGET_EXCEEDED"
	}
	if s.scanner.scans >= maxSensitiveValueScans {
		return "SCAN_BUDGET_EXCEEDED"
	}
	rule, matched := matchValueRules(value, responseSensitiveValueLocation, s.scanner.rules, &s.scanner.scans)
	if matched {
		s.scanner.addMatch(path, rule)
	}
	return ""
}

func NoteResponseBodyValueUnchecked(ctx *dsctx.RequestContext, format, field, reason string) {
	if ctx == nil || reason == "" {
		return
	}
	if field == "" {
		field = "response_body"
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "sensitive_data",
		RuleID:     "sensitive.response_body_unchecked",
		Category:   "INFO",
		Severity:   "INFO",
		Message:    "response body value inspection incomplete",
		Confidence: 1.0,
		Evidence: map[string]string{
			"field":       field,
			"format":      format,
			"location":    responseSensitiveValueLocation,
			"direction":   "RESPONSE",
			"completion":  "partial",
			"skip_reason": reason,
		},
	})
}

func HasResponseBodySensitiveLocation(rules []SensitiveValueRule) bool {
	for _, rule := range rules {
		for _, location := range rule.Locations {
			if location == responseSensitiveValueLocation {
				return true
			}
		}
	}
	return false
}
