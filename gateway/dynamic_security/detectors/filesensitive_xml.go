package detectors

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const (
	maxFileXMLDepth   = 32
	maxFileXMLNodes   = 2048
	maxFileXMLPathLen = 512
)

func (s *fileSensitiveScanner) checkXML(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete bool, rules []CompiledSensitiveValueRule) {
	if !complete {
		fileSensitiveSkip(ctx, *obs, "TRUNCATED_XML")
		return
	}
	if !utf8.Valid(body) {
		fileSensitiveSkip(ctx, *obs, "UNSUPPORTED_TEXT_ENCODING")
		return
	}
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	hits, reason := s.scanXML(ctx, *obs, body, rules)
	if reason != "" {
		if reason == "SCAN_BUDGET_EXCEEDED" {
			s.skipBudget(ctx, *obs)
		} else {
			fileSensitiveSkip(ctx, *obs, reason)
		}
		return
	}
	s.emitFileSensitiveHits(ctx, obs, part, hits, "XML_DOCUMENT", len(body), false, 0)
}

func (s *fileSensitiveScanner) scanXML(ctx *dsctx.RequestContext, obs dsctx.FileObservation, body []byte, rules []CompiledSensitiveValueRule) (map[string]fileSensitiveHit, string) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	stack := make([]string, 0, 8)
	hits := map[string]fileSensitiveHit{}
	rootSeen, rootClosed := false, false
	nodes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || len(stack) != 0 {
				return nil, "INVALID_XML"
			}
			return hits, ""
		}
		if err != nil {
			return nil, "INVALID_XML"
		}
		nodes++
		if nodes > maxFileXMLNodes {
			return nil, "XML_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			return nil, "UNSUPPORTED_XML_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return nil, "UNSUPPORTED_XML_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			if rootClosed || len(stack) >= maxFileXMLDepth {
				if rootClosed {
					return nil, "INVALID_XML"
				}
				return nil, "XML_DEPTH_EXCEEDED"
			}
			stack = append(stack, value.Name.Local)
			rootSeen = true
			path := strings.Join(stack, ".")
			if len(path) > maxFileXMLPathLen {
				return nil, "XML_PATH_TOO_LONG"
			}
			for _, attribute := range value.Attr {
				field := path + ".@" + attribute.Name.Local
				if len(field) > maxFileXMLPathLen {
					return nil, "XML_PATH_TOO_LONG"
				}
				if reason := s.scanXMLValue(ctx, obs, field, attribute.Value, rules, hits); reason != "" {
					return nil, reason
				}
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, "INVALID_XML"
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
				return nil, "INVALID_XML"
			}
			if reason := s.scanXMLValue(ctx, obs, strings.Join(stack, "."), text, rules, hits); reason != "" {
				return nil, reason
			}
		}
	}
}

func (s *fileSensitiveScanner) scanXMLValue(ctx *dsctx.RequestContext, obs dsctx.FileObservation, path, value string, rules []CompiledSensitiveValueRule, hits map[string]fileSensitiveHit) string {
	if s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
		return "SCAN_BUDGET_EXCEEDED"
	}
	rule, matched := matchValueRules(value, "file", rules, &s.scans)
	if !matched {
		return ""
	}
	hit := hits[rule.dataType]
	if sensitiveLevelRank(rule.level) > sensitiveLevelRank(hit.level) {
		hit.level = rule.level
	}
	if hit.field == "" {
		hit.field = path
	}
	hit.count++
	hits[rule.dataType] = hit
	return ""
}
