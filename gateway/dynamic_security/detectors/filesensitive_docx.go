package detectors

import (
	"sort"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const (
	maxOOXMLPackageBytes  = 32 << 20
	maxOOXMLDocumentBytes = 8 << 20
	maxOOXMLParts         = 64
)

func (s *fileSensitiveScanner) checkDOCX(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete bool, rules []CompiledSensitiveValueRule) {
	if !complete {
		fileSensitiveSkip(ctx, *obs, "TRUNCATED_OOXML")
		return
	}
	if len(body) > maxOOXMLPackageBytes {
		fileSensitiveSkip(ctx, *obs, "OOXML_TOO_LARGE")
		return
	}
	parts, reason := readDOCXTextParts(body)
	if reason != "" {
		fileSensitiveSkip(ctx, *obs, reason)
		return
	}
	type scanResult struct {
		part docxTextPart
		hits map[string]fileSensitiveHit
	}
	results := make([]scanResult, 0, len(parts))
	for _, textPart := range parts {
		hits, reason := s.scanXML(ctx, *obs, textPart.Body, rules)
		if reason != "" {
			if reason == "SCAN_BUDGET_EXCEEDED" {
				s.skipBudget(ctx, *obs)
			} else {
				fileSensitiveSkip(ctx, *obs, reason)
			}
			return
		}
		results = append(results, scanResult{part: textPart, hits: hits})
	}
	types := map[string]bool{}
	for _, result := range results {
		if len(result.hits) == 0 {
			continue
		}
		if s.matches >= maxSensitiveMatches {
			s.skipBudget(ctx, *obs)
			break
		}
		s.emitFileSensitiveHitsAtSource(ctx, obs, part, result.hits, result.part.Scope, len(result.part.Body), result.part.Name, false, 0)
		for _, dataType := range obs.SensitiveTypes {
			types[dataType] = true
		}
	}
	labels := make([]string, 0, len(types))
	for dataType := range types {
		labels = append(labels, dataType)
	}
	sort.Strings(labels)
	obs.SensitiveTypes = labels
	if part != nil {
		part.SensitiveTypes = append([]string(nil), labels...)
	}
}
