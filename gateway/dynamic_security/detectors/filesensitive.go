package detectors

import (
	"bytes"
	"encoding/csv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

type fileSensitiveScanner struct {
	matches         int
	scans           int
	emitted         map[string]bool
	budgetDisclosed bool
}

type fileSensitiveHit struct {
	level string
	count int
	field string
}

// HasFileSensitiveLocation reports whether any published rule explicitly opts
// into file-content inspection. Other protocol locations do not opt in.
func HasFileSensitiveLocation(rules []SensitiveValueRule) bool {
	for _, rule := range rules {
		for _, location := range rule.Locations {
			if location == "file" {
				return true
			}
		}
	}
	return false
}

func hasCompiledFileSensitiveLocation(rules []CompiledSensitiveValueRule) bool {
	for _, rule := range rules {
		if rule.locations["file"] {
			return true
		}
	}
	return false
}

// CheckFileSensitiveContent inspects text values in one downloaded file. The
// observation receives only data-type labels; matched values stay out of events.
func CheckFileSensitiveContent(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, body []byte, complete, streamed bool, rules []CompiledSensitiveValueRule) {
	scanner := fileSensitiveScanner{emitted: map[string]bool{}}
	scanner.check(ctx, obs, nil, body, complete, streamed, rules)
}

// CheckUploadFileSensitiveContent inspects multipart prefixes with one shared
// CPU/event budget and propagates type labels back into file observations.
func CheckUploadFileSensitiveContent(ctx *dsctx.RequestContext, parts []parser.PartMeta, partsCapped bool, rules []CompiledSensitiveValueRule) {
	if ctx == nil || !hasCompiledFileSensitiveLocation(rules) {
		return
	}
	scanner := fileSensitiveScanner{emitted: map[string]bool{}}
	for i := range parts {
		observations := parser.BuildUploadFileObservations([]parser.PartMeta{parts[i]})
		if len(observations) == 0 {
			continue
		}
		prefix, complete := parts[i].ContentPrefix()
		scanner.check(ctx, &observations[0], &parts[i], prefix, complete, false, rules)
	}
	if partsCapped {
		fileSensitiveSkip(ctx, dsctx.FileObservation{Direction: dsctx.FileDirectionUpload}, "MULTIPART_PARTS_CAPPED")
	}
}

func (s *fileSensitiveScanner) check(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete, streamed bool, rules []CompiledSensitiveValueRule) {
	if ctx == nil || obs == nil || !hasCompiledFileSensitiveLocation(rules) {
		return
	}
	if streamed {
		fileSensitiveSkip(ctx, *obs, "STREAMED")
		return
	}
	if len(body) == 0 {
		if !complete {
			fileSensitiveSkip(ctx, *obs, "TRUNCATED_BODY_UNAVAILABLE")
		}
		return
	}
	if format := fileStructuredFormat(*obs); format != "" {
		switch format {
		case "xml":
			s.checkXML(ctx, obs, part, body, complete, rules)
		case "docx":
			s.checkDOCX(ctx, obs, part, body, complete, rules)
		case "xlsx":
			s.checkXLSX(ctx, obs, part, body, complete, rules)
		case "pptx":
			s.checkPPTX(ctx, obs, part, body, complete, rules)
		default:
			s.checkJSON(ctx, obs, part, body, complete, format, rules)
		}
		return
	}
	format, ok := fileSensitiveTextFormat(*obs)
	if !ok {
		fileSensitiveSkip(ctx, *obs, "UNSUPPORTED_FILE_FORMAT")
		return
	}
	if !utf8.Valid(body) {
		fileSensitiveSkip(ctx, *obs, "UNSUPPORTED_TEXT_ENCODING")
		return
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	lines := strings.Split(string(body), "\n")
	if !complete && !strings.HasSuffix(string(body), "\n") {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		fileSensitiveSkip(ctx, *obs, "TRUNCATED_TEXT_LINE")
		return
	}
	hits := map[string]fileSensitiveHit{}
	validLines, skippedLines := 0, 0
	for _, line := range lines {
		if s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
			s.skipBudget(ctx, *obs)
			return
		}
		values, err := fileSensitiveTextValues(line, format)
		if err != nil {
			skippedLines++
			continue
		}
		if len(values) == 0 {
			continue
		}
		validLines++
		for _, value := range values {
			if s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
				s.skipBudget(ctx, *obs)
				return
			}
			rule, matched := matchValueRules(value, "file", rules, &s.scans)
			if !matched {
				continue
			}
			hit := hits[rule.dataType]
			if sensitiveLevelRank(rule.level) > sensitiveLevelRank(hit.level) {
				hit.level = rule.level
			}
			hit.count++
			hits[rule.dataType] = hit
		}
	}
	if validLines == 0 && skippedLines > 0 {
		fileSensitiveSkip(ctx, *obs, "INVALID_TEXT_RECORD")
		return
	}
	s.emitFileSensitiveHits(ctx, obs, part, hits, "", len(body), !complete, skippedLines)
}

func (s *fileSensitiveScanner) skipBudget(ctx *dsctx.RequestContext, obs dsctx.FileObservation) {
	if s.budgetDisclosed {
		return
	}
	s.budgetDisclosed = true
	fileSensitiveSkip(ctx, obs, "SCAN_BUDGET_EXCEEDED")
}

func fileSensitiveSkip(ctx *dsctx.RequestContext, obs dsctx.FileObservation, reason string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "file", RuleID: "file.sensitive_content_not_inspected",
		Category: "OBSERVE", Severity: "INFO", Message: "file text was not fully inspected for sensitive values",
		Evidence: map[string]string{
			"direction": obs.Direction, "filename": obs.FileName, "ext": obs.Extension,
			"mime": obs.MIME, "reason": reason, "scope": "SENSITIVE_CONTENT",
		},
		Confidence: 1,
	})
}

func fileSensitiveTextFormat(obs dsctx.FileObservation) (string, bool) {
	switch obs.Extension {
	case "csv":
		return "csv", true
	case "tsv":
		return "tsv", true
	case "txt", "log":
		return "text", true
	case "":
		switch obs.MIME {
		case "text/csv":
			return "csv", true
		case "text/tab-separated-values":
			return "tsv", true
		case "text/plain":
			return "text", true
		}
	}
	return "", false
}

func fileSensitiveTextValues(line, format string) ([]string, error) {
	line = strings.TrimSuffix(line, "\r")
	if strings.TrimSpace(line) == "" {
		return nil, nil
	}
	if format == "csv" || format == "tsv" {
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = -1
		reader.LazyQuotes = true
		reader.TrimLeadingSpace = true
		if format == "tsv" {
			reader.Comma = '\t'
		}
		return reader.Read()
	}
	line = strings.TrimSpace(line)
	if _, value, ok := strings.Cut(line, "="); ok {
		return []string{strings.TrimSpace(value)}, nil
	}
	if key, value, ok := strings.Cut(line, ":"); ok && len(key) <= 64 {
		return []string{strings.TrimSpace(value)}, nil
	}
	return []string{line}, nil
}

func sensitiveLevelRank(level string) int {
	switch level {
	case "CORE":
		return 4
	case "IMPORTANT":
		return 3
	case "SENSITIVE":
		return 2
	case "GENERAL":
		return 1
	default:
		return 0
	}
}
