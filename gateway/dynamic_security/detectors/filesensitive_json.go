package detectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

var errInvalidFileJSON = errors.New("invalid json document")

func fileStructuredFormat(obs dsctx.FileObservation) string {
	switch obs.Extension {
	case "json":
		return "json"
	case "jsonl", "ndjson":
		return "jsonl"
	case "xml":
		return "xml"
	case "docx":
		return "docx"
	case "xlsx":
		return "xlsx"
	case "pptx":
		return "pptx"
	case "":
		switch obs.MIME {
		case "application/json":
			return "json"
		case "application/x-ndjson", "application/jsonl":
			return "jsonl"
		case "application/xml", "text/xml":
			return "xml"
		case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
			return "docx"
		case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
			return "xlsx"
		case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
			return "pptx"
		}
	}
	return ""
}

func (s *fileSensitiveScanner) checkJSON(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete bool, format string, rules []CompiledSensitiveValueRule) {
	if !utf8.Valid(body) {
		fileSensitiveSkip(ctx, *obs, "UNSUPPORTED_TEXT_ENCODING")
		return
	}
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	if format == "json" {
		if !complete {
			fileSensitiveSkip(ctx, *obs, "TRUNCATED_JSON")
			return
		}
		parsed, err := parseFileJSONDocument(body)
		if err != nil {
			fileSensitiveSkip(ctx, *obs, "INVALID_JSON")
			return
		}
		hits := map[string]fileSensitiveHit{}
		s.scanJSONValues(ctx, *obs, parsed.JSONValues, rules, hits)
		s.emitFileSensitiveHits(ctx, obs, part, hits, "JSON_DOCUMENT", len(body), false, 0)
		return
	}
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
		if strings.TrimSpace(line) == "" {
			continue
		}
		parsed, err := parseFileJSONDocument([]byte(line))
		if err != nil {
			skippedLines++
			continue
		}
		validLines++
		s.scanJSONValues(ctx, *obs, parsed.JSONValues, rules, hits)
	}
	if validLines == 0 && skippedLines > 0 {
		fileSensitiveSkip(ctx, *obs, "INVALID_JSONL")
		return
	}
	scope := "COMPLETE_LINES"
	if complete {
		scope = "JSON_LINES"
	}
	s.emitFileSensitiveHits(ctx, obs, part, hits, scope, len(body), !complete, skippedLines)
}

func (s *fileSensitiveScanner) scanJSONValues(ctx *dsctx.RequestContext, obs dsctx.FileObservation, values map[string]string, rules []CompiledSensitiveValueRule, hits map[string]fileSensitiveHit) {
	for _, path := range sortedKeys(values) {
		if s.matches >= maxSensitiveMatches || s.scans >= maxSensitiveValueScans {
			s.skipBudget(ctx, obs)
			return
		}
		rule, matched := matchValueRules(values[path], "file", rules, &s.scans)
		if !matched {
			continue
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
	}
}

func (s *fileSensitiveScanner) emitFileSensitiveHits(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, hits map[string]fileSensitiveHit, scope string, sampleBytes int, truncated bool, skippedLines int) {
	s.emitFileSensitiveHitsAtSource(ctx, obs, part, hits, scope, sampleBytes, "", truncated, skippedLines)
}

func (s *fileSensitiveScanner) emitFileSensitiveHitsAtSource(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, hits map[string]fileSensitiveHit, scope string, sampleBytes int, sourcePart string, truncated bool, skippedLines int) {
	types := make([]string, 0, len(hits))
	for dataType := range hits {
		types = append(types, dataType)
	}
	sort.Strings(types)
	obs.SensitiveTypes = append([]string(nil), types...)
	if part != nil {
		part.SensitiveTypes = append([]string(nil), types...)
	}
	for _, dataType := range types {
		dedupKey := dataType
		if sourcePart != "" {
			dedupKey = sourcePart + "\x00" + dataType
		}
		if s.emitted[dedupKey] {
			continue
		}
		s.emitted[dedupKey] = true
		s.matches++
		hit := hits[dataType]
		if scope == "" {
			scope = "COMPLETE_LINES"
			if !truncated {
				scope = "FULL_TEXT"
			}
		}
		evidence := map[string]string{
			"direction": obs.Direction, "filename": obs.FileName, "ext": obs.Extension,
			"mime": obs.MIME, "data_type": dataType, "level": hit.level,
			"match_count": strconv.Itoa(hit.count), "scope": scope,
			"sample_bytes": strconv.Itoa(sampleBytes), "sample_truncated": strconv.FormatBool(truncated),
			"location": "file",
		}
		if sourcePart != "" {
			evidence["source_part"] = sourcePart
		}
		if hit.field != "" {
			evidence["field"] = hit.field
		}
		if skippedLines > 0 {
			evidence["skipped_lines"] = strconv.Itoa(skippedLines)
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "file", RuleID: "file.sensitive_content",
			Category: "OBSERVE", Severity: "MEDIUM", Message: "sensitive value observed in file text",
			Evidence: evidence, ScoreDelta: 15, Confidence: 0.9,
		})
	}
}

func parseFileJSONDocument(body []byte) (*parser.Parsed, error) {
	if !json.Valid(body) {
		return nil, errInvalidFileJSON
	}
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	req, err := http.NewRequest(http.MethodPost, "http://file.local/document", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	parsed, err := parser.ParseRequest(req, dsctx.New("file-json", limits))
	if err != nil {
		return nil, err
	}
	if parsed == nil || len(parsed.Ambiguities) > 0 {
		return nil, errInvalidFileJSON
	}
	return parsed, nil
}
