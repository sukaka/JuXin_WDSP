package detectors

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const maxPPTXTextBytes = 16 << 20

type pptxSlide struct {
	Index       int
	Body        []byte
	Root        string
	FieldPrefix string
	Scope       string
	SourcePart  string
}

func (s *fileSensitiveScanner) checkPPTX(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete bool, rules []CompiledSensitiveValueRule) {
	if !complete {
		fileSensitiveSkip(ctx, *obs, "TRUNCATED_OOXML")
		return
	}
	parts, mainSampleBytes, reason := readPPTXPackage(body)
	if reason != "" {
		fileSensitiveSkip(ctx, *obs, reason)
		return
	}
	type noteResult struct {
		part pptxSlide
		hits map[string]fileSensitiveHit
	}
	mainHits := map[string]fileSensitiveHit{}
	notes := make([]noteResult, 0, 4)
	for _, textPart := range parts {
		hits := map[string]fileSensitiveHit{}
		if reason := s.scanPPTXSlide(ctx, *obs, textPart, rules, hits); reason != "" {
			if reason == "SCAN_BUDGET_EXCEEDED" {
				s.skipBudget(ctx, *obs)
			} else {
				fileSensitiveSkip(ctx, *obs, reason)
			}
			return
		}
		if textPart.Scope == "PPTX_NOTES" {
			notes = append(notes, noteResult{part: textPart, hits: hits})
			continue
		}
		for dataType, hit := range hits {
			merged := mainHits[dataType]
			if sensitiveLevelRank(hit.level) > sensitiveLevelRank(merged.level) {
				merged.level = hit.level
			}
			if merged.field == "" {
				merged.field = hit.field
			}
			merged.count += hit.count
			mainHits[dataType] = merged
		}
	}
	types := map[string]bool{}
	emit := func(hits map[string]fileSensitiveHit, scope string, sampleBytes int, sourcePart string) bool {
		if len(hits) == 0 {
			return true
		}
		if s.matches >= maxSensitiveMatches {
			s.skipBudget(ctx, *obs)
			return false
		}
		if sourcePart == "" {
			s.emitFileSensitiveHits(ctx, obs, part, hits, scope, sampleBytes, false, 0)
		} else {
			s.emitFileSensitiveHitsAtSource(ctx, obs, part, hits, scope, sampleBytes, sourcePart, false, 0)
		}
		for _, dataType := range obs.SensitiveTypes {
			types[dataType] = true
		}
		return true
	}
	finish := func() {
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
	if !emit(mainHits, "PPTX_SLIDES", mainSampleBytes, "") {
		finish()
		return
	}
	for _, note := range notes {
		if !emit(note.hits, "PPTX_NOTES", len(note.part.Body), note.part.SourcePart) {
			break
		}
	}
	finish()
}

func readPPTXPackage(body []byte) ([]pptxSlide, int, string) {
	pkg, reason := openOOXMLPackage(body)
	if reason != "" {
		return nil, 0, reason
	}
	var presentation *zip.File
	parts := make([]pptxSlide, 0, 16)
	seenSlides := map[int]bool{}
	seenNotes := map[int]bool{}
	sampleBytes := 0
	mainSampleBytes := 0
	for _, entry := range pkg.File {
		if entry.Name == "ppt/presentation.xml" {
			if presentation != nil {
				return nil, 0, "PPTX_DUPLICATE_PART"
			}
			presentation = entry
			continue
		}
		scope := ""
		index, ok := pptxSlideIndex(entry.Name)
		if ok {
			if seenSlides[index] {
				return nil, 0, "PPTX_DUPLICATE_SLIDE"
			}
			seenSlides[index] = true
			scope = "PPTX_SLIDES"
		} else {
			index, ok = pptxNotesSlideIndex(entry.Name)
			if !ok {
				continue
			}
			if seenNotes[index] {
				return nil, 0, "PPTX_DUPLICATE_NOTES_SLIDE"
			}
			seenNotes[index] = true
			scope = "PPTX_NOTES"
		}
		raw, reason := readOOXMLPart(pkg, entry)
		if reason != "" {
			return nil, 0, reason
		}
		sampleBytes += len(raw)
		if sampleBytes > maxPPTXTextBytes {
			return nil, 0, "PPTX_CONTENT_TOO_LARGE"
		}
		textPart := pptxSlide{Index: index, Body: raw, Scope: scope, FieldPrefix: "slide", Root: "sld"}
		if scope == "PPTX_NOTES" {
			textPart.FieldPrefix = "notesSlide"
			textPart.Root = "notes"
			textPart.SourcePart = entry.Name
		} else {
			mainSampleBytes += len(raw)
		}
		parts = append(parts, textPart)
	}
	if presentation == nil {
		return nil, 0, "PPTX_PRESENTATION_MISSING"
	}
	presentationRaw, reason := readOOXMLPart(pkg, presentation)
	if reason != "" {
		return nil, 0, reason
	}
	sampleBytes += len(presentationRaw)
	if sampleBytes > maxPPTXTextBytes {
		return nil, 0, "PPTX_CONTENT_TOO_LARGE"
	}
	mainSampleBytes += len(presentationRaw)
	if reason := validatePPTXPresentation(presentationRaw); reason != "" {
		return nil, 0, reason
	}
	hasSlides := false
	for _, textPart := range parts {
		if textPart.Scope == "PPTX_SLIDES" {
			hasSlides = true
			break
		}
	}
	if !hasSlides {
		return nil, 0, "PPTX_SLIDE_MISSING"
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].Scope != parts[j].Scope {
			return parts[i].Scope == "PPTX_SLIDES"
		}
		return parts[i].Index < parts[j].Index
	})
	return parts, mainSampleBytes, ""
}

func pptxSlideIndex(name string) (int, bool) {
	return pptxNumberedPartIndex(name, "ppt/slides/", "slide")
}

func pptxNotesSlideIndex(name string) (int, bool) {
	return pptxNumberedPartIndex(name, "ppt/notesSlides/", "notesSlide")
}

func pptxNumberedPartIndex(name, directory, prefix string) (int, bool) {
	if !strings.HasPrefix(name, directory+prefix) || !strings.HasSuffix(name, ".xml") {
		return 0, false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(name, directory+prefix), ".xml")
	if raw == "" || raw == "0" || strings.HasPrefix(raw, "0") {
		return 0, false
	}
	index, err := strconv.Atoi(raw)
	if err != nil || index <= 0 {
		return 0, false
	}
	return index, true
}

func validatePPTXPresentation(raw []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	depth, nodes := 0, 0
	rootSeen, rootClosed := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || depth != 0 {
				return "INVALID_PPTX_XML"
			}
			return ""
		}
		if err != nil {
			return "INVALID_PPTX_XML"
		}
		nodes++
		if nodes > maxFileXMLNodes {
			return "XML_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			return "PPTX_UNSUPPORTED_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return "PPTX_UNSUPPORTED_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			if rootClosed {
				return "INVALID_PPTX_XML"
			}
			if depth >= maxFileXMLDepth {
				return "XML_DEPTH_EXCEEDED"
			}
			depth++
			if depth == 1 {
				if value.Name.Local != "presentation" {
					return "INVALID_PPTX_XML"
				}
				rootSeen = true
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return "INVALID_PPTX_XML"
			}
			if depth == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return "INVALID_PPTX_XML"
			}
		}
	}
}

func (s *fileSensitiveScanner) scanPPTXSlide(ctx *dsctx.RequestContext, obs dsctx.FileObservation, slide pptxSlide, rules []CompiledSensitiveValueRule, hits map[string]fileSensitiveHit) string {
	decoder := xml.NewDecoder(bytes.NewReader(slide.Body))
	depth, nodes := 0, 0
	rootSeen, rootClosed := false, false
	inParagraph, inText := false, false
	paragraphIndex := 0
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || depth != 0 || inParagraph || inText {
				return "INVALID_PPTX_XML"
			}
			return ""
		}
		if err != nil {
			return "INVALID_PPTX_XML"
		}
		nodes++
		if nodes > maxFileXMLNodes {
			return "XML_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			return "PPTX_UNSUPPORTED_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return "PPTX_UNSUPPORTED_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			if rootClosed {
				return "INVALID_PPTX_XML"
			}
			if depth >= maxFileXMLDepth {
				return "XML_DEPTH_EXCEEDED"
			}
			depth++
			if depth == 1 {
				root := slide.Root
				if root == "" {
					root = "sld"
				}
				if value.Name.Local != root {
					return "INVALID_PPTX_XML"
				}
				rootSeen = true
			}
			switch value.Name.Local {
			case "p":
				if inParagraph {
					return "INVALID_PPTX_XML"
				}
				inParagraph = true
				paragraphIndex++
				text.Reset()
			case "t":
				if inParagraph {
					if inText {
						return "INVALID_PPTX_XML"
					}
					inText = true
				}
			}
		case xml.CharData:
			if inText {
				text.Write(value)
				if text.Len() > maxSensitiveValueInputLen {
					return "PPTX_VALUE_TOO_LONG"
				}
			} else if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return "INVALID_PPTX_XML"
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return "INVALID_PPTX_XML"
			}
			switch value.Name.Local {
			case "t":
				inText = false
			case "p":
				if !inParagraph || inText {
					return "INVALID_PPTX_XML"
				}
				value := strings.TrimSpace(text.String())
				inParagraph = false
				text.Reset()
				if value != "" {
					prefix := slide.FieldPrefix
					if prefix == "" {
						prefix = "slide"
					}
					field := fmt.Sprintf("%s%d!p%d", prefix, slide.Index, paragraphIndex)
					if reason := s.scanXMLValue(ctx, obs, field, value, rules, hits); reason != "" {
						return reason
					}
				}
			}
			if depth == 0 {
				rootClosed = true
			}
		}
	}
}
