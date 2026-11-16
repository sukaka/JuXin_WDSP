package detectors

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const (
	maxXLSXWorksheets    = 16
	maxXLSXSharedStrings = 4096
	maxXLSXTextBytes     = 16 << 20
)

type xlsxWorkbook struct {
	Sheets []struct {
		Name       string `xml:"name,attr"`
		SheetID    int    `xml:"sheetId,attr"`
		RelationID string `xml:"id,attr"`
	} `xml:"sheets>sheet"`
}

type xlsxRelationships struct {
	Relations []struct {
		ID     string `xml:"Id,attr"`
		Target string `xml:"Target,attr"`
	} `xml:"Relationship"`
}

type xlsxWorksheet struct {
	Name string
	Body []byte
}

func (s *fileSensitiveScanner) checkXLSX(ctx *dsctx.RequestContext, obs *dsctx.FileObservation, part *parser.PartMeta, body []byte, complete bool, rules []CompiledSensitiveValueRule) {
	if !complete {
		fileSensitiveSkip(ctx, *obs, "TRUNCATED_OOXML")
		return
	}
	shared, sheets, sampleBytes, reason := readXLSXWorkbook(body)
	if reason != "" {
		fileSensitiveSkip(ctx, *obs, reason)
		return
	}
	hits := map[string]fileSensitiveHit{}
	for _, sheet := range sheets {
		reason := s.scanXLSXWorksheet(ctx, *obs, sheet, shared, rules, hits)
		if reason != "" {
			if reason == "SCAN_BUDGET_EXCEEDED" {
				s.skipBudget(ctx, *obs)
			} else {
				fileSensitiveSkip(ctx, *obs, reason)
			}
			return
		}
	}
	s.emitFileSensitiveHits(ctx, obs, part, hits, "XLSX_WORKSHEETS", sampleBytes, false, 0)
}

func readXLSXWorkbook(body []byte) ([]string, []xlsxWorksheet, int, string) {
	pkg, reason := openOOXMLPackage(body)
	if reason != "" {
		return nil, nil, 0, reason
	}
	workbookPart := findOOXMLPart(pkg, "xl/workbook.xml")
	if workbookPart == nil {
		return nil, nil, 0, "XLSX_WORKBOOK_MISSING"
	}
	workbookRaw, reason := readOOXMLPart(pkg, workbookPart)
	if reason != "" {
		return nil, nil, 0, reason
	}
	var workbook xlsxWorkbook
	if err := xml.Unmarshal(workbookRaw, &workbook); err != nil {
		return nil, nil, 0, "INVALID_XLSX_XML"
	}
	relationTargets := map[string]string{}
	if relsPart := findOOXMLPart(pkg, "xl/_rels/workbook.xml.rels"); relsPart != nil {
		raw, reason := readOOXMLPart(pkg, relsPart)
		if reason != "" {
			return nil, nil, 0, reason
		}
		var rels xlsxRelationships
		if err := xml.Unmarshal(raw, &rels); err != nil {
			return nil, nil, 0, "INVALID_XLSX_XML"
		}
		for _, rel := range rels.Relations {
			relationTargets[rel.ID] = rel.Target
		}
	}
	sheets := make([]xlsxWorksheet, 0, len(workbook.Sheets))
	sampleBytes := 0
	for _, sheet := range workbook.Sheets {
		target := relationTargets[sheet.RelationID]
		if target == "" {
			target = fmt.Sprintf("worksheets/sheet%d.xml", sheet.SheetID)
		}
		target = normalizeXLSXTarget(target)
		if target == "" {
			return nil, nil, 0, "INVALID_XLSX_REFERENCE"
		}
		part := findOOXMLPart(pkg, target)
		if part == nil {
			continue
		}
		raw, reason := readOOXMLPart(pkg, part)
		if reason != "" {
			return nil, nil, 0, reason
		}
		sampleBytes += len(raw)
		if sampleBytes > maxXLSXTextBytes {
			return nil, nil, 0, "XLSX_CONTENT_TOO_LARGE"
		}
		name := strings.TrimSpace(sheet.Name)
		if name == "" {
			name = strings.TrimSuffix(path.Base(target), ".xml")
		}
		name = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, name)
		if utf8.RuneCountInString(name) > 255 {
			name = string([]rune(name)[:255])
		}
		sheets = append(sheets, xlsxWorksheet{Name: name, Body: raw})
		if len(sheets) > maxXLSXWorksheets {
			return nil, nil, 0, "XLSX_TOO_MANY_WORKSHEETS"
		}
	}
	if len(sheets) == 0 {
		return nil, nil, 0, "XLSX_WORKSHEET_MISSING"
	}
	var shared []string
	if sharedPart := findOOXMLPart(pkg, "xl/sharedStrings.xml"); sharedPart != nil {
		raw, reason := readOOXMLPart(pkg, sharedPart)
		if reason != "" {
			return nil, nil, 0, reason
		}
		sampleBytes += len(raw)
		if sampleBytes > maxXLSXTextBytes {
			return nil, nil, 0, "XLSX_CONTENT_TOO_LARGE"
		}
		shared, reason = readXLSXSharedStrings(raw)
		if reason != "" {
			return nil, nil, 0, reason
		}
	}
	return shared, sheets, sampleBytes, ""
}

func normalizeXLSXTarget(target string) string {
	target = strings.TrimPrefix(strings.TrimSpace(target), "/")
	if target == "" || strings.HasPrefix(target, "../") || strings.Contains(target, "/../") {
		return ""
	}
	if !strings.HasPrefix(target, "xl/") {
		target = "xl/" + target
	}
	if strings.Contains(target, "..") {
		return ""
	}
	return target
}

func readXLSXSharedStrings(raw []byte) ([]string, string) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	shared := []string{}
	var text strings.Builder
	inSI, inT, rootSeen, rootClosed := false, false, false, false
	skipRPh, nodes := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || inSI {
				return nil, "INVALID_XLSX_XML"
			}
			return shared, ""
		}
		if err != nil {
			return nil, "INVALID_XLSX_XML"
		}
		nodes++
		if nodes > maxFileXMLNodes {
			return nil, "XML_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			return nil, "XLSX_UNSUPPORTED_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return nil, "XLSX_UNSUPPORTED_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			switch value.Name.Local {
			case "sst":
				if rootSeen {
					return nil, "INVALID_XLSX_XML"
				}
				rootSeen = true
			case "si":
				if inSI {
					return nil, "INVALID_XLSX_XML"
				}
				inSI = true
				text.Reset()
			case "t":
				if inSI && skipRPh == 0 {
					inT = true
				}
			case "rPh":
				if inSI {
					skipRPh++
				}
			}
		case xml.CharData:
			if inT && skipRPh == 0 {
				text.Write(value)
			}
		case xml.EndElement:
			switch value.Name.Local {
			case "t":
				inT = false
			case "rPh":
				if skipRPh > 0 {
					skipRPh--
				}
			case "si":
				if !inSI {
					return nil, "INVALID_XLSX_XML"
				}
				if text.Len() > maxSensitiveValueInputLen {
					return nil, "XLSX_VALUE_TOO_LONG"
				}
				shared = append(shared, text.String())
				if len(shared) > maxXLSXSharedStrings {
					return nil, "XLSX_SHARED_STRINGS_TOO_MANY"
				}
				inSI = false
				inT = false
			case "sst":
				rootClosed = true
			}
		}
	}
}

type xlsxCell struct {
	ref, typ  string
	value     strings.Builder
	inline    strings.Builder
	active    bool
	captureV  bool
	captureT  bool
	captureIS bool
}

func (s *fileSensitiveScanner) scanXLSXWorksheet(ctx *dsctx.RequestContext, obs dsctx.FileObservation, sheet xlsxWorksheet, shared []string, rules []CompiledSensitiveValueRule, hits map[string]fileSensitiveHit) string {
	decoder := xml.NewDecoder(bytes.NewReader(sheet.Body))
	var cell xlsxCell
	rootSeen, rootClosed := false, false
	nodes := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || cell.active {
				return "INVALID_XLSX_XML"
			}
			return ""
		}
		if err != nil {
			return "INVALID_XLSX_XML"
		}
		nodes++
		if nodes > maxFileXMLNodes {
			return "XML_BUDGET_EXCEEDED"
		}
		switch value := token.(type) {
		case xml.Directive:
			return "XLSX_UNSUPPORTED_DIRECTIVE"
		case xml.ProcInst:
			if value.Target != "xml" {
				return "XLSX_UNSUPPORTED_PROCESS_INSTRUCTION"
			}
		case xml.StartElement:
			switch value.Name.Local {
			case "worksheet":
				rootSeen = true
			case "c":
				if cell.active {
					return "INVALID_XLSX_XML"
				}
				cell = xlsxCell{active: true}
				for _, attr := range value.Attr {
					switch attr.Name.Local {
					case "r":
						cell.ref = attr.Value
					case "t":
						cell.typ = attr.Value
					}
				}
			case "v":
				if cell.active {
					cell.captureV = true
				}
			case "is":
				if cell.active {
					cell.captureIS = true
				}
			case "t":
				if cell.captureIS {
					cell.captureT = true
				}
			}
		case xml.CharData:
			if cell.captureV {
				cell.value.Write(value)
			}
			if cell.captureIS && cell.captureT {
				cell.inline.Write(value)
			}
		case xml.EndElement:
			switch value.Name.Local {
			case "v":
				cell.captureV = false
			case "t":
				cell.captureT = false
			case "is":
				cell.captureIS = false
			case "c":
				if !cell.active {
					return "INVALID_XLSX_XML"
				}
				if cell.ref == "" || len(cell.ref) > 32 {
					return "XLSX_INVALID_CELL_REFERENCE"
				}
				text := cell.value.String()
				if cell.typ == "inlineStr" {
					text = cell.inline.String()
				}
				if cell.typ == "s" {
					index, err := strconv.Atoi(strings.TrimSpace(text))
					if err != nil || index < 0 || index >= len(shared) {
						return "XLSX_INVALID_REFERENCE"
					}
					text = shared[index]
				}
				if cell.typ != "e" {
					if reason := s.scanXMLValue(ctx, obs, sheet.Name+"!"+cell.ref, text, rules, hits); reason != "" {
						return reason
					}
				}
				cell.active = false
			case "worksheet":
				rootClosed = true
			}
		}
	}
}
