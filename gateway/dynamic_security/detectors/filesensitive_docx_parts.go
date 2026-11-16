package detectors

import (
	"archive/zip"
	"sort"
	"strconv"
	"strings"
)

const maxDOCXTextBytes = 16 << 20

type docxTextPart struct {
	Name  string
	Scope string
	Body  []byte
}

func readDOCXTextParts(body []byte) ([]docxTextPart, string) {
	pkg, reason := openOOXMLPackage(body)
	if reason != "" {
		return nil, reason
	}
	entries := make([]*zip.File, 0, 8)
	seen := map[string]bool{}
	for _, entry := range pkg.File {
		if entry.Name != "word/document.xml" && !isDOCXHeaderFooterPart(entry.Name) && !isDOCXAnnotationPart(entry.Name) {
			continue
		}
		if seen[entry.Name] {
			return nil, "DOCX_DUPLICATE_PART"
		}
		seen[entry.Name] = true
		entries = append(entries, entry)
	}
	if !seen["word/document.xml"] {
		return nil, "OOXML_DOCUMENT_MISSING"
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == "word/document.xml" {
			return true
		}
		if entries[j].Name == "word/document.xml" {
			return false
		}
		return entries[i].Name < entries[j].Name
	})
	parts := make([]docxTextPart, 0, len(entries))
	sampleBytes := 0
	for _, entry := range entries {
		raw, reason := readOOXMLPart(pkg, entry)
		if reason != "" {
			return nil, reason
		}
		sampleBytes += len(raw)
		if sampleBytes > maxDOCXTextBytes {
			return nil, "DOCX_CONTENT_TOO_LARGE"
		}
		scope := "DOCX_HEADER_FOOTER"
		switch {
		case entry.Name == "word/document.xml":
			scope = "DOCX_MAIN_DOCUMENT"
		case isDOCXAnnotationPart(entry.Name):
			scope = "DOCX_ANNOTATIONS"
		}
		parts = append(parts, docxTextPart{Name: entry.Name, Scope: scope, Body: raw})
	}
	return parts, ""
}

func isDOCXAnnotationPart(name string) bool {
	switch name {
	case "word/comments.xml", "word/footnotes.xml", "word/endnotes.xml":
		return true
	default:
		return false
	}
}

func isDOCXHeaderFooterPart(name string) bool {
	for _, kind := range []string{"header", "footer"} {
		prefix := "word/" + kind
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".xml") {
			continue
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".xml")
		if raw == "" || raw == "0" || strings.HasPrefix(raw, "0") {
			continue
		}
		if index, err := strconv.Atoi(raw); err == nil && index > 0 {
			return true
		}
	}
	return false
}
