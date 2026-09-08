package reports

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"
)

// sampleReportData 测试用主报告数据。
func sampleReportData() *ReportData {
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	return &ReportData{
		ReportType:     TypeDaily,
		RangeStart:     now,
		RangeEnd:       now.Add(24 * time.Hour),
		GeneratedAt:    now,
		ScopeAll:       true,
		RiskLevel:      "MEDIUM",
		TotalRequests:  12345,
		RequestsTrend:  []Point{{Time: now, Value: 100}},
		EventsTotal:    12,
		EventsBlocked:  8,
		EventsObserved: 4,
		AttackTypes:    []KV{{Key: "sqli", Value: 8}},
		SeverityDist:   []KV{{Key: "HIGH", Value: 3}},
		AttackTrend:    []Point{{Time: now, Value: 5}},
		TopSourceIPs:   []KV{{Key: "1.2.3.4", Value: 10}},
		AttackedApps:   []KV{{Key: "shop", Value: 7}},
		Conclusions:    []string{"结论A"},
		Suggestions:    []string{"建议A"},
	}
}

// unzipDocx 打开 docx（zip）并返回文件名集合与 document.xml 内容。
func unzipDocx(t *testing.T, data []byte) (map[string]bool, string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	names := map[string]bool{}
	var docXML string
	for _, f := range zr.File {
		names[f.Name] = true
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open document.xml: %v", err)
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(rc)
			_ = rc.Close()
			docXML = buf.String()
		}
	}
	return names, docXML
}

func TestRenderDOCX(t *testing.T) {
	data := sampleReportData()
	charts, err := BuildMainCharts(data, testFontPath(t))
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	out, err := RenderDOCX(nil, data, "JZ-202608-0001", charts)
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	if len(out) < 2 || string(out[:2]) != "PK" {
		t.Fatal("docx magic invalid")
	}
	names, docXML := unzipDocx(t, out)
	if !names["word/document.xml"] {
		t.Fatal("docx missing word/document.xml")
	}
	for _, want := range []string{"安全报告", "JZ-202608-0001", "管理摘要", "结论A", "建议A"} {
		if !strings.Contains(docXML, want) {
			t.Fatalf("document.xml missing %q", want)
		}
	}
	// 图表：媒体文件应嵌入包内
	var hasMedia bool
	for n := range names {
		if strings.HasPrefix(n, "word/media/") {
			hasMedia = true
			break
		}
	}
	if !hasMedia {
		t.Fatal("docx missing embedded chart image (word/media/)")
	}
}

func TestRenderDOCXWithoutCharts(t *testing.T) {
	out, err := RenderDOCX(nil, sampleReportData(), "JZ-202608-0002", nil)
	if err != nil {
		t.Fatalf("render docx without charts: %v", err)
	}
	if len(out) < 2 || string(out[:2]) != "PK" {
		t.Fatal("docx magic invalid")
	}
}

func TestRenderDOCXNilData(t *testing.T) {
	if _, err := RenderDOCX(nil, nil, "JZ-202608-0003", nil); err == nil {
		t.Fatal("expect error for nil data")
	}
}

func TestRenderDOCXSectionSwitch(t *testing.T) {
	tpl := BuiltinTemplate()
	tpl.Sections = DefaultSections()
	tpl.Sections[SectionCover] = false
	tpl.Sections[SectionConclusions] = false
	out, err := RenderDOCX(tpl, sampleReportData(), "JZ-202608-0004", nil)
	if err != nil {
		t.Fatalf("render docx: %v", err)
	}
	_, docXML := unzipDocx(t, out)
	if strings.Contains(docXML, "结论A") {
		t.Fatal("conclusions section should be disabled")
	}
}

func TestRenderAPIDOCX(t *testing.T) {
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	data := &APIReportData{
		ReportType:  TypeAPIAsset,
		RangeStart:  now,
		RangeEnd:    now.Add(7 * 24 * time.Hour),
		GeneratedAt: now,
		Asset: &APIAssetReport{
			TotalEndpoints: 10,
			StatusDist:     []KV{{Key: "CONFIRMED", Value: 6}, {Key: "ZOMBIE", Value: 1}},
		},
		Conclusions: []string{"结论B"},
		Suggestions: []string{"建议B"},
	}
	charts, err := BuildAPICharts(data, testFontPath(t))
	if err != nil {
		t.Fatalf("build api charts: %v", err)
	}
	out, err := RenderAPIDOCX(nil, data, "JZ-202608-0005", charts)
	if err != nil {
		t.Fatalf("render api docx: %v", err)
	}
	if len(out) < 2 || string(out[:2]) != "PK" {
		t.Fatal("api docx magic invalid")
	}
	names, docXML := unzipDocx(t, out)
	for _, want := range []string{"API资产周报", "资产总览", "结论B"} {
		if !strings.Contains(docXML, want) {
			t.Fatalf("api document.xml missing %q", want)
		}
	}
	var hasMedia bool
	for n := range names {
		if strings.HasPrefix(n, "word/media/") {
			hasMedia = true
			break
		}
	}
	if !hasMedia {
		t.Fatal("api docx missing embedded chart image")
	}
}

func TestRenderAPIDOCXNilData(t *testing.T) {
	if _, err := RenderAPIDOCX(nil, nil, "JZ-202608-0006", nil); err == nil {
		t.Fatal("expect error for nil data")
	}
}
