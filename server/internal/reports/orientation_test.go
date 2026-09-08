package reports

import (
	"regexp"
	"strings"
	"testing"
)

// TestOrientationPlumbing 纸张方向端到端：PDF MediaBox 与 docx sectPr。
func TestOrientationPlumbing(t *testing.T) {
	data := sampleCombinedData()
	data.PageOrientation = OrientationLandscape
	fontPath := testFontPath(t)

	pdf, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0902", fontPath, nil)
	if err != nil {
		t.Fatalf("render landscape pdf: %v", err)
	}
	m := regexp.MustCompile(`MediaBox\s*\[([^\]]+)\]`).FindStringSubmatch(string(pdf))
	if len(m) < 2 || m[1] != "0 0 841.89 595.28" {
		t.Fatalf("landscape pdf mediabox wrong: %v", m)
	}

	docx, err := RenderDOCX(BuiltinTemplate(), data, "JZ-202608-0903", nil)
	if err != nil {
		t.Fatalf("render landscape docx: %v", err)
	}
	_, docXML := unzipDocx(t, docx)
	if !strings.Contains(docXML, `orient="landscape"`) {
		t.Fatal("docx should contain landscape orientation")
	}

	// 默认（空值）→ 竖向
	data.PageOrientation = ""
	pdfP, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0904", fontPath, nil)
	if err != nil {
		t.Fatalf("render portrait pdf: %v", err)
	}
	mP := regexp.MustCompile(`MediaBox\s*\[([^\]]+)\]`).FindStringSubmatch(string(pdfP))
	if len(mP) < 2 || mP[1] != "0 0 595.28 841.89" {
		t.Fatalf("portrait pdf mediabox wrong: %v", mP)
	}
	docxP, err := RenderDOCX(BuiltinTemplate(), data, "JZ-202608-0905", nil)
	if err != nil {
		t.Fatalf("render portrait docx: %v", err)
	}
	_, docXMLP := unzipDocx(t, docxP)
	if strings.Contains(docXMLP, `orient="landscape"`) {
		t.Fatal("portrait docx should not be landscape")
	}
}

func TestValidPageOrientation(t *testing.T) {
	if !validPageOrientation("") || !validPageOrientation("P") || !validPageOrientation("L") {
		t.Fatal("valid orientations rejected")
	}
	if validPageOrientation("X") {
		t.Fatal("invalid orientation accepted")
	}
	if NormalizePageOrientation("") != OrientationPortrait || NormalizePageOrientation("L") != OrientationLandscape {
		t.Fatal("normalize wrong")
	}
}
