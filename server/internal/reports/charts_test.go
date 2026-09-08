package reports

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testFontPath 测试用中文字体路径（相对包目录）。
func testFontPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "assets", "fonts", FontFileName)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("chart font not available: %v", err)
	}
	return p
}

func TestNewChartBuilderDegrade(t *testing.T) {
	b, err := newChartBuilder(filepath.Join(t.TempDir(), "missing.ttf"))
	if err != nil {
		t.Fatalf("missing font should degrade without error, got %v", err)
	}
	if b.fontOK {
		t.Fatal("fontOK should be false when font file missing")
	}
}

func TestNewChartBuilderBadFont(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.ttf")
	if err := os.WriteFile(bad, []byte("not a font"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newChartBuilder(bad)
	if !errors.Is(err, errChartFont) {
		t.Fatalf("expect errChartFont, got %v", err)
	}
}

func TestBuildMainChartsEmptyData(t *testing.T) {
	mc, err := BuildMainCharts(&ReportData{}, testFontPath(t))
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	if mc.Traffic != nil || mc.AttackTypes != nil || mc.SourceIPs != nil {
		t.Fatal("charts should be nil when data empty")
	}
}

func TestBuildMainCharts(t *testing.T) {
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	data := &ReportData{
		RequestsTrend: []Point{{Time: now, Value: 100}, {Time: now.Add(24 * time.Hour), Value: 200}},
		AttackTrend:   []Point{{Time: now, Value: 5}, {Time: now.Add(time.Hour), Value: 9}},
		AttackTypes:   []KV{{Key: "sqli", Value: 8}, {Key: "xss", Value: 4}},
		SeverityDist:  []KV{{Key: "HIGH", Value: 3}, {Key: "LOW", Value: 9}},
		TopSourceIPs:  []KV{{Key: "1.2.3.4", Value: 10}, {Key: "5.6.7.8", Value: 6}},
		AttackedApps:  []KV{{Key: "app-<b>", Value: 7}},
	}
	mc, err := BuildMainCharts(data, testFontPath(t))
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	for name, img := range map[string]*ChartImage{
		"traffic": mc.Traffic, "attack_trend": mc.AttackTrend, "attack_types": mc.AttackTypes,
		"severity": mc.Severity, "source_ips": mc.SourceIPs, "attacked_apps": mc.AttackedApps,
	} {
		if img == nil {
			t.Fatalf("chart %s should not be nil", name)
		}
		if len(img.PNG) < 8 || string(img.PNG[1:4]) != "PNG" {
			t.Fatalf("chart %s png magic invalid", name)
		}
		if !strings.Contains(img.SVG, "<svg") {
			t.Fatalf("chart %s svg missing root element", name)
		}
	}
	// 标签消毒：应用名中的 <b> 不得原样进入 SVG
	if strings.Contains(mc.AttackedApps.SVG, "app-<b>") {
		t.Fatal("svg contains unsanitized label")
	}
	if !strings.Contains(mc.AttackedApps.SVG, "app-＜b＞") {
		t.Fatal("svg should contain sanitized full-width label")
	}
}

func TestBuildAPICharts(t *testing.T) {
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name                  string
		data                  *APIReportData
		wantD1, wantD2, wantT bool
	}{
		{"asset", &APIReportData{ReportType: TypeAPIAsset, Asset: &APIAssetReport{
			StatusDist: []KV{{Key: "CONFIRMED", Value: 3}, {Key: "ZOMBIE", Value: 1}},
		}}, true, false, false},
		{"risk", &APIReportData{ReportType: TypeAPIRisk, Risk: &APIRiskReport{
			TypeDist: []KV{{Key: "SHADOW", Value: 2}}, SeverityDist: []KV{{Key: "HIGH", Value: 2}},
		}}, true, true, false},
		{"weak", &APIReportData{ReportType: TypeAPIWeak, Weakness: &APIWeaknessReport{
			StatusDist: []KV{{Key: "TO_FIX", Value: 2}}, SeverityDist: []KV{{Key: "MEDIUM", Value: 2}},
		}}, true, true, false},
		{"sens", &APIReportData{ReportType: TypeAPISens, Sensitive: &APISensitiveReport{
			TypeDist: []KV{{Key: "phone", Value: 5}},
			DailyNew: []Point{{Time: now, Value: 1}, {Time: now.Add(24 * time.Hour), Value: 2}},
		}}, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac, err := BuildAPICharts(tc.data, testFontPath(t))
			if err != nil {
				t.Fatalf("build api charts: %v", err)
			}
			if (ac.Dist1 != nil) != tc.wantD1 {
				t.Fatalf("Dist1 presence = %v, want %v", ac.Dist1 != nil, tc.wantD1)
			}
			if (ac.Dist2 != nil) != tc.wantD2 {
				t.Fatalf("Dist2 presence = %v, want %v", ac.Dist2 != nil, tc.wantD2)
			}
			if (ac.Trend != nil) != tc.wantT {
				t.Fatalf("Trend presence = %v, want %v", ac.Trend != nil, tc.wantT)
			}
		})
	}
}

func TestSanitizeChartLabel(t *testing.T) {
	got := sanitizeChartLabel(`a<b>&"c"'`)
	if strings.ContainsAny(got, `<>&"'`) {
		t.Fatalf("label still contains xml meta chars: %s", got)
	}
	if got != `a＜b＞＆＂c＂＇` {
		t.Fatalf("unexpected sanitized label: %s", got)
	}
}

func TestTrendLabelFormat(t *testing.T) {
	now := time.Now()
	hourly := []Point{{Time: now}, {Time: now.Add(time.Hour)}}
	if f := trendLabelFormat(hourly); f != "01-02 15:04" {
		t.Fatalf("hourly format = %s", f)
	}
	daily := []Point{{Time: now}, {Time: now.Add(24 * time.Hour)}}
	if f := trendLabelFormat(daily); f != "01-02" {
		t.Fatalf("daily format = %s", f)
	}
}

func TestRenderHTMLWithCharts(t *testing.T) {
	data := sampleReportData()
	charts, err := BuildMainCharts(data, testFontPath(t))
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0010", charts)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	if !strings.Contains(out, `<div class="chart"><svg`) {
		t.Fatal("html should contain inline svg chart")
	}
	// 无图表（字体降级）时不应出现 chart 容器
	html2, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0011", nil)
	if err != nil {
		t.Fatalf("render html without charts: %v", err)
	}
	if strings.Contains(string(html2), `<div class="chart">`) {
		t.Fatal("html without charts should not contain chart container")
	}
}

func TestRenderPDFWithCharts(t *testing.T) {
	data := sampleReportData()
	fontPath := testFontPath(t)
	charts, err := BuildMainCharts(data, fontPath)
	if err != nil {
		t.Fatalf("build charts: %v", err)
	}
	pdf, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0012", fontPath, charts)
	if err != nil {
		t.Fatalf("render pdf: %v", err)
	}
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		t.Fatal("pdf magic invalid")
	}
}
