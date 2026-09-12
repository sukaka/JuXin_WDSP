package reports

import (
	"strings"
	"testing"
)

func TestContentScopeBasics(t *testing.T) {
	if !validContentScope("") || !validContentScope(ScopeWAF) || !validContentScope(ScopeAPI) || !validContentScope(ScopeWAFAPI) {
		t.Fatal("validContentScope should accept empty/WAF/API/WAF_API")
	}
	if validContentScope("ALL") {
		t.Fatal("invalid scope should be rejected")
	}
	if NormalizeContentScope("") != ScopeWAFAPI {
		t.Fatal("empty scope should normalize to WAF_API")
	}
	if !ContentScopeIncludesAPI(ScopeWAFAPI) || !ContentScopeIncludesAPI(ScopeAPI) || ContentScopeIncludesAPI(ScopeWAF) {
		t.Fatal("includes api wrong")
	}
	if !ContentScopeIncludesWeb(ScopeWAFAPI) || !ContentScopeIncludesWeb(ScopeWAF) || ContentScopeIncludesWeb(ScopeAPI) {
		t.Fatal("includes web wrong")
	}
	if ContentScopeName(ScopeAPI) != "API 动态防护" {
		t.Fatalf("scope name wrong: %q", ContentScopeName(ScopeAPI))
	}
}

func TestTplForScope(t *testing.T) {
	tpl := BuiltinTemplate()
	// WAF：API 部分章节关闭，Web 章节保留
	w := tplForScope(tpl, ScopeWAF)
	for _, k := range apiPartSectionKeys {
		if w.Show(k) {
			t.Fatalf("api section %s should be closed in WAF scope", k)
		}
	}
	if !w.Show(SectionSummary) || !w.Show(SectionAttackTrend) {
		t.Fatal("web sections should stay open in WAF scope")
	}
	// API：Web 内容章节关闭，API 章节保留，元章节保留
	a := tplForScope(tpl, ScopeAPI)
	for _, k := range webContentSectionKeys {
		if a.Show(k) {
			t.Fatalf("web section %s should be closed in API scope", k)
		}
	}
	if !a.Show(SectionAPIOverview) || !a.Show(SectionPeriod) || !a.Show(SectionScope) || !a.Show(SectionConclusions) {
		t.Fatal("api/meta sections should stay open in API scope")
	}
	// WAF_API：原样返回
	if tplForScope(tpl, ScopeWAFAPI) != tpl {
		t.Fatal("WAF_API should pass through")
	}
	// 原模板不被修改
	if !tpl.Show(SectionAPIOverview) {
		t.Fatal("original template should not be mutated")
	}
}

func TestRenderHTMLScopeAPI(t *testing.T) {
	data := sampleCombinedData()
	data.ContentScope = ScopeAPI
	// 模拟采集裁剪：API-only 时无 Web 结论
	data.Conclusions = nil
	data.Suggestions = nil
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0700", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	// Web 内容章节不得出现
	for _, absent := range []string{"管理摘要", "环比对比", "攻击趋势", "命中规则 TOP10", "系统运行", "下篇：API 动态防护"} {
		if strings.Contains(out, absent) {
			t.Fatalf("web section should be absent in API scope: %q", absent)
		}
	}
	// API 章节与分隔标题（API-only 无「下篇」前缀）
	for _, want := range []string{"API 动态防护", "API 资产总览", "涉敏端点 TOP10", "内容范围：API 动态防护", "API 安全结论"} {
		if !strings.Contains(out, want) {
			t.Fatalf("api scope html missing %q", want)
		}
	}
}

func TestRenderHTMLScopeWAF(t *testing.T) {
	data := sampleCombinedData()
	data.ContentScope = ScopeWAF
	html, err := RenderHTML(BuiltinTemplate(), data, "JZ-202608-0701", nil)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	out := string(html)
	for _, absent := range []string{"下篇：API 动态防护", "API 资产总览", "涉敏端点 TOP10"} {
		if strings.Contains(out, absent) {
			t.Fatalf("api section should be absent in WAF scope: %q", absent)
		}
	}
	if !strings.Contains(out, "管理摘要") {
		t.Fatal("web sections should be present in WAF scope")
	}
}

func TestRenderPDFScopeAPI(t *testing.T) {
	data := sampleCombinedData()
	data.ContentScope = ScopeAPI
	pdf, err := RenderPDF(BuiltinTemplate(), data, "JZ-202608-0702", testFontPath(t), nil)
	if err != nil {
		t.Fatalf("render pdf scope api: %v", err)
	}
	if len(pdf) < 5 || string(pdf[:5]) != "%PDF-" {
		t.Fatal("pdf magic invalid")
	}
}
