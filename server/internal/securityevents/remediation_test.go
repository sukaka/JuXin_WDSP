package securityevents

import "testing"

func TestRemediationFor(t *testing.T) {
	r := RemediationFor("SQL_INJECTION")
	if r.AttackLabel != "SQL 注入" || len(r.AnalyzeSteps) == 0 || len(r.FixSuggestions) == 0 {
		t.Errorf("SQL_INJECTION remediation incomplete: %+v", r)
	}
	x := RemediationFor("XSS")
	if len(x.Hardening) == 0 {
		t.Errorf("XSS hardening empty")
	}
	// LFI 复用路径穿越知识
	l := RemediationFor("LOCAL_FILE_INCLUSION")
	if l.AttackLabel != "本地文件包含（LFI）" || len(l.AnalyzeSteps) == 0 {
		t.Errorf("LFI fallback broken: %+v", l)
	}
	// 未知类型回退通用建议且保留原类型
	g := RemediationFor("SOME_FUTURE_TYPE")
	if g.AttackType != "SOME_FUTURE_TYPE" || len(g.AnalyzeSteps) == 0 {
		t.Errorf("generic fallback broken: %+v", g)
	}
}
