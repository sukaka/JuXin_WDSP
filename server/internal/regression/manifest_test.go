// manifest_test.go manifest/分块 schema 校验与计数对账测试。
package regression

import (
	"strings"
	"testing"
)

const testFP = "cfgfpv1:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
const testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validManifestJSON() string {
	return `{"candidate":{"build_digest":"sha256:bb","compiler":"go1.24","config_fingerprint":"` + testFP + `","corpus_id":"p1-corpus","corpus_sha256":"` + testHash + `","corpus_version":1,"plan_sha256":"` + testHash + `"},"counts":{"blocked":0,"executed":2,"failed":0,"mandatory_failed":0,"mandatory_total":1,"not_run":0,"passed":2,"planned":2,"skipped":0},"created_at":"2026-09-08T01:00:00Z","declared_status":"PASS","files":[{"name":"cases-0.json","role":"CASES_CHUNK","sha256":"` + testHash + `","size_bytes":100}],"level":"FULL","run_finished_at":"2026-09-08T01:10:00Z","run_id":"20260908T010000-abcdef","run_started_at":"2026-09-08T01:00:00Z","schema_version":1}`
}

func TestParseManifestValid(t *testing.T) {
	m, reasons := ParseManifest([]byte(validManifestJSON()))
	if reasons != nil {
		t.Fatalf("valid manifest rejected: %v", reasons)
	}
	if m.RunID != "20260908T010000-abcdef" || m.Level != LevelFull || m.Counts.Planned != 2 {
		t.Fatalf("parsed mismatch: %+v", m)
	}
}

func TestParseManifestRejections(t *testing.T) {
	cases := map[string]string{
		"unknown schema version": strings.Replace(validManifestJSON(), `"schema_version":1`, `"schema_version":2`, 1),
		"bad level":              strings.Replace(validManifestJSON(), `"level":"FULL"`, `"level":"PARTIAL"`, 1),
		"bad fingerprint":        strings.Replace(validManifestJSON(), testFP, "deadbeef", 1),
		"bad status":             strings.Replace(validManifestJSON(), `"declared_status":"PASS"`, `"declared_status":"GREEN"`, 1),
		"bad time":               strings.Replace(validManifestJSON(), `"created_at":"2026-09-08T01:00:00Z"`, `"created_at":"yesterday"`, 1),
		"manifest role in files": strings.Replace(validManifestJSON(), `"role":"CASES_CHUNK"`, `"role":"MANIFEST"`, 1),
		"path in name":           strings.Replace(validManifestJSON(), `"name":"cases-0.json"`, `"name":"../evil.json"`, 1),
		"unknown field":          strings.Replace(validManifestJSON(), `"schema_version":1`, `"schema_version":1,"skip_gate":true`, 1),
	}
	for name, doc := range cases {
		if _, reasons := ParseManifest([]byte(doc)); reasons == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

const chunkJSON = `{"cases":[{"case_id":"WAF-SQLI-001","case_version":1,"criticality":"MANDATORY","family":"sqli","status":"PASS","truth":"ATTACK"},{"case_id":"WAF-BENIGN-001","case_version":1,"criticality":"OPTIONAL","family":"benign","status":"PASS","truth":"BENIGN"}],"run_id":"20260908T010000-abcdef","schema_version":1}`

func TestParseCasesChunkValid(t *testing.T) {
	ch, reasons := ParseCasesChunk([]byte(chunkJSON), "20260908T010000-abcdef")
	if reasons != nil {
		t.Fatalf("valid chunk rejected: %v", reasons)
	}
	if len(ch.Cases) != 2 {
		t.Fatalf("cases=%d", len(ch.Cases))
	}
}

func TestParseCasesChunkRunIDMismatch(t *testing.T) {
	if _, reasons := ParseCasesChunk([]byte(chunkJSON), "other-run"); reasons == nil {
		t.Fatal("run_id mismatch accepted")
	}
}

func TestReconcileCounts(t *testing.T) {
	m, reasons := ParseManifest([]byte(validManifestJSON()))
	if reasons != nil {
		t.Fatal(reasons)
	}
	ch, _ := ParseCasesChunk([]byte(chunkJSON), m.RunID)
	if bad := ReconcileCounts(m, []*CasesChunk{ch}); len(bad) > 0 {
		t.Fatalf("consistent counts rejected: %v", bad)
	}
	// 计数不一致
	m2 := *m
	m2.Counts.Planned = 3
	if bad := ReconcileCounts(&m2, []*CasesChunk{ch}); len(bad) == 0 {
		t.Fatal("inconsistent planned count accepted")
	}
	// 用例重复（跨块）
	dup := *ch
	dup.Cases = append([]CaseResult{}, ch.Cases...)
	if bad := ReconcileCounts(m, []*CasesChunk{ch, &dup}); len(bad) == 0 {
		t.Fatal("duplicate case_id across chunks accepted")
	}
	// 强制用例未过：与 manifest mandatory_failed=0 不一致
	mandatoryFail := &CasesChunk{SchemaVersion: 1, RunID: m.RunID, Cases: []CaseResult{
		{CaseID: "WAF-SQLI-001", CaseVersion: 1, Criticality: "MANDATORY", Family: "sqli", Status: "FAIL", Truth: "ATTACK"},
		{CaseID: "WAF-BENIGN-001", CaseVersion: 1, Criticality: "OPTIONAL", Family: "benign", Status: "PASS", Truth: "BENIGN"},
	}}
	if bad := ReconcileCounts(m, []*CasesChunk{mandatoryFail}); len(bad) == 0 {
		t.Fatal("mandatory failure not detected by reconciliation")
	}
}
