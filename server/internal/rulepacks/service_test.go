package rulepacks

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jiuzhang-waf/server/internal/wafrules"
)

func TestComputeRuleDiff(t *testing.T) {
	oldRules := []*wafrules.Rule{
		{RuleID: 942100, RuleSource: wafrules.SourceCRS, Name: "SQLi", AttackType: "SQL_INJECTION", Severity: "CRITICAL", ContentHash: "h1", Tags: json.RawMessage(`["attack-sqli"]`)},
		{RuleID: 1000001, RuleSource: wafrules.SourceCustomPack, Name: "Old CVE", AttackType: "COMMAND_INJECTION", Severity: "CRITICAL", ContentHash: "h2", Tags: json.RawMessage(`["attack-rce"]`)},
		{RuleID: 1000002, RuleSource: wafrules.SourceCustomPack, Name: "Deprecated", AttackType: "OTHER", Severity: "NOTICE", ContentHash: "h3", Tags: json.RawMessage(`[]`)},
	}
	newRules := []*wafrules.Rule{
		{RuleID: 942100, RuleSource: wafrules.SourceCRS, Name: "SQLi", AttackType: "SQL_INJECTION", Severity: "CRITICAL", ContentHash: "h1", Tags: json.RawMessage(`["attack-sqli"]`)},
		{RuleID: 1000001, RuleSource: wafrules.SourceCustomPack, Name: "Old CVE v2", AttackType: "COMMAND_INJECTION", Severity: "CRITICAL", ContentHash: "h2-new", Tags: json.RawMessage(`["attack-rce"]`)},
		{RuleID: 1000099, RuleSource: wafrules.SourceCustomPack, Name: "New CVE", AttackType: "SSRF", Severity: "CRITICAL", ContentHash: "h4", Tags: json.RawMessage(`["attack-ssrf"]`)},
	}

	diff, addedByTag, removed, updated := computeRuleDiff(oldRules, newRules)
	if diff.TotalRules != 3 || diff.AddedCount != 1 || diff.UpdatedCount != 1 || diff.RemovedCount != 1 || diff.UnchangedCount != 1 {
		t.Fatalf("unexpected diff summary: %+v", diff)
	}
	if addedByTag["attack-ssrf"] != 1 {
		t.Fatalf("expected addedByTag[attack-ssrf]=1, got %v", addedByTag)
	}
	if !removed[1000002] || !updated[1000001] {
		t.Fatalf("expected removed[1000002] & updated[1000001], got removed=%v updated=%v", removed, updated)
	}
}

func TestHandlerCurrentAndUploadValidation(t *testing.T) {
	seedDir := makeMinimalRulesTree(t)
	storeDir := filepath.Join(t.TempDir(), "rules-store")
	svc := NewService(Config{
		StoreDir:             storeDir,
		ArchivesDir:          filepath.Join(t.TempDir(), "archives"),
		SeedDir:              seedDir,
		FallbackCRSDir:       filepath.Join(seedDir, "crs", "rules"),
		FallbackCRSVersion:   "4.28.0",
		GatewayRulesRoot:     "/etc/caddy/rules",
		CurrentSystemVersion: "1.19.1",
		LocalNodeName:        "gw-test-01",
		Retention:            5,
	}, nil, nil)
	if err := svc.EnsureInitialized(context.Background()); err != nil {
		t.Fatalf("EnsureInitialized: %v", err)
	}
	h := NewHandler(svc, nil)

	// 1. GET /current returns VERSIONED mode + seeded builtin version
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rule-packs/current", nil)
	h.Current(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /current status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data CurrentStatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode current response: %v", err)
	}
	if resp.Data.StorageMode != StorageModeVersioned || !resp.Data.Writable || resp.Data.ActiveVersion != "builtin-1.19.1" {
		t.Fatalf("unexpected current status: %+v", resp.Data)
	}
	if resp.Data.GatewayRulesBasePath != "/etc/caddy/rules/releases/builtin-1.19.1" {
		t.Fatalf("unexpected gateway rules base path: %q", resp.Data.GatewayRulesBasePath)
	}
	if got := readCRSVersionFromDir(repoRulesRoot, "fallback"); got != "4.28.0" {
		t.Fatalf("readCRSVersionFromDir(real repo) = %q, want 4.28.0", got)
	}

	// 2. POST /upload rejects non-.tar.gz extension
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "evil.zip")
	_, _ = fw.Write([]byte("PK\x03\x04"))
	_ = mw.Close()
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/rule-packs/upload", &body)
	req2.Header.Set("Content-Type", mw.FormDataContentType())
	h.Upload(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for .zip upload, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// 3. POST /nodes/{id}/retry-sync returns 503 in single-node mode
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/rule-packs/nodes/11111111-1111-4111-8111-111111111111/retry-sync", nil)
	req3.SetPathValue("node_id", "11111111-1111-4111-8111-111111111111")
	h.RetryNodeSync(rec3, req3)
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for single-node retry-sync, got %d body=%s", rec3.Code, rec3.Body.String())
	}
}
