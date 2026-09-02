package identityevents

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeIdentityEvidence(t *testing.T) {
	got := sanitizeIdentityEvidence([]string{
		"credential:oauth_unverified",
		"credential:oauth_unverified",
		"credential:oauth:raw-secret",
		"browser_fingerprint",
		strings.Repeat("x", maxIdentityEvidenceBytes+1),
	})
	if len(got) != 2 || got[0] != "credential:oauth_unverified" || got[1] != "browser_fingerprint" {
		t.Fatalf("sanitized evidence = %#v", got)
	}
}

func TestSanitizeSignalMetadata(t *testing.T) {
	got := sanitizeSignalMetadata(map[string]any{
		"hit_count":     3,
		"path":          "/.git/config",
		"authorization": "Bearer secret",
		"unknown":       "must be dropped",
		"nested":        map[string]any{"token": "secret"},
		"long":          strings.Repeat("x", maxSignalMetadataString+1),
	})
	if got["hit_count"] != 3 || got["path"] != "/.git/config" {
		t.Fatalf("safe metadata missing: %#v", got)
	}
	for _, key := range []string{"authorization", "unknown", "nested", "long"} {
		if _, ok := got[key]; ok {
			t.Fatalf("metadata key %q was not removed: %#v", key, got)
		}
	}
	raw, err := json.Marshal(got)
	if err != nil || len(raw) > maxSignalMetadataBytes {
		t.Fatalf("metadata size = %d, err=%v", len(raw), err)
	}
}

func TestParseSignalSanitizesEvidenceAndMetadata(t *testing.T) {
	line := `{"record_type":"recon_signal","occurred_at":"2026-09-01T10:00:00Z","identity_key":"ik-safe","identity_evidence":["credential:jwt","jwt:raw-token"],"rule_code":"JR-RECON-001","signal":"URI_ENUMERATION","metadata":{"request_count":3,"token":"secret"}}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse signal: %v", err)
	}
	if len(rec.IdentityEvidence) != 1 || rec.IdentityEvidence[0] != "credential:jwt" {
		t.Fatalf("evidence = %#v", rec.IdentityEvidence)
	}
	if rec.Metadata["request_count"] != float64(3) {
		t.Fatalf("metadata = %#v", rec.Metadata)
	}
	if _, ok := rec.Metadata["token"]; ok {
		t.Fatalf("sensitive metadata survived: %#v", rec.Metadata)
	}
}
