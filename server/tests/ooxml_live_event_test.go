package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func assertOOXMLLiveEvent(t *testing.T, logPath, direction string, format liveOOXMLFormat) {
	t.Helper()
	readPath := logPath
	if dir := os.Getenv("WDSP_OOXML_LIVE_LOG_READ_DIR"); dir != "" {
		readPath = strings.TrimSuffix(dir, "/") + "/" + strings.TrimPrefix(logPath, "/var/log/caddy/")
	}
	raw, err := os.ReadFile(readPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("unexpected event log size: %d", len(raw))
	}
	if bytes.Contains(raw, []byte(format.Marker)) {
		t.Fatal("live event contains the original sensitive marker")
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("want one isolated %s event, got %d", direction, len(lines))
	}
	var event struct {
		IsAPI          bool `json:"is_api"`
		ResponseStatus int  `json:"response_status"`
		Details        []struct {
			RuleID   string            `json:"rule_id"`
			Category string            `json:"category"`
			Severity string            `json:"severity"`
			Evidence map[string]string `json:"evidence"`
		} `json:"details"`
		FileObservations []struct {
			Direction      string   `json:"direction"`
			FileName       string   `json:"filename"`
			SensitiveTypes []string `json:"sensitive_types"`
			ContentSHA256  string   `json:"content_sha256"`
		} `json:"file_observations"`
	}
	if err := json.Unmarshal(lines[0], &event); err != nil {
		t.Fatal(err)
	}
	if !event.IsAPI || event.ResponseStatus != 200 {
		t.Fatalf("%s must be a completed API event: %+v", direction, event)
	}
	if len(event.FileObservations) != 1 {
		t.Fatalf("%s asset observation missing: %+v", direction, event.FileObservations)
	}
	observation := event.FileObservations[0]
	if observation.Direction != direction || observation.FileName != format.Filename || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "wdsp_test_marker" || observation.ContentSHA256 != format.ContentSHA256 {
		t.Fatalf("unexpected %s asset observation: %+v", direction, observation)
	}
	found := false
	for _, detail := range event.Details {
		if detail.RuleID == "file.sensitive_content_not_inspected" {
			t.Fatalf("%s was not fully inspected: %+v", direction, detail)
		}
		if detail.RuleID != "file.sensitive_content" {
			continue
		}
		found = true
		if format.SourcePart != "" && detail.Evidence["source_part"] != format.SourcePart {
			t.Fatalf("unexpected %s source part: %+v", direction, detail)
		}
		if detail.Category != "OBSERVE" || detail.Severity != "MEDIUM" || detail.Evidence["direction"] != direction || detail.Evidence["data_type"] != "wdsp_test_marker" || detail.Evidence["field"] != format.Field || detail.Evidence["scope"] != format.Scope || detail.Evidence["sample_truncated"] != "false" {
			t.Fatalf("unexpected %s evidence: %+v", direction, detail)
		}
	}
	if !found {
		t.Fatalf("%s file finding missing: %+v", direction, event.Details)
	}
}
