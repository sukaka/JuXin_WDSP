package apiruntime

import (
	"reflect"
	"strings"
	"testing"
)

func TestMergeFileSensitivity(t *testing.T) {
	got := mergeFileSensitivity("pem", []string{"email", "credential_file", "EMAIL", "", "bad\x00type", strings.Repeat("x", 65)})
	want := []string{"credential_file", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged types=%v want=%v", got, want)
	}
	if got := mergeFileSensitivity("txt", []string{"phone", "id_card"}); !reflect.DeepEqual(got, []string{"id_card", "phone"}) {
		t.Fatalf("content types must be sorted: %v", got)
	}
	if got := mergeFileSensitivity("txt", nil); len(got) != 0 {
		t.Fatalf("no evidence must remain non-sensitive: %v", got)
	}
}

func TestFileObservationSensitiveTypesJSONContract(t *testing.T) {
	rec := Record{FileObservations: []FileObservation{{
		Direction: "UPLOAD", FileName: "contacts.csv", Extension: "csv", MIME: "text/csv", Size: 128,
		SensitiveTypes: []string{"email", "phone"},
	}}}
	raw := mustJSON(t, rec)
	if !strings.Contains(raw, `"sensitive_types":["email","phone"]`) {
		t.Fatalf("sensitive type labels must use the existing metadata contract: %s", raw)
	}
}
