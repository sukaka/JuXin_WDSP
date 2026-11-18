package pcapevidence

import (
	"encoding/json"
	"testing"
)

func TestArtifactIDRoundTripAndValidation(t *testing.T) {
	id, err := NewArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	if id.IsZero() {
		t.Fatal("generated artifact id is zero")
	}
	parsed, err := ParseArtifactID(id.String())
	if err != nil || parsed != id {
		t.Fatalf("artifact id round trip failed: %v", err)
	}
	encoded, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ArtifactID
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != id {
		t.Fatalf("artifact JSON round trip failed: %v", err)
	}
	for _, invalid := range []string{"", "not-a-uuid", "0123456789abcdef0123456789abcdef", "01234567-89ab-cdef-0123-456789abcdez"} {
		if _, err := ParseArtifactID(invalid); err == nil {
			t.Fatalf("invalid artifact id %q was accepted", invalid)
		}
	}
}
