package detectors

import "testing"

func TestObjectEnumerationHMACCanonicalizesIdentifiers(t *testing.T) {
	ref := objectRef{source: "path", typ: "numeric", dim: "2"}
	if objectEnumerationHMAC("salt", "GET /v1/cases/{id}", ref, "004100") != objectEnumerationHMAC("salt", "GET /v1/cases/{id}", ref, "4100") {
		t.Fatal("leading zeros must not inflate the distinct-object set")
	}
	ref.typ = "uuid"
	if objectEnumerationHMAC("salt", "GET /v1/documents/{uuid}", ref, "550E8400-E29B-41D4-A716-446655440000") != objectEnumerationHMAC("salt", "GET /v1/documents/{uuid}", ref, "550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("UUID case must not inflate the distinct-object set")
	}
	if objectEnumerationHMAC("salt", "app-a\x00GET /v1/cases/{id}", ref, "4100") == objectEnumerationHMAC("salt", "app-b\x00GET /v1/cases/{id}", ref, "4100") {
		t.Fatal("application isolation must extend to protected object references")
	}
}
