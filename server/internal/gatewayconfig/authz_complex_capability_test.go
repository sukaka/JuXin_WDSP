package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRequiredCapabilitiesAuthzComplexRelations(t *testing.T) {
	tests := []struct {
		name  string
		facts CapabilityFacts
		want  string
	}{
		{name: "legacy observe", facts: CapabilityFacts{AuthzSnapshotV2: true}, want: "az/2"},
		{name: "legacy protect", facts: CapabilityFacts{AuthzSnapshotV2: true, AuthzEnforceProtect: true}, want: "az/3"},
		{name: "complex observe", facts: CapabilityFacts{AuthzSnapshotV2: true, AuthzComplexRelations: true}, want: "az/4"},
		{name: "complex protect", facts: CapabilityFacts{AuthzSnapshotV2: true, AuthzEnforceProtect: true, AuthzComplexRelations: true}, want: "az/4"},
		{name: "complex without schema", facts: CapabilityFacts{AuthzComplexRelations: true}, want: "az/4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := RequiredCapabilities(tc.facts)
			if got := detectorVersion(manifest, "authzdecide"); got != tc.want {
				t.Fatalf("authzdecide=%q, want %q; detectors=%+v", got, tc.want, manifest.Detectors)
			}
			count := 0
			for _, detector := range manifest.Detectors {
				if detector.Name == "authzdecide" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("authzdecide requirement count=%d, want 1", count)
			}
		})
	}
}

func TestCapabilityFactsAuthzComplexCurrentAndPreviousValid(t *testing.T) {
	legacy := GuardAuthzObjectModel{RequiredRelation: "OWNER", Enforcement: "PROTECT"}
	complex := GuardAuthzObjectModel{RequiredRelation: "ANY_OF", RequiredRelations: []string{"OWNER", "SHARED_WITH"}, Enforcement: "OBSERVE"}
	if facts := capabilityFactsFromGuard(&GuardConfig{APIAuthzModels: []GuardAuthzObjectModel{legacy}}); facts.AuthzComplexRelations || !facts.AuthzEnforceProtect {
		t.Fatalf("legacy model facts=%+v", facts)
	}
	if facts := capabilityFactsFromGuard(&GuardConfig{APIAuthzModels: []GuardAuthzObjectModel{complex}}); !facts.AuthzComplexRelations || facts.AuthzEnforceProtect {
		t.Fatalf("current OBSERVE ANY_OF facts=%+v", facts)
	}
	if facts := capabilityFactsFromGuard(&GuardConfig{APIAuthzPreviousValid: &GuardAuthzSnapshot{Models: []GuardAuthzObjectModel{complex}}}); !facts.AuthzComplexRelations {
		t.Fatalf("PreviousValid ANY_OF facts=%+v", facts)
	}
	if facts := capabilityFactsFromGuard(&GuardConfig{APIAuthzPreviousValid: &GuardAuthzSnapshot{Models: []GuardAuthzObjectModel{legacy}}}); facts.AuthzComplexRelations {
		t.Fatalf("legacy PreviousValid facts=%+v", facts)
	}
}

func TestCapabilityGateAuthzComplexRelations(t *testing.T) {
	cfg := &GuardConfig{
		APIAuthzSchema: AuthzSnapshotSchemaV2,
		APIAuthzModels: []GuardAuthzObjectModel{{RequiredRelation: "ANY_OF", RequiredRelations: []string{"OWNER", "SHARED_WITH"}, Enforcement: "OBSERVE"}},
	}
	dir := t.TempDir()
	az3 := fullManifest("gw-az3", time.Now().UTC())
	for i := range az3.Detectors {
		if az3.Detectors[i].Name == "authzdecide" {
			az3.Detectors[i].Version = "az/3"
		}
	}
	writeManifest(t, dir, az3)
	publisher := &Publisher{sidecarDir: dir}
	ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), cfg)
	if ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "required=az/4,actual=az/3") {
		t.Fatalf("az/3 must reject OBSERVE ANY_OF: ok=%t code=%s msg=%s", ok, code, msg)
	}

	dir4 := t.TempDir()
	az4 := fullManifest("gw-az4", time.Now().UTC())
	for i := range az4.Detectors {
		if az4.Detectors[i].Name == "authzdecide" {
			az4.Detectors[i].Version = "az/4"
		}
	}
	writeManifest(t, dir4, az4)
	publisher = &Publisher{sidecarDir: dir4}
	if ok, code, msg := publisher.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
		t.Fatalf("az/4 must accept OBSERVE ANY_OF: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

func TestGuardAuthzRequiredRelationsJSONCompatibility(t *testing.T) {
	legacy, err := json.Marshal(GuardAuthzObjectModel{RequiredRelation: "OWNER"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "required_relations") {
		t.Fatalf("legacy OWNER must omit required_relations: %s", legacy)
	}
	complex, err := json.Marshal(GuardAuthzObjectModel{RequiredRelation: "ANY_OF", RequiredRelations: []string{"OWNER", "SHARED_WITH"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(complex), `"required_relations":["OWNER","SHARED_WITH"]`) {
		t.Fatalf("ANY_OF must carry canonical required_relations: %s", complex)
	}
}
