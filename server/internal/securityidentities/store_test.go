package securityidentities

import "testing"

func TestNormalizeIdentityTypeRetiresMachineValue(t *testing.T) {
	if got := normalizeIdentityType("MACHINE"); got != "UNKNOWN" {
		t.Fatalf("legacy MACHINE should be exposed as UNKNOWN, got %q", got)
	}
	for _, identityType := range []string{"HUMAN", "BOT", "APPLICATION", "SERVICE", "AGENT", "UNKNOWN"} {
		if got := normalizeIdentityType(identityType); got != identityType {
			t.Fatalf("identity type %q changed unexpectedly to %q", identityType, got)
		}
	}
}
