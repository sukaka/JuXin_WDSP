package securityidentities

import "testing"

func TestValidIdentityTypesExcludeRemovedMachineType(t *testing.T) {
	for _, identityType := range []string{
		"HUMAN", "BOT", "APPLICATION", "SERVICE", "AGENT", "UNKNOWN",
	} {
		if !validTypes[identityType] {
			t.Errorf("identity type %q is not accepted by the list filter", identityType)
		}
	}
	if validTypes["MACHINE"] {
		t.Fatal("removed identity type MACHINE must not be accepted by the list filter")
	}
}
