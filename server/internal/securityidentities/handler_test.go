package securityidentities

import "testing"

func TestValidIdentityTypesIncludeV11Contract(t *testing.T) {
	for _, identityType := range []string{
		"HUMAN", "BOT", "APPLICATION", "SERVICE", "MACHINE", "AGENT", "UNKNOWN",
	} {
		if !validTypes[identityType] {
			t.Errorf("identity type %q is not accepted by the list filter", identityType)
		}
	}
}
