package context

import "testing"

func TestRequestContextSetIdentityClampsAndCopiesEvidence(t *testing.T) {
	rc := New("req-1", ParseLimits{})
	evidence := []string{"credential:api_key"}
	rc.SetIdentity("APPLICATION", 120, evidence)
	evidence[0] = "credential:secret-value"

	if rc.IdentityType != "APPLICATION" || rc.IdentityConfidence != 100 {
		t.Fatalf("identity contract = type=%q confidence=%d", rc.IdentityType, rc.IdentityConfidence)
	}
	if len(rc.IdentityEvidence) != 1 || rc.IdentityEvidence[0] != "credential:api_key" {
		t.Fatalf("identity evidence was not copied safely: %v", rc.IdentityEvidence)
	}
}

func TestRequestContextSetIdentityUnknownClearsEvidence(t *testing.T) {
	rc := New("req-2", ParseLimits{})
	rc.SetIdentity("UNKNOWN", 0, []string{"client_ip"})
	if rc.IdentityType != "UNKNOWN" || rc.IdentityConfidence != 0 || len(rc.IdentityEvidence) != 0 {
		t.Fatalf("unknown identity contract = type=%q confidence=%d evidence=%v", rc.IdentityType, rc.IdentityConfidence, rc.IdentityEvidence)
	}
}

func TestRequestContextSetIdentityClampsNegativeConfidence(t *testing.T) {
	rc := New("req-3", ParseLimits{})
	rc.SetIdentity("HUMAN", -1, []string{"user_agent:browser"})
	if rc.IdentityConfidence != 0 || len(rc.IdentityEvidence) != 0 {
		t.Fatalf("negative confidence was not clamped: confidence=%d evidence=%v", rc.IdentityConfidence, rc.IdentityEvidence)
	}
}
