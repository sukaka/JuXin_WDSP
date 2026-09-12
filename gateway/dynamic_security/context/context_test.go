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

func TestSetObjectIdentifiersCapsAndCopies(t *testing.T) {
	rc := New("req-obj-1", ParseLimits{})
	ids := make([]ObjectIdentifier, 0, MaxObjectIdentifiers+2)
	for i := 0; i < MaxObjectIdentifiers+2; i++ {
		ids = append(ids, ObjectIdentifier{Source: "path", Param: "id", ValueHash: "h"})
	}
	rc.SetObjectIdentifiers(ids)
	// 超上限截断
	if got := len(rc.ObjectIdentifiers); got != MaxObjectIdentifiers {
		t.Fatalf("object identifiers = %d, want capped at %d", got, MaxObjectIdentifiers)
	}
	// 拷贝隔离：改入参不影响上下文
	ids[0].ValueHash = "mutated"
	if rc.ObjectIdentifiers[0].ValueHash != "h" {
		t.Fatal("object identifiers must be copied, not aliased")
	}
	// CopyObjectIdentifiers 同样为副本
	cp := rc.CopyObjectIdentifiers()
	cp[0].ValueHash = "mutated-again"
	if rc.ObjectIdentifiers[0].ValueHash != "h" {
		t.Fatal("CopyObjectIdentifiers must return a copy")
	}
	// 空入参清空为 nil（事件 omitempty 省略）
	rc.SetObjectIdentifiers(nil)
	if rc.ObjectIdentifiers != nil {
		t.Fatalf("nil input must clear to nil, got %v", rc.ObjectIdentifiers)
	}
	if got := rc.CopyObjectIdentifiers(); got != nil {
		t.Fatalf("empty context must copy to nil, got %v", got)
	}
}
