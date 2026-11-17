package apiauthzwizard

import (
	"strings"
	"testing"
)

func TestDeriveReadinessAnyOfRelationContract(t *testing.T) {
	input := readyInput()
	input.RequiredRelation = "ANY_OF"
	input.RequiredRelations = []string{"OWNER", "SHARED_WITH"}
	if badge, reasons := DeriveReadiness(input); badge != ReadinessReady || len(reasons) != 0 {
		t.Fatalf("canonical ANY_OF readiness=%s reasons=%v", badge, reasons)
	}

	for _, tc := range []struct {
		name      string
		relation  string
		relations []string
		want      string
	}{
		{name: "ANY_OF missing relations", relation: "ANY_OF", want: "required_relations"},
		{name: "ANY_OF wrong order", relation: "ANY_OF", relations: []string{"SHARED_WITH", "OWNER"}, want: "OWNER,SHARED_WITH"},
		{name: "OWNER with relations", relation: "OWNER", relations: []string{"OWNER"}, want: "必须为空"},
		{name: "delegation remains unsupported", relation: "ANY_OF", relations: []string{"OWNER", "DELEGATED_TO"}, want: "required_relations"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := readyInput()
			in.RequiredRelation = tc.relation
			in.RequiredRelations = tc.relations
			badge, reasons := DeriveReadiness(in)
			joined := strings.Join(reasons, "\n")
			if badge != ReadinessNotPublishable || !strings.Contains(joined, tc.want) {
				t.Fatalf("readiness=%s reasons=%v, want NOT_PUBLISHABLE containing %q", badge, reasons, tc.want)
			}
		})
	}
}

func TestReadinessAnyOfRequiresAz4(t *testing.T) {
	input := readyInput()
	input.RequiredRelation = "ANY_OF"
	input.RequiredRelations = []string{"OWNER", "SHARED_WITH"}
	input.NodeCapabilityLow = true
	badge, reasons := DeriveReadiness(input)
	if badge != ReadinessBlockedByNode || !strings.Contains(strings.Join(reasons, "\n"), "az/4") {
		t.Fatalf("ANY_OF capability readiness=%s reasons=%v", badge, reasons)
	}
	if got := requiredAuthzAZ("OWNER"); got != 3 {
		t.Fatalf("OWNER required az=%d, want 3", got)
	}
	if got := requiredAuthzAZ("any_of"); got != 4 {
		t.Fatalf("ANY_OF required az=%d, want 4", got)
	}
}
