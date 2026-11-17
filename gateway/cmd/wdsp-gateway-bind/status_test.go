package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseProcessStatus(t *testing.T) {
	input := `Name:	caddy
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:
CapInh:	0000000000000400
CapPrm:	0000000000000400
CapEff:	0000000000000400
CapBnd:	0000000000000400
CapAmb:	0000000000000400
NoNewPrivs:	1
`
	state, err := parseProcessStatus(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseProcessStatus() error = %v", err)
	}
	if !reflect.DeepEqual(state, expectedState()) {
		t.Fatalf("state = %+v, want %+v", state, expectedState())
	}
}

func TestParseProcessStatusWithSupplementaryGroups(t *testing.T) {
	input := `Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:	10 20
CapInh:	0000000000000400
CapPrm:	0000000000000400
CapEff:	0000000000000400
CapBnd:	0000000000000400
CapAmb:	0000000000000400
NoNewPrivs:	1
`
	state, err := parseProcessStatus(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseProcessStatus() error = %v", err)
	}
	if !reflect.DeepEqual(state.Groups, []int{10, 20}) {
		t.Fatalf("Groups = %v, want [10 20]", state.Groups)
	}
	if err := verifyState(state); err == nil {
		t.Fatal("verifyState() accepted supplementary groups")
	}
}

func TestParseProcessStatusRejectsIncompleteOrInvalidInput(t *testing.T) {
	valid := `Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:
CapInh:	0000000000000400
CapPrm:	0000000000000400
CapEff:	0000000000000400
CapBnd:	0000000000000400
CapAmb:	0000000000000400
NoNewPrivs:	1
`
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "missing ambient", input: strings.Replace(valid, "CapAmb:\t0000000000000400\n", "", 1), want: "missing CapAmb"},
		{name: "bad capability", input: strings.Replace(valid, "CapEff:\t0000000000000400", "CapEff:\tinvalid", 1), want: "parse CapEff"},
		{name: "short UID", input: strings.Replace(valid, "Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000", 1), want: "parse Uid"},
		{name: "bad group", input: strings.Replace(valid, "Groups:\n", "Groups:\tunknown\n", 1), want: "parse Groups"},
		{name: "bad no-new-privileges", input: strings.Replace(valid, "NoNewPrivs:\t1", "NoNewPrivs:\tinvalid", 1), want: "parse NoNewPrivs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseProcessStatus(strings.NewReader(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseProcessStatus() error = %v, want %q", err, test.want)
			}
		})
	}
}
