package main

import "testing"

func TestParsePortsIsExplicitAndBounded(t *testing.T) {
	ports, err := parsePorts("80,443,8080")
	if err != nil || len(ports) != 3 || ports[1] != 443 {
		t.Fatalf("valid ports rejected: %v %v", ports, err)
	}
	for _, invalid := range []string{"", "0", "80,80", "80,,443", "65536", "-1"} {
		if _, err := parsePorts(invalid); err == nil {
			t.Fatalf("invalid capture ports %q accepted", invalid)
		}
	}
}
