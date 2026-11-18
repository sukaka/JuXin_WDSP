package systemops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testFirewallCommand() Command {
	return Command{
		Action:       ActionFirewallEnsure,
		RequestedBy:  "gateway-publish",
		UserID:       "00000000-0000-0000-0000-000000000001",
		RequestID:    "req-firewall",
		RequestedAt:  "2026-11-17T00:00:00Z",
		DelaySeconds: 0,
		Ports:        []int{443, 82, 82},
	}
}

func TestFirewallCanonicalPayloadV2(t *testing.T) {
	cmd := testFirewallCommand()
	want := "v2\nfirewall_ensure\ngateway-publish\n00000000-0000-0000-0000-000000000001\nreq-firewall\n2026-11-17T00:00:00Z\n0\n82,443"
	if got := CanonicalPayload(cmd); got != want {
		t.Fatalf("CanonicalPayload() = %q, want %q", got, want)
	}
	if !slices.Equal(cmd.Ports, []int{443, 82, 82}) {
		t.Fatalf("CanonicalPayload() mutated ports: %v", cmd.Ports)
	}
}

func TestFirewallSignCommandGolden(t *testing.T) {
	cmd := testFirewallCommand()
	SignCommand(&cmd, []byte(testSecret))
	const want = "e88720ad7aee82e5be622046d572d3526c46e17565261e43279867fec58a5ec4"
	if cmd.HMAC != want {
		t.Fatalf("HMAC = %s, want %s", cmd.HMAC, want)
	}
}

func TestLegacyCanonicalPayloadRemainsV1WithPorts(t *testing.T) {
	for _, action := range []string{ActionReboot, ActionShutdown, ActionFactoryReset} {
		cmd := testCommand()
		cmd.Action = action
		cmd.Ports = []int{443, 82}
		want := "v1\n" + action + "\ntester\nuid-1\nr1\n2026-09-05T00:00:00Z\n3"
		if got := CanonicalPayload(cmd); got != want {
			t.Fatalf("CanonicalPayload(%s) = %q, want %q", action, got, want)
		}
	}
}

func TestEnsureFirewallPortsWritesSortedSignedCommand(t *testing.T) {
	dir := t.TempDir()
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if err := EnsureFirewallPorts(dir, []int{443, 82, 443, 82}, userID, "publish-82"); err != nil {
		t.Fatalf("EnsureFirewallPorts() error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "firewall_ensure-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("firewall flag count = %d, want 1", len(matches))
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var got Command
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionFirewallEnsure || got.RequestedBy != "gateway-publish" ||
		got.UserID != userID.String() || got.RequestID != "publish-82" || got.DelaySeconds != 0 {
		t.Fatalf("unexpected firewall command metadata: %+v", got)
	}
	if !slices.Equal(got.Ports, []int{82, 443}) {
		t.Fatalf("ports = %v, want [82 443]", got.Ports)
	}
	secret, err := LoadOrCreateHostctlSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantHMAC := got.HMAC
	got.HMAC = ""
	SignCommand(&got, secret)
	if got.HMAC != wantHMAC {
		t.Fatalf("HMAC = %s, recomputed = %s", wantHMAC, got.HMAC)
	}
	if _, err := time.Parse(time.RFC3339, got.RequestedAt); err != nil {
		t.Fatalf("requestedAt = %q: %v", got.RequestedAt, err)
	}
}

func TestEnsureFirewallPortsEmptyDoesNotTouchDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	if err := EnsureFirewallPorts(dir, nil, uuid.Nil, "empty"); err != nil {
		t.Fatalf("EnsureFirewallPorts(nil) error = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("empty request created hostctl directory: %v", err)
	}
}

func TestEnsureFirewallPortsRejectsInvalidInput(t *testing.T) {
	tooMany := make([]int, maxFirewallPorts+1)
	for i := range tooMany {
		tooMany[i] = i + 1
	}
	tests := []struct {
		name  string
		ports []int
	}{
		{name: "zero", ports: []int{0}},
		{name: "negative", ports: []int{-1}},
		{name: "above maximum", ports: []int{65536}},
		{name: "one invalid among valid", ports: []int{82, 65536}},
		{name: "too many unique", ports: tooMany},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := EnsureFirewallPorts(dir, tt.ports, uuid.Nil, "invalid"); err == nil {
				t.Fatal("EnsureFirewallPorts() error = nil, want validation error")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid request wrote hostctl files: %v", entries)
			}
		})
	}
}

func TestEnsureFirewallPortsAccepts128UniquePorts(t *testing.T) {
	ports := make([]int, maxFirewallPorts*2)
	for i := range ports {
		ports[i] = i%maxFirewallPorts + 1
	}
	dir := t.TempDir()
	if err := EnsureFirewallPorts(dir, ports, uuid.Nil, "maximum"); err != nil {
		t.Fatalf("EnsureFirewallPorts(128 unique ports) error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "firewall_ensure-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("firewall flag count = %d, want 1", len(matches))
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"ports":[`) {
		t.Fatal("firewall command omitted ports")
	}
}
