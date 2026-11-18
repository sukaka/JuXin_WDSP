package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/systemops"
)

type firewallConfigurerRecorder struct {
	ensurer gatewayconfig.FirewallEnsurer
}

func (r *firewallConfigurerRecorder) SetFirewallEnsurer(ensurer gatewayconfig.FirewallEnsurer) {
	r.ensurer = ensurer
}

func TestConfigurePublisherFirewallEnsurerUsesSystemOpsHostctlDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.SystemOps.HostctlDir = dir
	publisher := &firewallConfigurerRecorder{}
	configurePublisherFirewallEnsurer(publisher, cfg)
	if publisher.ensurer == nil {
		t.Fatal("production publisher firewall ensurer was not injected")
	}
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if err := publisher.ensurer([]int{443, 82, 82}, userID, "app-assembly"); err != nil {
		t.Fatalf("injected ensurer error = %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "firewall_ensure-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("firewall flag count in configured HostctlDir = %d, want 1", len(matches))
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var cmd systemops.Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Action != systemops.ActionFirewallEnsure || cmd.RequestedBy != "gateway-publish" ||
		cmd.UserID != userID.String() || cmd.RequestID != "app-assembly" || cmd.DelaySeconds != 0 {
		t.Fatalf("unexpected command: %+v", cmd)
	}
	if !slices.Equal(cmd.Ports, []int{82, 443}) {
		t.Fatalf("ports = %v, want [82 443]", cmd.Ports)
	}
	secret, err := systemops.LoadOrCreateHostctlSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantHMAC := cmd.HMAC
	cmd.HMAC = ""
	systemops.SignCommand(&cmd, secret)
	if cmd.HMAC != wantHMAC {
		t.Fatalf("injected ensurer wrote unverifiable HMAC: got %s, want %s", wantHMAC, cmd.HMAC)
	}
}
