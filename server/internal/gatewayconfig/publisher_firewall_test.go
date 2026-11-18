package gatewayconfig

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

func firewallTestPort(port int) *int { return &port }

func TestListenerTCPPortsMatchesGeneratedSites(t *testing.T) {
	apps := []AppData{
		{
			Code:           "bypass",
			ProtectionMode: applications.ModeBypass,
			DeploymentMode: applications.DeployModeReverseProxy,
			Domains: []applications.Domain{
				{HTTPEnabled: true, HTTPPort: firewallTestPort(82), HTTPSEnabled: true, HTTPSPort: firewallTestPort(8443)},
				{HTTPEnabled: true, HTTPPort: firewallTestPort(82)},
			},
		},
		{
			Code:           "protected",
			ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{
				{HTTPEnabled: true, HTTPPort: firewallTestPort(80), HTTPSEnabled: true, HTTPSPort: firewallTestPort(443)},
				{HTTPEnabled: true, HTTPPort: firewallTestPort(80), HTTPSEnabled: false, HTTPSPort: firewallTestPort(444)},
				{HTTPEnabled: false, HTTPPort: firewallTestPort(90), HTTPSEnabled: true, HTTPSPort: nil},
			},
		},
		{
			Code:           "mirror",
			DeploymentMode: applications.DeployModeMirror,
			Domains: []applications.Domain{
				{HTTPEnabled: true, HTTPPort: firewallTestPort(8080), HTTPSEnabled: true, HTTPSPort: firewallTestPort(4443)},
			},
		},
	}
	want := []int{80, 82, 443, 8443}
	if got := listenerTCPPorts(apps); !slices.Equal(got, want) {
		t.Fatalf("listenerTCPPorts() = %v, want %v", got, want)
	}
}

func TestListenerTCPPortsEmpty(t *testing.T) {
	apps := []AppData{{
		DeploymentMode: applications.DeployModeMirror,
		Domains:        []applications.Domain{{HTTPEnabled: true, HTTPPort: firewallTestPort(82)}},
	}}
	if got := listenerTCPPorts(apps); len(got) != 0 {
		t.Fatalf("listenerTCPPorts() = %v, want empty", got)
	}
}

type firewallTestLoader struct {
	current   string
	readCalls int
	loadCalls int
	callOrder *[]string
}

func (f *firewallTestLoader) GetCurrentConfig(context.Context) (string, error) {
	f.readCalls++
	if f.callOrder != nil {
		*f.callOrder = append(*f.callOrder, "read")
	}
	return f.current, nil
}

func (f *firewallTestLoader) LoadConfig(context.Context, string) error {
	f.loadCalls++
	if f.callOrder != nil {
		*f.callOrder = append(*f.callOrder, "load")
	}
	return nil
}

func TestFirewallEnsureFailureBlocksAllGatewayLoadOperations(t *testing.T) {
	p := &Publisher{}
	secretError := errors.New("hostctl secret=do-not-record")
	p.SetFirewallEnsurer(func([]int, uuid.UUID, string) error { return secretError })
	loader := &firewallTestLoader{current: `{"old":true}`}
	apps := []AppData{{Domains: []applications.Domain{{HTTPEnabled: true, HTTPPort: firewallTestPort(82)}}}}

	previous, ports, err := p.loadGatewayConfigWithFirewall(context.Background(), loader, `{"new":true}`, apps, PublishInput{})
	if !errors.Is(err, errFirewallEnsureFailed) {
		t.Fatalf("error = %v, want errFirewallEnsureFailed", err)
	}
	if previous != "" || ports != nil {
		t.Fatalf("previous, ports = %q, %v; want empty on failure", previous, ports)
	}
	if loader.readCalls != 0 || loader.loadCalls != 0 {
		t.Fatalf("gateway read/load calls = %d/%d, want 0/0", loader.readCalls, loader.loadCalls)
	}
	code, message, ok := firewallEnsureTaskFailure(err)
	if !ok || code != "FIREWALL_ENSURE_FAILED" {
		t.Fatalf("task failure = %q/%q/%v", code, message, ok)
	}
	if strings.Contains(message, "do-not-record") || strings.Contains(message, "secret") {
		t.Fatalf("task failure message leaked underlying error: %q", message)
	}
}

func TestFirewallEnsureRunsBeforeGatewayLoad(t *testing.T) {
	order := []string{}
	loader := &firewallTestLoader{current: "previous", callOrder: &order}
	p := &Publisher{}
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	p.SetFirewallEnsurer(func(ports []int, gotUser uuid.UUID, requestID string) error {
		order = append(order, "ensure")
		if !slices.Equal(ports, []int{82, 443}) {
			t.Fatalf("ensurer ports = %v, want [82 443]", ports)
		}
		if gotUser != userID || requestID != "publish-request" {
			t.Fatalf("ensurer identity = %s/%q", gotUser, requestID)
		}
		return nil
	})
	apps := []AppData{{Domains: []applications.Domain{{
		HTTPEnabled: true, HTTPPort: firewallTestPort(443),
		HTTPSEnabled: true, HTTPSPort: firewallTestPort(82),
	}}}}

	previous, ports, err := p.loadGatewayConfigWithFirewall(context.Background(), loader, "candidate", apps, PublishInput{
		RequestedBy: userID,
		RequestID:   "publish-request",
	})
	if err != nil {
		t.Fatalf("loadGatewayConfigWithFirewall() error = %v", err)
	}
	if previous != "previous" || !slices.Equal(ports, []int{82, 443}) {
		t.Fatalf("previous, ports = %q, %v", previous, ports)
	}
	if !slices.Equal(order, []string{"ensure", "read", "load"}) {
		t.Fatalf("call order = %v, want [ensure read load]", order)
	}
}

func TestNilFirewallEnsurerKeepsExistingLoadBehavior(t *testing.T) {
	loader := &firewallTestLoader{current: "previous"}
	p := &Publisher{}
	previous, ports, err := p.loadGatewayConfigWithFirewall(context.Background(), loader, "candidate", nil, PublishInput{})
	if err != nil || previous != "previous" || len(ports) != 0 {
		t.Fatalf("previous, ports, error = %q, %v, %v", previous, ports, err)
	}
	if loader.readCalls != 1 || loader.loadCalls != 1 {
		t.Fatalf("gateway read/load calls = %d/%d, want 1/1", loader.readCalls, loader.loadCalls)
	}
}

func TestFirewallEnsureSummaryOnlyClaimsSubmission(t *testing.T) {
	got := "发布成功" + firewallEnsureSummary([]int{82, 443})
	want := "发布成功；已提交防火墙放行：82/tcp、443/tcp"
	if got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
	if strings.Contains(got, "执行完成") || strings.Contains(got, "已生效") {
		t.Fatalf("summary overstates host execution: %q", got)
	}
	if got := firewallEnsureSummary(nil); got != "" {
		t.Fatalf("empty summary = %q, want empty", got)
	}
}
