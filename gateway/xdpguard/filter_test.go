package xdpguard

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func fakeHostAddrs(cidrs ...string) HostAddrsProvider {
	return func() ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(cidrs))
		for _, c := range cidrs {
			ip, ipNet, err := net.ParseCIDR(c)
			if err != nil {
				return nil, err
			}
			ipNet.IP = ip
			out = append(out, ipNet)
		}
		return out, nil
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"198.51.100.7", "198.51.100.7/32", true},
		{" 198.51.100.77/24 ", "198.51.100.0/24", true},
		{"::ffff:198.51.100.7", "198.51.100.7/32", true},
		{"::ffff:198.51.100.9/120", "198.51.100.0/24", true},
		{"2001:db8::1", "2001:db8::1/128", true},
		{"2001:db8::abcd/32", "2001:db8::/32", true},
		{"", "", false},
		{"not-an-ip", "", false},
		{"198.51.100.1/33", "", false},
		{"fe80::1%eth0", "", false},
	}

	for _, tc := range cases {
		got, ok := NormalizePrefix(tc.in)
		if ok != tc.ok {
			t.Fatalf("NormalizePrefix(%q) ok=%v, want %v", tc.in, ok, tc.ok)
		}
		if ok && got.String() != tc.want {
			t.Fatalf("NormalizePrefix(%q) = %s, want %s", tc.in, got.String(), tc.want)
		}
	}
}

func TestFilterBlocklistDoubleGuardProtectedExclusion(t *testing.T) {
	hostProvider := fakeHostAddrs("192.168.50.10/24", "2001:db8:10::5/64")

	blocked := []string{
		// Allowed public attacker CIDRs (including duplicates & IPv4-mapped IPv6)
		"203.0.113.5",
		"203.0.113.5/32",
		"::ffff:203.0.113.5",
		"198.51.100.99/24",
		"2001:db8:beef::1",
		// Allowed peer on same /24 as host (host IP itself is /32 protected, not whole /24)
		"192.168.50.99",

		// Must be EXCLUDED by hard-coded unbannable ranges:
		"127.0.0.1",           // loopback
		"127.10.0.0/16",       // loopback subset
		"169.254.169.254",     // link-local / cloud metadata
		"0.0.0.0/32",          // unspecified
		"224.0.0.1",           // multicast
		"255.255.255.255/32",  // broadcast
		"::1",                 // v6 loopback
		"fe80::1/128",         // v6 link-local
		"::/128",              // v6 unspecified
		"ff02::1",             // v6 multicast
		"0.0.0.0/0",           // broad CIDR overlapping loopback/host/protected
		"::/0",                // broad v6 CIDR overlapping ::1/host/protected
		"::ffff:127.0.0.1",    // IPv4-in-IPv6 loopback -> unmaps to 127.0.0.1/32 (deduped with 127.0.0.1)

		// Must be EXCLUDED by host NIC IP overlap:
		"192.168.50.10",       // exact host v4 IP
		"192.168.50.0/24",     // broad CIDR covering host v4 IP
		"2001:db8:10::/48",    // broad CIDR covering host v6 IP

		// Must be EXCLUDED by caller-supplied protected_cidrs overlap:
		"10.0.0.5",            // exact protected IP
		"10.0.0.0/8",          // broad CIDR covering protected IP 10.0.0.5/32
		"198.18.1.42",         // subset of protected 198.18.0.0/16

		// Invalid entries (counted in InvalidCIDRsSkipped):
		"bad-ip",
		"999.999.999.999",
		"",
	}
	protected := []string{
		"10.0.0.5/32",
		"198.18.0.0/16",
	}

	res, err := FilterBlocklist(blocked, protected, hostProvider)
	if err != nil {
		t.Fatalf("FilterBlocklist failed: %v", err)
	}

	wantV4 := []netip.Prefix{
		netip.MustParsePrefix("192.168.50.99/32"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.5/32"),
	}
	wantV6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:beef::1/128"),
	}
	if len(res.BlockedV4) != len(wantV4) {
		t.Fatalf("BlockedV4 = %v, want %v", res.BlockedV4, wantV4)
	}
	for i := range wantV4 {
		if res.BlockedV4[i] != wantV4[i] {
			t.Fatalf("BlockedV4[%d] = %s, want %s", i, res.BlockedV4[i], wantV4[i])
		}
	}
	if len(res.BlockedV6) != len(wantV6) || res.BlockedV6[0] != wantV6[0] {
		t.Fatalf("BlockedV6 = %v, want %v", res.BlockedV6, wantV6)
	}
	// 12 unique hardcoded + 3 host-overlapping + 3 caller-protected-overlapping = 18 excluded.
	if res.ExcludedProtectedCount != 18 {
		t.Fatalf("ExcludedProtectedCount = %d, want 18", res.ExcludedProtectedCount)
	}
	if res.InvalidCIDRsSkipped != 3 {
		t.Fatalf("InvalidCIDRsSkipped = %d, want 3", res.InvalidCIDRsSkipped)
	}
}

func TestFilterBlocklistErrorsOnInvalidProtectedOrHostFailure(t *testing.T) {
	_, err := FilterBlocklist([]string{"203.0.113.1"}, []string{"not-valid-protected"}, fakeHostAddrs("192.0.2.1/24"))
	var valErr *ValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("expected ValidationError for invalid protected_cidrs, got %v", err)
	}

	boom := errors.New("netlink failed")
	_, err = FilterBlocklist([]string{"203.0.113.1"}, nil, func() ([]net.Addr, error) {
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected host discovery error to propagate, got %v", err)
	}
}

func TestValidateInterfaceNameAndExcludePolicy(t *testing.T) {
	excluded := ParseExcludedInterfaces([]string{"eno1", "Mgmt0"})

	valid := []string{"eth0", "ens192", "enp3s0f0", "bond0", "eth0.100", "a", "nic_1-2.3"}
	for _, name := range valid {
		if err := ValidateInterfaceName(name, excluded); err != nil {
			t.Fatalf("expected %q to be valid, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		" eth0",
		"eth0 ",
		"-eth0",
		"eth/0",
		"interface_name_over_15",
		"lo",
		"LO",
		"docker0",
		"DOCKER_gw",
		"br-abcdef12",
		"veth12345",
		"virbr0",
		"cni0",
		"flannel.1",
		"cali12345",
		"tun0",
		"tap0",
		"wg0",
		"eno1",
		"ENO1",
		"mgmt0",
	}
	for _, name := range invalid {
		if err := ValidateInterfaceName(name, excluded); err == nil {
			t.Fatalf("expected interface %q to be rejected", name)
		}
	}

	// MaxInterfaces boundary check.
	tooMany := make([]string, MaxInterfaces+1)
	for i := range tooMany {
		tooMany[i] = "eth" + string(rune('a'+i))
	}
	if _, err := ValidateInterfaces(tooMany, nil); err == nil {
		t.Fatalf("expected > %d interfaces to fail", MaxInterfaces)
	}
}
