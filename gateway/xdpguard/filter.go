package xdpguard

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

const (
	// AttachModeAuto tries driver/native XDP first and falls back to generic (SKB) XDP.
	AttachModeAuto = "auto"
	// AttachModeNative requires driver-level native XDP attach.
	AttachModeNative = "native"
	// AttachModeGeneric attaches using kernel SKB generic XDP mode.
	AttachModeGeneric = "generic"

	// ModeXDPNative indicates driver-level native XDP is active.
	ModeXDPNative = "xdp_native"
	// ModeXDPGeneric indicates kernel generic (SKB) XDP is active.
	ModeXDPGeneric = "xdp_generic"
	// ModeFallbackUserspace indicates XDP is inactive/detached and filtering stays in userspace.
	ModeFallbackUserspace = "fallback_userspace"

	// MaxInterfaces is the hard upper bound on interfaces accepted per sync or CLI config.
	MaxInterfaces = 16
)

var (
	interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

	forbiddenInterfacePrefixes = []string{
		"docker",
		"br-",
		"veth",
		"virbr",
		"cni",
		"flannel",
		"cali",
		"tun",
		"tap",
		"wg",
	}

	hardcodedProtectedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),       // IPv4 loopback
		netip.MustParsePrefix("169.254.0.0/16"),    // IPv4 link-local
		netip.MustParsePrefix("0.0.0.0/32"),        // IPv4 unspecified
		netip.MustParsePrefix("224.0.0.0/4"),       // IPv4 multicast
		netip.MustParsePrefix("255.255.255.255/32"), // IPv4 broadcast
		netip.MustParsePrefix("::1/128"),           // IPv6 loopback
		netip.MustParsePrefix("fe80::/10"),         // IPv6 link-local
		netip.MustParsePrefix("::/128"),            // IPv6 unspecified
		netip.MustParsePrefix("ff00::/8"),          // IPv6 multicast
	}
)

// HostAddrsProvider returns local host interface addresses. Defaults to net.InterfaceAddrs.
type HostAddrsProvider func() ([]net.Addr, error)

// FilterResult contains canonical, safety-filtered IPv4/IPv6 blocklist prefixes and counters.
type FilterResult struct {
	BlockedV4              []netip.Prefix
	BlockedV6              []netip.Prefix
	ExcludedProtectedCount int
	InvalidCIDRsSkipped    int
}

// HardcodedProtectedPrefixes returns a copy of the immutable unbannable prefix list.
func HardcodedProtectedPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(hardcodedProtectedPrefixes))
	copy(out, hardcodedProtectedPrefixes)
	return out
}

// ValidateAttachMode validates requested XDP attach mode.
func ValidateAttachMode(mode string) error {
	switch mode {
	case AttachModeAuto, AttachModeNative, AttachModeGeneric:
		return nil
	default:
		return fmt.Errorf("invalid attach_mode %q: must be one of auto, native, generic", mode)
	}
}

// ParseExcludedInterfaces converts raw operator-excluded NIC names into a normalized lookup set.
func ParseExcludedInterfaces(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, raw := range names {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		out[strings.ToLower(trimmed)] = struct{}{}
	}
	return out
}

// ValidateInterfaceName enforces physical NIC naming and safety exclusion rules.
// It strictly rejects invalid syntax, loopback ("lo"), virtual/container prefixes,
// and any operator-excluded management NICs.
func ValidateInterfaceName(name string, excluded map[string]struct{}) error {
	if !interfaceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid interface name %q: must match ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$", name)
	}
	lower := strings.ToLower(name)
	if lower == "lo" {
		return fmt.Errorf("interface %q is loopback and strictly forbidden for XDP", name)
	}
	for _, prefix := range forbiddenInterfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("interface %q matches forbidden virtual/container prefix %q", name, prefix)
		}
	}
	if len(excluded) > 0 {
		if _, ok := excluded[lower]; ok {
			return fmt.Errorf("interface %q is excluded by operator management NIC policy", name)
		}
		if _, ok := excluded[name]; ok {
			return fmt.Errorf("interface %q is excluded by operator management NIC policy", name)
		}
	}
	return nil
}

// ValidateInterfaces validates, deduplicates, and bounds a list of target interface names.
func ValidateInterfaces(ifaces []string, excluded map[string]struct{}) ([]string, error) {
	if len(ifaces) > MaxInterfaces {
		return nil, fmt.Errorf("too many interfaces (%d): maximum allowed is %d", len(ifaces), MaxInterfaces)
	}
	seen := make(map[string]struct{}, len(ifaces))
	out := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if err := ValidateInterfaceName(iface, excluded); err != nil {
			return nil, err
		}
		if _, dup := seen[iface]; dup {
			continue
		}
		seen[iface] = struct{}{}
		out = append(out, iface)
	}
	return out, nil
}

// NormalizePrefix parses an IP address or CIDR string into a canonical masked netip.Prefix.
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d and /96..128 prefixes) are unmapped to IPv4.
// Zone-scoped IPv6 addresses are rejected because LPM keys carry no interface scope.
func NormalizePrefix(raw string) (netip.Prefix, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, false
	}

	if strings.ContainsRune(s, '/') {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.IsValid() {
			return netip.Prefix{}, false
		}
		addr := p.Addr()
		if addr.Zone() != "" {
			return netip.Prefix{}, false
		}
		if addr.Is4In6() && p.Bits() >= 96 {
			v4 := addr.Unmap()
			return netip.PrefixFrom(v4, p.Bits()-96).Masked(), true
		}
		return p.Masked(), true
	}

	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.IsValid() || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// DiscoverHostPrefixes collects all local host interface IPs as /32 or /128 protected prefixes.
func DiscoverHostPrefixes(provider HostAddrsProvider) ([]netip.Prefix, error) {
	if provider == nil {
		provider = net.InterfaceAddrs
	}
	addrs, err := provider()
	if err != nil {
		return nil, fmt.Errorf("discover host interface addresses: %w", err)
	}
	seen := make(map[netip.Prefix]struct{}, len(addrs))
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		p := netip.PrefixFrom(addr, addr.BitLen())
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

// FilterBlocklist normalizes blocked CIDRs and enforces the double-guard protected exclusion:
// any candidate prefix that overlaps hard-coded unbannable ranges, local host NIC IPs,
// or caller-supplied protected_cidrs is strictly excluded and counted in ExcludedProtectedCount.
// Invalid blocked entries are skipped and counted in InvalidCIDRsSkipped.
// Invalid protected_cidrs entries cause a fail-safe error so protection cannot silently weaken.
func FilterBlocklist(blockedRaw, protectedRaw []string, hostProvider HostAddrsProvider) (FilterResult, error) {
	protected := make([]netip.Prefix, 0, len(hardcodedProtectedPrefixes)+len(protectedRaw)+8)
	protected = append(protected, hardcodedProtectedPrefixes...)

	hostPrefixes, err := DiscoverHostPrefixes(hostProvider)
	if err != nil {
		return FilterResult{}, err
	}
	protected = append(protected, hostPrefixes...)

	for _, raw := range protectedRaw {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, ok := NormalizePrefix(raw)
		if !ok {
			return FilterResult{}, &ValidationError{Msg: fmt.Sprintf("invalid protected_cidrs entry %q", raw)}
		}
		protected = append(protected, p)
	}

	res := FilterResult{
		BlockedV4: make([]netip.Prefix, 0),
		BlockedV6: make([]netip.Prefix, 0),
	}

	seen := make(map[netip.Prefix]struct{}, len(blockedRaw))
	for _, raw := range blockedRaw {
		p, ok := NormalizePrefix(raw)
		if !ok {
			res.InvalidCIDRsSkipped++
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		if overlapsAny(p, protected) {
			res.ExcludedProtectedCount++
			continue
		}
		if p.Addr().Is4() {
			res.BlockedV4 = append(res.BlockedV4, p)
		} else {
			res.BlockedV6 = append(res.BlockedV6, p)
		}
	}

	slices.SortFunc(res.BlockedV4, comparePrefixes)
	slices.SortFunc(res.BlockedV6, comparePrefixes)
	return res, nil
}

func overlapsAny(candidate netip.Prefix, protected []netip.Prefix) bool {
	for _, p := range protected {
		if candidate.Overlaps(p) {
			return true
		}
	}
	return false
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	switch {
	case a.Bits() < b.Bits():
		return -1
	case a.Bits() > b.Bits():
		return 1
	default:
		return 0
	}
}
