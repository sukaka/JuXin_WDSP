package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

const maxExpandedLocalIPs = 4096

type ipPool struct {
	ips []net.IP
	idx atomic.Uint64
}

func newIPPool(ips []net.IP) *ipPool {
	return &ipPool{ips: ips}
}

func (p *ipPool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.ips)
}

func (p *ipPool) Next() net.IP {
	if p == nil || len(p.ips) == 0 {
		return nil
	}
	n := p.idx.Add(1) - 1
	return p.ips[n%uint64(len(p.ips))]
}

func ipv4ToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func uint32ToIPv4(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}

// parseLocalIPs 解析逗号分隔的本地源 IP 规格，支持单 IP、IPv4 范围 (a.b.c.1-a.b.c.32) 和 CIDR (a.b.c.0/27)。
func parseLocalIPs(spec string) ([]net.IP, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []net.IP
	seen := make(map[string]struct{})
	addIP := func(ip net.IP) error {
		key := ip.String()
		if _, ok := seen[key]; ok {
			return nil
		}
		if len(out) >= maxExpandedLocalIPs {
			return fmt.Errorf("local-ips exceeds maximum allowed count (%d)", maxExpandedLocalIPs)
		}
		seen[key] = struct{}{}
		out = append(out, ip)
		return nil
	}

	for _, rawToken := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(rawToken)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "/") {
			_, ipNet, err := net.ParseCIDR(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 {
				return nil, fmt.Errorf("CIDR range expansion currently supports IPv4 only: %q", tok)
			}
			base, ok := ipv4ToUint32(ipNet.IP)
			if !ok {
				return nil, fmt.Errorf("invalid IPv4 CIDR %q", tok)
			}
			hostCount := uint64(1) << uint(32-ones)
			start := uint64(base)
			end := start + hostCount - 1
			if ones <= 30 && hostCount >= 4 {
				start++ // skip network address
				end--   // skip broadcast address
			}
			for v := start; v <= end; v++ {
				if err := addIP(uint32ToIPv4(uint32(v))); err != nil {
					return nil, err
				}
			}
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			if startIP == nil || endIP == nil {
				return nil, fmt.Errorf("invalid IP range %q", tok)
			}
			sv, ok1 := ipv4ToUint32(startIP)
			ev, ok2 := ipv4ToUint32(endIP)
			if !ok1 || !ok2 || ev < sv {
				return nil, fmt.Errorf("invalid IPv4 range %q", tok)
			}
			for v := uint64(sv); v <= uint64(ev); v++ {
				if err := addIP(uint32ToIPv4(uint32(v))); err != nil {
					return nil, err
				}
			}
			continue
		}
		ip := net.ParseIP(tok)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", tok)
		}
		if err := addIP(ip); err != nil {
			return nil, err
		}
	}
	return out, nil
}
