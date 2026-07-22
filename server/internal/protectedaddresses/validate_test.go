package protectedaddresses

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	valid := []struct{ in, want string }{
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
	}
	for _, c := range valid {
		got, err := normalizeIP(c.in)
		if err != nil {
			t.Errorf("normalizeIP(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	invalid := []string{
		"", "example.com", "192.168.1.0/24", "1.2.3.4:8080", "192.168.1.*",
		"fe80::1%eth0", "10.0.0.1\n", strings.Repeat("9", 65),
	}
	for _, in := range invalid {
		if _, err := normalizeIP(in); err == nil {
			t.Errorf("normalizeIP(%q) should be rejected", in)
		} else if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("normalizeIP(%q) error should wrap ErrInvalidInput, got %v", in, err)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	valid := []struct{ in, want string }{
		{"169.254.0.0/16", "169.254.0.0/16"},
		{"192.168.1.77/24", "192.168.1.0/24"},
		{"fe80::/10", "fe80::/10"},
		{"2001:db8::dead:1/32", "2001:db8::/32"},
		{"::ffff:c0a8:14d/120", "192.168.1.0/24"},
	}
	for _, c := range valid {
		got, err := normalizePrefix(c.in)
		if err != nil {
			t.Errorf("normalizePrefix(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	invalid := []string{
		"", "192.168.1.1", "example.com/24", "10.0.0.0/33", "::ffff:1.2.3.4/80",
		"10.0.0.0/8\r", "http://10.0.0.0/8",
	}
	for _, in := range invalid {
		if _, err := normalizePrefix(in); err == nil {
			t.Errorf("normalizePrefix(%q) should be rejected", in)
		} else if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("normalizePrefix(%q) error should wrap ErrInvalidInput, got %v", in, err)
		}
	}
}

func validAddress() *ProtectedAddress {
	return &ProtectedAddress{
		Name:        "运维跳板机",
		Address:     "10.10.0.5",
		AddressType: TypeCustom,
		SourceType:  SourceManual,
		Status:      StatusEnabled,
	}
}

func TestValidateInputAddressOrCIDR(t *testing.T) {
	a := validAddress()
	if err := ValidateInput(a); err != nil {
		t.Fatalf("valid address rejected: %v", err)
	}
	// 二选一：都填
	a = validAddress()
	a.CIDR = "10.10.0.0/24"
	if err := ValidateInput(a); err == nil {
		t.Error("both address and cidr should be rejected")
	}
	// 二选一：都不填
	a = validAddress()
	a.Address = ""
	if err := ValidateInput(a); err == nil {
		t.Error("neither address nor cidr should be rejected")
	}
	// 仅 CIDR，且被掩码化
	a = validAddress()
	a.Address = ""
	a.CIDR = "10.10.0.77/24"
	if err := ValidateInput(a); err != nil {
		t.Fatalf("valid cidr rejected: %v", err)
	}
	if a.CIDR != "10.10.0.0/24" {
		t.Errorf("cidr not masked: %q", a.CIDR)
	}
}

func TestValidateInputNormalization(t *testing.T) {
	a := validAddress()
	a.Address = "::ffff:10.10.0.5"
	if err := ValidateInput(a); err != nil {
		t.Fatalf("mapped address rejected: %v", err)
	}
	if a.Address != "10.10.0.5" {
		t.Errorf("mapped address not normalized: %q", a.Address)
	}
}

func TestValidateInputFields(t *testing.T) {
	a := validAddress()
	a.Name = ""
	if err := ValidateInput(a); err == nil {
		t.Error("empty name should be rejected")
	}
	a = validAddress()
	a.Name = strings.Repeat("n", 101)
	if err := ValidateInput(a); err == nil {
		t.Error("name >100 should be rejected")
	}
	a = validAddress()
	a.AddressType = "UNKNOWN"
	if err := ValidateInput(a); err == nil {
		t.Error("unknown address_type should be rejected")
	}
	a = validAddress()
	a.SourceType = "IMPORT"
	if err := ValidateInput(a); err == nil {
		t.Error("unknown source_type should be rejected")
	}
	a = validAddress()
	a.Description = strings.Repeat("d", 501)
	if err := ValidateInput(a); err == nil {
		t.Error("description >500 should be rejected")
	}
}

func TestCollectStaticEntries(t *testing.T) {
	// 无环境变量：仅回环与链路本地 4 条
	entries := collectStaticEntries(func(string) string { return "" })
	if len(entries) != 4 {
		t.Fatalf("expected 4 static entries, got %d", len(entries))
	}
	types := map[string]bool{}
	for _, e := range entries {
		types[e.AddressType] = true
	}
	if !types[TypeLoopback] || !types[TypeLinkLocal] {
		t.Errorf("missing loopback/link_local entries: %v", types)
	}

	// 环境变量为 IP：登记；为主机名：跳过
	env := map[string]string{
		"POSTGRES_HOST":     "10.0.0.2",
		"VALKEY_HOST":       "valkey",
		"GATEWAY_NODE_NAME": "::ffff:192.168.10.5",
	}
	entries = collectStaticEntries(func(k string) string { return env[k] })
	if len(entries) != 6 {
		t.Fatalf("expected 6 entries, got %d", len(entries))
	}
	var db, gw *refreshEntry
	for i := range entries {
		switch entries[i].AddressType {
		case TypeDatabase:
			db = &entries[i]
		case TypeGateway:
			gw = &entries[i]
		case TypeCache:
			t.Error("hostname VALKEY_HOST should be skipped")
		}
	}
	if db == nil || db.Address != "10.0.0.2" {
		t.Errorf("database entry wrong: %+v", db)
	}
	if gw == nil || gw.Address != "192.168.10.5" {
		t.Errorf("gateway entry should be unmapped IPv4: %+v", gw)
	}
}
