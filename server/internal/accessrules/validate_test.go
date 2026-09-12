package accessrules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeAddress_Valid(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantVer string
	}{
		{"ipv4", "192.168.1.1", "192.168.1.1", IPVersion4},
		{"ipv4_trim", "  10.0.0.1  ", "10.0.0.1", IPVersion4},
		{"ipv4_full_range", "0.0.0.0", "0.0.0.0", IPVersion4},
		{"ipv4_mapped_v6", "::ffff:192.168.1.1", "192.168.1.1", IPVersion4},
		{"ipv6", "2001:db8::1", "2001:db8::1", IPVersion6},
		{"ipv6_upper_compressed", "2001:0DB8:0000::0001", "2001:db8::1", IPVersion6},
		{"ipv4_cidr_masked", "192.168.1.77/24", "192.168.1.0/24", IPVersion4},
		{"ipv4_cidr_exact", "10.0.0.0/8", "10.0.0.0/8", IPVersion4},
		{"ipv4_host_cidr", "1.2.3.4/32", "1.2.3.4/32", IPVersion4},
		{"ipv4_zero_cidr", "0.0.0.0/0", "0.0.0.0/0", IPVersion4},
		{"ipv6_cidr", "2001:db8::/32", "2001:db8::/32", IPVersion6},
		{"ipv6_cidr_masked", "2001:db8::1/64", "2001:db8::/64", IPVersion6},
		{"mapped_v6_prefix", "::ffff:192.168.1.0/120", "192.168.1.0/24", IPVersion4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ver, err := NormalizeAddress(c.in)
			if err != nil {
				t.Fatalf("NormalizeAddress(%q) 报错: %v", c.in, err)
			}
			if got != c.want || ver != c.wantVer {
				t.Fatalf("NormalizeAddress(%q) = (%q, %q), 期望 (%q, %q)", c.in, got, ver, c.want, c.wantVer)
			}
		})
	}
}

func TestNormalizeAddress_Invalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"spaces_only", "   "},
		{"domain", "example.com"},
		{"domain_with_dot", "www.example.com"},
		{"protocol", "http://1.2.3.4"},
		{"port", "1.2.3.4:8080"},
		{"wildcard", "192.168.1.*"},
		{"wildcard_full", "*"},
		{"octet_overflow", "256.1.1.1"},
		{"bad_cidr_bits", "1.2.3.4/33"},
		{"negative_bits", "1.2.3.4/-1"},
		{"ipv6_bits_overflow", "2001:db8::/129"},
		{"non_numeric_bits", "1.2.3.4/abc"},
		{"zone", "fe80::1%eth0"},
		{"control_char", "1.2.3.4\x00"},
		{"newline", "1.2.3.4\n1.2.3.5"},
		{"too_long", strings.Repeat("1", 65)},
		{"comma", "1.2.3.4,1.2.3.5"},
		{"mapped_bits_too_small", "::ffff:192.168.1.0/80"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := NormalizeAddress(c.in)
			if err == nil {
				t.Fatalf("NormalizeAddress(%q) 应报错, 得到 %q", c.in, got)
			}
			if !errors.Is(err, ErrInvalidAddress) {
				t.Fatalf("NormalizeAddress(%q) 错误应为 ErrInvalidAddress, 得到 %v", c.in, err)
			}
		})
	}
}

func validCreateInput() CreateInput {
	return CreateInput{
		Name:      "测试规则",
		RuleType:  RuleTypeDeny,
		ScopeType: ScopeGlobal,
		Address:   "192.168.1.0/24",
	}
}

func TestValidateInput_Valid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	appID := uuid.New()

	t.Run("minimal_with_defaults", func(t *testing.T) {
		in := validCreateInput()
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("应通过: %v", err)
		}
		if in.ScopeType != ScopeGlobal || in.ValidityType != ValidityPermanent || in.SourceType != SourceManual {
			t.Fatalf("默认值未填充: %+v", in)
		}
	})
	t.Run("application_scope", func(t *testing.T) {
		in := validCreateInput()
		in.ScopeType = ScopeApplication
		in.ApplicationID = &appID
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("应通过: %v", err)
		}
	})
	t.Run("temporary", func(t *testing.T) {
		in := validCreateInput()
		in.ValidityType = ValidityTemporary
		in.EffectiveUntil = &future
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("应通过: %v", err)
		}
	})
	t.Run("temporary_with_from", func(t *testing.T) {
		in := validCreateInput()
		in.ValidityType = ValidityTemporary
		in.EffectiveFrom = &past
		in.EffectiveUntil = &future
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("应通过: %v", err)
		}
	})
	t.Run("permanent_with_past_from", func(t *testing.T) {
		in := validCreateInput()
		in.EffectiveFrom = &past
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("永久规则允许过去的生效时间: %v", err)
		}
	})
}

func TestValidateInput_Invalid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	appID := uuid.New()

	cases := []struct {
		name   string
		mutate func(*CreateInput)
	}{
		{"empty_name", func(in *CreateInput) { in.Name = "" }},
		{"long_name", func(in *CreateInput) { in.Name = strings.Repeat("规", 201) }},
		{"long_reason", func(in *CreateInput) { in.Reason = strings.Repeat("原", 501) }},
		{"bad_rule_type", func(in *CreateInput) { in.RuleType = "BLOCK" }},
		{"bad_scope", func(in *CreateInput) { in.ScopeType = "NODE" }},
		{"global_with_app", func(in *CreateInput) { in.ApplicationID = &appID }},
		{"app_scope_no_app", func(in *CreateInput) { in.ScopeType = ScopeApplication }},
		{"bad_address", func(in *CreateInput) { in.Address = "example.com" }},
		{"bad_validity", func(in *CreateInput) { in.ValidityType = "FOREVER" }},
		{"permanent_with_until", func(in *CreateInput) { in.EffectiveUntil = &future }},
		{"temporary_no_until", func(in *CreateInput) { in.ValidityType = ValidityTemporary }},
		{"temporary_until_past", func(in *CreateInput) {
			in.ValidityType = ValidityTemporary
			in.EffectiveUntil = &past
		}},
		{"until_before_from", func(in *CreateInput) {
			in.ValidityType = ValidityTemporary
			in.EffectiveFrom = &future
			in.EffectiveUntil = &now
		}},
		{"bad_source_type", func(in *CreateInput) { in.SourceType = "HACKER" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := validCreateInput()
			c.mutate(&in)
			if err := ValidateInput(&in, now); err == nil {
				t.Fatalf("应报错: %+v", in)
			}
		})
	}
}

// fakeChecker 测试用保护地址检查器。
type fakeChecker struct {
	protected map[string]string // address → name
	err       error
	calls     []string
}

func (f *fakeChecker) IsProtected(_ context.Context, ip string) (bool, string, error) {
	f.calls = append(f.calls, ip)
	if f.err != nil {
		return false, "", f.err
	}
	name, ok := f.protected[ip]
	return ok, name, nil
}

func TestCheckProtected(t *testing.T) {
	ctx := context.Background()

	t.Run("nil_checker", func(t *testing.T) {
		if err := CheckProtected(ctx, nil, RuleTypeDeny, "1.2.3.4"); err != nil {
			t.Fatalf("nil checker 不应报错: %v", err)
		}
	})
	t.Run("allow_skips_check", func(t *testing.T) {
		fc := &fakeChecker{protected: map[string]string{"1.2.3.4": "网关"}}
		if err := CheckProtected(ctx, fc, RuleTypeAllow, "1.2.3.4"); err != nil {
			t.Fatalf("ALLOW 不应检查: %v", err)
		}
		if len(fc.calls) != 0 {
			t.Fatalf("ALLOW 不应调用 checker")
		}
	})
	t.Run("deny_hit_protected", func(t *testing.T) {
		fc := &fakeChecker{protected: map[string]string{"1.2.3.4": "网关地址"}}
		err := CheckProtected(ctx, fc, RuleTypeDeny, "1.2.3.4")
		if !errors.Is(err, ErrProtectedAddress) {
			t.Fatalf("应为 ErrProtectedAddress: %v", err)
		}
		if !strings.Contains(err.Error(), "网关地址") {
			t.Fatalf("错误应包含保护地址名称: %v", err)
		}
	})
	t.Run("deny_not_protected", func(t *testing.T) {
		fc := &fakeChecker{protected: map[string]string{}}
		if err := CheckProtected(ctx, fc, RuleTypeDeny, "1.2.3.4"); err != nil {
			t.Fatalf("不应报错: %v", err)
		}
	})
	t.Run("checker_error", func(t *testing.T) {
		fc := &fakeChecker{err: errors.New("db down")}
		err := CheckProtected(ctx, fc, RuleTypeDeny, "1.2.3.4")
		if err == nil || errors.Is(err, ErrProtectedAddress) {
			t.Fatalf("应透传检查错误且不是保护冲突: %v", err)
		}
	})
}

func TestParseTimeFlex(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"2026-12-31T23:59:59Z", false},
		{"2026-12-31T23:59:59+08:00", false},
		{"2026-12-31T23:59:59", false},
		{"2026-12-31 23:59:59", false},
		{"2026-12-31", false},
		{"2026/12/31", true},
		{"not-a-time", true},
		{"", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			_, err := parseTimeFlex(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("parseTimeFlex(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			}
		})
	}
}

func TestValidateUpdateInput(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)

	t.Run("valid", func(t *testing.T) {
		in := UpdateInput{Name: "更新", Address: "10.0.0.0/8", ValidityType: ValidityTemporary, EffectiveUntil: &future}
		if err := validateUpdateInput(&in, now); err != nil {
			t.Fatalf("应通过: %v", err)
		}
	})
	t.Run("bad_address", func(t *testing.T) {
		in := UpdateInput{Name: "更新", Address: "bad"}
		if err := validateUpdateInput(&in, now); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("应为地址错误: %v", err)
		}
	})
	t.Run("empty_name", func(t *testing.T) {
		in := UpdateInput{Address: "10.0.0.1"}
		if err := validateUpdateInput(&in, now); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("应为输入错误: %v", err)
		}
	})
}
