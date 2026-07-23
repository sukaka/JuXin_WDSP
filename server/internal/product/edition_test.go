package product

import (
	"testing"
)

func TestLoadDefaultsWAF(t *testing.T) {
	t.Setenv("PRODUCT_EDITION", "")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "")
	s := Load()
	if s.Edition != EditionWAF {
		t.Fatalf("edition=%s want waf", s.Edition)
	}
	if s.APIDynamicProtection {
		t.Fatal("API dynamic protection must default off for waf")
	}
	if s.MaxBodyParseBytes != 1<<20 {
		t.Fatalf("parse bytes=%d", s.MaxBodyParseBytes)
	}
}

func TestLoadWDSPEnablesAPIByDefault(t *testing.T) {
	t.Setenv("PRODUCT_EDITION", "wdsp")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "")
	s := Load()
	if !s.IsWDSP() {
		t.Fatal("expected wdsp")
	}
	if !s.APIDynamicProtection {
		t.Fatal("wdsp should enable API dynamic protection by default")
	}
}

func TestLoadAPIOverride(t *testing.T) {
	t.Setenv("PRODUCT_EDITION", "wdsp")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "false")
	s := Load()
	if s.APIDynamicProtection {
		t.Fatal("explicit false must win")
	}
	t.Setenv("PRODUCT_EDITION", "waf")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "true")
	s = Load()
	if !s.APIDynamicProtection {
		t.Fatal("waf + explicit true should enable for lab/debug")
	}
}

func TestLoadInvalidAPIOverrideFailsClosed(t *testing.T) {
	t.Setenv("PRODUCT_EDITION", "wdsp")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "tru")

	s := Load()
	if s.APIDynamicProtection {
		t.Fatal("invalid explicit API dynamic protection value must fail closed")
	}
}

func TestAPIDynamicProtectionEnabledRequiresWDSPAndFlag(t *testing.T) {
	tests := []struct {
		name string
		in   Settings
		want bool
	}{
		{name: "wdsp enabled", in: Settings{Edition: EditionWDSP, APIDynamicProtection: true}, want: true},
		{name: "wdsp disabled", in: Settings{Edition: EditionWDSP, APIDynamicProtection: false}, want: false},
		{name: "waf flag ignored", in: Settings{Edition: EditionWAF, APIDynamicProtection: true}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.APIDynamicProtectionEnabled(); got != tt.want {
				t.Fatalf("APIDynamicProtectionEnabled()=%v want %v", got, tt.want)
			}
		})
	}
}
