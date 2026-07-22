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
