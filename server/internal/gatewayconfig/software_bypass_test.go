package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

func TestSoftwareBypassFromSettings(t *testing.T) {
	cfg, err := softwareBypassFromSettings(map[string]json.RawMessage{
		"enabled":                  json.RawMessage(`true`),
		"cpu_threshold_percent":    json.RawMessage(`85`),
		"memory_threshold_percent": json.RawMessage(`90`),
		"min_hold_seconds":         json.RawMessage(`20`),
		"session_cookie_names":     json.RawMessage(`"JSESSIONID, MYSESSION, JSESSIONID"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.CPUThresholdPercent != 85 || cfg.MemoryThresholdPercent != 90 || cfg.MinHoldSeconds != 20 {
		t.Fatalf("config = %+v", cfg)
	}
	if len(cfg.SessionCookieNames) != 2 || cfg.SessionCookieNames[0] != "JSESSIONID" || cfg.SessionCookieNames[1] != "MYSESSION" {
		t.Fatalf("session cookie names = %v", cfg.SessionCookieNames)
	}
}

func TestSoftwareBypassDefaultsAndValidation(t *testing.T) {
	cfg, err := softwareBypassFromSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.CPUThresholdPercent != 80 || cfg.MemoryThresholdPercent != 80 || cfg.MinHoldSeconds != 10 {
		t.Fatalf("defaults = %+v", cfg)
	}
	for _, values := range []map[string]json.RawMessage{
		{"cpu_threshold_percent": json.RawMessage(`0`)},
		{"memory_threshold_percent": json.RawMessage(`101`)},
		{"min_hold_seconds": json.RawMessage(`301`)},
		{"session_cookie_names": json.RawMessage(`"bad name"`)},
	} {
		if _, err := softwareBypassFromSettings(values); err == nil {
			t.Fatalf("invalid settings accepted: %v", values)
		}
	}
	empty, err := parseSoftwareBypassCookieNames("")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty cookie names = %v, %v", empty, err)
	}
}

func TestGenerateSoftwareBypassHasIsolatedChains(t *testing.T) {
	guard := testGuardConfig()
	guard.SoftwareBypass = defaultSoftwareBypass()
	guard.SoftwareBypass.Enabled = true
	generated, err := Generate(GenerateInput{
		Apps: sampleApps(), AdminSocket: "unix//var/run/caddy/admin.sock", Guard: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(generated.JSON), &root); err != nil {
		t.Fatal(err)
	}
	var selector map[string]interface{}
	var walk func(interface{})
	walk = func(value interface{}) {
		switch typed := value.(type) {
		case map[string]interface{}:
			if typed["handler"] == "jiuzhang_software_bypass" {
				selector = typed
			}
			for _, child := range typed {
				walk(child)
			}
		case []interface{}:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(root)
	if selector == nil {
		t.Fatal("software bypass selector not generated")
	}
	normal, _ := json.Marshal(selector["normal"])
	bypass, _ := json.Marshal(selector["bypass"])
	for _, want := range []string{`"handler":"waf"`, `"handler":"jiuzhang_guard"`} {
		if !strings.Contains(string(normal), want) {
			t.Errorf("normal chain missing %s", want)
		}
		if strings.Contains(string(bypass), want) {
			t.Errorf("pure proxy chain contains %s", want)
		}
	}
	if !strings.Contains(generated.JSON, `"wrapper":"jiuzhang_connection_metrics"`) {
		t.Error("connection metrics listener wrapper not generated")
	}
	if !strings.Contains(generated.JSON, `"handler":"reverse_proxy"`) {
		t.Error("shared reverse proxy missing")
	}
}

func TestGenerateSoftwareBypassPreservesManualBypass(t *testing.T) {
	apps := sampleApps()
	apps[0].ProtectionMode = applications.ModeBypass
	guard := testGuardConfig()
	guard.SoftwareBypass = defaultSoftwareBypass()
	generated, err := Generate(GenerateInput{Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock", Guard: guard})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(generated.JSON, `"handler":"waf"`) || strings.Contains(generated.JSON, `"handler":"jiuzhang_guard"`) {
		t.Fatal("manual BYPASS must not contain detection handlers in either chain")
	}
}
