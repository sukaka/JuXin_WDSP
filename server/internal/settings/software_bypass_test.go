package settings

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSoftwareBypassSettings(t *testing.T) {
	keys := []string{"enabled", "cpu_threshold_percent", "memory_threshold_percent", "min_hold_seconds", "session_cookie_names"}
	for _, key := range keys {
		if !AllowedSettingKeys["software_bypass:"+key] {
			t.Errorf("software_bypass:%s is not editable", key)
		}
		if isSensitiveSetting("software_bypass", key, false) {
			t.Errorf("software_bypass:%s must not be sensitive", key)
		}
	}
	for _, test := range []struct {
		key   string
		value string
		valid bool
	}{
		{"cpu_threshold_percent", "80", true},
		{"cpu_threshold_percent", "0", false},
		{"memory_threshold_percent", "101", false},
		{"min_hold_seconds", "300", true},
		{"min_hold_seconds", "0", false},
	} {
		err := validateValueRange("software_bypass", test.key, "integer", json.RawMessage(test.value))
		if (err == nil) != test.valid {
			t.Errorf("%s=%s validation error = %v, valid = %v", test.key, test.value, err, test.valid)
		}
	}
	if settingStringMaxLen["software_bypass:session_cookie_names"] != 512 {
		t.Fatal("session cookie list must have a 512-byte limit")
	}
	longValue := `"` + strings.Repeat("a", 513) + `"`
	if err := validateStringLen("software_bypass", "session_cookie_names", "string", json.RawMessage(longValue)); err == nil {
		t.Fatal("overlong session cookie list accepted")
	}
}
