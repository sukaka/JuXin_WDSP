package settings

import (
	"encoding/json"
	"testing"
)

func TestTenantRatePerMinuteSetting(t *testing.T) {
	const key = "gateway_runtime:tenant_rate_per_minute"
	if !AllowedSettingKeys[key] {
		t.Fatalf("%s 未登记 AllowedSettingKeys", key)
	}
	if isSensitiveSetting("gateway_runtime", "tenant_rate_per_minute", false) {
		t.Fatal("tenant rate must not be sensitive")
	}
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "空串", value: `""`},
		{name: "空白", value: `" \t "`},
		{name: "零", value: `"0"`},
		{name: "正数", value: `"120"`},
		{name: "带空白正数", value: `" 60 "`},
		{name: "负数", value: `"-1"`, wantErr: true},
		{name: "非数字", value: `"many"`, wantErr: true},
		{name: "浮点", value: `"1.5"`, wantErr: true},
		{name: "指数", value: `"1e2"`, wantErr: true},
		{name: "JSON 数值", value: `60`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := json.RawMessage(tc.value)
			err := validateValueType("string", value)
			if err == nil {
				err = validateValueRange("gateway_runtime", "tenant_rate_per_minute", "string", value)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("validation error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
