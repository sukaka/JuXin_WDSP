package settings

import (
	"encoding/json"
	"testing"
)

func TestAPIRateLimitActionSettings(t *testing.T) {
	for _, key := range []string{"api_rate_limit_action", "api_temp_block_seconds"} {
		if !AllowedSettingKeys["gateway_runtime:"+key] {
			t.Errorf("gateway_runtime:%s 未登记 AllowedSettingKeys", key)
		}
		if isSensitiveSetting("gateway_runtime", key, false) {
			t.Errorf("gateway_runtime:%s 不应按敏感设置处理", key)
		}
	}

	for _, tc := range []struct {
		key     string
		value   string
		wantErr bool
	}{
		{key: "api_rate_limit_action", value: `""`},
		{key: "api_rate_limit_action", value: `"RATE_LIMIT"`},
		{key: "api_rate_limit_action", value: `"BLOCK"`},
		{key: "api_rate_limit_action", value: `"TEMP_BLOCK"`},
		{key: "api_rate_limit_action", value: `" temp_block "`},
		{key: "api_rate_limit_action", value: `"REJECT"`, wantErr: true},
		{key: "api_rate_limit_action", value: `60`, wantErr: true},
		{key: "api_temp_block_seconds", value: `""`},
		{key: "api_temp_block_seconds", value: `"1"`},
		{key: "api_temp_block_seconds", value: `"60"`},
		{key: "api_temp_block_seconds", value: `"86400"`},
		{key: "api_temp_block_seconds", value: `" 60 "`},
		{key: "api_temp_block_seconds", value: `"0"`, wantErr: true},
		{key: "api_temp_block_seconds", value: `"-1"`, wantErr: true},
		{key: "api_temp_block_seconds", value: `"86401"`, wantErr: true},
		{key: "api_temp_block_seconds", value: `"abc"`, wantErr: true},
		{key: "api_temp_block_seconds", value: `"1.5"`, wantErr: true},
		{key: "api_temp_block_seconds", value: `60`, wantErr: true},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			value := json.RawMessage(tc.value)
			err := validateValueType("string", value)
			if err == nil {
				err = validateValueRange("gateway_runtime", tc.key, "string", value)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("%s=%s validation error = %v, wantErr %v", tc.key, tc.value, err, tc.wantErr)
			}
		})
	}
}
