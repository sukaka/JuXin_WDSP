package settings

import (
	"encoding/json"
	"testing"
)

// TestValidateValueRange 数值类安全策略取值范围回归（审查 LOW-S13）：
// 0/负数不得写入（如 max_failed_attempts=0 会关闭账号锁定、min_length=0 放行弱口令）。
func TestValidateValueRange(t *testing.T) {
	cases := []struct {
		name      string
		group     string
		key       string
		valueType string
		value     string
		wantErr   bool
	}{
		{"min_length 合法", "password", "min_length", "integer", "12", false},
		{"min_length 下限", "password", "min_length", "integer", "8", false},
		{"min_length 过低", "password", "min_length", "integer", "4", true},
		{"min_length 零", "password", "min_length", "integer", "0", true},
		{"min_length 负数", "password", "min_length", "integer", "-1", true},
		{"max_failed_attempts 零（关闭锁定）", "login", "max_failed_attempts", "integer", "0", true},
		{"max_failed_attempts 合法", "login", "max_failed_attempts", "integer", "5", false},
		{"lock_minutes 负数", "login", "lock_minutes", "integer", "-5", true},
		{"expire_days 零合法（不过期）", "password", "expire_days", "integer", "0", false},
		{"expire_days 负数", "password", "expire_days", "integer", "-1", true},
		{"idle_timeout 合法", "session", "idle_timeout_minutes", "integer", "30", false},
		{"idle_timeout 零", "session", "idle_timeout_minutes", "integer", "0", true},
		{"未列入范围的键不校验", "display", "system_name", "integer", "-99", false},
		{"非 integer 类型不校验", "password", "min_length", "string", `"0"`, false},
		{"范围键非法 JSON", "password", "min_length", "integer", `"x"`, true},
	}
	for _, c := range cases {
		err := validateValueRange(c.group, c.key, c.valueType, json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateValueRange err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
}

// TestIsSensitiveSetting 敏感设置判定回归（审查 MED-14）：秘密材料键即使 DB 行
// is_sensitive=false（清单生效前写入的历史行）也按敏感处理（List 脱敏/审计脱敏）。
func TestIsSensitiveSetting(t *testing.T) {
	cases := []struct {
		group        string
		key          string
		rowSensitive bool
		want         bool
	}{
		{"gateway_runtime", "identity_salt", false, true},
		{"gateway_runtime", "tls_session_ticket_key", false, true},
		{"gateway_runtime", "api_file_signature_key", false, true},
		{"api_scan", "signing_key", false, true},
		{"apm_agent", "ca_material", false, true},
		{"traffic_agent_ca", "ca_material", false, true},
		{"password", "min_length", false, false},
		{"gateway_runtime", "api_file_signature_kid", false, false}, // kid 非秘密（随 token 明文嵌入文件）
		{"display", "system_name", true, true},                      // DB 行标记优先保留
	}
	for _, c := range cases {
		if got := isSensitiveSetting(c.group, c.key, c.rowSensitive); got != c.want {
			t.Errorf("%s:%s rowSensitive=%v: got %v, want %v", c.group, c.key, c.rowSensitive, got, c.want)
		}
	}
}
