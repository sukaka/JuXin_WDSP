package aiagents

import (
	"testing"
	"time"
)

func TestAttackTypeDisplayName(t *testing.T) {
	tests := map[string]string{
		"SCANNER_DETECTION":      "扫描器探测",
		"SQL_INJECTION":          "SQL注入",
		"INFORMATION_DISCLOSURE": "信息泄露",
		"XXE_INJECTION":          "XML外部实体注入（XXE）",
		"WEBSHELL":               "WebShell攻击",
		"DESERIALIZATION":        "不安全反序列化",
		"SSTI":                   "服务端模板注入（SSTI）",
		"DOS":                    "拒绝服务攻击（DoS）",
		"MASS_ASSIGNMENT":        "批量赋值攻击",
		"EXCLUSION":              "规则排除",
		"OTHER":                  "其他攻击",
		"UNKNOWN_TYPE":           "UNKNOWN_TYPE",
	}
	for input, want := range tests {
		if got := attackTypeDisplayName(input); got != want {
			t.Errorf("attackTypeDisplayName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatChineseDateTime(t *testing.T) {
	value := time.Date(2026, 9, 1, 17, 0, 38, 0, time.UTC)
	if got, want := formatChineseDateTime(value), "2026年09月01日 17:00:38"; got != want {
		t.Fatalf("formatChineseDateTime() = %q, want %q", got, want)
	}
}
