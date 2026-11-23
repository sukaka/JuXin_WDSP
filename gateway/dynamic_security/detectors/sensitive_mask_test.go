package detectors

import (
	"strings"
	"testing"
)

func TestMaskSensitiveSample(t *testing.T) {
	tests := []struct {
		name     string
		dataType string
		raw      string
		want     string
	}{
		{name: "phone 11 digits", dataType: "phone", raw: "13800138000", want: "138****8000"},
		{name: "phone with +86", dataType: "phone", raw: "+8613800138000", want: "+86*******8000"},
		{name: "phone short", dataType: "phone", raw: "123456", want: "****"},
		{name: "id_card 18", dataType: "id_card", raw: "110101199001011234", want: "110***********1234"},
		{name: "id_card 15", dataType: "id_card", raw: "110101900101123", want: "110********1123"},
		{name: "bank_card 16", dataType: "bank_card", raw: "6222021234567890", want: "6222********7890"},
		{name: "bank_card 19", dataType: "bank_card", raw: "6222021234567890123", want: "6222***********0123"},
		{name: "email long local", dataType: "email", raw: "zhangsan@example.com", want: "zh*****n@example.com"},
		{name: "email 4-char local", dataType: "email", raw: "user@example.com", want: "us**@example.com"},
		{name: "email 3-char local", dataType: "email", raw: "abc@example.com", want: "a*c@example.com"},
		{name: "email 2-char local", dataType: "email", raw: "ab@example.com", want: "a*@example.com"},
		{name: "email 1-char local", dataType: "email", raw: "a@example.com", want: "*@example.com"},
		{name: "jwt never exposes prefix", dataType: "jwt", raw: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", want: "******"},
		{name: "password never exposes prefix", dataType: "password", raw: "SuperSecret!123", want: "******"},
		{name: "token never exposes prefix", dataType: "token", raw: "tok_live_1234567890", want: "******"},
		{name: "credential never exposes prefix", dataType: "credential", raw: "ak_123456789", want: "******"},
		{name: "custom long capped stars", dataType: "external_identifier", raw: "123456789012345678901234567890", want: "123****************7890"},
		{name: "custom short", dataType: "custom", raw: "abcd", want: "****"},
		{name: "control chars stripped", dataType: "phone", raw: " \r\n13800138000\t ", want: "138****8000"},
		{name: "empty input", dataType: "phone", raw: "   \r\n", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskSensitiveSample(tc.dataType, tc.raw)
			if got != tc.want {
				t.Fatalf("MaskSensitiveSample(%q, %q) = %q, want %q", tc.dataType, tc.raw, got, tc.want)
			}
			clean := strings.TrimSpace(tc.raw)
			if clean != "" && strings.Contains(got, clean) {
				t.Fatalf("masked output %q must not contain raw plaintext %q", got, clean)
			}
		})
	}
}
