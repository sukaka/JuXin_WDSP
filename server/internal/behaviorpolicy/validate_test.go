package behaviorpolicy

import (
	"strings"
	"testing"
)

func validPolicy() *Policy {
	return &Policy{
		Enabled:                  true,
		Mode:                     ModeObserve,
		Version:                  1,
		URIEnumUniqueThreshold:   50,
		URIEnumNewRatioThreshold: 0.8,
		NotFoundRatioThreshold:   0.7,
		NotFoundMinRequests:      30,
		MethodEnumThreshold:      4,
		ParamMutationThreshold:   30,
		AuthFailThreshold:        10,
		LowSlowSensitiveMinHits:  10,
		SensitivePaths:           []string{"/.git", "/.env"},
		Scores:                   map[string]int{"URI_ENUMERATION": 15, "AUTH_FAIL_PROBE": 15},
		WhitelistIPs:             []string{"10.0.0.0/8", "192.168.1.1"},
		WhitelistUAs:             []string{"internal-monitor"},
	}
}

// TestValidateDefaultsOK 合法默认策略通过校验。
func TestValidateDefaultsOK(t *testing.T) {
	if errs := Validate(validPolicy()); len(errs) != 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}
}

// TestValidateRatios 比率必须 0-1。
func TestValidateRatios(t *testing.T) {
	p := validPolicy()
	p.URIEnumNewRatioThreshold = 1.5
	p.NotFoundRatioThreshold = -0.1
	errs := Validate(p)
	assertFieldErr(t, errs, "uri_enum_new_ratio_threshold")
	assertFieldErr(t, errs, "not_found_ratio_threshold")
}

// TestValidateThresholds 阈值必须 0-100000。
func TestValidateThresholds(t *testing.T) {
	p := validPolicy()
	p.URIEnumUniqueThreshold = -1
	p.AuthFailThreshold = 100001
	errs := Validate(p)
	assertFieldErr(t, errs, "uri_enum_unique_threshold")
	assertFieldErr(t, errs, "auth_fail_threshold")
}

// TestValidateMode 当前仅支持 OBSERVE。
func TestValidateMode(t *testing.T) {
	p := validPolicy()
	p.Mode = "ENFORCE"
	assertFieldErr(t, Validate(p), "mode")
}

// TestValidateSensitivePaths 敏感路径必须以 / 开头。
func TestValidateSensitivePaths(t *testing.T) {
	p := validPolicy()
	p.SensitivePaths = []string{"/.git", "etc/passwd"}
	assertFieldErr(t, Validate(p), "sensitive_paths[1]")
}

// TestValidateScores scores 键限定 10 种信号、值 0-100。
func TestValidateScores(t *testing.T) {
	p := validPolicy()
	p.Scores = map[string]int{"NOPE": 10}
	assertFieldErr(t, Validate(p), "scores")

	p = validPolicy()
	p.Scores = map[string]int{"URI_ENUMERATION": 101}
	assertFieldErr(t, Validate(p), "scores.URI_ENUMERATION")
}

// TestValidateEnumerationFields 校验账号/对象枚举阈值和标识字段边界。
func TestValidateEnumerationFields(t *testing.T) {
	p := validPolicy()
	p.AccountEnumThreshold = -1
	p.ObjectEnumThreshold = 100001
	p.AccountIdentifierFields = []string{"account", ""}
	p.ObjectIdentifierFields = []string{strings.Repeat("x", maxFieldLen+1)}
	errs := Validate(p)
	assertFieldErr(t, errs, "account_enum_threshold")
	assertFieldErr(t, errs, "object_enum_threshold")
	assertFieldErr(t, errs, "account_identifier_fields[1]")
	assertFieldErr(t, errs, "object_identifier_fields[0]")
}

// TestValidateWhitelistIPs 白名单 IP 必须合法 IP 或 CIDR。
func TestValidateWhitelistIPs(t *testing.T) {
	p := validPolicy()
	p.WhitelistIPs = []string{"10.0.0.0/8", "not-an-ip", "10.1.2.*"}
	errs := Validate(p)
	assertFieldErr(t, errs, "whitelist_ips[1]")
	assertFieldErr(t, errs, "whitelist_ips[2]")
	if len(errs) != 2 {
		t.Fatalf("want exactly 2 errors, got %+v", errs)
	}
}

// TestValidateWhitelistUAs UA 白名单单项 ≤128 字符且非空。
func TestValidateWhitelistUAs(t *testing.T) {
	p := validPolicy()
	p.WhitelistUAs = []string{"", strings.Repeat("a", 129)}
	errs := Validate(p)
	assertFieldErr(t, errs, "whitelist_uas[0]")
	assertFieldErr(t, errs, "whitelist_uas[1]")
}

func assertFieldErr(t *testing.T, errs []FieldError, field string) {
	t.Helper()
	for _, e := range errs {
		if e.Field == field {
			return
		}
	}
	t.Fatalf("want field error %q, got %+v", field, errs)
}
