package validation

import (
	"strings"
	"testing"
)

func TestNormalizeCNNVDIDsValid(t *testing.T) {
	got, err := NormalizeCNNVDIDs([]string{"cnnvd-202401-2345", " CNNVD-202401-2345 ", "CNNVD-199901-001"})
	if err != nil {
		t.Fatalf("valid ids rejected: %v", err)
	}
	want := []string{"CNNVD-202401-2345", "CNNVD-199901-001"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v（大写归一 + 去重保序）", got, want)
	}
}

func TestNormalizeCNNVDIDsInvalid(t *testing.T) {
	bad := []string{
		"CNNVD-20241-2345",   // 年月段不足 6 位
		"CNNVD-2024013-2345", // 年月段超 6 位
		"CNNVD-202401-23",    // 序号不足 3 位
		"CNNVD_202401_2345",  // 分隔符非法
		"CNVD-2024-01-2345",  // 前缀非法
		"",                   // 空串
		"CVE-2024-0001",      // 编号体系混淆
	}
	for _, v := range bad {
		if _, err := NormalizeCNNVDIDs([]string{v}); err == nil {
			t.Errorf("invalid CNNVD id %q should be rejected", v)
		}
	}
}

func TestNormalizeCVEIDsValid(t *testing.T) {
	got, err := NormalizeCVEIDs([]string{"cve-2024-0001", "CVE-1999-0067", "CVE-2024-0001"})
	if err != nil {
		t.Fatalf("valid ids rejected: %v", err)
	}
	want := []string{"CVE-2024-0001", "CVE-1999-0067"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNormalizeCVEIDsInvalid(t *testing.T) {
	bad := []string{
		"CVE-24-0001",     // 年份不足 4 位
		"CVE-2024-001",    // 序号不足 4 位
		"CVE-2024",        // 缺序号段
		"CVE20240001",     // 无分隔符
		"CNNVD-202401-23", // 编号体系混淆
	}
	for _, v := range bad {
		if _, err := NormalizeCVEIDs([]string{v}); err == nil {
			t.Errorf("invalid CVE id %q should be rejected", v)
		}
	}
}

func TestNormalizeVulnIDsEmptyAndCap(t *testing.T) {
	got, err := NormalizeCNNVDIDs(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil input should return empty slice, got %v err=%v", got, err)
	}
	over := make([]string, MaxVulnIDsPerRule+1)
	for i := range over {
		over[i] = "CNNVD-202401-2345" // 去重前超限即拒绝
	}
	if _, err := NormalizeCNNVDIDs(over); err == nil {
		t.Error("exceeding MaxVulnIDsPerRule should be rejected")
	}
}

func TestValidateSingleIDs(t *testing.T) {
	v, err := ValidateCNNVDID("cnnvd-202401-2345")
	if err != nil || v != "CNNVD-202401-2345" {
		t.Errorf("ValidateCNNVDID = %q, %v", v, err)
	}
	if _, err := ValidateCNNVDID("bad"); err == nil {
		t.Error("bad CNNVD id should be rejected")
	}
	if v, err := ValidateCVEID(""); err != nil || v != "" {
		t.Errorf("empty CVE id should pass through, got %q, %v", v, err)
	}
	if v, err := ValidateCVEID("cve-2024-0001"); err != nil || v != "CVE-2024-0001" {
		t.Errorf("ValidateCVEID = %q, %v", v, err)
	}
	if _, err := ValidateCVEID("CVE-2024-1"); err == nil {
		t.Error("short CVE serial should be rejected")
	}
}
