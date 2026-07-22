package systemalerts

import "testing"

// TestSeverityRulesMatrix 告警类型→等级规则矩阵（任务书 §11.1/11.2）。
func TestSeverityRulesMatrix(t *testing.T) {
	cases := []struct {
		alertType string
		severity  string
	}{
		{TypeGatewayDown, SeverityCritical},
		{TypeManagementAPIDown, SeverityHigh},
		{TypeDatabaseUnavailable, SeverityCritical},
		{TypeValkeyUnavailable, SeverityHigh},
		{TypeEventCollectorLag, SeverityMedium},
		{TypeParseFailureRateHigh, SeverityMedium},
		{TypeSourceUnhealthy, SeverityMedium},
		{TypeCertificateExpiring, SeverityLow},
		{TypeCertificateExpired, SeverityHigh},
		{TypeConfigPublishFailed, SeverityHigh},
		{TypeConfigHashMismatch, SeverityMedium},
		{TypeDiskSpaceLow, SeverityHigh},
		{TypeDatabaseCapacityHigh, SeverityMedium},
		{TypeBackupFailed, SeverityHigh},
		{TypeRestoreValidationFailed, SeverityHigh},
		{TypeReportFailed, SeverityMedium},
		{TypeUpgradeFailed, SeverityHigh},
		{TypeAuditIntegrityFailed, SeverityCritical},
	}
	if len(cases) != 18 {
		t.Fatalf("规则矩阵应覆盖 18 种告警类型，实际 %d", len(cases))
	}
	for _, c := range cases {
		if !IsValidType(c.alertType) {
			t.Errorf("%s 应为合法类型", c.alertType)
		}
		if got := SeverityFor(c.alertType); got != c.severity {
			t.Errorf("%s 等级 = %s，期望 %s", c.alertType, got, c.severity)
		}
	}
	if IsValidType("NO_SUCH_TYPE") {
		t.Error("未知类型不应合法")
	}
	if SeverityFor("NO_SUCH_TYPE") != "" {
		t.Error("未知类型等级应为空串")
	}
}

// TestSeverityForCertExpiring 证书临期动态等级：≤7 天 MEDIUM，≤30 天 LOW。
func TestSeverityForCertExpiring(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{0, SeverityMedium},
		{1, SeverityMedium},
		{7, SeverityMedium},
		{8, SeverityLow},
		{30, SeverityLow},
	}
	for _, c := range cases {
		if got := SeverityForCertExpiring(c.days); got != c.want {
			t.Errorf("剩余 %d 天等级 = %s，期望 %s", c.days, got, c.want)
		}
	}
}

// TestStatusAndSeverityValidity 状态/等级合法性。
func TestStatusAndSeverityValidity(t *testing.T) {
	for _, s := range []string{StatusOpen, StatusAcknowledged, StatusResolved, StatusIgnored} {
		if !IsValidStatus(s) {
			t.Errorf("%s 应为合法状态", s)
		}
	}
	if IsValidStatus("CLOSED") {
		t.Error("CLOSED 不是合法状态")
	}
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if !IsValidSeverity(sev) {
			t.Errorf("%s 应为合法等级", sev)
		}
	}
	if IsValidSeverity("WARN") {
		t.Error("WARN 不是合法等级")
	}
	if !IsOpenStatus(StatusOpen) || !IsOpenStatus(StatusAcknowledged) {
		t.Error("OPEN/ACKNOWLEDGED 应属未关闭")
	}
	if IsOpenStatus(StatusResolved) || IsOpenStatus(StatusIgnored) {
		t.Error("RESOLVED/IGNORED 不属未关闭")
	}
}
