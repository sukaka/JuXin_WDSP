// Package systemalerts 提供阶段6系统告警：规则评估、状态机（OPEN/ACKNOWLEDGED/RESOLVED/IGNORED）、
// 抑制合并（同类合并、冷却、抖动抑制、最大未关闭保护）与处置接口。
package systemalerts

// 告警类型（任务书 §11.1）
const (
	TypeGatewayDown             = "GATEWAY_DOWN"
	TypeManagementAPIDown       = "MANAGEMENT_API_DOWN"
	TypeDatabaseUnavailable     = "DATABASE_UNAVAILABLE"
	TypeValkeyUnavailable       = "VALKEY_UNAVAILABLE"
	TypeEventCollectorLag       = "EVENT_COLLECTOR_LAG"
	TypeParseFailureRateHigh    = "EVENT_PARSE_FAILURE_RATE_HIGH"
	TypeSourceUnhealthy         = "SOURCE_UNHEALTHY"
	TypeCertificateExpiring     = "CERTIFICATE_EXPIRING"
	TypeCertificateExpired      = "CERTIFICATE_EXPIRED"
	TypeConfigPublishFailed     = "CONFIG_PUBLISH_FAILED"
	TypeConfigHashMismatch      = "CONFIG_HASH_MISMATCH"
	TypeDiskSpaceLow            = "DISK_SPACE_LOW"
	TypeDatabaseCapacityHigh    = "DATABASE_CAPACITY_HIGH"
	TypeBackupFailed            = "BACKUP_FAILED"
	TypeRestoreValidationFailed = "RESTORE_VALIDATION_FAILED"
	TypeReportFailed            = "REPORT_FAILED"
	TypeUpgradeFailed           = "UPGRADE_FAILED"
	TypeAuditIntegrityFailed    = "AUDIT_INTEGRITY_FAILED"
)

// 告警等级（任务书 §11.2）
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// 告警状态（任务书 §11.3）
const (
	StatusOpen         = "OPEN"
	StatusAcknowledged = "ACKNOWLEDGED"
	StatusResolved     = "RESOLVED"
	StatusIgnored      = "IGNORED"
)

// 解决方式（system_alerts.resolve_type）
const (
	ResolveManual    = "MANUAL"
	ResolveRecovered = "RECOVERED"
)

// severityRules 是告警类型→静态等级映射（任务书 §11.1/11.2）。
// CERTIFICATE_EXPIRING 等级随剩余天数动态判定，见 SeverityForCertExpiring。
var severityRules = map[string]string{
	TypeGatewayDown:             SeverityCritical,
	TypeManagementAPIDown:       SeverityHigh,
	TypeDatabaseUnavailable:     SeverityCritical,
	TypeValkeyUnavailable:       SeverityHigh,
	TypeEventCollectorLag:       SeverityMedium,
	TypeParseFailureRateHigh:    SeverityMedium,
	TypeSourceUnhealthy:         SeverityMedium,
	TypeCertificateExpiring:     SeverityLow, // ≤30 天；≤7 天升 MEDIUM
	TypeCertificateExpired:      SeverityHigh,
	TypeConfigPublishFailed:     SeverityHigh,
	TypeConfigHashMismatch:      SeverityMedium,
	TypeDiskSpaceLow:            SeverityHigh,
	TypeDatabaseCapacityHigh:    SeverityMedium,
	TypeBackupFailed:            SeverityHigh,
	TypeRestoreValidationFailed: SeverityHigh,
	TypeReportFailed:            SeverityMedium,
	TypeUpgradeFailed:           SeverityHigh,
	TypeAuditIntegrityFailed:    SeverityCritical,
}

// IsValidType 判断告警类型是否合法。
func IsValidType(alertType string) bool {
	_, ok := severityRules[alertType]
	return ok
}

// AllTypes 返回全部告警类型（固定声明顺序之外的排序按字典序，供筛选器）。
func AllTypes() []string {
	out := make([]string, 0, len(severityRules))
	for t := range severityRules {
		out = append(out, t)
	}
	return out
}

// SeverityFor 返回告警类型的默认等级；未知类型返回空串。
func SeverityFor(alertType string) string {
	return severityRules[alertType]
}

// SeverityForCertExpiring 证书临期动态等级：≤7 天 MEDIUM，≤30 天 LOW。
func SeverityForCertExpiring(daysRemaining int) string {
	if daysRemaining <= 7 {
		return SeverityMedium
	}
	return SeverityLow
}

// IsValidSeverity 判断等级是否合法。
func IsValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// IsValidStatus 判断状态是否合法。
func IsValidStatus(s string) bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusResolved, StatusIgnored:
		return true
	}
	return false
}

// IsOpenStatus 判断状态是否属于未关闭（参与合并去重）。
func IsOpenStatus(s string) bool {
	return s == StatusOpen || s == StatusAcknowledged
}
