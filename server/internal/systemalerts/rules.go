// Package systemalerts 提供阶段6系统告警：规则评估、状态机（OPEN/ACKNOWLEDGED/RESOLVED/IGNORED）、
// 抑制合并（同类合并、冷却、抖动抑制、最大未关闭保护）与处置接口。
package systemalerts

// 告警类型（任务书 §11.1）
const (
	TypeGatewayDown          = "GATEWAY_DOWN"
	TypeManagementAPIDown    = "MANAGEMENT_API_DOWN"
	TypeDatabaseUnavailable  = "DATABASE_UNAVAILABLE"
	TypeValkeyUnavailable    = "VALKEY_UNAVAILABLE"
	TypeEventCollectorLag    = "EVENT_COLLECTOR_LAG"
	TypeParseFailureRateHigh = "EVENT_PARSE_FAILURE_RATE_HIGH"
	TypeSourceUnhealthy      = "SOURCE_UNHEALTHY"
	TypeCertificateExpiring        = "CERTIFICATE_EXPIRING"
	TypeCertificateExpired         = "CERTIFICATE_EXPIRED"
	TypeCertificateAutoRenewFailed = "CERTIFICATE_AUTO_RENEW_FAILED"
	TypeConfigPublishFailed  = "CONFIG_PUBLISH_FAILED"
	TypeConfigHashMismatch   = "CONFIG_HASH_MISMATCH"
	TypeDiskSpaceLow         = "DISK_SPACE_LOW"
	TypeDatabaseCapacityHigh = "DATABASE_CAPACITY_HIGH"
	// 文件句柄使用率告警（阶段6 §10.2 补齐）：runtimehealth 采集器按
	// Options.FDUsageHighPercent（默认 80%）判 API 组件降级并产出 fd_usage_percent
	// 指标；快照→告警映射挂接在评估器（同 DISK_SPACE_LOW 模式）。
	TypeFDUsageHigh             = "FD_USAGE_HIGH"
	TypeBackupFailed            = "BACKUP_FAILED"
	TypeRestoreValidationFailed = "RESTORE_VALIDATION_FAILED"
	TypeReportFailed            = "REPORT_FAILED"
	TypeUpgradeFailed           = "UPGRADE_FAILED"
	TypeAuditIntegrityFailed    = "AUDIT_INTEGRITY_FAILED"
	TypeAuditWriteFailed        = "AUDIT_WRITE_FAILED"

	// API 安全告警（W6-B / P1-08）：评估器周期扫描 api_runtime_findings 触发，
	// 见 api_findings.go。
	TypeAPICriticalFinding = "API_CRITICAL_FINDING" // 新增 CRITICAL 级风险发现
	TypeAPIFindingSpike    = "API_FINDING_SPIKE"    // 同 finding_type 窗口内激增超阈
	TypeAPIMaskFailure     = "API_MASK_FAILURE"     // MASK_RESPONSE 脱敏执行失败

	// 安全事件聚合告警（通知二期）：周期评估 security_events / access_control_events，
	// 见 security_spike.go；LOGIN_BRUTE_FORCE 为事件驱动（登录失败锁定触发点，见 auth 包挂点）。
	TypeSecurityEventSpike = "SECURITY_EVENT_SPIKE" // 窗口内 HIGH/CRITICAL 安全事件超阈
	TypeLoginBruteForce    = "LOGIN_BRUTE_FORCE"    // 登录连续失败触发账号锁定
	TypeCCBanSpike         = "CC_BAN_SPIKE"         // 窗口内 CC 封禁超阈

	// 运维操作告警补注册（通知二期）：backups/restores/upgrades 实际 Raise 的类型，
	// 此前不在 severityRules 会被引擎拒绝（告警丢失），按业务方实际使用字符串补齐。
	TypeBackupVerifyFailed    = "BACKUP_VERIFY_FAILED"    // 备份完成后校验失败
	TypeRestoreCleanupFailed  = "RESTORE_CLEANUP_FAILED"  // 恢复隔离环境清理失败
	TypeUpgradeRollbackFailed = "UPGRADE_ROLLBACK_FAILED" // 升级失败且自动/手动回滚失败
	TypeUpgradeRolledBack     = "UPGRADE_ROLLED_BACK"     // 升级失败已自动回滚（告知性）

	// 离线授权告警（产品侧授权门控）：事件驱动——license 服务复核/导入钩子与
	// API 端点采集链路直接 Raise（非周期评估），合并/冷却复用引擎既有机制。
	TypeLicenseInvalid       = "LICENSE_INVALID"        // 无有效授权（未导入/已到期/指纹失配/数据非法）
	TypeLicenseExpiringSoon  = "LICENSE_EXPIRING_SOON"  // 授权临期（剩余 ≤ 7 天）
	TypeLicenseQuotaExceeded = "LICENSE_QUOTA_EXCEEDED" // 授权配额超限（API 端点新发现拒绝落库）

	// 主备高可用与网络执行告警（M4；hastatus 清扫器周期读边车状态文件与多节点汇聚状态触发，
	// 见 internal/hastatus/sweeper.go）。
	TypeHAVIPFault         = "HA_VIP_FAULT"         // 主备 VIP 异常（keepalived 不存活/实例 FAULT/havipd 停止）
	TypeHASplitBrain       = "HA_SPLIT_BRAIN"       // 主备双主脑裂（同组多节点同时 MASTER 或同时持有相同 VIP）
	TypeNetworkApplyFailed = "NETWORK_APPLY_FAILED" // 网络配置（网桥/路由）执行失败
	TypeLinkPairDown       = "LINK_PAIR_DOWN"       // 端口联动已触发（链路故障，配对口已联动 down）
	TypeLinkPairSuppressed = "LINK_PAIR_SUPPRESSED" // 端口联动频率超限进入抑制态

	// APM 端点性能告警（阶段1 WP5）：评估器周期读端点级分钟聚合（metric_minute_aggregates）
	// 触发，见 endpoint_perf.go；component 为 app/endpoint 维度（超长截断+摘要后缀，
	// 见 endpointPerfComponent）；伪端点保留桶 __OTHER__/__UNCLASSIFIED__ 不评估。
	TypeEndpointLatencyHigh   = "ENDPOINT_LATENCY_HIGH"    // 端点 p95 持续超阈
	TypeEndpointErrorRateHigh = "ENDPOINT_ERROR_RATE_HIGH" // 端点 5xx 错误率持续超阈

	// APM SLO 违约告警：评估器周期读 apm 包 SLO 评估结果（apm_slos 定义 +
	// metric_hour_aggregates 窗口聚合，口径归 apm 包）触发，见 slo_breach.go；
	// component 为 service/SLO 名维度（超长截断+摘要后缀，同端点告警口径）。
	TypeAPMSLOBreach = "APM_SLO_BREACH" // SLO 状态进入 BREACHED（错误预算耗尽）

	// APM 数据面采集滞后告警（APM 阶段2 数据面容量/健康）：评估器周期查 ClickHouse
	// otel_traces 最新遥测时间与当前时间差（供给方 apm.CHHealth）触发，见
	// ingest_lag.go；component 固定 clickhouse（数据面逻辑组件，不按表/服务放大）。
	TypeAPMIngestLag = "APM_INGEST_LAG" // OTel 数据面采集停滞（最新遥测超阈未更新）

	// AI 运营计划连续失败熔断（AI 能力增强第二波）：apiops.Sweeper 在计划连续失败
	// 达阈（api_ai_ops.circuit_threshold，默认 3）自动熔断停用时事件驱动 Raise；
	// component 固定 AI_OPS（同类型同组件走引擎合并/冷却，消息携带计划与原因）。
	TypeAIOpsScheduleCircuitOpen = "AI_OPS_SCHEDULE_CIRCUIT_OPEN" // AI 运营计划熔断停用

	// 漏洞情报提醒（VULN_INTEL MVP）：vulnintel.Alerter 在 NVD 同步/离线导入产生
	// 新建情报且命中订阅（watch_techs + min_severity）时事件驱动 Raise；
	// component 为 vuln_intel:<tech> 维度（同技术栈后续提醒走引擎合并/冷却），
	// vuln_alerted 表保证同一漏洞同一技术栈只提醒一次。
	TypeVulnIntelNew = "VULN_INTEL_NEW" // 订阅技术栈出现新漏洞

	// 纯离线 WAF 规则包热更新告警（OFFLINE_RULEPACK_UPDATE_DESIGN.md）：
	TypeRulePackApplyFailed = "RULEPACK_APPLY_FAILED" // 离线规则包应用/回滚执行失败
	TypeRulePackNodeDrift   = "RULEPACK_NODE_DRIFT"   // HA 降级仅主节点生效导致主备规则包漂移

	// IP 库更新告警（IP_LIBRARY_UPDATE_DESIGN.md）：GeoIP 归属地库与威胁情报 IP 黑名单库。
	TypeGeoIPSyncFailed        = "GEOIP_SYNC_FAILED"         // GeoIP 归属地库更新失败
	TypeGeoIPNodeDrift         = "GEOIP_NODE_DRIFT"          // HA 主备 GeoIP 归属地库不一致
	TypeThreatIntelSyncFailed  = "THREAT_INTEL_SYNC_FAILED"  // 威胁情报 IP 库拉取/护栏拦截失败
	TypeThreatIntelCircuitOpen = "THREAT_INTEL_CIRCUIT_OPEN" // 威胁情报订阅源连续失败触发熔断
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

// 列表三态视图（W6-B / P1-08 静默能力）：由 status + silenced_until 推导，
// 不扩展状态词表；与 status 筛选参数互斥。
const (
	ViewActive   = "ACTIVE"   // 未关闭且未在静默期
	ViewSilenced = "SILENCED" // 未关闭且 silenced_until > now()
	ViewHistory  = "HISTORY"  // RESOLVED / IGNORED
)

// IsValidView 判断列表视图口径是否合法。
func IsValidView(s string) bool {
	switch s {
	case ViewActive, ViewSilenced, ViewHistory:
		return true
	}
	return false
}

// severityRules 是告警类型→静态等级映射（任务书 §11.1/11.2）。
// CERTIFICATE_EXPIRING 等级随剩余天数动态判定，见 SeverityForCertExpiring。
var severityRules = map[string]string{
	TypeGatewayDown:              SeverityCritical,
	TypeManagementAPIDown:        SeverityHigh,
	TypeDatabaseUnavailable:      SeverityCritical,
	TypeValkeyUnavailable:        SeverityHigh,
	TypeEventCollectorLag:        SeverityMedium,
	TypeParseFailureRateHigh:     SeverityMedium,
	TypeSourceUnhealthy:          SeverityMedium,
	TypeCertificateExpiring:        SeverityLow, // ≤30 天；≤7 天升 MEDIUM
	TypeCertificateExpired:         SeverityHigh,
	TypeCertificateAutoRenewFailed: SeverityHigh,
	TypeConfigPublishFailed:      SeverityHigh,
	TypeConfigHashMismatch:       SeverityMedium,
	TypeDiskSpaceLow:             SeverityHigh,
	TypeDatabaseCapacityHigh:     SeverityMedium,
	TypeFDUsageHigh:              SeverityHigh, // 句柄耗尽直接拒绝新连接，参照 DISK_SPACE_LOW 档
	TypeBackupFailed:             SeverityHigh,
	TypeRestoreValidationFailed:  SeverityHigh,
	TypeReportFailed:             SeverityMedium,
	TypeUpgradeFailed:            SeverityHigh,
	TypeAuditIntegrityFailed:     SeverityCritical,
	TypeAuditWriteFailed:         SeverityHigh,
	TypeAPICriticalFinding:       SeverityCritical,
	TypeAPIFindingSpike:          SeverityHigh,
	TypeAPIMaskFailure:           SeverityHigh,
	TypeSecurityEventSpike:       SeverityHigh,
	TypeLoginBruteForce:          SeverityMedium,
	TypeCCBanSpike:               SeverityMedium,
	TypeBackupVerifyFailed:       SeverityHigh,
	TypeRestoreCleanupFailed:     SeverityMedium,
	TypeUpgradeRollbackFailed:    SeverityCritical,
	TypeUpgradeRolledBack:        SeverityMedium,
	TypeLicenseInvalid:           SeverityCritical,
	TypeLicenseExpiringSoon:      SeverityHigh,
	TypeLicenseQuotaExceeded:     SeverityHigh,
	TypeHAVIPFault:               SeverityHigh,
	TypeHASplitBrain:             SeverityCritical,
	TypeNetworkApplyFailed:       SeverityHigh,
	TypeLinkPairDown:             SeverityMedium,
	TypeLinkPairSuppressed:       SeverityHigh,
	TypeEndpointLatencyHigh:      SeverityMedium, // 端点性能劣化，参照 SOURCE_UNHEALTHY 档
	TypeEndpointErrorRateHigh:    SeverityHigh,   // 持续 5xx 为用户可见故障，参照 SPIKE 类档
	TypeAPMSLOBreach:             SeverityMedium, // SLO 违约（预算耗尽），参照 SOURCE_UNHEALTHY 档
	TypeAPMIngestLag:             SeverityMedium, // 数据面采集滞后，参照 EVENT_COLLECTOR_LAG 档
	TypeAIOpsScheduleCircuitOpen: SeverityHigh,   // 运营计划熔断停用 = 自动化能力丧失，参照 CONFIG_PUBLISH_FAILED 档
	TypeVulnIntelNew:             SeverityHigh,   // 订阅技术栈新漏洞；批次含 CRITICAL 时调用方显式升 CRITICAL
	TypeRulePackApplyFailed:      SeverityHigh,   // 离线规则包应用或回滚失败
	TypeRulePackNodeDrift:        SeverityHigh,   // HA 节点规则包版本漂移（需补齐同步）
	TypeGeoIPSyncFailed:          SeverityMedium, // GeoIP 定时更新失败（旧库仍保持服务，不中断业务）
	TypeGeoIPNodeDrift:           SeverityMedium, // HA 备节点 GeoIP 同步失败导致主备版本漂移
	TypeThreatIntelSyncFailed:    SeverityMedium, // 威胁情报拉取失败或触发防误清空护栏
	TypeThreatIntelCircuitOpen:   SeverityHigh,   // 威胁情报订阅源连续失败熔断停用
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
