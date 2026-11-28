import { describe, expect, it } from 'vitest'
import { formatBytes } from '../format'
import {
  ALERT_COMPONENT_NAME_META,
  ALERT_SEVERITY_META,
  ALERT_STATUS_META,
  ALERT_TYPE_META,
  BACKUP_STATUS_META,
  BACKUP_TYPE_META,
  BACKUP_VERIFY_STATUS_META,
  CHECK_RESULT_META,
  COMPONENT_NAME_META,
  COMPONENT_STATUS_META,
  CONTENT_SCOPE_META,
  REPORT_FORMAT_META,
  REPORT_SECTION_OPTIONS,
  REPORT_STATUS_META,
  REPORT_TYPE_META,
  RESTORE_SCOPE_META,
  RESTORE_STATUS_META,
  SEARCH_RANGE_OPTIONS,
  TREND_RANGE_OPTIONS,
  UPGRADE_PACKAGE_STATUS_META,
  UPGRADE_STATUS_META,
  formatAlertComponent,
  formatAlertMessage,
  formatUptime,
  isTerminalBackupStatus,
  isTerminalDeliveryStatus,
  isTerminalReportStatus,
  isTerminalRestoreStatus,
  isTerminalUpgradeStatus,
  summarizeCheckResult,
} from '../stage6'

describe('阶段6 展示元数据完整性', () => {
  it('报告类型覆盖 DAILY/WEEKLY/MONTHLY/CUSTOM', () => {
    expect(Object.keys(REPORT_TYPE_META)).toEqual(['DAILY', 'WEEKLY', 'MONTHLY', 'CUSTOM'])
  })

  it('报告内容范围元数据可用', () => {
    expect(CONTENT_SCOPE_META.WAF_API.label).toBe('Web + API')
    expect(CONTENT_SCOPE_META.WAF).toBeDefined()
    expect(CONTENT_SCOPE_META.API).toBeDefined()
  })

  it('报告任务状态覆盖任务书全部 7 个状态', () => {
    expect(Object.keys(REPORT_STATUS_META)).toEqual([
      'PENDING',
      'COLLECTING',
      'AGGREGATING',
      'RENDERING',
      'SUCCESS',
      'FAILED',
      'CANCELLED',
    ])
  })

  it('系统告警等级覆盖 CRITICAL/HIGH/MEDIUM/LOW/INFO', () => {
    expect(Object.keys(ALERT_SEVERITY_META)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
  })

  it('系统告警状态覆盖 OPEN/ACKNOWLEDGED/RESOLVED/IGNORED', () => {
    expect(Object.keys(ALERT_STATUS_META)).toEqual(['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'IGNORED'])
  })

  it('系统告警类型覆盖全部 49 类（含 FD_USAGE_HIGH、VULN_INTEL_NEW、WDSP/APM/HA 与 IP 库告警）', () => {
    expect(Object.keys(ALERT_TYPE_META).sort()).toEqual(
      [
        'GATEWAY_DOWN',
        'MANAGEMENT_API_DOWN',
        'DATABASE_UNAVAILABLE',
        'VALKEY_UNAVAILABLE',
        'EVENT_COLLECTOR_LAG',
        'EVENT_PARSE_FAILURE_RATE_HIGH',
        'FD_USAGE_HIGH',
        'SOURCE_UNHEALTHY',
        'CERTIFICATE_EXPIRING',
        'CERTIFICATE_EXPIRED',
        'CERTIFICATE_AUTO_RENEW_FAILED',
        'CONFIG_PUBLISH_FAILED',
        'CONFIG_HASH_MISMATCH',
        'DISK_SPACE_LOW',
        'DATABASE_CAPACITY_HIGH',
        'BACKUP_FAILED',
        'BACKUP_VERIFY_FAILED',
        'RESTORE_VALIDATION_FAILED',
        'RESTORE_CLEANUP_FAILED',
        'REPORT_FAILED',
        'UPGRADE_FAILED',
        'UPGRADE_ROLLBACK_FAILED',
        'UPGRADE_ROLLED_BACK',
        'AUDIT_INTEGRITY_FAILED',
        'AUDIT_WRITE_FAILED',
        'VULN_INTEL_NEW',
        'API_CRITICAL_FINDING',
        'API_FINDING_SPIKE',
        'API_MASK_FAILURE',
        'SECURITY_EVENT_SPIKE',
        'LOGIN_BRUTE_FORCE',
        'CC_BAN_SPIKE',
        'LICENSE_INVALID',
        'LICENSE_EXPIRING_SOON',
        'LICENSE_QUOTA_EXCEEDED',
        'HA_VIP_FAULT',
        'HA_SPLIT_BRAIN',
        'NETWORK_APPLY_FAILED',
        'LINK_PAIR_DOWN',
        'LINK_PAIR_SUPPRESSED',
        'ENDPOINT_LATENCY_HIGH',
        'ENDPOINT_ERROR_RATE_HIGH',
        'APM_SLO_BREACH',
        'APM_INGEST_LAG',
        'AI_OPS_SCHEDULE_CIRCUIT_OPEN',
        'RULEPACK_APPLY_FAILED',
        'RULEPACK_NODE_DRIFT',
        'GEOIP_SYNC_FAILED',
        'GEOIP_NODE_DRIFT',
        'THREAT_INTEL_SYNC_FAILED',
        'THREAT_INTEL_CIRCUIT_OPEN',
      ].sort(),
    )
  })

  it('备份类型覆盖 FULL/CONFIG_ONLY', () => {
    expect(Object.keys(BACKUP_TYPE_META)).toEqual(['FULL', 'CONFIG_ONLY'])
  })

  it('备份/恢复/升级/检查状态元数据均含成功与失败态', () => {
    for (const meta of [BACKUP_STATUS_META, RESTORE_STATUS_META]) {
      expect(meta.SUCCESS).toBeDefined()
      expect(meta.FAILED).toBeDefined()
      expect(meta.CANCELLED).toBeDefined()
    }
    expect(UPGRADE_STATUS_META.SUCCESS).toBeDefined()
    expect(UPGRADE_STATUS_META.FAILED).toBeDefined()
    expect(UPGRADE_STATUS_META.ROLLED_BACK).toBeDefined()
    expect(BACKUP_VERIFY_STATUS_META.PASSED).toBeDefined()
    expect(BACKUP_VERIFY_STATUS_META.FAILED).toBeDefined()
  })

  it('检查结果覆盖 PASS/WARNING/FAIL/NOT_APPLICABLE', () => {
    expect(Object.keys(CHECK_RESULT_META)).toEqual(['PASS', 'WARNING', 'FAIL', 'NOT_APPLICABLE'])
  })

  it('监控组件名覆盖任务书组件清单（含 API_SECURITY 与 APM_CLICKHOUSE）', () => {
    for (const c of [
      'GATEWAY',
      'CORAZA',
      'GUARD',
      'API',
      'POSTGRES',
      'VALKEY',
      'EVENT_COLLECTOR',
      'UPSTREAM',
      'CERTIFICATE',
      'DISK',
      'API_SECURITY',
      'APM_CLICKHOUSE',
    ]) {
      expect(COMPONENT_NAME_META[c]).toBeTruthy()
    }
    expect(COMPONENT_NAME_META.API_SECURITY).toBe('API 安全采集')
    expect(COMPONENT_NAME_META.APM_CLICKHOUSE).toBe('APM 时序存储')
    expect(COMPONENT_STATUS_META.UP).toBeDefined()
    expect(COMPONENT_STATUS_META.DOWN).toBeDefined()
  })

  it('恢复范围/报告格式/趋势范围元数据可用', () => {
    expect(RESTORE_SCOPE_META.FULL.label).toBe('全系统恢复')
    expect(REPORT_FORMAT_META.html).toBeDefined()
    expect(REPORT_FORMAT_META.pdf).toBeDefined()
    expect(REPORT_FORMAT_META.docx.label).toBe('Word 文档')
    expect(TREND_RANGE_OPTIONS.map((o) => o.value)).toEqual(['1h', '24h', '7d', '30d'])
    // 检索类接口（调用链/SQL/异常/依赖/运行时）后端限窗 24h，快捷档位不含 7d/30d
    expect(SEARCH_RANGE_OPTIONS.map((o) => o.value)).toEqual(['1h', '24h'])
  })

  it('报告章节选项值不重复且与后端 SectionTitles 键一致', () => {
    const values = REPORT_SECTION_OPTIONS.map((s) => s.value)
    expect(new Set(values).size).toBe(values.length)
    expect(values).toEqual([
      'summary',
      'traffic',
      'events_overview',
      'risk_level',
      'attack_types',
      'source_ips',
      'applications',
      'rule_hits',
      'cc_protection',
      'ip_lists',
      'disposition',
      'upstream_health',
      'certificates',
      'system_health',
      'conclusions',
    ])
    expect(values).toContain('conclusions')
    expect(values.length).toBeGreaterThanOrEqual(10)
  })

  it('所有元数据条目均有非空颜色与中文标签', () => {
    const metas = [
      REPORT_TYPE_META,
      REPORT_STATUS_META,
      REPORT_FORMAT_META,
      ALERT_SEVERITY_META,
      ALERT_STATUS_META,
      ALERT_TYPE_META,
      COMPONENT_STATUS_META,
      BACKUP_TYPE_META,
      BACKUP_STATUS_META,
      BACKUP_VERIFY_STATUS_META,
      RESTORE_SCOPE_META,
      RESTORE_STATUS_META,
      UPGRADE_STATUS_META,
      CHECK_RESULT_META,
    ]
    for (const meta of metas) {
      for (const [key, item] of Object.entries(meta)) {
        expect(item.color, key).toBeTruthy()
        expect(item.label, key).toBeTruthy()
      }
    }
  })
})

describe('阶段6 终态判定', () => {
  it('报告任务终态：SUCCESS/FAILED/CANCELLED', () => {
    expect(isTerminalReportStatus('SUCCESS')).toBe(true)
    expect(isTerminalReportStatus('FAILED')).toBe(true)
    expect(isTerminalReportStatus('CANCELLED')).toBe(true)
    expect(isTerminalReportStatus('PENDING')).toBe(false)
    expect(isTerminalReportStatus('RENDERING')).toBe(false)
  })

  it('备份/恢复任务终态判定', () => {
    expect(isTerminalBackupStatus('RUNNING')).toBe(false)
    expect(isTerminalBackupStatus('VERIFYING')).toBe(false)
    expect(isTerminalBackupStatus('SUCCESS')).toBe(true)
    expect(isTerminalRestoreStatus('AWAITING_CONFIRM')).toBe(false)
    expect(isTerminalRestoreStatus('FAILED')).toBe(true)
  })

  it('升级任务终态含 ROLLED_BACK', () => {
    expect(isTerminalUpgradeStatus('ROLLED_BACK')).toBe(true)
    expect(isTerminalUpgradeStatus('RUNNING')).toBe(false)
  })

  it('交付检查终态判定', () => {
    expect(isTerminalDeliveryStatus('PENDING')).toBe(false)
    expect(isTerminalDeliveryStatus('PASS')).toBe(true)
    expect(isTerminalDeliveryStatus('WARNING')).toBe(true)
    expect(isTerminalDeliveryStatus('FAIL')).toBe(true)
    expect(isTerminalDeliveryStatus('SUCCESS')).toBe(false)
    expect(isTerminalDeliveryStatus('FAILED')).toBe(false)
    expect(isTerminalDeliveryStatus('COMPLETED')).toBe(false)
  })
})

describe('formatBytes 文件大小格式化', () => {
  it('空值与非法值返回占位符', () => {
    expect(formatBytes(undefined)).toBe('-')
    expect(formatBytes(null)).toBe('-')
    expect(formatBytes(-1)).toBe('-')
    expect(formatBytes(NaN)).toBe('-')
  })

  it('字节/KB/MB/GB 分级格式化', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1024)).toBe('1.00 KB')
    expect(formatBytes(1536)).toBe('1.50 KB')
    expect(formatBytes(1048576)).toBe('1.00 MB')
    expect(formatBytes(1073741824)).toBe('1.00 GB')
  })
})

describe('formatUptime 运行时长格式化', () => {
  it('空值返回占位符，字符串原样展示', () => {
    expect(formatUptime(undefined)).toBe('-')
    expect(formatUptime('')).toBe('-')
    expect(formatUptime('3天2小时')).toBe('3天2小时')
  })

  it('秒数格式化为天/小时/分钟', () => {
    expect(formatUptime(90061)).toBe('1 天 1 小时')
    expect(formatUptime(3661)).toBe('1 小时 1 分钟')
    expect(formatUptime(61)).toBe('1 分钟')
    expect(formatUptime(-5)).toBe('-')
  })
})

describe('升级包状态元数据', () => {
  it('覆盖后端升级包状态枚举', () => {
    for (const s of ['REGISTERED', 'VERIFIED', 'REJECTED']) {
      expect(UPGRADE_PACKAGE_STATUS_META[s]).toBeDefined()
    }
  })
})

describe('summarizeCheckResult 预检整体结果汇总', () => {
  it('任一 FAIL → FAIL', () => {
    expect(summarizeCheckResult([{ result: 'PASS' }, { result: 'FAIL' }])).toBe('FAIL')
  })

  it('无 FAIL 但任一 WARNING → WARNING', () => {
    expect(summarizeCheckResult([{ result: 'PASS' }, { result: 'WARNING' }])).toBe('WARNING')
  })

  it('全部 PASS 或空列表 → PASS', () => {
    expect(summarizeCheckResult([{ result: 'PASS' }])).toBe('PASS')
    expect(summarizeCheckResult([])).toBe('PASS')
  })
})

describe('系统告警组件与详情中文化格式化', () => {
  it('formatAlertComponent 支持大小写不敏感组件名与 vuln_intel 前缀', () => {
    expect(ALERT_COMPONENT_NAME_META.WAF).toBe('WAF 防护')
    expect(formatAlertComponent('waf')).toBe('WAF 防护')
    expect(formatAlertComponent('cc')).toBe('CC 防护')
    expect(formatAlertComponent('clickhouse')).toBe('ClickHouse 时序存储')
    expect(formatAlertComponent('API_SECURITY')).toBe('API 安全采集')
    expect(formatAlertComponent('API_ENDPOINT_DISCOVERY')).toBe('API 端点发现')
    expect(formatAlertComponent('waf_rule_packs')).toBe('离线规则包')
    expect(formatAlertComponent('vuln_intel:php')).toBe('漏洞情报：php')
    expect(formatAlertComponent('geoip:ip2region_v4')).toBe('GeoIP 归属地库：ip2region_v4')
    expect(formatAlertComponent('threat_intel:feodo')).toBe('威胁情报：feodo')
    expect(formatAlertComponent('shop/GET /v1/orders')).toBe('shop/GET /v1/orders')
    expect(formatAlertComponent('')).toBe('-')
  })

  it('formatAlertMessage 中文化存量英文风险发现码、严重级别与检测器标题', () => {
    expect(
      formatAlertMessage(
        '最近 60 分钟同类型风险发现超过阈值 20：IDENTITY_COOKIE_PRESENT 219 条；CREDENTIAL_COOKIE_SENSITIVE 219 条；AUTH_CREDENTIAL_CONCURRENCY 129 条 等 4 类',
      ),
    ).toBe(
      '最近 60 分钟同类型风险发现超过阈值 20：携带 Cookie 会话头 219 条；Cookie 携带敏感凭据 219 条；凭据异常并发使用 129 条 等 4 类',
    )

    expect(formatAlertMessage('最近 1 分钟 HIGH/CRITICAL 级安全事件 12 条（阈值 10）')).toBe(
      '最近 1 分钟高危/严重级安全事件 12 条（阈值 10）',
    )

    expect(
      formatAlertMessage('最近 10 分钟新增 3 条响应脱敏（MASK_RESPONSE）失败记录，存在未脱敏数据外发风险'),
    ).toBe('最近 10 分钟新增 3 条响应脱敏失败记录，存在未脱敏数据外发风险')

    const criticalLocalized = formatAlertMessage(
      '最近 10 分钟新增 2 条 CRITICAL 级风险发现：BOLA_UNAUTHENTICATED_OBJECT_ACCESS（object access without credential）；AUTHZ_BOLA_001（AUTHZ_BOLA_001）',
    )
    expect(criticalLocalized).toBe(
      '最近 10 分钟新增 2 条严重级风险发现：未认证对象越权访问（未携带认证凭据访问对象资源）；对象级越权（BOLA）',
    )
    // 二次格式化幂等（后端已中文化后再经前端渲染不二次改写括号简称）
    expect(formatAlertMessage(criticalLocalized)).toBe(criticalLocalized)

    expect(
      formatAlertMessage(
        '最高级别：CRITICAL；CVE 列表：CVE-2026-0001；参考链接：https://example.com/AUTH_TEST/CVE-2026-0001',
      ),
    ).toBe(
      '最高级别：严重；CVE 列表：CVE-2026-0001；参考链接：https://example.com/AUTH_TEST/CVE-2026-0001',
    )
  })
})
