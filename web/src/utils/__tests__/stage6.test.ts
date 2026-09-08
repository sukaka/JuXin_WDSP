import { describe, expect, it } from 'vitest'
import { formatBytes } from '../format'
import {
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

  it('系统告警类型覆盖任务书全部 18 类', () => {
    expect(Object.keys(ALERT_TYPE_META).sort()).toEqual(
      [
        'GATEWAY_DOWN',
        'MANAGEMENT_API_DOWN',
        'DATABASE_UNAVAILABLE',
        'VALKEY_UNAVAILABLE',
        'EVENT_COLLECTOR_LAG',
        'EVENT_PARSE_FAILURE_RATE_HIGH',
        'SOURCE_UNHEALTHY',
        'CERTIFICATE_EXPIRING',
        'CERTIFICATE_EXPIRED',
        'CONFIG_PUBLISH_FAILED',
        'CONFIG_HASH_MISMATCH',
        'DISK_SPACE_LOW',
        'DATABASE_CAPACITY_HIGH',
        'BACKUP_FAILED',
        'RESTORE_VALIDATION_FAILED',
        'REPORT_FAILED',
        'UPGRADE_FAILED',
        'AUDIT_INTEGRITY_FAILED',
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

  it('监控组件名覆盖任务书组件清单', () => {
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
    ]) {
      expect(COMPONENT_NAME_META[c]).toBeTruthy()
    }
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

  it('报告章节选项值不重复且含结论章节', () => {
    const values = REPORT_SECTION_OPTIONS.map((s) => s.value)
    expect(new Set(values).size).toBe(values.length)
    expect(values).toContain('conclusion')
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
    expect(isTerminalDeliveryStatus('RUNNING')).toBe(false)
    expect(isTerminalDeliveryStatus('SUCCESS')).toBe(true)
    expect(isTerminalDeliveryStatus('FAILED')).toBe(true)
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
