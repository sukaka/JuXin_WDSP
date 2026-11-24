import type { ApiSpecAudit } from '../../api/apiSecurity'
import {
  formatSpecAuditFormat,
  formatSpecAuditParamIn,
  formatSpecAuditRule,
  formatSpecAuditSeverity,
} from './specAuditMeta'

type CsvCell = string | number | boolean

const CSV_HEADER: readonly CsvCell[] = [
  '规范 ID',
  '规范格式',
  '操作数',
  '问题数',
  '高危问题',
  '中危问题',
  '是否截断',
  '规则',
  '严重级别',
  '接口键',
  '参数位置',
  '参数名称',
  '说明',
]

function encodeCsvCell(value: CsvCell): string {
  let text = String(value)
  if (/^[=+\-@\t\r\n]/.test(text)) {
    text = `'${text}`
  }
  return `"${text.replace(/"/g, '""')}"`
}

function encodeCsvRow(row: readonly CsvCell[]): string {
  return row.map(encodeCsvCell).join(',')
}

export function specAuditCSV(audit: ApiSpecAudit): string {
  const summary: CsvCell[] = [
    audit.spec_id,
    formatSpecAuditFormat(audit.format),
    audit.operation_count,
    audit.issue_count,
    audit.high_count,
    audit.medium_count,
    audit.truncated ? '是' : '否',
  ]
  const rows: CsvCell[][] = audit.items.map((item) => [
    ...summary,
    formatSpecAuditRule(item.rule_id),
    formatSpecAuditSeverity(item.severity),
    item.endpoint_key,
    formatSpecAuditParamIn(item.param_in),
    item.param_name,
    item.message,
  ])

  if (rows.length === 0) {
    rows.push([...summary, '', '', '', '', '', ''])
  }

  return `\uFEFF${[CSV_HEADER, ...rows].map(encodeCsvRow).join('\r\n')}\r\n`
}
