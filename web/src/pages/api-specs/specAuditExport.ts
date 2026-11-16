import type { ApiSpecAudit } from '../../api/apiSecurity'

type CsvCell = string | number | boolean

const CSV_HEADER: readonly CsvCell[] = [
  'spec_id',
  'format',
  'operation_count',
  'issue_count',
  'high_count',
  'medium_count',
  'truncated',
  'rule_id',
  'severity',
  'endpoint_key',
  'param_in',
  'param_name',
  'message',
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
    audit.format,
    audit.operation_count,
    audit.issue_count,
    audit.high_count,
    audit.medium_count,
    audit.truncated,
  ]
  const rows: CsvCell[][] = audit.items.map((item) => [
    ...summary,
    item.rule_id,
    item.severity,
    item.endpoint_key,
    item.param_in,
    item.param_name,
    item.message,
  ])

  if (rows.length === 0) {
    rows.push([...summary, '', '', '', '', '', ''])
  }

  return `\uFEFF${[CSV_HEADER, ...rows].map(encodeCsvRow).join('\r\n')}\r\n`
}
