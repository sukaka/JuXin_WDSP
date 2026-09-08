import { useMemo } from 'react'
import { Descriptions, Drawer, Typography } from 'antd'
import { formatDateTime, formatJson } from '../utils/format'

/**
 * RecordDetailDrawer：通用只读行详情抽屉。
 * 用于没有专属详情视图的列表：双击行打开，以 Descriptions 展示该行全部字段。
 * 口径：null/undefined/空串 → '-'；布尔 → 是/否；对象/数组 → JSON 缩进展示；
 * ISO 时间串 → 本地时间格式；长文本省略悬浮可见。
 */

/** 键名或值形似时间字段时按时间渲染（occurred_at/created_at/...At 等） */
const TIME_KEY_PATTERN = /(_at|_time|At|Time|_date|Date)$/
const ISO_DATETIME_PATTERN = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/

function isEmpty(v: unknown): boolean {
  return v === null || v === undefined || v === ''
}

function renderValue(key: string, value: unknown) {
  if (isEmpty(value)) return <Typography.Text type="secondary">-</Typography.Text>
  if (typeof value === 'boolean') return value ? '是' : '否'
  if (typeof value === 'object') {
    return (
      <Typography.Paragraph
        copyable
        style={{ fontFamily: 'monospace', fontSize: 12, whiteSpace: 'pre-wrap', marginBottom: 0 }}
      >
        {formatJson(value)}
      </Typography.Paragraph>
    )
  }
  const text = String(value)
  if (
    (TIME_KEY_PATTERN.test(key) || ISO_DATETIME_PATTERN.test(text)) &&
    ISO_DATETIME_PATTERN.test(text)
  ) {
    return formatDateTime(text)
  }
  if (text.length > 200) {
    return (
      <Typography.Paragraph
        copyable
        ellipsis={{ rows: 3, expandable: true, symbol: '展开' }}
        style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}
      >
        {text}
      </Typography.Paragraph>
    )
  }
  return text
}

export interface RecordDetailDrawerProps {
  open: boolean
  title: string
  /** 当前行记录（null 时不渲染内容） */
  record: Record<string, unknown> | null
  onClose: () => void
  width?: number
}

export default function RecordDetailDrawer({
  open,
  title,
  record,
  onClose,
  width = 640,
}: RecordDetailDrawerProps) {
  const items = useMemo(
    () =>
      Object.entries(record ?? {}).map(([key, value]) => ({
        key,
        label: key,
        children: renderValue(key, value),
      })),
    [record],
  )
  return (
    <Drawer title={title} open={open} onClose={onClose} width={width} destroyOnHidden>
      <Descriptions column={1} bordered size="small" items={items} />
    </Drawer>
  )
}
