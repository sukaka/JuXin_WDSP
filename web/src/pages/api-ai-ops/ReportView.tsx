import { useState } from 'react'
import { Descriptions, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatJson } from '../../utils/format'
import {
  AI_REPORT_FIELD_LABELS,
  COMMON_DETAIL_FIELD_LABELS,
  COMMON_DETAIL_VALUE_LABELS,
  FILE_SENSITIVE_TYPE_LABELS,
} from '../../utils/i18nLabels'
import {
  API_ENDPOINT_STATUS_META,
  API_FINDING_SEVERITY_META,
  API_PARAM_DIRECTION_META,
  API_SENSITIVE_TYPE_META,
  getApiFindingTypeMeta,
} from '../../utils/stage8'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'

/** 单键值清单表格化时最多展示的列数与行数（报告可能较宽，防爆版式） */
const MAX_LIST_COLS = 5
const MAX_LIST_ROWS = 5

/** 标量（string/number/boolean）直接入关键指标区 */
function isScalar(v: unknown): v is string | number | boolean {
  return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
}

/** 字段名中文映射 */
function reportFieldLabel(key: string): string {
  return AI_REPORT_FIELD_LABELS[key] ?? COMMON_DETAIL_FIELD_LABELS[key] ?? key
}

/** 标量展示文本（布尔转是/否，已知枚举按字段键映射为中文） */
function scalarText(v: string | number | boolean, fieldKey?: string): string {
  if (typeof v === 'boolean') return v ? '是' : '否'
  if (typeof v !== 'string') return String(v)
  if (!fieldKey) return v
  if (fieldKey === 'asset_status') {
    return API_ENDPOINT_STATUS_META[v]?.label ?? COMMON_DETAIL_VALUE_LABELS.asset_status?.[v] ?? v
  }
  if (fieldKey === 'finding_type') {
    return getApiFindingTypeMeta(v).label
  }
  if (fieldKey === 'severity') {
    return API_FINDING_SEVERITY_META[v]?.label ?? COMMON_DETAIL_VALUE_LABELS.severity?.[v] ?? v
  }
  if (fieldKey === 'status') {
    return COMMON_DETAIL_VALUE_LABELS.status?.[v] ?? v
  }
  if (fieldKey === 'direction') {
    return API_PARAM_DIRECTION_META[v]?.label ?? COMMON_DETAIL_VALUE_LABELS.direction?.[v] ?? v
  }
  if (fieldKey === 'data_type') {
    return API_SENSITIVE_TYPE_META[v]?.label ?? FILE_SENSITIVE_TYPE_LABELS[v] ?? v
  }
  return COMMON_DETAIL_VALUE_LABELS[fieldKey]?.[v] ?? v
}

/**
 * 执行报告（report_json）关键字段表格化：
 * - 顶层标量 → 关键指标 Descriptions；
 * - 对象数组 → 每个键一张小表（列取首行标量键，限 MAX_LIST_COLS 列 / MAX_LIST_ROWS 行）；
 * - 标量数组 → Tag 清单；
 * - 其余嵌套结构 → JSON 原文兜底。
 * 五种内置任务报告结构不同，组件按通用规则降级呈现，不逐类型硬编码。
 */
export default function ReportView({ report }: { report: Record<string, unknown> | null | undefined }) {
  const [detailRecord, setDetailRecord] = useState<Record<string, unknown> | null>(null)
  const entries = Object.entries(report ?? {})
  if (entries.length === 0) {
    return <Typography.Text type="secondary">无结构化报告</Typography.Text>
  }
  const scalars = entries.filter((e): e is [string, string | number | boolean] => isScalar(e[1]))
  const objectLists = entries.filter(
    ([, v]) => Array.isArray(v) && v.length > 0 && v.every((it) => it !== null && typeof it === 'object' && !Array.isArray(it)),
  )
  const scalarLists = entries.filter(
    ([, v]) => Array.isArray(v) && v.length > 0 && v.every((it) => isScalar(it)),
  )
  const others = entries.filter(
    ([, v]) =>
      !isScalar(v) &&
      !(Array.isArray(v) && v.every((it) => isScalar(it))) &&
      !(Array.isArray(v) && v.length > 0 && v.every((it) => it !== null && typeof it === 'object' && !Array.isArray(it))),
  )

  return (
    <div>
      {scalars.length > 0 ? (
        <Descriptions column={2} size="small" bordered style={{ marginBottom: 12 }}>
          {scalars.map(([k, v]) => (
            <Descriptions.Item key={k} label={reportFieldLabel(k)}>
              {scalarText(v, k)}
            </Descriptions.Item>
          ))}
        </Descriptions>
      ) : null}
      {objectLists.map(([k, v]) => {
        const rows = (v as Record<string, unknown>[]).slice(0, MAX_LIST_ROWS)
        const colKeys = Object.keys(rows[0] ?? {})
          .filter((ck) => isScalar(rows[0][ck]))
          .slice(0, MAX_LIST_COLS)
        const columns: ColumnsType<Record<string, unknown>> = colKeys.map((ck) => ({
          title: reportFieldLabel(ck),
          dataIndex: ck,
          ellipsis: true,
          render: (cv: unknown) => (isScalar(cv) ? scalarText(cv, ck) : formatJson(cv)),
        }))
        return (
          <div key={k} style={{ marginBottom: 12 }}>
            <Typography.Text strong style={{ fontSize: 12 }}>
              {reportFieldLabel(k)}（{(v as unknown[]).length} 条{(v as unknown[]).length > MAX_LIST_ROWS ? `，展示前 ${MAX_LIST_ROWS} 条` : ''}）
            </Typography.Text>
            <Table<Record<string, unknown>>
              rowKey={(_, i) => `${k}-${i}`}
              size="small"
              columns={columns}
              dataSource={rows}
              pagination={false}
              onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
              style={{ marginTop: 4 }}
            />
          </div>
        )
      })}
      {scalarLists.map(([k, v]) => (
        <div key={k} style={{ marginBottom: 12 }}>
          <Typography.Text strong style={{ fontSize: 12 }}>
            {reportFieldLabel(k)}：
          </Typography.Text>
          {(v as (string | number | boolean)[]).map((it, i) => (
            <Tag key={i} style={{ marginTop: 4 }}>
              {scalarText(it, k)}
            </Tag>
          ))}
        </div>
      ))}
      {others.map(([k, v]) => (
        <div key={k} style={{ marginBottom: 12 }}>
          <Typography.Text strong style={{ fontSize: 12 }}>
            {reportFieldLabel(k)}：
          </Typography.Text>
          <Typography.Paragraph>
            <pre style={{ margin: '4px 0 0', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {formatJson(v)}
            </pre>
          </Typography.Paragraph>
        </div>
      ))}
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="记录详情"
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />
    </div>
  )
}
