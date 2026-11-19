import { useMemo, useState } from 'react'
import { Table, Tag, Typography } from 'antd'
import dayjs from 'dayjs'
import type { ApmOtelSpan } from '../types'

/** span 类型中文映射（大小写归一，兼容 OpenTelemetry SPAN_KIND_* 前缀） */
const SPAN_KIND_LABELS: Record<string, string> = {
  SERVER: '服务端',
  SPAN_KIND_SERVER: '服务端',
  CLIENT: '客户端',
  SPAN_KIND_CLIENT: '客户端',
  INTERNAL: '内部调用',
  SPAN_KIND_INTERNAL: '内部调用',
  PRODUCER: '消息生产',
  SPAN_KIND_PRODUCER: '消息生产',
  CONSUMER: '消息消费',
  SPAN_KIND_CONSUMER: '消息消费',
  UNSPECIFIED: '未指定',
  SPAN_KIND_UNSPECIFIED: '未指定',
}

/** span 状态码中文映射（大小写归一，兼容 OpenTelemetry STATUS_CODE_* 前缀） */
const SPAN_STATUS_LABELS: Record<string, string> = {
  UNSET: '未设置',
  STATUS_CODE_UNSET: '未设置',
  OK: '正常',
  STATUS_CODE_OK: '正常',
  ERROR: '错误',
  STATUS_CODE_ERROR: '错误',
}

function formatSpanKind(kind?: string): string {
  const raw = (kind || '').trim()
  if (!raw) return ''
  return SPAN_KIND_LABELS[raw.toUpperCase()] ?? raw
}

function formatSpanStatus(statusCode?: string): string {
  const raw = (statusCode || '').trim()
  if (!raw) return '未设置'
  return SPAN_STATUS_LABELS[raw.toUpperCase()] ?? raw
}

/** span 状态条配色：ERROR 红、OK 绿、UNSET/其它蓝（与 antd 主题色一致，不引入新依赖） */
function spanBarColor(statusCode: string): string {
  const s = (statusCode || '').toUpperCase()
  if (s === 'ERROR' || s === 'STATUS_CODE_ERROR') return '#ff4d4f'
  if (s === 'OK' || s === 'STATUS_CODE_OK') return '#52c41a'
  return '#1677ff'
}

interface SpanNode {
  span: ApmOtelSpan
  children: SpanNode[]
}

/** 按 parent_span_id 组树；父 span 缺失（截断/采样）的节点提升为根，避免丢段 */
function buildSpanTree(spans: ApmOtelSpan[]): SpanNode[] {
  const byId = new Map<string, SpanNode>()
  for (const s of spans) {
    if (!byId.has(s.span_id)) byId.set(s.span_id, { span: s, children: [] })
  }
  const roots: SpanNode[] = []
  for (const node of byId.values()) {
    const parent = node.span.parent_span_id ? byId.get(node.span.parent_span_id) : undefined
    if (parent && parent !== node) parent.children.push(node)
    else roots.push(node)
  }
  const byStart = (a: SpanNode, b: SpanNode) =>
    dayjs(a.span.start_time).valueOf() - dayjs(b.span.start_time).valueOf()
  const sortRec = (nodes: SpanNode[]) => {
    nodes.sort(byStart)
    nodes.forEach((n) => sortRec(n.children))
  }
  sortRec(roots)
  return roots
}

interface FlatRow {
  span: ApmOtelSpan
  depth: number
}

function flattenTree(roots: SpanNode[]): FlatRow[] {
  const out: FlatRow[] = []
  const visited = new Set<string>()
  const walk = (nodes: SpanNode[], depth: number) => {
    for (const n of nodes) {
      if (visited.has(n.span.span_id)) continue // 环保护（异常数据下不死循环）
      visited.add(n.span.span_id)
      out.push({ span: n.span, depth })
      walk(n.children, depth + 1)
    }
  }
  walk(roots, 0)
  return out
}

/**
 * Trace 瀑布图（轻量自绘：div + CSS 比例条，无新依赖）。
 * - 按 parent_span_id 组树、缩进层级展示；
 * - 水平条按 duration_ms 占整条链路时间窗比例绘制；
 * - ERROR span 红色标识；
 * - 点击行展开 attributes 明细表。
 */
export default function ApmTraceWaterfall({ spans }: { spans: ApmOtelSpan[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const rows = useMemo(() => flattenTree(buildSpanTree(spans)), [spans])

  // 链路时间窗：最早 start ~ 最晚 end；零宽防御按 1ms 处理
  const window_ = useMemo(() => {
    let minStart = Infinity
    let maxEnd = -Infinity
    for (const s of spans) {
      const st = dayjs(s.start_time).valueOf()
      if (!Number.isFinite(st)) continue
      const en = st + Math.max(0, s.duration_ms || 0)
      if (st < minStart) minStart = st
      if (en > maxEnd) maxEnd = en
    }
    if (!Number.isFinite(minStart) || !Number.isFinite(maxEnd)) return null
    return { minStart, total: Math.max(1, maxEnd - minStart) }
  }, [spans])

  if (rows.length === 0 || !window_) {
    return <Typography.Text type="secondary">暂无 span 数据</Typography.Text>
  }

  return (
    <div>
      {/* 表头：左为 span 名称列，右为时间比例尺 */}
      <div style={{ display: 'flex', fontSize: 12, color: '#8c8c8c', marginBottom: 4 }}>
        <div style={{ width: '42%', flexShrink: 0 }}>服务 / 操作（{rows.length} 个 span）</div>
        <div style={{ flex: 1, display: 'flex', justifyContent: 'space-between' }}>
          <span>0 ms</span>
          <span>{window_.total} ms</span>
        </div>
      </div>
      {rows.map(({ span, depth }) => {
        const start = dayjs(span.start_time).valueOf()
        const leftPct = Number.isFinite(start)
          ? Math.min(100, Math.max(0, ((start - window_.minStart) / window_.total) * 100))
          : 0
        const widthPct = Math.max(0.5, Math.min(100 - leftPct, (Math.max(0, span.duration_ms || 0) / window_.total) * 100))
        const isError =
          (span.status_code || '').toUpperCase() === 'ERROR' ||
          (span.status_code || '').toUpperCase() === 'STATUS_CODE_ERROR'
        const expanded = expandedId === span.span_id
        return (
          <div key={span.span_id}>
            <div
              role="button"
              tabIndex={0}
              aria-label={`span ${span.operation_name}`}
              onClick={() => setExpandedId(expanded ? null : span.span_id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') setExpandedId(expanded ? null : span.span_id)
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                padding: '4px 0',
                cursor: 'pointer',
                background: expanded ? '#f5f5f5' : undefined,
              }}
            >
              <div
                style={{
                  width: '42%',
                  flexShrink: 0,
                  paddingLeft: depth * 16,
                  overflow: 'hidden',
                  whiteSpace: 'nowrap',
                  textOverflow: 'ellipsis',
                  fontSize: 12,
                }}
              >
                <Typography.Text strong style={{ fontSize: 12 }}>
                  {span.service_name || '-'}
                </Typography.Text>{' '}
                <Typography.Text style={{ fontSize: 12, fontFamily: 'monospace' }}>
                  {span.operation_name || '-'}
                </Typography.Text>{' '}
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {span.duration_ms} ms
                </Typography.Text>
                {isError && (
                  <Tag color="red" style={{ marginLeft: 4 }}>
                    错误
                  </Tag>
                )}
              </div>
              <div style={{ flex: 1, position: 'relative', height: 14, background: '#fafafa', borderRadius: 2 }}>
                <div
                  data-testid={`span-bar-${span.span_id}`}
                  style={{
                    position: 'absolute',
                    left: `${leftPct}%`,
                    width: `${widthPct}%`,
                    top: 2,
                    bottom: 2,
                    background: spanBarColor(span.status_code),
                    borderRadius: 2,
                  }}
                />
              </div>
            </div>
            {expanded && (
              <div style={{ padding: '4px 0 8px', paddingLeft: depth * 16 + 16 }}>
                <div style={{ fontSize: 12, color: '#8c8c8c', marginBottom: 4 }}>
                  Span ID：<Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                    {span.span_id}
                  </Typography.Text>
                  {span.parent_span_id ? (
                    <>
                      {'　'}父 Span：
                      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {span.parent_span_id}
                      </Typography.Text>
                    </>
                  ) : (
                    <Tag style={{ marginLeft: 8 }}>根 Span</Tag>
                  )}
                  {span.span_kind && <Tag style={{ marginLeft: 8 }}>{formatSpanKind(span.span_kind)}</Tag>}
                  <Tag style={{ marginLeft: 8 }}>{formatSpanStatus(span.status_code)}</Tag>
                </div>
                <Table
                  size="small"
                  rowKey={(r) => r.key}
                  pagination={false}
                  dataSource={Object.entries(span.attributes ?? {})
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([key, value]) => ({ key, value }))}
                  columns={[
                    { title: '属性', dataIndex: 'key', width: 220, ellipsis: true },
                    {
                      title: '值',
                      dataIndex: 'value',
                      render: (v: string) => (
                        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                          {v}
                        </Typography.Text>
                      ),
                    },
                  ]}
                  locale={{ emptyText: '无属性' }}
                />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
