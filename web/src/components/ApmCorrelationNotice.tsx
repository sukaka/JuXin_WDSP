import { Button, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Link } from 'react-router-dom'
import type { ApmCorrelation, ApmCorrelationCandidate } from '../types'
import { APM_CORRELATION_STATE_META, APM_MATCH_BASIS_LABELS } from '../utils/apm'
import { formatDateTime } from '../utils/format'

/**
 * 关联判定（correlation，P1-01 §4.3）统一展示：关联强度（state + match_basis + candidate_count）
 * 与人类可读 reason；AMBIGUOUS 时逐候选列出时间/服务/匹配依据，由用户人工选择，系统不自动任选。
 * correlation 缺失（旧后端或本就不携带的查询形态）时不渲染，由调用方决定是否提示「状态信息不足」。
 */
export default function ApmCorrelationNotice({
  correlation,
  currentTraceId,
  onSelectTrace,
}: {
  correlation?: ApmCorrelation | null
  /** 当前正在查看的 trace_id（候选列表中标识「当前」） */
  currentTraceId?: string
  /** 提供后候选「查看」按钮就地切换；缺省降级为跳转 /apm-traces?trace_id= */
  onSelectTrace?: (traceId: string) => void
}) {
  if (correlation == null) return null
  const meta = APM_CORRELATION_STATE_META[correlation.state] ?? {
    color: 'default',
    label: correlation.state || '未知',
  }
  const candidates = correlation.candidates ?? []

  const columns: ColumnsType<ApmCorrelationCandidate> = [
    {
      title: 'Trace ID',
      dataIndex: 'trace_id',
      ellipsis: true,
      render: (v: string) => (
        <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {v ? `${v.slice(0, 8)}…` : '-'}
        </Typography.Text>
      ),
    },
    {
      title: '候选时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string | null) => (v ? formatDateTime(v) : '未知'),
    },
    {
      title: '涉及服务',
      dataIndex: 'services',
      ellipsis: true,
      render: (v: string[] | null) => (v && v.length > 0 ? v.join('、') : '未知'),
    },
    {
      title: '匹配依据',
      dataIndex: 'match_basis',
      width: 190,
      render: (v: string) => APM_MATCH_BASIS_LABELS[v] ?? v,
    },
    {
      title: '操作',
      key: 'action',
      width: 110,
      render: (_, r) =>
        r.trace_id === currentTraceId ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            当前
          </Typography.Text>
        ) : onSelectTrace ? (
          <Button type="link" size="small" onClick={() => onSelectTrace(r.trace_id)}>
            查看该 Trace
          </Button>
        ) : (
          <Link to={`/apm-traces?trace_id=${encodeURIComponent(r.trace_id)}`}>
            <Button type="link" size="small">
              查看该 Trace
            </Button>
          </Link>
        ),
    },
  ]

  return (
    <div style={{ marginBottom: 12 }}>
      <Space wrap size={8}>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          关联强度：
        </Typography.Text>
        <Tag color={meta.color}>{meta.label}</Tag>
        {correlation.match_basis && (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            匹配依据：{APM_MATCH_BASIS_LABELS[correlation.match_basis] ?? correlation.match_basis}
          </Typography.Text>
        )}
        {correlation.candidate_count > 1 && (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            候选数：{correlation.candidate_count}
          </Typography.Text>
        )}
      </Space>
      {correlation.reason && (
        <div style={{ marginTop: 4 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {correlation.reason}
          </Typography.Text>
        </div>
      )}
      {correlation.state === 'AMBIGUOUS' && candidates.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 4 }}>
            存在多个候选，请人工核对时间与服务后选择；系统不会自动任选其一。
          </Typography.Text>
          <Table<ApmCorrelationCandidate>
            size="small"
            rowKey="trace_id"
            pagination={false}
            dataSource={candidates}
            columns={columns}
          />
        </div>
      )}
    </div>
  )
}
