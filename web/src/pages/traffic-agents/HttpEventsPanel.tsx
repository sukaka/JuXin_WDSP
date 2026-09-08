import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Descriptions,
  Input,
  Modal,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type {
  TrafficHttpEvent,
  TrafficHttpMessage,
} from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatBytes, formatJson } from '../../utils/format'
import {
  BODY_SKIPPED_REASON_META,
  TLS_VISIBILITY_META,
  formatUnixTime,
  httpStatusColor,
} from './meta'

/** TLS 可见性 Tag（ENCRYPTED 附带"加密流量无法完整分析"提示） */
export function TlsVisibilityTag({ value }: { value: string }) {
  const meta = TLS_VISIBILITY_META[value]
  if (!meta) return <Tag>{value || '-'}</Tag>
  const tag = <Tag color={meta.color}>{meta.label}</Tag>
  return meta.tooltip ? <Tooltip title={meta.tooltip}>{tag}</Tooltip> : tag
}

const METHOD_OPTIONS = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'HEAD',
  'OPTIONS',
].map((m) => ({
  value: m,
  label: m,
}))

/** 状态码 Tag（§9：2xx 绿/3xx 蓝/4xx 橙/5xx 红，响应未捕获灰色"无响应"） */
function StatusTagCell({ status }: { status: number | null }) {
  if (status === null) return <Tag>无响应</Tag>
  return <Tag color={httpStatusColor(status)}>{status}</Tag>
}

/** 方向展示（与流量事件 Tab 同口径） */
function directionLabel(value: string): string {
  if (value === 'ingress') return '入站'
  if (value === 'egress') return '出站'
  return value || '-'
}

/** 请求/响应 Header 表（脱敏值即最终值，原样展示） */
function HeadersTable({
  headers,
}: {
  headers?: Record<string, string> | null
}) {
  const rows = Object.entries(headers ?? {}).map(([name, value]) => ({
    name,
    value,
  }))
  return (
    <Table
      rowKey="name"
      size="small"
      pagination={false}
      columns={[
        { title: '名称', dataIndex: 'name', width: 240 },
        {
          title: '值',
          dataIndex: 'value',
          ellipsis: true,
          render: (v: string) => (
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {v}
            </Typography.Text>
          ),
        },
      ]}
      dataSource={rows}
      locale={{ emptyText: '无 Header（采集等级 L0 或未捕获）' }}
    />
  )
}

/** Body 只读展示：JSON 美化；截断与 skipped 用 Alert 明示（§4/§9）；脱敏值即最终值 */
function BodyView({ message }: { message: TrafficHttpMessage }) {
  const skipped = message.body_skipped_reason || ''
  return (
    <div>
      {skipped ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 8 }}
          message={`Body 未采集（${skipped}）：${BODY_SKIPPED_REASON_META[skipped] ?? skipped}`}
          description={`原始大小 ${formatBytes(message.original_body_size)}`}
        />
      ) : message.body_truncated ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 8 }}
          message="Body 已截断"
          description={`受策略 max_body_size 上限限制仅采集前缀，原始大小 ${formatBytes(message.original_body_size)}`}
        />
      ) : null}
      {message.body ? (
        <pre
          style={{
            margin: 0,
            padding: 8,
            background: '#fafafa',
            border: '1px solid #f0f0f0',
            borderRadius: 4,
            maxHeight: 260,
            overflow: 'auto',
            fontSize: 12,
            wordBreak: 'break-all',
            whiteSpace: 'pre-wrap',
          }}
        >
          {formatJson(message.body)}
        </pre>
      ) : !skipped ? (
        <Typography.Text type="secondary">无 Body</Typography.Text>
      ) : null}
      <Typography.Text
        type="secondary"
        style={{ display: 'block', fontSize: 12, marginTop: 4 }}
      >
        数据已在 Agent 侧脱敏（离主机前完成），此处展示为最终值
      </Typography.Text>
    </div>
  )
}

/** 单条 HTTP 事件详情（五元组/方向/TLS 可见性 + 请求/响应 headers 与 body） */
function HttpEventDetail({ event }: { event: TrafficHttpEvent }) {
  const req = event.request
  const resp = event.response
  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Descriptions column={2} size="small" bordered>
        <Descriptions.Item label="Flow ID" span={2}>
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {event.flow_id}
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="五元组" span={2}>
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {`${event.src_ip}:${event.src_port} → ${event.dst_ip}:${event.dst_port}`}
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="方向">
          {directionLabel(event.direction)}
        </Descriptions.Item>
        <Descriptions.Item label="TLS 可见性">
          <TlsVisibilityTag value={event.tls_visibility} />
        </Descriptions.Item>
        {event.k8s ? (
          <Descriptions.Item label="K8s 工作负载" span={2}>
            <Tooltip
              title={`集群: ${event.k8s.cluster || '-'}；工作负载: ${event.k8s.workload || '-'}；服务: ${event.k8s.service || '-'}；端点: ${event.k8s.side}`}
            >
              {`${event.k8s.namespace}/${event.k8s.pod}`}
            </Tooltip>
          </Descriptions.Item>
        ) : null}
        <Descriptions.Item label="请求时间">
          {formatUnixTime(event.request_ts)}
        </Descriptions.Item>
        <Descriptions.Item label="响应时间">
          {event.response_ts !== null ? formatUnixTime(event.response_ts) : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="时延">
          {event.latency_ms !== null ? `${event.latency_ms} ms` : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="状态">
          <StatusTagCell status={resp?.status ?? null} />
        </Descriptions.Item>
      </Descriptions>

      <div>
        <Typography.Text strong>请求</Typography.Text>
        <div
          style={{ margin: '4px 0 8px', fontFamily: 'monospace', fontSize: 12 }}
        >
          {`${req.method} ${req.scheme}://${req.host}${req.uri}`}
        </div>
        <HeadersTable headers={req.headers} />
        <Typography.Text
          strong
          style={{ display: 'block', margin: '8px 0 4px' }}
        >
          请求 Body
        </Typography.Text>
        <BodyView message={req} />
      </div>

      <div>
        <Typography.Text strong>响应</Typography.Text>
        {resp ? (
          <>
            <div style={{ margin: '4px 0 8px' }}>
              <StatusTagCell status={resp.status} />
            </div>
            <HeadersTable headers={resp.headers} />
            <Typography.Text
              strong
              style={{ display: 'block', margin: '8px 0 4px' }}
            >
              响应 Body
            </Typography.Text>
            <BodyView message={resp} />
          </>
        ) : (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 4 }}
            message="响应未捕获（超时或连接中断），无响应数据"
          />
        )}
      </div>
    </Space>
  )
}

/** Agent HTTP 事件面板（Phase 3 契约 §9）：服务端分页表 + host/method 过滤 + 行点击详情 */
export default function HttpEventsPanel({
  agentId,
  enabled = true,
}: {
  agentId: string
  enabled?: boolean
}) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [host, setHost] = useState<string | undefined>()
  const [method, setMethod] = useState<string | undefined>()
  const [detailId, setDetailId] = useState<number | null>(null)

  const listQuery = useQuery({
    queryKey: [
      'traffic-agents',
      'http-events',
      agentId,
      page,
      pageSize,
      host,
      method,
    ],
    queryFn: () =>
      trafficAgentsApi.agentHttpEvents(agentId, {
        page,
        page_size: pageSize,
        host,
        method,
      }),
    enabled: enabled && !!agentId,
  })

  const detailQuery = useQuery({
    queryKey: ['traffic-agents', 'http-event', agentId, detailId],
    queryFn: () => trafficAgentsApi.agentHttpEvent(agentId, detailId as number),
    enabled: enabled && !!agentId && detailId !== null,
  })

  const columns: ColumnsType<TrafficHttpEvent> = [
    {
      title: '时间',
      key: 'time',
      width: 160,
      render: (_, r) => formatUnixTime(r.request_ts),
    },
    {
      title: '请求',
      key: 'request',
      ellipsis: true,
      render: (_, r) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {`${r.request.method} ${r.request.host}${r.request.uri}`}
        </Typography.Text>
      ),
    },
    {
      title: 'K8s 工作负载',
      key: 'k8s',
      width: 190,
      render: (_, r) =>
        r.k8s ? (
          <Tooltip
            title={`集群: ${r.k8s.cluster || '-'}；命名空间: ${r.k8s.namespace || '-'}；Pod: ${r.k8s.pod || '-'}；工作负载: ${r.k8s.workload || '-'}；服务: ${r.k8s.service || '-'}；端点: ${r.k8s.side}`}
          >
            <Typography.Text ellipsis style={{ maxWidth: 170 }}>
              {`${r.k8s.namespace}/${r.k8s.pod}`}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '状态',
      key: 'status',
      width: 90,
      render: (_, r) => <StatusTagCell status={r.response?.status ?? null} />,
    },
    {
      title: '时延',
      dataIndex: 'latency_ms',
      width: 90,
      render: (v: number | null) =>
        v !== null && v !== undefined ? `${v} ms` : '-',
    },
    {
      title: '截断',
      key: 'truncated',
      width: 130,
      render: (_, r) => {
        const tags = []
        if (r.request.body_truncated) {
          tags.push(
            <Tooltip key="req" title="请求 Body 已按策略上限截断">
              <Tag color="orange">请求截断</Tag>
            </Tooltip>,
          )
        }
        if (r.response?.body_truncated) {
          tags.push(
            <Tooltip key="resp" title="响应 Body 已按策略上限截断">
              <Tag color="orange">响应截断</Tag>
            </Tooltip>,
          )
        }
        return tags.length > 0 ? <Space size={0}>{tags}</Space> : '-'
      },
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 12 }} wrap>
        <Input.Search
          placeholder="按 Host 过滤"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setHost(v.trim() || undefined)
            setPage(1)
          }}
        />
        <Select
          placeholder="按 Method 过滤"
          allowClear
          style={{ width: 140 }}
          options={METHOD_OPTIONS}
          value={method}
          onChange={(v) => {
            setMethod(v)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 HTTP 事件失败" />
      ) : (
        <SmartTable<TrafficHttpEvent>
          storageKey="traffic-agent-http-events"
          rowKey="id"
          size="small"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 760 }}
          locale={{ emptyText: '暂无 HTTP 事件' }}
          onRow={(r) => ({
            onClick: () => setDetailId(r.id),
            style: { cursor: 'pointer' },
          })}
          pagination={{
            current: page,
            pageSize,
            total: listQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
          }}
        />
      )}

      <Modal
        title={
          detailId !== null ? `HTTP 事件详情（#${detailId}）` : 'HTTP 事件详情'
        }
        open={detailId !== null}
        onCancel={() => setDetailId(null)}
        footer={null}
        width={780}
        destroyOnHidden
      >
        {detailQuery.isLoading ? (
          <div style={{ textAlign: 'center', padding: 48 }}>
            <Spin />
          </div>
        ) : detailQuery.isError ? (
          <QueryErrorAlert
            error={detailQuery.error}
            message="加载 HTTP 事件详情失败"
          />
        ) : detailQuery.data ? (
          <HttpEventDetail event={detailQuery.data} />
        ) : null}
      </Modal>
    </>
  )
}
