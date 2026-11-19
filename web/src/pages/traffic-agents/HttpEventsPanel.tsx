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
  TrafficGrpcMeta,
  TrafficHttpEvent,
  TrafficHttpHeaders,
  TrafficHttpMessage,
} from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatBytes, formatJson } from '../../utils/format'
import {
  ASSOC_REASON_META,
  ASSOC_STATE_META,
  BODY_SKIPPED_REASON_META,
  GRPC_STREAM_STATE_META,
  REPLAY_DELAY_THRESHOLD_SEC,
  SOURCE_TYPE_META,
  TLS_VISIBILITY_META,
  formatK8sSide,
  formatUnixTime,
  httpStatusColor,
  httpVersionLabel,
  ingestionDelaySec,
  supportsHttpEventV2,
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

/** 采集来源 Tag（v2；v1 行返回占位符——旧采集无来源观测信息，不伪造） */
function SourceTypeTag({ event }: { event: TrafficHttpEvent }) {
  if (event.schema_version !== 2) return <span>-</span>
  const meta = SOURCE_TYPE_META[event.source_type ?? '']
  const tag = (
    <Tag color={meta?.color}>{meta?.label ?? event.source_type ?? '-'}</Tag>
  )
  const tip = `实例: ${event.source_instance || '-'}；代次: ${event.source_epoch ?? 0}${
    event.source_capabilities_version
      ? `；能力版本: ${event.source_capabilities_version}`
      : ''
  }${meta?.tooltip ? `；${meta.tooltip}` : ''}`
  return <Tooltip title={tip}>{tag}</Tooltip>
}

/** 关联状态 Tag（v2；COMPLETE 之外附原因提示） */
function AssociationTag({ event }: { event: TrafficHttpEvent }) {
  if (!event.association_state) return <span>-</span>
  const meta = ASSOC_STATE_META[event.association_state]
  const tag = (
    <Tag color={meta?.color}>{meta?.label ?? event.association_state}</Tag>
  )
  const reason = event.association_reason
    ? (ASSOC_REASON_META[event.association_reason] ?? event.association_reason)
    : ''
  return reason ? <Tooltip title={reason}>{tag}</Tooltip> : tag
}

/** 请求/响应 Header 表（脱敏值即最终值，原样纯文本展示——不渲染 HTML；
 * v1 string map 与 v2 数组 map 双形态兼容，v2 重复值逐行保序展示） */
function HeadersTable({
  headers,
  emptyText = '无 Header（采集等级 L0 或未捕获）',
}: {
  headers?: TrafficHttpHeaders | null
  emptyText?: string
}) {
  const rows = Object.entries(headers ?? {}).flatMap(([name, value]) =>
    (Array.isArray(value) ? value : [value]).map((v, idx) => ({
      key: `${name}#${idx}`,
      name,
      value: v,
    })),
  )
  return (
    <Table
      rowKey="key"
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
      locale={{ emptyText }}
    />
  )
}

/** Body 数据质量说明（v2 body_quality 子对象；未知长度如实展示"未知"，不按 0 处理） */
function BodyQualityLine({ message }: { message: TrafficHttpMessage }) {
  const q = message.body_quality
  if (!q) return null
  return (
    <Typography.Text
      type="secondary"
      style={{ display: 'block', fontSize: 12, marginTop: 4 }}
    >
      {`数据质量：实际捕获 ${formatBytes(q.captured_bytes)} / 原始总大小 ${
        q.original_total_size === null ? '未知' : formatBytes(q.original_total_size)
      }${q.truncated ? ' / 已截断' : ''}${
        q.skipped_reason
          ? ` / 未采集（${BODY_SKIPPED_REASON_META[q.skipped_reason] ?? q.skipped_reason}）`
          : ''
      }`}
    </Typography.Text>
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
          message={`正文未采集：${BODY_SKIPPED_REASON_META[skipped] ?? skipped}`}
          description={`原始大小 ${formatBytes(message.original_body_size)}`}
        />
      ) : message.body_truncated ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 8 }}
          message="正文已截断"
          description={`受策略最大正文长度上限限制仅采集前缀，原始大小 ${formatBytes(message.original_body_size)}`}
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
        <Typography.Text type="secondary">无正文</Typography.Text>
      ) : null}
      <BodyQualityLine message={message} />
      <Typography.Text
        type="secondary"
        style={{ display: 'block', fontSize: 12, marginTop: 4 }}
      >
        数据已在 Agent 侧脱敏（离主机前完成），此处展示为最终值
      </Typography.Text>
    </div>
  )
}

/** v2 来源/协议/数据质量区块（仅 v2 行渲染；v1 行无此口径不伪造） */
function EventV2Section({ event }: { event: TrafficHttpEvent }) {
  if (event.schema_version !== 2) return null
  const delay = ingestionDelaySec(event.collection_ts, event.ingestion_ts)
  const replaySuspected = delay !== null && delay > REPLAY_DELAY_THRESHOLD_SEC
  return (
    <div>
      <Typography.Text strong>来源与数据质量（v2 协议）</Typography.Text>
      <Descriptions
        column={2}
        size="small"
        bordered
        style={{ marginTop: 8 }}
      >
        <Descriptions.Item label="事件 ID（幂等去重键）" span={2}>
          <Space size={8} wrap>
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {event.event_id ?? '-'}
            </Typography.Text>
            <Tooltip title="重试与缓存补传不改变 event_id，服务端按（Agent, event_id）幂等去重，不重复入库、不扩大资产计数">
              <Tag color="green">幂等去重生效</Tag>
            </Tooltip>
          </Space>
        </Descriptions.Item>
        <Descriptions.Item label="采集来源">
          <SourceTypeTag event={event} />
        </Descriptions.Item>
        <Descriptions.Item label="来源实例 / 代次">
          {`${event.source_instance || '-'} / 代次 ${event.source_epoch ?? 0}`}
        </Descriptions.Item>
        <Descriptions.Item label="来源能力版本">
          {event.source_capabilities_version || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="协议（观测 / 原始）">
          {`${httpVersionLabel(event.observed_http_version)} / ${
            event.original_http_version === null ||
            event.original_http_version === undefined
              ? '不可确认'
              : httpVersionLabel(event.original_http_version)
          }`}
        </Descriptions.Item>
        <Descriptions.Item label="关联状态">
          <AssociationTag event={event} />
        </Descriptions.Item>
        <Descriptions.Item label="流标识">
          {event.capture_stream_id ? (
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {event.capture_stream_id}
            </Typography.Text>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="来源绑定">
          {event.application_binding_id ? (
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {`${event.application_binding_id}（v${event.binding_version ?? '-'}）`}
            </Typography.Text>
          ) : (
            '未绑定（资产关联待确认）'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="采集时间">
          {event.collection_ts != null ? formatUnixTime(event.collection_ts) : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="入库时间 / 延迟">
          <Space size={8} wrap>
            <span>
              {event.ingestion_ts != null
                ? `${formatUnixTime(event.ingestion_ts)} / ${
                    delay !== null ? `${delay.toFixed(1)}s` : '-'
                  }`
                : '-'}
            </span>
            {replaySuspected ? (
              <Tooltip title="采集→入库延迟超过阈值，大概率为磁盘缓存补传（断线恢复后回放）；延迟不混入业务时延">
                <Tag color="orange">疑似缓存补传</Tag>
              </Tooltip>
            ) : null}
          </Space>
        </Descriptions.Item>
      </Descriptions>
    </div>
  )
}

/** gRPC 元数据区块（v2 契约 §2.2：本期仅元数据；HTTP 200 ≠ RPC 成功，不伪造 grpc-status=0） */
function GrpcSection({ grpc }: { grpc: TrafficGrpcMeta }) {
  const stateMeta = GRPC_STREAM_STATE_META[grpc.stream_state]
  return (
    <div>
      <Typography.Text strong>gRPC 元数据</Typography.Text>
      <Descriptions
        column={2}
        size="small"
        bordered
        style={{ marginTop: 8 }}
      >
        <Descriptions.Item label="服务">{grpc.service || '-'}</Descriptions.Item>
        <Descriptions.Item label="方法">{grpc.method || '-'}</Descriptions.Item>
        <Descriptions.Item label="grpc-status">
          {grpc.grpc_status === null || grpc.grpc_status === undefined ? (
            <Tooltip title="流未结束或 trailers 不可见——不伪造 grpc-status=0；HTTP 200 ≠ RPC 成功">
              <span>未知（流未结束/不可见）</span>
            </Tooltip>
          ) : (
            <Tag color={grpc.grpc_status === 0 ? 'green' : 'red'}>
              {grpc.grpc_status}
            </Tag>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="流状态">
          <Tag color={stateMeta?.color}>
            {stateMeta?.label ?? grpc.stream_state}
          </Tag>
        </Descriptions.Item>
      </Descriptions>
      <Typography.Text
        type="secondary"
        style={{ display: 'block', fontSize: 12, marginTop: 4 }}
      >
        本期仅采集 gRPC 元数据（服务/方法/状态/流状态），不解析 Protobuf 消息正文
      </Typography.Text>
    </div>
  )
}

/** 单条 HTTP 事件详情（五元组/方向/TLS 可见性 + v2 来源与质量 + 请求/响应 headers 与 body） */
function HttpEventDetail({ event }: { event: TrafficHttpEvent }) {
  const req = event.request
  const resp = event.response
  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Descriptions column={2} size="small" bordered>
        <Descriptions.Item label="流 ID" span={2}>
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
              title={`集群: ${event.k8s.cluster || '-'}；工作负载: ${event.k8s.workload || '-'}；服务: ${event.k8s.service || '-'}；端点: ${formatK8sSide(event.k8s.side)}`}
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

      <EventV2Section event={event} />
      {event.grpc ? <GrpcSection grpc={event.grpc} /> : null}

      <div>
        <Typography.Text strong>请求</Typography.Text>
        <div
          style={{ margin: '4px 0 8px', fontFamily: 'monospace', fontSize: 12 }}
        >
          {`${req.method} ${req.scheme}://${req.host}${req.uri}`}
        </div>
        <HeadersTable headers={req.headers} />
        {req.trailers ? (
          <>
            <Typography.Text
              strong
              style={{ display: 'block', margin: '8px 0 4px' }}
            >
              请求尾部头
            </Typography.Text>
            <HeadersTable
              headers={req.trailers}
              emptyText="确认无请求尾部头"
            />
          </>
        ) : null}
        <Typography.Text
          strong
          style={{ display: 'block', margin: '8px 0 4px' }}
        >
          请求正文
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
            {resp.trailers ? (
              <>
                <Typography.Text
                  strong
                  style={{ display: 'block', margin: '8px 0 4px' }}
                >
                  响应尾部头
                </Typography.Text>
                <HeadersTable
                  headers={resp.trailers}
                  emptyText="确认无响应尾部头"
                />
              </>
            ) : null}
            <Typography.Text
              strong
              style={{ display: 'block', margin: '8px 0 4px' }}
            >
              响应正文
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

/** Agent HTTP 事件面板（Phase 3 契约 §9 + P1-03 §4.3 v2 展示）：
 * 服务端分页表 + host/method 过滤 + 行点击详情；来源/协议/关联/数据质量独立状态展示；
 * 旧 Agent（能力集不含 v2）明示「需升级」，不假报 v2 能力已启用 */
export default function HttpEventsPanel({
  agentId,
  enabled = true,
  httpEventSchemas,
}: {
  agentId: string
  enabled?: boolean
  /** Agent 能力协商生效集（http_event_schemas）；缺省视为未知（不提示升级） */
  httpEventSchemas?: number[]
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

  const upgradeNeeded =
    httpEventSchemas !== undefined && !supportsHttpEventV2(httpEventSchemas)

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
      title: '来源',
      key: 'source',
      width: 110,
      render: (_, r) => <SourceTypeTag event={r} />,
    },
    {
      title: '协议',
      key: 'protocol',
      width: 90,
      render: (_, r) =>
        r.schema_version === 2 ? (
          <Tooltip
            title={`观测协议；原协议: ${
              r.original_http_version == null
                ? '不可确认'
                : httpVersionLabel(r.original_http_version)
            }（分开记录，不互相回填）`}
          >
            <span>{httpVersionLabel(r.observed_http_version)}</span>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '关联',
      key: 'association',
      width: 100,
      render: (_, r) => <AssociationTag event={r} />,
    },
    {
      title: 'K8s 工作负载',
      key: 'k8s',
      width: 190,
      render: (_, r) =>
        r.k8s ? (
          <Tooltip
            title={`集群: ${r.k8s.cluster || '-'}；命名空间: ${r.k8s.namespace || '-'}；Pod: ${r.k8s.pod || '-'}；工作负载: ${r.k8s.workload || '-'}；服务: ${r.k8s.service || '-'}；端点: ${formatK8sSide(r.k8s.side)}`}
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
            <Tooltip key="req" title="请求正文已按策略上限截断">
              <Tag color="orange">请求截断</Tag>
            </Tooltip>,
          )
        }
        if (r.response?.body_truncated) {
          tags.push(
            <Tooltip key="resp" title="响应正文已按策略上限截断">
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
      {upgradeNeeded ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="该 Agent 仅支持 v1 事件（需升级）"
          description="来源、协议观测、关联状态、正文数据质量等 v2 字段需要 Agent 升级并在注册/心跳中声明 v2 协议能力后才会产生；当前列表中 v1 记录的相应位置显示为「-」。"
        />
      ) : null}
      <Space style={{ marginBottom: 12 }} wrap>
        <Input.Search
          placeholder="按域名过滤"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setHost(v.trim() || undefined)
            setPage(1)
          }}
        />
        <Select
          placeholder="按请求方法过滤"
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
          scroll={{ x: 1080 }}
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
