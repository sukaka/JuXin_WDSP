import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Popconfirm,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type {
  TrafficAgentInterface,
  TrafficFlowEvent,
} from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatBytes, formatDateTime } from '../../utils/format'
import { formatRelativeTime } from '../../utils/apm'
import HealthScoreBadge from './HealthScoreBadge'
import HttpEventsPanel, { TlsVisibilityTag } from './HttpEventsPanel'
import CaptureOverridesPanel from './CaptureOverridesPanel'
import HttpAssetSourcesPanel from './HttpAssetSourcesPanel'
import {
  FLOW_EVENT_TYPE_META,
  TRAFFIC_AGENT_STATUS_META,
  formatClockOffset,
  formatK8sSide,
  formatMbps,
  formatRate,
  formatUnixTime,
  healthReasonLabels,
  supportsHttpEventV2,
} from './meta'

const CAPTURE_BACKEND_LABELS: Record<string, string> = {
  ebpf: 'eBPF / TCX (Linux)',
  afpacket: 'AF_PACKET (Linux)',
  bpf: '原生 BPF (macOS)',
  npcap: 'Npcap 动态加载 (Windows)',
  rawsocket: 'IPv4 Raw Socket (Windows 回退)',
}

const interfaceColumns: ColumnsType<TrafficAgentInterface> = [
  { title: '网卡', dataIndex: 'name', width: 110 },
  { title: 'MAC', dataIndex: 'mac', width: 150 },
  { title: 'IPv4', dataIndex: 'ipv4', width: 130 },
  {
    title: 'IPv6',
    dataIndex: 'ipv6',
    width: 180,
    ellipsis: true,
    render: (v: string) => v || '-',
  },
  { title: 'MTU', dataIndex: 'mtu', width: 80 },
  {
    title: '速率（Mbps）',
    dataIndex: 'speed_mbps',
    width: 110,
    render: (v: number) => (v ? String(v) : '-'),
  },
]

/** Agent 详情抽屉：基本信息/实时指标/策略绑定、网卡、流量事件（契约 §4 详情+events 端点） */
export default function AgentDetailDrawer({
  agentId,
  open,
  onClose,
  canManage,
}: {
  agentId: string | null
  open: boolean
  onClose: () => void
  canManage: boolean
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [eventsPage, setEventsPage] = useState(1)
  const [eventsPageSize, setEventsPageSize] = useState(20)
  const [bindPolicyId, setBindPolicyId] = useState<string | undefined>()

  const detailQuery = useQuery({
    queryKey: ['traffic-agents', 'detail', agentId],
    queryFn: () => trafficAgentsApi.agent(agentId as string),
    enabled: open && !!agentId,
    refetchInterval: 30_000,
  })

  const eventsQuery = useQuery({
    queryKey: ['traffic-agents', 'events', agentId, eventsPage, eventsPageSize],
    queryFn: () =>
      trafficAgentsApi.agentEvents(agentId as string, {
        page: eventsPage,
        page_size: eventsPageSize,
      }),
    enabled: open && !!agentId,
  })

  const policiesQuery = useQuery({
    queryKey: ['traffic-agents', 'policies', 'all'],
    queryFn: () => trafficAgentsApi.policies({ page: 1, page_size: 100 }),
    enabled: open && canManage,
  })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const invalidateDetail = () => {
    void queryClient.invalidateQueries({
      queryKey: ['traffic-agents', 'detail', agentId],
    })
    void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'list'] })
  }

  const bindMutation = useMutation({
    mutationFn: (policyId: string) =>
      trafficAgentsApi.bindPolicy(agentId as string, policyId),
    onSuccess: () => {
      message.success('策略已绑定')
      setBindPolicyId(undefined)
      invalidateDetail()
    },
    onError,
  })

  const unbindMutation = useMutation({
    mutationFn: () => trafficAgentsApi.unbindPolicy(agentId as string),
    onSuccess: () => {
      message.success('策略已解绑')
      invalidateDetail()
    },
    onError,
  })

  const detail = detailQuery.data
  const metrics = detail?.last_metrics ?? null

  const eventColumns: ColumnsType<TrafficFlowEvent> = [
    {
      title: '类型',
      dataIndex: 'event_type',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={FLOW_EVENT_TYPE_META} />,
    },
    {
      title: '时间',
      key: 'time',
      width: 160,
      render: (_, r) =>
        typeof r.ts === 'string'
          ? formatDateTime(r.ts)
          : formatUnixTime(r.timestamp ?? r.ts),
    },
    {
      title: '五元组',
      key: 'tuple',
      width: 260,
      render: (_, r) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {`${r.src_ip}:${r.src_port} → ${r.dst_ip}:${r.dst_port}/${r.protocol}`}
        </Typography.Text>
      ),
    },
    {
      title: '方向',
      dataIndex: 'direction',
      width: 80,
      render: (v: string) =>
        v === 'ingress' ? '入站' : v === 'egress' ? '出站' : v || '-',
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
      title: 'HTTP',
      key: 'http',
      ellipsis: true,
      render: (_, r) =>
        r.http_method || r.http_host || r.http_uri
          ? `${r.http_method ?? ''} ${r.http_host ?? ''}${r.http_uri ?? ''}`.trim()
          : '-',
    },
    {
      title: 'TLS 可见性',
      dataIndex: 'tls_visibility',
      width: 110,
      render: (v: string) => <TlsVisibilityTag value={v} />,
    },
    {
      title: '字节数',
      key: 'bytes',
      width: 110,
      render: (_, r) => formatBytes((r.bytes_in ?? 0) + (r.bytes_out ?? 0)),
    },
  ]

  return (
    <Drawer
      title={
        detail
          ? `Agent 详情：${detail.hostname || detail.agent_id}`
          : 'Agent 详情'
      }
      open={open}
      onClose={onClose}
      width={860}
      destroyOnHidden
    >
      {detailQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : detailQuery.isError ? (
        <QueryErrorAlert
          error={detailQuery.error}
          message="加载 Agent 详情失败"
        />
      ) : detail ? (
        <Tabs
          items={[
            {
              key: 'info',
              label: '基本信息',
              children: (
                <Space
                  direction="vertical"
                  size={16}
                  style={{ display: 'flex' }}
                >
                  <Descriptions column={2} size="small" bordered>
                    <Descriptions.Item label="主机名">
                      {detail.hostname || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="状态">
                      <Space size={8} wrap>
                        <StatusTag
                          value={detail.status}
                          map={TRAFFIC_AGENT_STATUS_META}
                        />
                        {metrics?.backpressure_cap ? (
                          <Tooltip
                            title={`出口拥塞触发背压逐级降级：生效等级 = min（策略/规则等级， 降级帽 ${metrics.backpressure_cap}），恢复后自动逐级回升${
                              metrics.backpressure_events !== undefined
                                ? `（累计降级 ${metrics.backpressure_events} 次）`
                                : ''
                            }`}
                          >
                            <Tag color="orange">
                              背压降级帽 {metrics.backpressure_cap}
                            </Tag>
                          </Tooltip>
                        ) : null}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label="健康分" span={2}>
                      <Space size={8} wrap>
                        <HealthScoreBadge
                          score={detail.health_score}
                          reasons={detail.health_reasons}
                        />
                        {(detail.health_reasons ?? []).length > 0 ? (
                          <Typography.Text
                            type="secondary"
                            style={{ fontSize: 12 }}
                          >
                            {healthReasonLabels(detail.health_reasons).join(
                              '；',
                            )}
                          </Typography.Text>
                        ) : (
                          <Typography.Text
                            type="secondary"
                            style={{ fontSize: 12 }}
                          >
                            无扣分项
                          </Typography.Text>
                        )}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label="时钟偏移" span={2}>
                      {formatClockOffset(detail.clock_offset_ms)}
                    </Descriptions.Item>
                    <Descriptions.Item label="Agent ID" span={2}>
                      <Typography.Text
                        copyable
                        style={{ fontFamily: 'monospace', fontSize: 12 }}
                      >
                        {detail.agent_id}
                      </Typography.Text>
                    </Descriptions.Item>
                    <Descriptions.Item label="IP">
                      {detail.ip || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="版本">
                      {detail.version || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="操作系统">
                      {detail.os || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="内核">
                      {detail.kernel || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="架构">
                      {detail.arch || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="HTTP 事件能力" span={2}>
                      <Space size={8} wrap>
                        {(detail.http_event_schemas ?? [1]).map((v) => (
                          <Tag key={v} color={v === 2 ? 'green' : 'default'}>
                            {`协议 v${v}`}
                          </Tag>
                        ))}
                        {supportsHttpEventV2(detail.http_event_schemas) ? null : (
                          <Tooltip title="该 Agent 能力协商生效集仅含 v1：来源、协议观测、关联状态、正文数据质量等 v2 事件字段不可用。升级 Agent 并重新注册/心跳声明能力集后自动生效">
                            <Tag color="orange">需升级</Tag>
                          </Tooltip>
                        )}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label="服务端目标版本">
                      {`v${detail.config_version}`}
                    </Descriptions.Item>
                    <Descriptions.Item label="Agent 已加载版本">
                      <Space size={8} wrap>
                        <span>{`v${detail.applied_config_version}`}</span>
                        {detail.applied_config_version >= detail.config_version ? (
                          <Tag color="green">已同步</Tag>
                        ) : (
                          <Tooltip title="Agent 收到的目标版本与实际加载结果分离显示；不一致表示配置尚未 ACK 或加载失败">
                            <Tag color="orange">待同步</Tag>
                          </Tooltip>
                        )}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label="最后心跳">
                      <Tooltip title={formatDateTime(detail.last_seen)}>
                        <span>{formatRelativeTime(detail.last_seen)}</span>
                      </Tooltip>
                    </Descriptions.Item>
                    <Descriptions.Item label="注册时间">
                      {formatDateTime(detail.created_at)}
                    </Descriptions.Item>
                  </Descriptions>

                  <div>
                    <Typography.Text strong>
                      实时指标（最近一次心跳上报）
                    </Typography.Text>
                    <Descriptions
                      column={3}
                      size="small"
                      bordered
                      style={{ marginTop: 8 }}
                    >
                      <Descriptions.Item label="CPU">
                        {metrics?.cpu_percent !== undefined
                          ? `${metrics.cpu_percent}%`
                          : '-'}
                      </Descriptions.Item>
                      <Descriptions.Item label="内存">
                        {metrics?.memory_mb !== undefined
                          ? `${metrics.memory_mb} MB`
                          : '-'}
                      </Descriptions.Item>
                      <Descriptions.Item label="队列深度">
                        {formatRate(metrics?.queue_depth)}
                      </Descriptions.Item>
                      <Descriptions.Item label="采集 PPS">
                        {formatRate(metrics?.capture_pps)}
                      </Descriptions.Item>
                      <Descriptions.Item label="采集 Mbps">
                        {formatMbps(metrics?.capture_bps)}
                      </Descriptions.Item>
                      <Descriptions.Item label="丢弃/s">
                        {formatRate(metrics?.drop_pps)}
                      </Descriptions.Item>
                      <Descriptions.Item label="发送 PPS">
                        {formatRate(metrics?.forward_pps)}
                      </Descriptions.Item>
                      <Descriptions.Item label="发送 Mbps">
                        {formatMbps(metrics?.forward_bps)}
                      </Descriptions.Item>
                      <Descriptions.Item label="磁盘缓存">
                        {formatBytes(metrics?.buffer_bytes)}
                      </Descriptions.Item>
                      <Descriptions.Item label="抓包后端" span={3}>
                        <Space size={8} wrap>
                          <span>
                            {metrics?.capture_backend
                              ? (CAPTURE_BACKEND_LABELS[metrics.capture_backend] ??
                                metrics.capture_backend)
                              : '未启用 / 仅控制通道'}
                          </span>
                          {metrics?.backend_fallback_reason ? (
                            <Tooltip title={metrics.backend_fallback_reason}>
                              <Tag color="orange">已自动回退</Tag>
                            </Tooltip>
                          ) : null}
                        </Space>
                      </Descriptions.Item>
                    </Descriptions>
                  </div>

                  <div>
                    <Typography.Text strong>采集策略绑定</Typography.Text>
                    <div style={{ marginTop: 8 }}>
                      <Space wrap>
                        {detail.policy_binding ? (
                          <>
                            <Tag color="blue">
                              {detail.policy_binding.policy_name ||
                                detail.policy_binding.policy_id}
                              {detail.policy_binding.policy_version !== undefined
                                ? `（v${detail.policy_binding.policy_version}）`
                                : ''}
                            </Tag>
                            {canManage ? (
                              <Popconfirm
                                title="解绑策略"
                                description="解绑后 Agent 将使用内置默认采集集，确定解绑吗？"
                                okText="确认解绑"
                                cancelText="取消"
                                onConfirm={() => unbindMutation.mutate()}
                              >
                                <Button
                                  size="small"
                                  danger
                                  loading={unbindMutation.isPending}
                                >
                                  解绑
                                </Button>
                              </Popconfirm>
                            ) : null}
                          </>
                        ) : (
                          <Typography.Text type="secondary">
                            未绑定策略，Agent 使用内置默认采集集
                          </Typography.Text>
                        )}
                      </Space>
                      <Typography.Text
                        type="secondary"
                        style={{ display: 'block', fontSize: 12, marginTop: 4 }}
                      >
                        {detail.policy_binding
                          ? `已保存策略版本 v${
                              detail.policy_binding.policy_version ?? '-'
                            }（策略历史链不可变）；保存/换绑后服务端目标版本升为 v${
                              detail.config_version
                            }，Agent 实际加载 v${detail.applied_config_version}——目标与实载分离显示`
                          : '策略保存生成新版本并作为服务端目标版本下发；Agent 收到版本与实际加载结果在上方分别显示'}
                      </Typography.Text>
                      {canManage ? (
                        <Space wrap style={{ marginTop: 8 }}>
                          <Select
                            placeholder="选择要绑定的策略"
                            style={{ width: 280 }}
                            value={bindPolicyId}
                            loading={policiesQuery.isLoading}
                            options={(policiesQuery.data?.items ?? []).map(
                              (p) => ({
                                value: p.id,
                                label: `${p.name}（v${p.version}）`,
                              }),
                            )}
                            onChange={(v) => setBindPolicyId(v)}
                          />
                          <Button
                            type="primary"
                            size="middle"
                            disabled={!bindPolicyId}
                            loading={bindMutation.isPending}
                            onClick={() =>
                              bindPolicyId && bindMutation.mutate(bindPolicyId)
                            }
                          >
                            {detail.policy_binding ? '换绑' : '绑定'}
                          </Button>
                        </Space>
                      ) : null}
                    </div>
                  </div>
                </Space>
              ),
            },
            {
              key: 'interfaces',
              label: '网卡',
              children: (
                <Table<TrafficAgentInterface>
                  rowKey="name"
                  size="small"
                  columns={interfaceColumns}
                  dataSource={detail.interfaces}
                  pagination={false}
                  locale={{ emptyText: '暂无网卡信息' }}
                />
              ),
            },
            {
              key: 'events',
              label: '流量事件',
              children: eventsQuery.isError ? (
                <QueryErrorAlert
                  error={eventsQuery.error}
                  message="加载流量事件失败"
                />
              ) : (
                <SmartTable<TrafficFlowEvent>
                  storageKey="traffic-agent-events"
                  rowKey={(r) =>
                    r.id !== undefined
                      ? String(r.id)
                      : `${r.flow_id}-${r.event_type}-${r.ts ?? r.timestamp ?? ''}`
                  }
                  size="small"
                  loading={eventsQuery.isLoading}
                  columns={eventColumns}
                  dataSource={eventsQuery.data?.items}
                  scroll={{ x: 980 }}
                  locale={{ emptyText: '暂无流量事件' }}
                  pagination={{
                    current: eventsPage,
                    pageSize: eventsPageSize,
                    total: eventsQuery.data?.total ?? 0,
                    showSizeChanger: true,
                    showTotal: (t) => `共 ${t} 条`,
                    onChange: (p, ps) => {
                      setEventsPage(p)
                      setEventsPageSize(ps)
                    },
                  }}
                />
              ),
            },
            {
              key: 'http-events',
              label: 'HTTP 事件',
              children: (
                <HttpEventsPanel
                  agentId={detail.agent_id}
                  enabled={open}
                  httpEventSchemas={detail.http_event_schemas}
                />
              ),
            },
            {
              key: 'asset-sources',
              label: '资产来源',
              children: (
                <HttpAssetSourcesPanel agentId={detail.agent_id} enabled={open} />
              ),
            },
            {
              key: 'overrides',
              label: '定向采集',
              children: (
                <CaptureOverridesPanel
                  agentId={detail.agent_id}
                  enabled={open}
                  canManage={canManage}
                />
              ),
            },
          ]}
        />
      ) : null}
    </Drawer>
  )
}
