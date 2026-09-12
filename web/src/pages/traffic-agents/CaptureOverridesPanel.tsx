import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type {
  CreateCaptureOverrideBody,
  TrafficCaptureOverride,
  TrafficCaptureOverrideMatch,
} from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { formatDateTime } from '../../utils/format'
import { validateIPOrCIDR } from '../../utils/stage5'

/** 采集等级着色（语义同 Phase 3：等级越高采集面越大，L3 含 RAW 通道） */
const LEVEL_TAG_COLORS: Record<string, string> = {
  L0: 'default',
  L1: 'blue',
  L2: 'orange',
  L3: 'red',
}

const LEVEL_OPTIONS = [
  { value: 'L0', label: 'L0：仅元数据' },
  { value: 'L1', label: 'L1：+ Header' },
  { value: 'L2', label: 'L2：+ Body' },
  { value: 'L3', label: 'L3：+ RAW 包' },
]

interface OverrideFormValues {
  dst_ip?: string
  dst_port?: number
  host?: string
  uri_prefix?: string
  capture_level: string
  ttl_minutes: number
  note?: string
}

/** 匹配条件可读化（仅展示已填字段，多字段 AND） */
function matchText(match: TrafficCaptureOverrideMatch): string[] {
  const parts: string[] = []
  if (match.dst_ip) parts.push(`dst_ip=${match.dst_ip}`)
  if (match.dst_port !== undefined && match.dst_port !== null)
    parts.push(`dst_port=${match.dst_port}`)
  if (match.host) parts.push(`host=${match.host}`)
  if (match.uri_prefix) parts.push(`uri_prefix=${match.uri_prefix}`)
  return parts
}

/** 剩余有效期展示（过期由调用方先行分支，不到这里） */
function formatRemaining(expiresAt: string): string {
  const diffMs = new Date(expiresAt).getTime() - Date.now()
  if (!Number.isFinite(diffMs) || diffMs <= 0) return '即将过期'
  const min = Math.floor(diffMs / 60_000)
  if (min < 1) return '剩余不足 1 分钟'
  if (min < 60) return `剩余 ${min} 分钟`
  const hour = Math.floor(min / 60)
  if (hour < 24) return `剩余 ${hour} 小时 ${min % 60} 分`
  return `剩余 ${Math.floor(hour / 24)} 天 ${hour % 24} 小时`
}

/** 定向采集规则面板（Phase 4 契约 §2）：规则列表 + 新增 + 删除；30s 轮询；写操作需 manage 权限 */
export default function CaptureOverridesPanel({
  agentId,
  enabled,
  canManage,
}: {
  agentId: string
  enabled: boolean
  canManage: boolean
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [editorOpen, setEditorOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<TrafficCaptureOverride | null>(null)
  const [form] = Form.useForm<OverrideFormValues>()

  const listQuery = useQuery({
    queryKey: ['traffic-agents', 'overrides', agentId],
    queryFn: () => trafficAgentsApi.agentOverrides(agentId),
    enabled,
    refetchInterval: 30_000,
  })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'overrides', agentId] })
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateCaptureOverrideBody) =>
      trafficAgentsApi.createOverride(agentId, body),
    onSuccess: () => {
      message.success('规则已创建，命中流量将即时提升采集等级')
      setEditorOpen(false)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (overrideId: string) => trafficAgentsApi.deleteOverride(agentId, overrideId),
    onSuccess: () => {
      message.success('规则已删除')
      invalidate()
    },
    onError,
  })

  const submitEditor = async () => {
    let values: OverrideFormValues
    try {
      values = await form.validateFields()
    } catch {
      // 表单校验未通过，antd 已展示错误提示
      return
    }
    const match: TrafficCaptureOverrideMatch = {}
    const dstIp = values.dst_ip?.trim()
    const host = values.host?.trim()
    const uriPrefix = values.uri_prefix?.trim()
    if (dstIp) match.dst_ip = dstIp
    if (values.dst_port !== undefined && values.dst_port !== null)
      match.dst_port = values.dst_port
    if (host) match.host = host
    if (uriPrefix) match.uri_prefix = uriPrefix
    if (Object.keys(match).length === 0) {
      message.error('至少填写一个匹配条件（dst_ip / dst_port / host / uri_prefix）')
      return
    }
    createMutation.mutate({
      match,
      capture_level: values.capture_level,
      ttl_minutes: values.ttl_minutes,
      note: values.note?.trim() ?? '',
    })
  }

  const columns: ColumnsType<TrafficCaptureOverride> = [
    {
      title: '匹配条件',
      key: 'match',
      ellipsis: true,
      render: (_, r) => (
        <Space size={4} wrap>
          {matchText(r.match).map((p) => (
            <Typography.Text key={p} code style={{ fontSize: 12 }}>
              {p}
            </Typography.Text>
          ))}
        </Space>
      ),
    },
    {
      title: '目标等级',
      dataIndex: 'capture_level',
      width: 100,
      render: (v: string, r) => (
        <Tag color={r.active ? (LEVEL_TAG_COLORS[v] ?? 'default') : 'default'}>{v}</Tag>
      ),
    },
    {
      title: '有效期',
      key: 'expires',
      width: 170,
      render: (_, r) =>
        r.active ? (
          <Tooltip title={`过期时间：${formatDateTime(r.expires_at)}`}>
            <span>{formatRemaining(r.expires_at)}</span>
          </Tooltip>
        ) : (
          <Tooltip title={`已于 ${formatDateTime(r.expires_at)} 过期`}>
            <Typography.Text type="secondary">已过期</Typography.Text>
          </Tooltip>
        ),
    },
    {
      title: '创建人',
      dataIndex: 'created_by',
      width: 110,
      render: (v: string) => v || '-',
    },
    {
      title: '备注',
      dataIndex: 'note',
      width: 140,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 90,
            render: (_: unknown, r: TrafficCaptureOverride) => (
              <Popconfirm
                title="删除定向采集规则"
                description="删除后 Agent 将重新拉取配置，命中流量恢复策略基础等级。确定删除吗？"
                okText="确认删除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => deleteMutation.mutate(r.id)}
              >
                <Button type="link" size="small" danger loading={deleteMutation.isPending}>
                  删除
                </Button>
              </Popconfirm>
            ),
          },
        ]
      : []),
  ]

  return (
    <Space direction="vertical" size={12} style={{ display: 'flex' }}>
      <Alert
        type="info"
        showIcon
        message="定向采集规则仅提升不降低采集等级（生效等级 = max（策略基础等级， 命中规则等级）），命中流量经配置热更即时生效；规则过期后 Agent 自动忽略。"
      />
      {canManage ? (
        <div>
          <Button type="primary" onClick={() => setEditorOpen(true)}>
            新增规则
          </Button>
        </div>
      ) : null}
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载定向采集规则失败" />
      ) : (
        <Table<TrafficCaptureOverride>
          rowKey="id"
          size="small"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          pagination={false}
          locale={{ emptyText: '暂无定向采集规则' }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
        />
      )}

      <Modal
        title="新增定向采集规则"
        open={editorOpen}
        onCancel={() => setEditorOpen(false)}
        onOk={() => void submitEditor()}
        okText="创建"
        cancelText="取消"
        confirmLoading={createMutation.isPending}
        width={560}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="规则仅提升不降低采集等级，命中流量即时生效（多匹配字段为 AND 关系，至少填写一项）"
        />
        <Form<OverrideFormValues>
          form={form}
          layout="vertical"
          initialValues={{ capture_level: 'L2', ttl_minutes: 30 }}
        >
          <Form.Item
            name="dst_ip"
            label="目标 IP / CIDR（dst_ip，v4/v6）"
            rules={[
              {
                // 与后端 CaptureOverrideMatch.validate 口径一致：单 IP 或 CIDR（v4/v6）
                validator: (_, v: string | undefined) => {
                  const s = (v ?? '').trim()
                  if (!s) return Promise.resolve()
                  const err = validateIPOrCIDR(s)
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input placeholder="如 10.10.20.30 或 10.10.20.0/24" maxLength={64} />
          </Form.Item>
          <Form.Item name="dst_port" label="目标端口（dst_port，1-65535）">
            <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="如 8443" />
          </Form.Item>
          <Form.Item name="host" label="Host（精确匹配，大小写不敏感）">
            <Input placeholder="如 api.example.com" maxLength={255} />
          </Form.Item>
          <Form.Item
            name="uri_prefix"
            label="URI 前缀（uri_prefix，以 / 开头，≤512 字节）"
            rules={[
              {
                // 与后端 CaptureOverrideMatch.validate 口径一致：须以 / 开头
                validator: (_, v: string | undefined) => {
                  const s = (v ?? '').trim()
                  if (!s || s.startsWith('/')) return Promise.resolve()
                  return Promise.reject(new Error('URI 前缀须以 / 开头'))
                },
              },
            ]}
          >
            <Input placeholder="如 /api/payment" maxLength={512} />
          </Form.Item>
          <Form.Item
            name="capture_level"
            label="目标采集等级"
            rules={[{ required: true, message: '请选择目标采集等级' }]}
          >
            <Select options={LEVEL_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="ttl_minutes"
            label="有效期（分钟，1-1440，默认 30）"
            rules={[{ required: true, message: '请填写有效期' }]}
          >
            <InputNumber min={1} max={1440} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="note" label="备注">
            <Input placeholder="如 支付链路排障" maxLength={512} />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="规则详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
