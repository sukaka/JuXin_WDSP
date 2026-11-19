import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Tabs,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type { TrafficAgentItem } from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { formatRelativeTime } from '../../utils/apm'
import { hasPermission } from '../../utils/permission'
import AgentDetailDrawer from './AgentDetailDrawer'
import HealthScoreBadge from './HealthScoreBadge'
import PolicyPanel from './PolicyPanel'
import { TRAFFIC_AGENT_STATUS_META, formatMbps, formatRate } from './meta'

interface TokenFormValues {
  label: string
  ttl_minutes: number
}

interface CreatedToken {
  id: string
  token: string
  expires_at: string
}

/** WDSP 流量采集 Agent 管理（权限 traffic.agents.view；写操作 traffic.agents.manage 按权限显隐）。
 * 列表/汇总 30s 轮询；策略管理在同页 Tab 内（不新增第二个菜单项）。 */
export default function TrafficAgentsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'traffic.agents.manage')

  const [status, setStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const [tokenModalOpen, setTokenModalOpen] = useState(false)
  const [tokenForm] = Form.useForm<TokenFormValues>()
  const [createdToken, setCreatedToken] = useState<CreatedToken | null>(null)

  const [detailAgentId, setDetailAgentId] = useState<string | null>(null)

  const summaryQuery = useQuery({
    queryKey: ['traffic-agents', 'summary'],
    queryFn: () => trafficAgentsApi.summary(),
    refetchInterval: 30_000,
  })

  const listQuery = useQuery({
    queryKey: ['traffic-agents', 'list', status, keyword, page, pageSize],
    queryFn: () =>
      trafficAgentsApi.agents({ status, q: keyword, page, page_size: pageSize }),
    refetchInterval: 30_000,
  })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const invalidateList = () => {
    void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'list'] })
    void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'summary'] })
  }

  const createTokenMutation = useMutation({
    mutationFn: (values: TokenFormValues) => trafficAgentsApi.createEnrollmentToken(values),
    onSuccess: (data) => {
      // 令牌原文仅此一次返回：留在 Modal 内一次性展示，关闭后丢弃
      setCreatedToken({ id: data.id, token: data.token, expires_at: data.expires_at })
    },
    onError,
  })

  const disableMutation = useMutation({
    mutationFn: (agentId: string) => trafficAgentsApi.disableAgent(agentId),
    onSuccess: () => {
      message.success('Agent 已禁用（停止抓包，保留心跳）')
      invalidateList()
    },
    onError,
  })

  const enableMutation = useMutation({
    mutationFn: (agentId: string) => trafficAgentsApi.enableAgent(agentId),
    onSuccess: () => {
      message.success('Agent 已启用')
      invalidateList()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (agentId: string) => trafficAgentsApi.deleteAgent(agentId),
    onSuccess: () => {
      message.success('Agent 已删除')
      invalidateList()
    },
    onError,
  })

  const closeTokenModal = () => {
    setTokenModalOpen(false)
    setCreatedToken(null)
    tokenForm.resetFields()
  }

  const columns: ColumnsType<TrafficAgentItem> = [
    { title: '主机名', dataIndex: 'hostname', width: 150, ellipsis: true },
    {
      title: 'Agent ID',
      dataIndex: 'agent_id',
      width: 110,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {v ? `${v.slice(0, 8)}…` : '-'}
          </Typography.Text>
        </Tooltip>
      ),
    },
    { title: 'IP', dataIndex: 'ip', width: 120 },
    { title: '操作系统', dataIndex: 'os', width: 140, ellipsis: true },
    { title: '版本', dataIndex: 'version', width: 90 },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={TRAFFIC_AGENT_STATUS_META} />,
    },
    {
      title: '健康分',
      key: 'health_score',
      width: 90,
      render: (_, r) => <HealthScoreBadge score={r.health_score} reasons={r.health_reasons} />,
    },
    {
      title: '采集 Mbps',
      key: 'capture_mbps',
      width: 100,
      render: (_, r) => formatMbps(r.last_metrics?.capture_bps),
    },
    {
      title: '发送 Mbps',
      key: 'forward_mbps',
      width: 100,
      render: (_, r) => formatMbps(r.last_metrics?.forward_bps),
    },
    {
      title: 'PPS',
      key: 'pps',
      width: 80,
      render: (_, r) => formatRate(r.last_metrics?.capture_pps),
    },
    {
      title: '丢包/秒',
      key: 'drop_pps',
      width: 80,
      render: (_, r) => formatRate(r.last_metrics?.drop_pps),
    },
    {
      title: '最后心跳',
      dataIndex: 'last_seen',
      width: 110,
      render: (v: string | null) => (
        <Tooltip title={formatDateTime(v)}>
          <span>{formatRelativeTime(v)}</span>
        </Tooltip>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: canManage ? 170 : 80,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailAgentId(record.agent_id)}>
            详情
          </Button>
          {canManage ? (
            <>
              {record.disabled ? (
                <Popconfirm
                  title="启用 Agent"
                  description={`确定启用 ${record.hostname || record.agent_id} 吗？启用后 Agent 恢复抓包。`}
                  okText="确认启用"
                  cancelText="取消"
                  onConfirm={() => enableMutation.mutate(record.agent_id)}
                >
                  <Button type="link" size="small">
                    启用
                  </Button>
                </Popconfirm>
              ) : (
                <Popconfirm
                  title="禁用 Agent"
                  description={`确定禁用 ${record.hostname || record.agent_id} 吗？禁用后 Agent 停止抓包（保留心跳）。`}
                  okText="确认禁用"
                  okButtonProps={{ danger: true }}
                  cancelText="取消"
                  onConfirm={() => disableMutation.mutate(record.agent_id)}
                >
                  <Button type="link" size="small" danger>
                    禁用
                  </Button>
                </Popconfirm>
              )}
              <Popconfirm
                title="删除 Agent"
                description={`确定删除 ${record.hostname || record.agent_id} 吗？删除后其凭证立即失效，绑定与网卡信息一并删除（保留审计）。`}
                okText="确认删除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => deleteMutation.mutate(record.agent_id)}
              >
                <Button type="link" size="small" danger>
                  删除
                </Button>
              </Popconfirm>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  const summary = summaryQuery.data

  const agentsTab = (
    <>
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={4}>
          <Card size="small">
            <Statistic title="Agent 总数" value={summary?.total ?? 0} />
          </Card>
        </Col>
        <Col span={4}>
          <Card size="small">
            <Statistic title="在线" value={summary?.online ?? 0} valueStyle={{ color: '#3f8600' }} />
          </Card>
        </Col>
        <Col span={4}>
          <Card size="small">
            <Statistic title="离线" value={summary?.offline ?? 0} />
          </Card>
        </Col>
        <Col span={4}>
          <Card size="small">
            <Statistic title="降级" value={summary?.degraded ?? 0} valueStyle={{ color: '#d48806' }} />
          </Card>
        </Col>
        <Col span={4}>
          <Card size="small">
            <Statistic title="禁用" value={summary?.disabled ?? 0} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
      </Row>

      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 140 }}
          options={Object.entries(TRAFFIC_AGENT_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="主机名 / IP / Agent ID"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setKeyword(v.trim() || undefined)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 Agent 列表失败" />
      ) : (
        <SmartTable<TrafficAgentItem>
          storageKey="traffic-agents"
          rowKey="agent_id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailAgentId(record.agent_id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1540 }}
          locale={{ emptyText: '暂无数据' }}
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
    </>
  )

  return (
    <Card
      title="流量采集 Agent 管理"
      extra={
        canManage ? (
          <Button
            type="primary"
            onClick={() => {
              setCreatedToken(null)
              tokenForm.resetFields()
              setTokenModalOpen(true)
            }}
          >
            创建注册令牌
          </Button>
        ) : undefined
      }
    >
      <Tabs
        items={[
          { key: 'agents', label: 'Agent 列表', children: agentsTab },
          { key: 'policies', label: '采集策略', children: <PolicyPanel canManage={canManage} /> },
        ]}
      />

      <Modal
        title="创建注册令牌"
        open={tokenModalOpen}
        onCancel={closeTokenModal}
        footer={
          createdToken ? (
            <Button type="primary" onClick={closeTokenModal}>
              完成
            </Button>
          ) : undefined
        }
        onOk={() => tokenForm.submit()}
        okText="创建"
        confirmLoading={createTokenMutation.isPending}
        destroyOnHidden
      >
        {createdToken ? (
          <Space direction="vertical" size={12} style={{ display: 'flex' }}>
            <Alert
              type="warning"
              showIcon
              message="令牌原文仅显示一次"
              description="请立即复制并妥善保存；关闭本窗口后将无法再次查看，只能重新创建。"
            />
            <Typography.Text
              copyable={{ text: createdToken.token }}
              style={{ fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-all' }}
            >
              {createdToken.token}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              过期时间：{formatDateTime(createdToken.expires_at)}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              在目标主机执行：wdsp-agent enroll --server &lt;管理面地址&gt; --token &lt;令牌&gt;
            </Typography.Text>
          </Space>
        ) : (
          <Form<TokenFormValues>
            form={tokenForm}
            layout="vertical"
            initialValues={{ ttl_minutes: 60 }}
            onFinish={(values) => createTokenMutation.mutate(values)}
          >
            <Form.Item
              name="label"
              label="用途标签"
              rules={[{ required: true, message: '请填写用途标签' }]}
            >
              <Input placeholder="如 prod-web" maxLength={64} />
            </Form.Item>
            <Form.Item
              name="ttl_minutes"
              label="有效期（分钟）"
              rules={[{ required: true, message: '请填写有效期' }]}
            >
              <InputNumber min={5} max={10080} style={{ width: '100%' }} />
            </Form.Item>
          </Form>
        )}
      </Modal>

      <AgentDetailDrawer
        agentId={detailAgentId}
        open={detailAgentId !== null}
        onClose={() => setDetailAgentId(null)}
        canManage={canManage}
      />
    </Card>
  )
}
