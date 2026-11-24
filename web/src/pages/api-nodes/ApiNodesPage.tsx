import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  ApiOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import {
  apiNodesApi,
  type ApiNode,
  type ApiNodeTestResult,
  type ApiNodeVersionGroup,
  type CreateApiNodeBody,
  type UpdateApiNodeBody,
} from '../../api/apiNodes'
import { ApiError } from '../../api/client'
import { gatewayConfigApi } from '../../api/gatewayConfig'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import TableRefreshControl from '../../components/TableRefreshControl'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

/** 节点状态展示映射（与 server/internal/apinodes 状态词表一致） */
const NODE_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '活跃' },
  STALE: { color: 'gold', label: '停滞' },
  SILENT: { color: 'default', label: '静默' },
}

/** 配置同步结果展示映射（last_sync_result 词表；空串 = 从未同步） */
const SYNC_RESULT_META: Record<string, { color: string; label: string }> = {
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  HASH_MISMATCH: { color: 'volcano', label: '哈希不一致' },
}

/** 连通性测试通道展示名 */
const TEST_CHANNEL_LABELS: Record<string, string> = {
  hasyncd: 'hasyncd 协同代理',
  caddy_admin: 'Caddy Admin 直连',
  none: '未配置通道',
}

/** hasyncd HMAC 密钥格式校验：至少 64 位十六进制字符（32 字节） */
const SYNC_SECRET_HEX_RE = /^[0-9a-fA-F]{64,}$/

interface NodeFormValues {
  node_name: string
  admin_addr?: string
  sync_agent_addr?: string
  sync_secret?: string
  clear_sync_secret?: boolean
  sync_enabled: boolean
}

/** 版本文本截断展示（空串 = 未上报，占位符；hover 显示完整值） */
function VersionText({ value }: { value?: string }) {
  if (!value) return <span>-</span>
  return (
    <Tooltip title={value}>
      <Typography.Text code ellipsis style={{ maxWidth: 200, verticalAlign: 'middle' }}>
        {value}
      </Typography.Text>
    </Tooltip>
  )
}

/** 地址截断展示 */
function AddrText({ value }: { value?: string }) {
  if (!value) return <Typography.Text type="secondary">-</Typography.Text>
  return (
    <Tooltip title={value}>
      <Typography.Text code ellipsis style={{ maxWidth: 220, verticalAlign: 'middle' }}>
        {value}
      </Typography.Text>
    </Tooltip>
  )
}

/**
 * 网关节点管理与版本校验：节点登记/编辑/连通测试/重试同步/删除 + 策略版本一致性判定。
 */
export default function ApiNodesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManageNodes =
    hasPermission(permissions, 'api_policy.publish') || hasPermission(permissions, 'ha.manage')
  const canRetrySync =
    hasPermission(permissions, 'gateway_configs.publish') ||
    hasPermission(permissions, 'api_policy.publish')

  const listQuery = useQuery({
    queryKey: ['api-nodes'],
    queryFn: () => apiNodesApi.list(),
  })

  const consistencyQuery = useQuery({
    queryKey: ['api-nodes', 'consistency'],
    queryFn: () => apiNodesApi.consistency(),
  })

  const currentVersionQuery = useQuery({
    queryKey: ['gateway-config-current'],
    queryFn: () => gatewayConfigApi.current(),
    enabled: canRetrySync,
    retry: false,
  })

  const report = consistencyQuery.data
  const currentVersionId = currentVersionQuery.data?.has_current
    ? currentVersionQuery.data.version?.id
    : undefined

  const [detailRecord, setDetailRecord] = useState<Record<string, unknown> | null>(null)
  const [detailTitle, setDetailTitle] = useState('记录详情')
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<ApiNode | null>(null)
  const [testingNodeId, setTestingNodeId] = useState<string | null>(null)
  const [retryingNodeId, setRetryingNodeId] = useState<string | null>(null)
  const [testOutcome, setTestOutcome] = useState<{
    nodeName: string
    result: ApiNodeTestResult
  } | null>(null)

  const [form] = Form.useForm<NodeFormValues>()
  const watchedClearSecret = Form.useWatch('clear_sync_secret', form)

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['api-nodes'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateApiNodeBody) => apiNodesApi.create(body),
    onSuccess: () => {
      message.success('节点已登记')
      setModalOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdateApiNodeBody }) =>
      apiNodesApi.update(id, body),
    onSuccess: () => {
      message.success('节点同步配置已更新')
      setModalOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const toggleSyncMutation = useMutation({
    mutationFn: ({ id, sync_enabled }: { id: string; sync_enabled: boolean }) =>
      apiNodesApi.update(id, { sync_enabled }),
    onSuccess: (_, vars) => {
      message.success(vars.sync_enabled ? '已开启该节点同步' : '已关闭该节点同步')
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiNodesApi.remove(id),
    onSuccess: (d) => {
      message.success(d.message || '节点已删除')
      invalidate()
    },
    onError,
  })

  const testMutation = useMutation({
    mutationFn: async (node: ApiNode) => {
      setTestingNodeId(node.id)
      const result = await apiNodesApi.testConnection(node.id)
      return { nodeName: node.node_name, result }
    },
    onSuccess: (outcome) => {
      setTestOutcome(outcome)
      if (outcome.result.ok) {
        message.success(`节点「${outcome.nodeName}」连通测试通过（${outcome.result.latency_ms}ms）`)
      } else {
        message.error(
          `节点「${outcome.nodeName}」连通测试失败：${outcome.result.error || '请检查地址与密钥'}`,
        )
      }
      invalidate()
    },
    onError,
    onSettled: () => setTestingNodeId(null),
  })

  const retrySyncMutation = useMutation({
    mutationFn: async (vars: { versionId: string; nodeId: string; nodeName: string }) => {
      setRetryingNodeId(vars.nodeId)
      const result = await apiNodesApi.retrySync(vars.versionId, vars.nodeId)
      return { nodeName: vars.nodeName, result }
    },
    onSuccess: ({ nodeName, result }) => {
      if (result.failed > 0 || result.record_failures > 0) {
        message.warning(
          `节点「${nodeName}」重试同步完成：成功 ${result.succeeded}，失败 ${result.failed}`,
        )
      } else if (result.attempted === 0) {
        message.info(`节点「${nodeName}」无需重试同步`)
      } else {
        message.success(`节点「${nodeName}」配置同步成功`)
      }
      invalidate()
    },
    onError,
    onSettled: () => setRetryingNodeId(null),
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    form.setFieldsValue({
      node_name: '',
      admin_addr: '',
      sync_agent_addr: '',
      sync_secret: undefined,
      clear_sync_secret: false,
      sync_enabled: true,
    })
    setModalOpen(true)
  }

  const openEdit = (node: ApiNode) => {
    setEditing(node)
    form.resetFields()
    form.setFieldsValue({
      node_name: node.node_name,
      admin_addr: node.admin_addr ?? '',
      sync_agent_addr: node.sync_agent_addr ?? '',
      sync_secret: undefined,
      clear_sync_secret: false,
      sync_enabled: node.sync_enabled,
    })
    setModalOpen(true)
  }

  const submitForm = async () => {
    let values: NodeFormValues
    try {
      values = await form.validateFields()
    } catch {
      return
    }
    const adminAddr = (values.admin_addr ?? '').trim()
    const syncAgentAddr = (values.sync_agent_addr ?? '').trim()
    const secretVal = (values.sync_secret ?? '').trim()

    if (editing) {
      const body: UpdateApiNodeBody = {
        admin_addr: adminAddr,
        sync_agent_addr: syncAgentAddr,
        sync_enabled: values.sync_enabled,
      }
      if (values.clear_sync_secret) {
        body.sync_secret = ''
      } else if (secretVal) {
        body.sync_secret = secretVal
      }
      updateMutation.mutate({ id: editing.id, body })
      return
    }

    const body: CreateApiNodeBody = {
      node_name: values.node_name.trim(),
      sync_enabled: values.sync_enabled,
    }
    if (adminAddr) body.admin_addr = adminAddr
    if (syncAgentAddr) body.sync_agent_addr = syncAgentAddr
    if (secretVal) body.sync_secret = secretVal
    createMutation.mutate(body)
  }

  const confirmDelete = (node: ApiNode) => {
    modal.confirm({
      title: `删除网关节点「${node.node_name}」？`,
      content: '删除后该节点将不再参与配置发布扇出与遥测汇聚；若节点仍归属主备高可用组，需先从主备组移除。',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => deleteMutation.mutate(node.id),
    })
  }

  const columns: ColumnsType<ApiNode> = [
    {
      title: '节点名称',
      dataIndex: 'node_name',
      width: 150,
      ellipsis: true,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 85,
      render: (v: string) => <StatusTag value={v} map={NODE_STATUS_META} />,
    },
    {
      title: '系统版本',
      dataIndex: 'reported_version',
      width: 110,
      render: (v?: string) => (v ? <Tag color="geekblue">{v}</Tag> : <span>-</span>),
    },
    {
      title: 'Caddy Admin 地址',
      dataIndex: 'admin_addr',
      width: 210,
      render: (v?: string) => <AddrText value={v} />,
    },
    {
      title: '协同代理地址（hasyncd）',
      dataIndex: 'sync_agent_addr',
      width: 230,
      render: (v: string | undefined, record: ApiNode) => (
        <Space size={4} wrap>
          <AddrText value={v} />
          {record.has_sync_secret && <Tag color="blue">已设密钥</Tag>}
        </Space>
      ),
    },
    {
      title: '参与同步',
      dataIndex: 'sync_enabled',
      width: 95,
      render: (v: boolean, record: ApiNode) =>
        canManageNodes ? (
          <Switch
            size="small"
            checked={v}
            loading={
              toggleSyncMutation.isPending && toggleSyncMutation.variables?.id === record.id
            }
            aria-label={`同步开关-${record.node_name}`}
            onChange={(checked) =>
              toggleSyncMutation.mutate({ id: record.id, sync_enabled: checked })
            }
          />
        ) : (
          <Tag color={v ? 'green' : 'default'}>{v ? '已启用' : '未启用'}</Tag>
        ),
    },
    {
      title: '配置同步',
      dataIndex: 'last_sync_result',
      width: 120,
      render: (v: string, record: ApiNode) => {
        if (!record.sync_enabled) return <Tag>未参与</Tag>
        if (!v) return <Tag>未同步</Tag>
        const tag = <StatusTag value={v} map={SYNC_RESULT_META} />
        const tips: string[] = []
        if (record.last_sync_at) tips.push(`最近同步：${formatDateTime(record.last_sync_at)}`)
        if (record.last_sync_error) tips.push(`错误：${record.last_sync_error}`)
        return tips.length > 0 ? <Tooltip title={tips.join('；')}>{tag}</Tooltip> : tag
      },
    },
    {
      title: '策略版本',
      dataIndex: 'last_policy_version',
      width: 200,
      render: (v: string) => <VersionText value={v} />,
    },
    {
      title: '模型版本',
      dataIndex: 'last_model_version',
      width: 180,
      render: (v: string) => <VersionText value={v} />,
    },
    {
      title: '版本一致',
      dataIndex: 'version_consistent',
      width: 95,
      render: (v: boolean | null) => {
        if (v === null || v === undefined) return '-'
        return v ? <Tag color="green">一致</Tag> : <Tag color="red">不一致</Tag>
      },
    },
    {
      title: '最近活性时间',
      dataIndex: 'last_seen_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '事件数', dataIndex: 'event_count', width: 85 },
    {
      title: '操作',
      key: 'actions',
      width: 260,
      fixed: 'right',
      render: (_, record) => {
        const retryVersionId = currentVersionId || record.last_sync_version_id || undefined
        const retryDisabled = !canRetrySync || !record.sync_enabled || !retryVersionId
        const retryTip = !record.sync_enabled
          ? '请先启用该节点的配置同步'
          : !retryVersionId
            ? '尚无已发布的配置版本'
            : '重新下发当前已发布配置版本至此节点'
        return (
          <Space size={4} wrap>
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              disabled={!canManageNodes}
              onClick={() => openEdit(record)}
              aria-label={`编辑-${record.node_name}`}
            >
              编辑
            </Button>
            <Button
              type="link"
              size="small"
              icon={<ApiOutlined />}
              disabled={!canManageNodes}
              loading={testingNodeId === record.id}
              onClick={() => testMutation.mutate(record)}
              aria-label={`连通测试-${record.node_name}`}
            >
              连通测试
            </Button>
            <Tooltip title={retryTip}>
              <Button
                type="link"
                size="small"
                icon={<SyncOutlined />}
                disabled={retryDisabled}
                loading={retryingNodeId === record.id}
                onClick={() =>
                  retryVersionId &&
                  retrySyncMutation.mutate({
                    versionId: retryVersionId,
                    nodeId: record.id,
                    nodeName: record.node_name,
                  })
                }
                aria-label={`重试同步-${record.node_name}`}
              >
                重试同步
              </Button>
            </Tooltip>
            <Button
              type="link"
              size="small"
              danger
              icon={<DeleteOutlined />}
              disabled={!canManageNodes}
              onClick={() => confirmDelete(record)}
              aria-label={`删除-${record.node_name}`}
            >
              删除
            </Button>
          </Space>
        )
      },
    },
  ]

  const groupColumns: ColumnsType<ApiNodeVersionGroup> = [
    {
      title: '策略版本',
      dataIndex: 'policy_version',
      width: 280,
      render: (v: string) => (v ? <VersionText value={v} /> : <Tag>未上报</Tag>),
    },
    { title: '节点数', dataIndex: 'node_count', width: 90 },
    {
      title: '节点',
      dataIndex: 'nodes',
      render: (nodes: string[]) => (
        <Space size={4} wrap>
          {nodes.map((n) => (
            <Tag key={n}>{n}</Tag>
          ))}
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="网关节点管理与版本校验"
      extra={
        <Space>
          {canManageNodes && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新增节点
            </Button>
          )}
          <TableRefreshControl
            storageKey="api-nodes"
            loading={listQuery.isFetching || consistencyQuery.isFetching}
            onRefresh={() =>
              Promise.all([
                listQuery.refetch(),
                consistencyQuery.refetch(),
                canRetrySync ? currentVersionQuery.refetch() : Promise.resolve(),
              ])
            }
          />
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        管理多节点网关的配置同步通道（推荐配置 hasyncd 协同代理地址与 HMAC 密钥以支持配置、证书、边车、防火墙与集群滚动升级）；
        节点状态按最近活性距当前时刻判定（5 分钟内活跃、5 分钟~1 小时停滞、超过 1 小时静默）。
      </Typography.Paragraph>
      {report ? (
        <>
          <Alert
            style={{ marginBottom: 16 }}
            type={report.consistent ? (report.evaluated_nodes > 0 ? 'success' : 'info') : 'error'}
            showIcon
            message={
              report.consistent
                ? report.evaluated_nodes > 0
                  ? `活跃节点策略版本一致（${report.evaluated_nodes} 个参与判定，版本 ${report.dominant_version}）`
                  : '无版本数据可比（当前没有活跃节点上报策略版本）'
                : `节点策略版本不一致：${report.evaluated_nodes} 个活跃节点存在多个版本`
            }
            description={
              report.silent_nodes.length > 0
                ? `静默节点（离线不参与判定）：${report.silent_nodes.join('、')}`
                : undefined
            }
          />
          {report.groups.length > 0 ? (
            <Table<ApiNodeVersionGroup>
              style={{ marginBottom: 16 }}
              rowKey={(g) => g.policy_version || '(unreported)'}
              onRow={(record) => ({
                onDoubleClick: () => {
                  setDetailTitle('版本分组详情')
                  setDetailRecord(record as unknown as Record<string, unknown>)
                },
                style: { cursor: 'pointer' },
              })}
              size="small"
              columns={groupColumns}
              dataSource={report.groups}
              pagination={false}
            />
          ) : null}
        </>
      ) : null}
      <QueryErrorAlert error={listQuery.error ?? consistencyQuery.error} />
      <SmartTable<ApiNode>
        storageKey="api-nodes"
        rowKey="id"
        onRow={(record) => ({
          onDoubleClick: () => {
            setDetailTitle('节点详情')
            setDetailRecord(record as unknown as Record<string, unknown>)
          },
          style: { cursor: 'pointer' },
        })}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 2050 }}
        pagination={false}
      />

      <Modal
        title={editing ? `编辑节点同步配置「${editing.node_name}」` : '新增网关节点'}
        open={modalOpen}
        onCancel={() => {
          setModalOpen(false)
          setEditing(null)
          form.resetFields()
        }}
        onOk={submitForm}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        okText="保存"
        cancelText="取消"
        width={560}
        destroyOnHidden
      >
        <Form<NodeFormValues> form={form} layout="vertical">
          <Form.Item
            name="node_name"
            label="节点名称"
            rules={[
              { required: true, message: '请输入节点名称（需与 GATEWAY_NODE_NAME 一致）' },
              { max: 128, message: '节点名称不超过 128 字符' },
            ]}
          >
            <Input placeholder="如 gw-standby-01" disabled={!!editing} />
          </Form.Item>
          <Form.Item
            name="sync_agent_addr"
            label="协同代理地址（hasyncd，推荐）"
            extra="仅允许内网 http(s)://host:port，如 https://10.0.0.12:18443；启用后可同步配置、边车、防火墙与滚动升级。"
          >
            <Input placeholder="如 https://10.0.0.12:18443" />
          </Form.Item>
          <Form.Item
            name="sync_secret"
            label={
              editing
                ? '协同代理 HMAC 密钥（留空表示保留原密钥）'
                : '协同代理 HMAC 密钥（可选，≥64 位十六进制字符）'
            }
            extra="与备节点 hasyncd 的 HASYNC_SECRET_FILE 内容保持一致；密文落库，保存后永不回显。"
            rules={[
              {
                validator: (_, value?: string) => {
                  if (watchedClearSecret || !value || !value.trim()) return Promise.resolve()
                  if (!SYNC_SECRET_HEX_RE.test(value.trim())) {
                    return Promise.reject(
                      new Error('HMAC 密钥必须为至少 64 位十六进制字符（0-9, a-f）'),
                    )
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Input.Password
              disabled={Boolean(watchedClearSecret)}
              placeholder={editing?.has_sync_secret ? '已配置（留空不变更）' : '64 位及以上十六进制密钥'}
              autoComplete="new-password"
            />
          </Form.Item>
          {editing?.has_sync_secret && (
            <Form.Item name="clear_sync_secret" valuePropName="checked" style={{ marginTop: -8 }}>
              <Checkbox
                onChange={(e) => {
                  if (e.target.checked) {
                    form.setFieldValue('sync_secret', undefined)
                  }
                }}
              >
                清除已有同步密钥
              </Checkbox>
            </Form.Item>
          )}
          <Form.Item
            name="admin_addr"
            label="Caddy Admin 直连地址（兼容备选）"
            extra="未配置 hasyncd 时回退使用；支持 /var/run/caddy/... Unix Socket 路径或内网 http(s)://host:port。"
          >
            <Input placeholder="如 http://10.0.0.12:2019 或 /var/run/caddy/node-b/admin.sock" />
          </Form.Item>
          <Form.Item name="sync_enabled" label="启用配置同步扇出" valuePropName="checked">
            <Switch aria-label="启用配置同步扇出" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={testOutcome ? `节点「${testOutcome.nodeName}」连通性测试结果` : '连通性测试结果'}
        open={testOutcome !== null}
        onCancel={() => setTestOutcome(null)}
        footer={
          <Button type="primary" onClick={() => setTestOutcome(null)}>
            关闭
          </Button>
        }
        destroyOnHidden
      >
        {testOutcome && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Alert
              type={testOutcome.result.ok ? 'success' : 'error'}
              showIcon
              message={testOutcome.result.ok ? '节点连通性检测通过' : '节点连通性检测失败'}
              description={testOutcome.result.error || undefined}
            />
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="探测通道">
                {TEST_CHANNEL_LABELS[testOutcome.result.channel] ?? testOutcome.result.channel}
              </Descriptions.Item>
              <Descriptions.Item label="探测延迟">
                {testOutcome.result.latency_ms} ms
              </Descriptions.Item>
              {testOutcome.result.version && (
                <Descriptions.Item label="远端系统版本">
                  <Tag color="geekblue">{testOutcome.result.version}</Tag>
                </Descriptions.Item>
              )}
              {typeof testOutcome.result.caddy_reachable === 'boolean' && (
                <Descriptions.Item label="Caddy Admin 可达">
                  <Tag color={testOutcome.result.caddy_reachable ? 'green' : 'red'}>
                    {testOutcome.result.caddy_reachable ? '可达' : '不可达'}
                  </Tag>
                </Descriptions.Item>
              )}
              {typeof testOutcome.result.hostctl_ready === 'boolean' && (
                <Descriptions.Item label="宿主防火墙通道（hostctl）">
                  <Tag color={testOutcome.result.hostctl_ready ? 'green' : 'orange'}>
                    {testOutcome.result.hostctl_ready ? '就绪' : '未就绪'}
                  </Tag>
                </Descriptions.Item>
              )}
              {typeof testOutcome.result.upgrade_ready === 'boolean' && (
                <Descriptions.Item label="远程升级执行器">
                  <Tag color={testOutcome.result.upgrade_ready ? 'green' : 'orange'}>
                    {testOutcome.result.upgrade_ready ? '就绪' : '未就绪'}
                  </Tag>
                </Descriptions.Item>
              )}
            </Descriptions>
          </Space>
        )}
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title={detailTitle}
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
