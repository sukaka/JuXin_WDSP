import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Timeline,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, EditOutlined, PlusOutlined, SwapOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { haGroupsApi } from '../../api/haGroups'
import TableRefreshControl from '../../components/TableRefreshControl'
import { apiNodesApi } from '../../api/apiNodes'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import type { HaGroup, HaGroupUpsert } from '../../types'

/** VRRP 运行状态展示（havipd state 取值） */
const HA_STATE_META: Record<string, { label: string; color?: string }> = {
  MASTER: { label: '主节点（持有 VIP）', color: 'green' },
  BACKUP: { label: '备节点（待命）', color: 'blue' },
  FAULT: { label: '实例故障', color: 'red' },
  DISABLED: { label: '已停用' },
  STOPPED: { label: '未下发' },
}

/** 表单值（members 固定两行） */
interface HaFormValues {
  name: string
  state: string
  vrid: number
  iface: string
  vips: string[]
  preempt: boolean
  advert_int_ms: number
  unicast: boolean
  unicast_peers?: string[]
  auth_pass?: string
  members: { node_id?: string; priority?: number }[]
}

function stateTag(state: string | undefined) {
  const meta = (state ? HA_STATE_META[state] : undefined) ?? { label: state || '未知' }
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 主备高可用：主备组配置（VIP 漂移）与运行状态、漂移历史展示 */
export default function HaGroupsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ha.manage')

  const groupsQuery = useQuery({ queryKey: ['ha-groups'], queryFn: haGroupsApi.list })
  const nodesQuery = useQuery({ queryKey: ['api-nodes'], queryFn: apiNodesApi.list })

  const groups = useMemo(() => groupsQuery.data?.items ?? [], [groupsQuery.data])
  const status = groupsQuery.data?.status ?? null
  const nodes = useMemo(() => nodesQuery.data?.items ?? [], [nodesQuery.data])

  const { rowSelection, batchDeleteButton } = useBatchDelete<HaGroup>({
    remove: (id) => haGroupsApi.remove(id),
    invalidateKeys: [['ha-groups']],
    entityName: 'HA 组',
    canDelete: canManage,
  })

  const [editing, setEditing] = useState<HaGroup | null>(null)
  const [detailRecord, setDetailRecord] = useState<HaGroup | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<HaFormValues>()

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['ha-groups'] })
  const onError = (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败')

  const deleteMutation = useMutation({
    mutationFn: (id: string) => haGroupsApi.remove(id),
    onSuccess: (d) => {
      message.success(d.message || '已删除')
      invalidate()
    },
    onError,
  })

  const failbackMutation = useMutation({
    mutationFn: ({ id, nodeId }: { id: string; nodeId: string }) => haGroupsApi.failback(id, nodeId),
    onSuccess: (d) => {
      message.success(d.message || '已回切')
      invalidate()
    },
    onError,
  })

  const saveMutation = useMutation({
    mutationFn: (payload: { id?: string; body: HaGroupUpsert }) =>
      payload.id ? haGroupsApi.update(payload.id, payload.body) : haGroupsApi.create(payload.body),
    onSuccess: () => {
      message.success(editing ? '主备组已更新并下发' : '主备组已创建并下发')
      setCreateOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  /** 打开编辑（回填表单；auth_pass 不回填，留空=不变更） */
  const openEdit = (g: HaGroup) => {
    setEditing(g)
    form.setFieldsValue({
      name: g.name,
      state: g.state,
      vrid: g.vrid,
      iface: g.iface,
      vips: g.vips,
      preempt: g.preempt,
      advert_int_ms: g.advert_int_ms,
      unicast: g.unicast,
      unicast_peers: g.unicast_peers,
      members: [
        { node_id: g.members[0]?.node_id, priority: g.members[0]?.priority ?? 120 },
        { node_id: g.members[1]?.node_id, priority: g.members[1]?.priority ?? 100 },
      ],
    })
    setCreateOpen(true)
  }

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    form.setFieldsValue({
      state: 'ENABLED',
      vrid: 51,
      preempt: false,
      advert_int_ms: 1000,
      unicast: false,
      vips: [],
      members: [{ priority: 120 }, { priority: 100 }],
    })
    setCreateOpen(true)
  }

  const submit = async () => {
    const v = await form.validateFields()
    const body: HaGroupUpsert = {
      name: v.name.trim(),
      state: v.state,
      vrid: v.vrid,
      iface: v.iface.trim(),
      vips: (v.vips ?? []).map((s) => s.trim()).filter(Boolean),
      preempt: v.preempt,
      advert_int_ms: v.advert_int_ms,
      unicast: v.unicast,
      unicast_peers: v.unicast ? (v.unicast_peers ?? []).map((s) => s.trim()).filter(Boolean) : [],
      members: [
        { node_id: v.members[0].node_id!, priority: v.members[0].priority! },
        { node_id: v.members[1].node_id!, priority: v.members[1].priority! },
      ],
    }
    if (editing) {
      body.version = editing.version
      if (v.auth_pass && v.auth_pass.trim()) body.auth_pass = v.auth_pass.trim()
      else if (v.auth_pass === '') body.auth_pass = '' // 显式清空 = 清除认证串
    } else if (v.auth_pass && v.auth_pass.trim()) {
      body.auth_pass = v.auth_pass.trim()
    }
    saveMutation.mutate({ id: editing?.id, body })
  }

  const confirmDelete = (g: HaGroup) => {
    modal.confirm({
      title: `删除主备组「${g.name}」？`,
      content: '删除后 havipd 将停止 keepalived 并释放 VIP，主备能力收回。该操作不可撤销。',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => deleteMutation.mutate(g.id),
    })
  }

  const confirmFailback = (g: HaGroup, nodeId: string, nodeName: string) => {
    modal.confirm({
      title: `将 VIP 回切到节点「${nodeName}」？`,
      content: '必要时将调整成员优先级并重新下发，VIP 随 VRRP 选举切换到目标节点；切换瞬间在途长连接会断开重连。',
      okText: '确认回切',
      cancelText: '取消',
      onOk: () => failbackMutation.mutate({ id: g.id, nodeId }),
    })
  }

  /**
   * 由本节点运行状态推断组的当前 VIP 持有节点名（null = 未知）。
   * 状态仅覆盖本节点卷（设计 §15 M2 边界）：本节点 MASTER/持有 VIP → 本节点；
   * 本节点 BACKUP 且 keepalived 存活 → 组内另一成员（2 节点组健康推断）。
   */
  const vipHolderOf = (g: HaGroup): string | null => {
    if (!status?.node) return null
    const selfIdx = g.members.findIndex((m) => m.node_name === status.node)
    if (selfIdx < 0) return null
    if (status.state === 'MASTER' || (status.vips_present?.length ?? 0) > 0) return status.node
    if (status.state === 'BACKUP' && status.keepalived_running) return g.members[1 - selfIdx]?.node_name ?? null
    return null
  }

  const columns: ColumnsType<HaGroup> = [
    { title: '组名', dataIndex: 'name', width: 140, render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
    {
      title: '状态',
      dataIndex: 'state',
      width: 110,
      render: (v: string) => (v === 'ENABLED' ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>),
    },
    {
      title: 'VIP',
      dataIndex: 'vips',
      render: (vips: string[]) => (
        <Space size={4} wrap>
          {vips.map((v) => (
            <Typography.Text code key={v}>{v}</Typography.Text>
          ))}
        </Space>
      ),
    },
    { title: 'VRID', dataIndex: 'vrid', width: 80 },
    { title: '承载网卡', dataIndex: 'iface', width: 110 },
    {
      title: '成员（优先级）',
      key: 'members',
      render: (_, g) => {
        const holder = vipHolderOf(g)
        return (
          <Space size={4} wrap>
            {[...g.members]
              .sort((a, b) => b.priority - a.priority)
              .map((m) => (
                <Tag key={m.node_id} color={m.priority === Math.max(...g.members.map((x) => x.priority)) ? 'gold' : undefined}>
                  {m.node_name || m.node_id}（{m.priority}）
                  {holder === m.node_name ? '·持有 VIP' : ''}
                </Tag>
              ))}
          </Space>
        )
      },
    },
    {
      title: '操作',
      key: 'action',
      width: 240,
      render: (_, g) => {
        const holder = vipHolderOf(g)
        const sorted = [...g.members].sort((a, b) => b.priority - a.priority)
        // 回切目标 = 当前未持有 VIP 的一方（nopreempt 故障转移后 = 配置高优先级的
        // 原主节点）；持有方未知（havipd 未上报）时退回低优先级成员。
        const target = holder ? g.members.find((m) => m.node_name !== holder) : sorted[1]
        return (
          <Space direction="vertical" size={4}>
            <Space size={4} wrap>
              <Button type="text" size="small" icon={<EditOutlined />} disabled={!canManage} onClick={() => openEdit(g)} aria-label={`编辑-${g.name}`} />
              <Button
                type="text"
                size="small"
                icon={<SwapOutlined />}
                disabled={!canManage || !target}
                onClick={() => target && confirmFailback(g, target.node_id, target.node_name || target.node_id)}
                aria-label={`回切-${g.name}`}
              >
                回切
              </Button>
              <Button type="text" size="small" danger icon={<DeleteOutlined />} disabled={!canManage} onClick={() => confirmDelete(g)} aria-label={`删除-${g.name}`} />
            </Space>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              VIP 持有：{holder ?? '未知'}
            </Typography.Text>
          </Space>
        )
      },
    },
  ]

  const nodeOptions = nodes.map((n) => ({ value: n.id, label: n.node_name }))

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card>
        <Space wrap style={{ width: '100%', justifyContent: 'space-between' }}>
          <Typography.Text type="secondary">
            主备高可用（VIP 漂移）：两台网关节点组成主备对，配置经发布通道全节点一致下发；网桥端口联动在「网络配置」页管理。
          </Typography.Text>
          {canManage && (
            <Space wrap>
              {batchDeleteButton}
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                新建主备组
              </Button>
            </Space>
          )}
        </Space>
        <Alert
          style={{ marginTop: 12 }}
          type="warning"
          showIcon
          message="主备配置属高危操作"
          description="VIP/优先级变更保存后立即下发执行，错误配置可能导致业务入口中断，请确认无误后再保存。"
        />
      </Card>

      {groupsQuery.isError ? (
        <Card>
          <QueryErrorAlert error={groupsQuery.error} message="加载主备组失败" />
        </Card>
      ) : (
        <Card
          title="主备组"
          extra={
            <TableRefreshControl
              storageKey="ha-groups"
              loading={groupsQuery.isFetching}
              onRefresh={() => Promise.all([groupsQuery.refetch(), nodesQuery.refetch()])}
            />
          }
        >
          <Table<HaGroup>
            rowKey="id"
            rowSelection={rowSelection}
            size="small"
            loading={groupsQuery.isLoading}
            columns={columns}
            dataSource={groups}
            pagination={false}
            onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
            locale={{ emptyText: '尚未配置主备组' }}
          />
        </Card>
      )}

      <Card title="运行状态（本网关节点）">
        {status == null ? (
          <Alert type="info" showIcon message="节点尚未上报主备状态（havipd 未运行或未下发配置）" />
        ) : (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space wrap size={24}>
              <span>
                <Typography.Text type="secondary">节点：</Typography.Text>
                {status.node}
              </span>
              <span>
                <Typography.Text type="secondary">状态：</Typography.Text>
                {stateTag(status.state)}
              </span>
              <Badge
                status={status.keepalived_running ? 'success' : 'error'}
                text={status.keepalived_running ? 'keepalived 运行中' : 'keepalived 未运行'}
              />
              <span>
                <Typography.Text type="secondary">持有 VIP：</Typography.Text>
                {status.vips_present?.length ? status.vips_present.join('、') : '无'}
              </span>
              {status.last_transition_at && (
                <span>
                  <Typography.Text type="secondary">最近迁移：</Typography.Text>
                  {dayjs(status.last_transition_at).format('YYYY-MM-DD HH:mm:ss')}
                </span>
              )}
            </Space>
            {status.message && <Alert type="info" showIcon message={status.message} />}
            {(status.events?.length ?? 0) > 0 && (
              <Timeline
                items={(status.events ?? []).slice(0, 10).map((e) => ({
                  color: e.to === 'MASTER' ? 'green' : e.to === 'FAULT' ? 'red' : 'blue',
                  children: (
                    <>
                      <Typography.Text strong>
                        {HA_STATE_META[e.from]?.label ?? e.from} → {HA_STATE_META[e.to]?.label ?? e.to}
                      </Typography.Text>
                      <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                        {dayjs(e.at).format('MM-DD HH:mm:ss')}
                      </Typography.Text>
                      {e.detail && <div style={{ fontSize: 12, color: '#666' }}>{e.detail}</div>}
                    </>
                  ),
                }))}
              />
            )}
          </Space>
        )}
      </Card>

      <Modal
        title={editing ? `编辑主备组「${editing.name}」` : '新建主备组'}
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={submit}
        confirmLoading={saveMutation.isPending}
        okText="保存并下发"
        cancelText="取消"
        width={640}
        destroyOnHidden
      >
        <Form form={form} layout="vertical">
          <Space size={16} wrap>
            <Form.Item name="name" label="组名" rules={[{ required: true, message: '请输入组名' }]} style={{ width: 200 }}>
              <Input placeholder="如 ha-main" disabled={!!editing} />
            </Form.Item>
            <Form.Item name="state" label="状态" rules={[{ required: true }]} style={{ width: 140 }}>
              <Select options={[{ value: 'ENABLED', label: '启用' }, { value: 'DISABLED', label: '停用' }]} />
            </Form.Item>
            <Form.Item name="vrid" label="VRID（1~255）" rules={[{ required: true, message: '请输入 VRID' }]} style={{ width: 150 }}>
              <InputNumber min={1} max={255} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="iface" label="VIP 承载网卡" rules={[{ required: true, message: '请输入网卡名' }]} style={{ width: 180 }}>
              <Input placeholder="如 eth0" />
            </Form.Item>
          </Space>
          <Form.Item name="vips" label="虚拟 IP（CIDR，可多个）" rules={[{ required: true, message: '至少 1 个 VIP' }]}>
            <Select mode="tags" placeholder="如 192.168.31.100/24，回车添加" open={false} suffixIcon={null} />
          </Form.Item>
          <Space size={16} wrap>
            <Form.Item name="advert_int_ms" label="通告间隔（ms）" rules={[{ required: true }]} style={{ width: 160 }}>
              <InputNumber min={200} max={10000} step={100} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="preempt" label="允许抢占" valuePropName="checked">
              <Switch aria-label="允许抢占" />
            </Form.Item>
            <Form.Item name="unicast" label="单播 VRRP" valuePropName="checked">
              <Switch aria-label="单播 VRRP" />
            </Form.Item>
          </Space>
          <Form.Item shouldUpdate={(a: HaFormValues, b: HaFormValues) => a.unicast !== b.unicast} noStyle>
            {({ getFieldValue }) =>
              getFieldValue('unicast') ? (
                <Form.Item name="unicast_peers" label="单播对端地址" rules={[{ required: true, message: '单播模式需提供对端地址' }]}>
                  <Select mode="tags" placeholder="如 192.168.31.62，回车添加" open={false} suffixIcon={null} />
                </Form.Item>
              ) : null
            }
          </Form.Item>
          <Form.Item
            name="auth_pass"
            label={editing ? 'VRRP 认证串（留空 = 不变更；清空并保存 = 清除）' : 'VRRP 认证串（可选，≤8 字符）'}
            rules={[{ max: 8, message: 'VRRPv2 上限 8 字符' }]}
          >
            <Input.Password placeholder={editing?.has_auth_pass ? '已配置（不显示）' : '可选'} autoComplete="new-password" />
          </Form.Item>
          <Typography.Text strong>成员（恰 2 台已登记网关节点，优先级高者倾向成为主节点）</Typography.Text>
          <Space size={16} wrap style={{ marginTop: 8 }}>
            {[0, 1].map((i) => (
              <Space key={i}>
                <Form.Item
                  name={['members', i, 'node_id']}
                  rules={[{ required: true, message: '选择节点' }]}
                  style={{ width: 220, marginBottom: 0 }}
                >
                  <Select placeholder={`节点 ${i + 1}`} options={nodeOptions} loading={nodesQuery.isLoading} aria-label={`成员节点${i + 1}`} />
                </Form.Item>
                <Form.Item
                  name={['members', i, 'priority']}
                  rules={[{ required: true, message: '优先级' }]}
                  style={{ width: 120, marginBottom: 0 }}
                >
                  <InputNumber min={1} max={254} placeholder="优先级" style={{ width: '100%' }} />
                </Form.Item>
              </Space>
            ))}
          </Space>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="主备组详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
