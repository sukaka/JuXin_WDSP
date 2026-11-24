import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  AutoComplete,
  Badge,
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input,
  InputNumber,
  Modal,
  Row,
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
import { networkConfigApi } from '../../api/networkConfig'
import { nodeInterfacesApi } from '../../api/nodeInterfaces'
import TableRefreshControl from '../../components/TableRefreshControl'
import { apiNodesApi } from '../../api/apiNodes'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { isValidIPv4 } from '../../utils/stage5'
import type {
  HaEvent,
  HaGroup,
  HaGroupUpsert,
  HaNodeRuntimeStatus,
  HaSyncResult,
  HaVipStatus,
} from '../../types'

/** 与后端 server/internal/hagroups/hagroups.go 一致的校验正则 */
const GROUP_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const IF_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/
const AUTH_PASS_RE = /^[A-Za-z0-9._:@+-]{1,8}$/

/** VRRP 运行状态展示（havipd state 取值） */
const HA_STATE_META: Record<string, { label: string; color?: string }> = {
  MASTER: { label: '主节点（持有 VIP）', color: 'green' },
  BACKUP: { label: '备节点（待命）', color: 'blue' },
  FAULT: { label: '实例故障', color: 'red' },
  DISABLED: { label: '已停用' },
  STOPPED: { label: '未下发' },
}

/** 持久化 HA 事件类型映射（ha_events.event_type） */
const HA_EVENT_TYPE_META: Record<string, { label: string; color: string }> = {
  FAILBACK: { label: '人工回切', color: 'blue' },
  SPLIT_BRAIN: { label: '双主脑裂', color: 'red' },
  VIP_TRANSITION: { label: 'VIP 漂移', color: 'green' },
  LINK_PAIR_CHANGE: { label: '端口联动', color: 'orange' },
  SYNC_FAILED: { label: '同步失败', color: 'red' },
}

const HA_EVENT_TYPE_OPTIONS = [
  { value: '', label: '全部事件类型' },
  { value: 'FAILBACK', label: '人工回切' },
  { value: 'SPLIT_BRAIN', label: '双主脑裂' },
  { value: 'VIP_TRANSITION', label: 'VIP 漂移' },
  { value: 'LINK_PAIR_CHANGE', label: '端口联动' },
  { value: 'SYNC_FAILED', label: '同步失败' },
]

/** 严格 IPv4 CIDR 校验（与后端 net.ParseCIDR + To4 一致，拒绝 IPv6 和裸 IP） */
function isIPv4CIDR(raw: string): boolean {
  const s = raw.trim()
  const parts = s.split('/')
  if (parts.length !== 2) return false
  const [addr, bits] = parts
  if (!isValidIPv4(addr)) return false
  if (!/^\d+$/.test(bits) || (bits.length > 1 && bits[0] === '0')) return false
  const n = Number(bits)
  return n >= 0 && n <= 32
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
  track_interfaces?: string[]
  auth_pass?: string
  clear_auth_pass?: boolean
  members: { node_id?: string; priority?: number }[]
}

interface SyncFeedback {
  action: string
  results: HaSyncResult[]
}

function stateTag(state: string | undefined) {
  const meta = (state ? HA_STATE_META[state] : undefined) ?? { label: state || '未知' }
  return <Tag color={meta.color}>{meta.label}</Tag>
}

function isMasterOrHoldingVIP(rt?: HaVipStatus | null): boolean {
  return Boolean(rt && (rt.state === 'MASTER' || (rt.vips_present?.length ?? 0) > 0))
}

function formatHaEventDetail(ev: HaEvent): string {
  const d = ev.detail ?? {}
  const parts: string[] = []
  if (typeof d.from === 'string' && typeof d.to === 'string') {
    const fromLabel = HA_STATE_META[d.from]?.label ?? d.from
    const toLabel = HA_STATE_META[d.to]?.label ?? d.to
    parts.push(`${fromLabel} → ${toLabel}`)
  }
  if (typeof d.message === 'string' && d.message) parts.push(d.message)
  if (typeof d.detail === 'string' && d.detail) parts.push(d.detail)
  if (typeof d.error === 'string' && d.error) parts.push(`错误：${d.error}`)
  if (typeof d.operator === 'string' && d.operator) parts.push(`操作人：${d.operator}`)
  if (parts.length > 0) return parts.join('；')
  const keys = Object.keys(d)
  if (keys.length === 0) return ''
  try {
    return JSON.stringify(d)
  } catch {
    return ''
  }
}

/** 主备高可用：主备组配置（VIP 漂移）与双节点运行状态、持久化事件时间线展示 */
export default function HaGroupsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ha.manage')
  const canReadInterfaces = canManage && hasPermission(permissions, 'system_health.read')

  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')
  const [syncFeedback, setSyncFeedback] = useState<SyncFeedback | null>(null)

  const groupsQuery = useQuery({ queryKey: ['ha-groups'], queryFn: haGroupsApi.list })
  const eventsQuery = useQuery({
    queryKey: ['ha-events', eventTypeFilter],
    queryFn: () =>
      haGroupsApi.listEvents({
        event_type: eventTypeFilter || undefined,
        page: 1,
        page_size: 20,
      }),
  })
  const nodesQuery = useQuery({ queryKey: ['api-nodes'], queryFn: apiNodesApi.list })
  const interfacesQuery = useQuery({
    queryKey: ['node-interfaces'],
    queryFn: () => nodeInterfacesApi.list(),
    enabled: canReadInterfaces,
  })
  const netConfigQuery = useQuery({
    queryKey: ['network-config-default'],
    queryFn: () => networkConfigApi.get(),
    enabled: canReadInterfaces,
  })

  const groups = useMemo(() => groupsQuery.data?.items ?? [], [groupsQuery.data])
  const status = groupsQuery.data?.status ?? null
  const nodeStatuses = useMemo<Record<string, HaNodeRuntimeStatus>>(
    () => groupsQuery.data?.node_statuses ?? {},
    [groupsQuery.data],
  )
  const nodes = useMemo(() => nodesQuery.data?.items ?? [], [nodesQuery.data])
  const haEvents = useMemo(() => eventsQuery.data?.items ?? [], [eventsQuery.data])

  const splitBrain = useMemo(() => {
    if (typeof groupsQuery.data?.split_brain === 'boolean') {
      return groupsQuery.data.split_brain
    }
    return groups.some((g) => {
      let masters = 0
      for (const m of g.members) {
        const ns = nodeStatuses[m.node_name]
        if (!ns?.fresh || !ns.status) continue
        if (ns.status.group && ns.status.group !== g.name) continue
        if (isMasterOrHoldingVIP(ns.status)) masters += 1
      }
      return masters >= 2
    })
  }, [groupsQuery.data?.split_brain, groups, nodeStatuses])

  /** 已加入网桥的成员口（ifname -> 网桥名）；HA VIP 承载网卡禁止选用网桥成员口，但推荐作为 track_interfaces */
  const bridgedPortMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const br of netConfigQuery.data?.desired?.bridges ?? []) {
      for (const port of br.ports ?? []) {
        map.set(port, br.name)
      }
    }
    return map
  }, [netConfigQuery.data])

  /** 可选非桥接网口列表（自动排除网桥成员口与镜像口，保留自定义输入兜底） */
  const ifaceOptions = useMemo(() => {
    const allNodes = interfacesQuery.data?.nodes ?? []
    const defaultNodeName = netConfigQuery.data?.default_node?.trim()
    const orderedNodes = defaultNodeName
      ? [
          ...allNodes.filter((n) => n.node_name === defaultNodeName),
          ...allNodes.filter((n) => n.node_name !== defaultNodeName),
        ]
      : allNodes
    const seen = new Set<string>()
    const options: { value: string; label: string }[] = []
    const roleLabels: Record<string, string> = {
      MANAGEMENT: '管理口',
      TRAFFIC: '业务口',
    }
    for (const node of orderedNodes) {
      for (const it of node.interfaces ?? []) {
        if (!it.present || it.role === 'MIRROR' || bridgedPortMap.has(it.ifname)) continue
        if (seen.has(it.ifname)) continue
        seen.add(it.ifname)
        const roleText = it.role && roleLabels[it.role] ? `（${roleLabels[it.role]}）` : ''
        options.push({
          value: it.ifname,
          label: `${it.ifname}${roleText}`,
        })
      }
    }
    return options
  }, [interfacesQuery.data, netConfigQuery.data, bridgedPortMap])

  const [editing, setEditing] = useState<HaGroup | null>(null)
  const [detailRecord, setDetailRecord] = useState<HaGroup | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<HaFormValues>()
  const watchedIface = Form.useWatch('iface', form)
  const watchedClearAuthPass = Form.useWatch('clear_auth_pass', form)
  const bridgedConflict = watchedIface ? bridgedPortMap.get(watchedIface.trim()) : undefined

  /** track_interfaces 多选推荐项：优先推荐网桥成员口，补充其他在线非镜像口，排除当前承载网卡 */
  const trackInterfaceOptions = useMemo(() => {
    const exclude = (watchedIface ?? '').trim()
    const seen = new Set<string>()
    const options: { value: string; label: string }[] = []
    for (const [port, brName] of bridgedPortMap.entries()) {
      if (port === exclude || seen.has(port)) continue
      seen.add(port)
      options.push({ value: port, label: `${port}（网桥 ${brName} 成员口 · 推荐）` })
    }
    for (const node of interfacesQuery.data?.nodes ?? []) {
      for (const it of node.interfaces ?? []) {
        if (!it.present || it.role === 'MIRROR' || it.ifname === exclude || seen.has(it.ifname)) continue
        seen.add(it.ifname)
        options.push({ value: it.ifname, label: it.ifname })
      }
    }
    return options
  }, [bridgedPortMap, interfacesQuery.data, watchedIface])

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['ha-groups'] })
    void queryClient.invalidateQueries({ queryKey: ['ha-events'] })
  }
  const onError = (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败')

  const handleSyncFeedback = (action: string, defaultSuccessMsg: string, results?: HaSyncResult[]) => {
    if (results && results.length > 0) {
      setSyncFeedback({ action, results })
      const failed = results.filter((r) => r.status !== 'SUCCESS')
      if (failed.length > 0) {
        message.warning(
          `${action}已入库，但 ${failed.length} 个节点边车同步失败：${failed.map((f) => f.node_name || f.scope).join('、')}`,
        )
        return
      }
    }
    message.success(defaultSuccessMsg)
  }

  const deleteMutation = useMutation({
    mutationFn: (id: string) => haGroupsApi.remove(id),
    onSuccess: (d) => {
      handleSyncFeedback('删除主备组', d.message || '已删除', d.sync_results)
      invalidate()
    },
    onError,
  })

  const failbackMutation = useMutation({
    mutationFn: ({ id, nodeId }: { id: string; nodeId: string }) => haGroupsApi.failback(id, nodeId),
    onSuccess: (d) => {
      handleSyncFeedback('人工回切', d.message || '已回切', d.sync_results)
      invalidate()
    },
    onError,
  })

  const saveMutation = useMutation({
    mutationFn: (payload: { id?: string; body: HaGroupUpsert }) =>
      payload.id ? haGroupsApi.update(payload.id, payload.body) : haGroupsApi.create(payload.body),
    onSuccess: (d) => {
      const action = editing ? '更新主备组' : '创建主备组'
      handleSyncFeedback(
        action,
        editing ? '主备组已更新并下发同步' : '主备组已创建并下发同步',
        d.sync_results,
      )
      setCreateOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  /** 打开编辑：先重置表单，防止上次编辑态的 auth_pass / clear_auth_pass / track_interfaces 残留 */
  const openEdit = (g: HaGroup) => {
    setEditing(g)
    form.resetFields()
    form.setFieldsValue({
      name: g.name,
      state: g.state,
      vrid: g.vrid,
      iface: g.iface,
      vips: g.vips ?? [],
      preempt: g.preempt,
      advert_int_ms: g.advert_int_ms,
      unicast: g.unicast,
      unicast_peers: g.unicast_peers ?? [],
      track_interfaces: g.track_interfaces ?? [],
      auth_pass: undefined,
      clear_auth_pass: false,
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
      track_interfaces: [],
      clear_auth_pass: false,
      members: [{ priority: 120 }, { priority: 100 }],
    })
    setCreateOpen(true)
  }

  const submit = async () => {
    let v: HaFormValues
    try {
      v = await form.validateFields()
    } catch {
      return
    }
    const trackInterfaces = Array.from(
      new Set((v.track_interfaces ?? []).map((s) => s.trim()).filter(Boolean)),
    )
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
      track_interfaces: trackInterfaces,
      members: [
        { node_id: v.members[0].node_id!, priority: v.members[0].priority! },
        { node_id: v.members[1].node_id!, priority: v.members[1].priority! },
      ],
    }
    if (editing) {
      body.version = editing.version
      if (v.clear_auth_pass) {
        body.auth_pass = ''
      } else if (v.auth_pass && v.auth_pass.length > 0) {
        body.auth_pass = v.auth_pass
      }
    } else if (v.auth_pass && v.auth_pass.length > 0) {
      body.auth_pass = v.auth_pass
    }
    saveMutation.mutate({ id: editing?.id, body })
  }

  const confirmDelete = (g: HaGroup) => {
    modal.confirm({
      title: `删除主备组「${g.name}」？`,
      content: '删除后本机及已同步远端节点的 havipd 将停止 keepalived 并释放 VIP，主备能力收回。该操作不可撤销。',
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
   * 优先依据全部成员的新鲜汇聚状态（node_statuses）校验组名与新鲜度判定当前 VIP 持有节点；
   * 脑裂（>=2 个 MASTER）时不判定为唯一持有方；单机无汇聚状态时回退到本机 status 并校验组名。
   */
  const vipHolderOf = (g: HaGroup): string | null => {
    const memberEntries = g.members
      .map((m) => ({ member: m, ns: nodeStatuses[m.node_name] }))
      .filter(
        (item) =>
          item.ns &&
          item.ns.fresh &&
          item.ns.status &&
          (!item.ns.status.group || item.ns.status.group === g.name),
      )

    if (memberEntries.length > 0) {
      const masters = memberEntries.filter((item) => isMasterOrHoldingVIP(item.ns?.status))
      if (masters.length === 1) return masters[0].member.node_name
      if (masters.length >= 2) return null
      if (g.members.length === 2 && memberEntries.length === 1) {
        const only = memberEntries[0]
        if (only.ns?.status?.state === 'BACKUP' && only.ns.status.keepalived_running) {
          const peer = g.members.find((m) => m.node_name !== only.member.node_name)
          return peer?.node_name ?? null
        }
      }
      return null
    }

    if (Object.keys(nodeStatuses).length > 0) {
      // node_statuses 已提供但该组无新鲜节点状态（全部过期/无匹配组）
      const hasAnyEntryForGroup = g.members.some((m) => Boolean(nodeStatuses[m.node_name]))
      if (hasAnyEntryForGroup) return null
    }

    if (!status?.node) return null
    if (status.group && status.group !== g.name) return null
    const selfIdx = g.members.findIndex((m) => m.node_name === status.node)
    if (selfIdx < 0) return null
    if (isMasterOrHoldingVIP(status)) return status.node
    if (status.state === 'BACKUP' && status.keepalived_running) {
      return g.members[1 - selfIdx]?.node_name ?? null
    }
    return null
  }

  /** 按主备组成员顺序组织的全部成员节点运行状态列表 */
  const runtimeNodeList = useMemo<HaNodeRuntimeStatus[]>(() => {
    const orderedNames: string[] = []
    const seen = new Set<string>()
    for (const g of groups) {
      for (const m of g.members) {
        if (m.node_name && !seen.has(m.node_name)) {
          seen.add(m.node_name)
          orderedNames.push(m.node_name)
        }
      }
    }
    for (const key of Object.keys(nodeStatuses)) {
      if (!seen.has(key)) {
        seen.add(key)
        orderedNames.push(key)
      }
    }
    if (Object.keys(nodeStatuses).length === 0) return []
    return orderedNames.map((name) => {
      const ns = nodeStatuses[name]
      if (ns) return ns
      return { node_name: name, status: null, updated_at: null, fresh: false, source: 'remote' }
    })
  }, [groups, nodeStatuses])

  const columns: ColumnsType<HaGroup> = [
    {
      title: '组名',
      dataIndex: 'name',
      width: 140,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'state',
      width: 90,
      render: (v: string) => (v === 'ENABLED' ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>),
    },
    {
      title: 'VIP',
      dataIndex: 'vips',
      render: (vips: string[]) => (
        <Space size={4} wrap>
          {vips.map((v) => (
            <Typography.Text code key={v}>
              {v}
            </Typography.Text>
          ))}
        </Space>
      ),
    },
    { title: 'VRID', dataIndex: 'vrid', width: 70 },
    {
      title: '承载网卡 / 跟踪口',
      key: 'iface',
      width: 170,
      render: (_, g) => (
        <Space direction="vertical" size={2}>
          <Typography.Text>{g.iface}</Typography.Text>
          {(g.track_interfaces?.length ?? 0) > 0 && (
            <Space size={4} wrap>
              {(g.track_interfaces ?? []).map((tif) => (
                <Tag key={tif} color="cyan">
                  跟踪:{tif}
                </Tag>
              ))}
            </Space>
          )}
        </Space>
      ),
    },
    {
      title: '成员（优先级）',
      key: 'members',
      render: (_, g) => {
        const holder = vipHolderOf(g)
        const maxPriority = Math.max(...g.members.map((x) => x.priority))
        return (
          <Space size={4} wrap>
            {[...g.members]
              .sort((a, b) => b.priority - a.priority)
              .map((m) => (
                <Tag key={m.node_id} color={m.priority === maxPriority ? 'gold' : undefined}>
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
        const target = holder ? g.members.find((m) => m.node_name !== holder) : sorted[1]
        return (
          <Space direction="vertical" size={4}>
            <Space size={4} wrap>
              <Button
                type="text"
                size="small"
                icon={<EditOutlined />}
                disabled={!canManage}
                onClick={() => openEdit(g)}
                aria-label={`编辑-${g.name}`}
              />
              <Button
                type="text"
                size="small"
                icon={<SwapOutlined />}
                disabled={!canManage || !target}
                onClick={() =>
                  target && confirmFailback(g, target.node_id, target.node_name || target.node_id)
                }
                aria-label={`回切-${g.name}`}
              >
                回切
              </Button>
              <Button
                type="text"
                size="small"
                danger
                icon={<DeleteOutlined />}
                disabled={!canManage}
                onClick={() => confirmDelete(g)}
                aria-label={`删除-${g.name}`}
              />
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
      {splitBrain && (
        <Alert
          type="error"
          showIcon
          message="检测到主备双主脑裂（HA_SPLIT_BRAIN）"
          description="同一主备组内有多个成员节点在实时状态窗口内同时处于 MASTER 或同时持有 VIP！请立即检查两节点间 VRRP 链路（交换机/防火墙策略、单播对端配置），待恢复单主后再执行回切或集群升级。"
        />
      )}

      <Card>
        <Space wrap style={{ width: '100%', justifyContent: 'space-between' }}>
          <Typography.Text type="secondary">
            主备高可用（VIP 漂移）：两台网关节点组成主备对，保存后自动写入本机边车卷（ha-vip.json）并通过协同代理（hasyncd）推送至已登记的远端成员节点；网桥端口联动在「网络配置」页管理。
          </Typography.Text>
          {canManage && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建主备组
            </Button>
          )}
        </Space>
        <Alert
          style={{ marginTop: 12 }}
          type="warning"
          showIcon
          message="主备配置属高危操作"
          description="VIP/优先级与跟踪接口变更保存后将立即下发本机及已启用协同代理（hasyncd）的远端成员节点执行；未配置协同代理的远端节点仍需手动同步 ha-vip.json。错误配置可能导致业务入口中断，请确认无误后再保存。"
        />
        {syncFeedback && (
          <Alert
            style={{ marginTop: 12 }}
            type={syncFeedback.results.some((r) => r.status !== 'SUCCESS') ? 'warning' : 'success'}
            showIcon
            closable
            onClose={() => setSyncFeedback(null)}
            message={`${syncFeedback.action}节点同步结果`}
            description={
              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                {syncFeedback.results.map((r, idx) => (
                  <div key={`${r.node_name}-${r.scope}-${idx}`}>
                    <Space size={6} wrap>
                      <Typography.Text strong>{r.node_name || '本机节点'}</Typography.Text>
                      <Tag>{r.scope === 'local' ? '本机' : '远端'}</Tag>
                      <Tag color={r.status === 'SUCCESS' ? 'green' : 'red'}>
                        {r.status === 'SUCCESS' ? '同步成功' : '同步失败'}
                      </Tag>
                      {r.error && <Typography.Text type="danger">{r.error}</Typography.Text>}
                    </Space>
                  </div>
                ))}
              </Space>
            }
          />
        )}
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
              loading={groupsQuery.isFetching || eventsQuery.isFetching}
              onRefresh={() =>
                Promise.all([groupsQuery.refetch(), eventsQuery.refetch(), nodesQuery.refetch()])
              }
            />
          }
        >
          <Table<HaGroup>
            rowKey="id"
            size="small"
            loading={groupsQuery.isLoading}
            columns={columns}
            dataSource={groups}
            pagination={false}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            locale={{ emptyText: '尚未配置主备组' }}
          />
        </Card>
      )}

      <Card title={runtimeNodeList.length > 0 ? '成员节点运行状态' : '运行状态（本网关节点）'}>
        {runtimeNodeList.length > 0 ? (
          <Row gutter={[12, 12]}>
            {runtimeNodeList.map((ns) => {
              const rt = ns.status
              return (
                <Col xs={24} md={12} key={ns.node_name}>
                  <Card
                    size="small"
                    title={
                      <Space size={6} wrap>
                        <Typography.Text strong>{ns.node_name}</Typography.Text>
                        <Tag>{ns.source === 'local' ? '本机' : '远端'}</Tag>
                        <Tag color={ns.fresh ? 'green' : 'orange'}>
                          {ns.fresh ? '状态实时' : '状态过期'}
                        </Tag>
                      </Space>
                    }
                  >
                    {!rt ? (
                      <Alert
                        type="info"
                        showIcon
                        message="该节点尚未上报主备运行状态（请确认 havipd 与 hasyncd 已运行）"
                      />
                    ) : (
                      <Space direction="vertical" size={8} style={{ width: '100%' }}>
                        <Space wrap size={12}>
                          <span>
                            <Typography.Text type="secondary">状态：</Typography.Text>
                            {stateTag(rt.state)}
                          </span>
                          <Badge
                            status={rt.keepalived_running ? 'success' : 'error'}
                            text={rt.keepalived_running ? 'keepalived 运行中' : 'keepalived 未运行'}
                          />
                        </Space>
                        <Space wrap size={16}>
                          <span>
                            <Typography.Text type="secondary">持有 VIP：</Typography.Text>
                            {rt.vips_present?.length ? rt.vips_present.join('、') : '无'}
                          </span>
                          {typeof rt.priority === 'number' && rt.priority > 0 && (
                            <span>
                              <Typography.Text type="secondary">优先级：</Typography.Text>
                              {rt.priority}
                            </span>
                          )}
                        </Space>
                        <Space wrap size={16}>
                          {ns.updated_at && (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              最近刷新：{dayjs(ns.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                            </Typography.Text>
                          )}
                          {rt.last_transition_at && (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              最近迁移：{dayjs(rt.last_transition_at).format('YYYY-MM-DD HH:mm:ss')}
                            </Typography.Text>
                          )}
                        </Space>
                        {rt.message && <Alert type="info" showIcon message={rt.message} />}
                      </Space>
                    )}
                  </Card>
                </Col>
              )
            })}
          </Row>
        ) : status == null ? (
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
          </Space>
        )}
      </Card>

      <Card
        title="漂移与联动事件时间线"
        extra={
          <Select
            style={{ width: 160 }}
            value={eventTypeFilter}
            onChange={(v) => setEventTypeFilter(v)}
            options={HA_EVENT_TYPE_OPTIONS}
            aria-label="事件类型筛选"
          />
        }
      >
        {eventsQuery.isError ? (
          <QueryErrorAlert error={eventsQuery.error} message="加载 HA 历史事件失败" />
        ) : haEvents.length > 0 ? (
          <Timeline
            items={haEvents.map((ev) => {
              const meta = HA_EVENT_TYPE_META[ev.event_type] ?? {
                label: ev.event_type,
                color: 'blue',
              }
              const detailText = formatHaEventDetail(ev)
              return {
                key: String(ev.id),
                color: meta.color,
                children: (
                  <div>
                    <Space size={6} wrap>
                      <Tag color={meta.color}>{meta.label}</Tag>
                      {ev.group_name && <Typography.Text strong>{ev.group_name}</Typography.Text>}
                      {ev.node_name && <Tag>{ev.node_name}</Tag>}
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {dayjs(ev.occurred_at).format('YYYY-MM-DD HH:mm:ss')}
                      </Typography.Text>
                    </Space>
                    {detailText && (
                      <div style={{ fontSize: 12, color: '#666', marginTop: 4 }}>{detailText}</div>
                    )}
                  </div>
                ),
              }
            })}
          />
        ) : !eventTypeFilter && (status?.events?.length ?? 0) > 0 ? (
          <Timeline
            items={(status?.events ?? []).slice(0, 10).map((e, idx) => ({
              key: `${e.at}-${idx}`,
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
        ) : (
          <Typography.Text type="secondary">暂无漂移与联动事件记录</Typography.Text>
        )}
      </Card>

      <Modal
        title={editing ? `编辑主备组「${editing.name}」` : '新建主备组'}
        open={createOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
          form.resetFields()
        }}
        onOk={submit}
        confirmLoading={saveMutation.isPending}
        okText="保存并下发"
        cancelText="取消"
        width={660}
        destroyOnHidden
      >
        <Form form={form} layout="vertical">
          <Space size={16} wrap>
            <Form.Item
              name="name"
              label="组名"
              rules={[
                { required: true, message: '请输入组名' },
                {
                  pattern: GROUP_NAME_RE,
                  message: '组名需 1~64 位字母数字开头，仅含字母数字与 . _ -',
                },
              ]}
              style={{ width: 200 }}
            >
              <Input placeholder="如 ha-main" disabled={!!editing} />
            </Form.Item>
            <Form.Item name="state" label="状态" rules={[{ required: true }]} style={{ width: 140 }}>
              <Select
                options={[
                  { value: 'ENABLED', label: '启用' },
                  { value: 'DISABLED', label: '停用' },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="vrid"
              label="VRID（1~255）"
              rules={[{ required: true, message: '请输入 VRID' }]}
              style={{ width: 150 }}
            >
              <InputNumber min={1} max={255} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="iface"
              label="VIP 承载网卡"
              rules={[
                { required: true, message: '请输入或选择网卡名' },
                {
                  validator: (_, value: string) => {
                    const name = (value ?? '').trim()
                    if (!name) return Promise.resolve()
                    if (!IF_NAME_RE.test(name)) {
                      return Promise.reject(new Error('接口名格式非法（1~15 位字母数字及 ._-）'))
                    }
                    const bridge = bridgedPortMap.get(name)
                    if (bridge) {
                      return Promise.reject(
                        new Error(`接口 ${name} 为网桥 ${bridge} 成员口，不得作为 VIP 承载网卡`),
                      )
                    }
                    return Promise.resolve()
                  },
                },
              ]}
              extra={
                bridgedPortMap.size > 0
                  ? `已排除网桥成员口（${Array.from(bridgedPortMap.keys()).join('、')}）；多节点网卡名不同时支持手动输入。`
                  : '可从非桥接网口中选择，多节点网卡名不同时支持手动输入（不得为网桥成员口）。'
              }
              style={{ width: 240 }}
            >
              <AutoComplete
                options={ifaceOptions}
                filterOption={(inputValue, option) =>
                  String(option?.value ?? '')
                    .toLowerCase()
                    .includes(inputValue.trim().toLowerCase())
                }
              >
                <Input placeholder="如 eth0" />
              </AutoComplete>
            </Form.Item>
          </Space>
          {bridgedConflict && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              message={`接口「${watchedIface?.trim()}」已分配给网桥「${bridgedConflict}」，不能作为 VIP 承载网卡，请选择非桥接网口。`}
            />
          )}
          <Form.Item
            name="vips"
            label="虚拟 IP（IPv4 CIDR，可多个）"
            rules={[
              { required: true, message: '至少 1 个 VIP' },
              {
                validator: (_, value?: string[]) => {
                  const list = (value ?? []).map((s) => s.trim()).filter(Boolean)
                  if (list.length === 0) return Promise.reject(new Error('至少 1 个 VIP'))
                  if (list.length > 8) return Promise.reject(new Error('VIP 数量不能超过 8 个'))
                  const bad = list.find((item) => !isIPv4CIDR(item))
                  if (bad) {
                    return Promise.reject(
                      new Error(`VIP「${bad}」格式非法，需 IPv4 CIDR（如 192.168.31.100/24）`),
                    )
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Select
              mode="tags"
              placeholder="如 192.168.31.100/24，回车添加"
              open={false}
              suffixIcon={null}
            />
          </Form.Item>
          <Form.Item
            name="track_interfaces"
            label="关联跟踪接口（Keepalived track_interface，可选）"
            extra="任一跟踪接口链路断开时将触发 Keepalived 切入 FAULT 释放 VIP；透明桥接模式推荐选择网桥成员口。"
            rules={[
              {
                validator: (_, value?: string[]) => {
                  const list = (value ?? []).map((s) => s.trim()).filter(Boolean)
                  if (list.length > 16) {
                    return Promise.reject(new Error('跟踪接口数量不能超过 16 个'))
                  }
                  const hostIface = (watchedIface ?? '').trim()
                  for (const tif of list) {
                    if (!IF_NAME_RE.test(tif)) {
                      return Promise.reject(new Error(`跟踪接口「${tif}」名称格式非法`))
                    }
                    if (hostIface && tif === hostIface) {
                      return Promise.reject(
                        new Error(`跟踪接口不得与 VIP 承载网卡「${hostIface}」相同`),
                      )
                    }
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Select
              mode="tags"
              placeholder="选择网桥成员口或输入接口名后回车添加"
              options={trackInterfaceOptions}
              aria-label="关联跟踪接口"
            />
          </Form.Item>
          <Space size={16} wrap>
            <Form.Item
              name="advert_int_ms"
              label="通告间隔（ms，整秒）"
              extra="1000~10000ms，步进 1000ms"
              rules={[
                { required: true, message: '请输入通告间隔' },
                {
                  validator: (_, value?: number) => {
                    if (value === undefined || value === null) return Promise.resolve()
                    if (value < 1000 || value > 10000 || value % 1000 !== 0) {
                      return Promise.reject(new Error('需为 1000~10000ms 且为 1000 的整秒倍数'))
                    }
                    return Promise.resolve()
                  },
                },
              ]}
              style={{ width: 200 }}
            >
              <InputNumber min={1000} max={10000} step={1000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="preempt" label="允许抢占" valuePropName="checked">
              <Switch aria-label="允许抢占" />
            </Form.Item>
            <Form.Item name="unicast" label="单播 VRRP" valuePropName="checked">
              <Switch aria-label="单播 VRRP" />
            </Form.Item>
          </Space>
          <Form.Item
            shouldUpdate={(a: HaFormValues, b: HaFormValues) => a.unicast !== b.unicast}
            noStyle
          >
            {({ getFieldValue }) =>
              getFieldValue('unicast') ? (
                <Form.Item
                  name="unicast_peers"
                  label="单播对端地址"
                  rules={[{ required: true, message: '单播模式需提供对端地址' }]}
                >
                  <Select
                    mode="tags"
                    placeholder="如 192.168.31.62，回车添加"
                    open={false}
                    suffixIcon={null}
                  />
                </Form.Item>
              ) : null
            }
          </Form.Item>
          <Form.Item
            name="auth_pass"
            label={
              editing
                ? 'VRRP 认证串（留空表示保留现有认证串；1~8 位安全字符）'
                : 'VRRP 认证串（可选，1~8 位安全字符）'
            }
            extra="仅允许字母、数字及 . _ : @ + -，不支持空格与特殊语法符号。"
            rules={[
              {
                validator: (_, value?: string) => {
                  if (watchedClearAuthPass || !value) return Promise.resolve()
                  if (value.length > 8) {
                    return Promise.reject(new Error('VRRPv2 上限 8 字符'))
                  }
                  if (!AUTH_PASS_RE.test(value)) {
                    return Promise.reject(
                      new Error('仅允许 1~8 位字母、数字及 . _ : @ + -'),
                    )
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Input.Password
              disabled={Boolean(watchedClearAuthPass)}
              placeholder={editing?.has_auth_pass ? '已配置（留空不变更）' : '可选'}
              autoComplete="new-password"
            />
          </Form.Item>
          {editing?.has_auth_pass && (
            <Form.Item name="clear_auth_pass" valuePropName="checked" style={{ marginTop: -8 }}>
              <Checkbox
                onChange={(e) => {
                  if (e.target.checked) {
                    form.setFieldValue('auth_pass', undefined)
                  }
                }}
              >
                清除已有 VRRP 认证串
              </Checkbox>
            </Form.Item>
          )}
          <Typography.Text strong>
            成员（恰 2 台已登记网关节点，优先级高者倾向成为主节点）
          </Typography.Text>
          <Space size={16} wrap style={{ marginTop: 8 }}>
            {[0, 1].map((i) => (
              <Space key={i}>
                <Form.Item
                  name={['members', i, 'node_id']}
                  rules={[{ required: true, message: '选择节点' }]}
                  style={{ width: 220, marginBottom: 0 }}
                >
                  <Select
                    placeholder={`节点 ${i + 1}`}
                    options={nodeOptions}
                    loading={nodesQuery.isLoading}
                    aria-label={`成员节点${i + 1}`}
                  />
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
