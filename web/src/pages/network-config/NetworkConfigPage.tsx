import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Card,
  Input,
  InputNumber,
  Popover,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DeleteOutlined, PlusOutlined, ReloadOutlined, SaveOutlined, SettingOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { networkConfigApi } from '../../api/networkConfig'
import { nodeInterfacesApi } from '../../api/nodeInterfaces'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import TableRefreshControl from '../../components/TableRefreshControl'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { isValidIPv4 } from '../../utils/stage5'
import type {
  NetworkBridgeConfig,
  NetworkBridgeStatus,
  NetworkDesiredConfig,
  NetworkLinkPairConfig,
  NetworkLinkPairStatus,
  NetworkRouteConfig,
  NetworkRouteStatus,
} from '../../types'

/** 介质类型展示：TP 电口 / FIBRE 光口 / UNKNOWN 未知 */
const MEDIA_TYPE_META: Record<string, { label: string; color?: string }> = {
  TP: { label: '电口', color: 'cyan' },
  FIBRE: { label: '光口', color: 'purple' },
  UNKNOWN: { label: '未知' },
}

/** 执行状态展示（边车 network-status.json 的 state 取值） */
const STATE_META: Record<string, { label: string; color?: string }> = {
  ok: { label: '成功', color: 'green' },
  error: { label: '失败', color: 'red' },
  skipped: { label: '跳过' },
}

/** 端口联动状态机展示（netmgrd link_pairs[].state 取值） */
const LINK_PAIR_STATE_META: Record<string, { label: string; color?: string }> = {
  BOTH_UP: { label: '正常', color: 'green' },
  PROPAGATED_DOWN: { label: '已联动断开', color: 'orange' },
  SUPPRESSED: { label: '已抑制', color: 'red' },
}

/** 透明串接牵引运行状态展示（netmgrd transparent.state 取值） */
const TRANSPARENT_STATE_META: Record<string, { label: string; color?: string }> = {
  ACTIVE: { label: '牵引生效', color: 'green' },
  INACTIVE: { label: '未启用' },
  DEGRADED: { label: '已降级', color: 'red' },
}

/** 端口联动参数缺省值（与服务端/netmgrd 一致，开启时预填） */
const DEFAULT_LINK_PAIR: NetworkLinkPairConfig = {
  enabled: true,
  hold_down_ms: 1000,
  hold_up_ms: 5000,
  max_flaps_per_hour: 20,
}

/** 网桥名校验：与后端 netconfig.go 一致，仅允许 br0 ~ br99 */
const BRIDGE_NAME_PATTERN = /^br\d{1,2}$/

/** 严格 IPv4 CIDR 校验（与后端 netconfig.go net.ParseCIDR + To4 一致，拒绝 IPv6） */
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

/** 取最小未使用的 br0~br99 编号作为新建网桥的建议名 */
function suggestBridgeName(bridges: NetworkBridgeConfig[]): string {
  const used = new Set(bridges.map((b) => b.name))
  for (let i = 0; i <= 99; i++) {
    const name = `br${i}`
    if (!used.has(name)) return name
  }
  return ''
}

/** 服务端 desired 允许缺省/null 字段，本地统一归一化为完整结构 */
function normalizeDesired(d?: Partial<NetworkDesiredConfig> | null): NetworkDesiredConfig {
  return {
    bridges: d?.bridges ?? [],
    ip_forward: d?.ip_forward ?? false,
    routes: d?.routes ?? [],
  }
}

function stateTag(state: string | undefined) {
  const meta = (state ? STATE_META[state] : undefined) ?? { label: state || '未知' }
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 执行信息列：失败时以红色 Alert 展示原因，其余直接展示文本 */
function statusMessage(record: { state: string; message?: string }) {
  if (record.state === 'error' && record.message) {
    return <Alert type="error" showIcon message={record.message} />
  }
  return record.message || '-'
}

/** 网络配置：节点网桥与路由牵引的期望配置编辑、全量保存与执行状态展示 */
export default function NetworkConfigPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')

  const interfacesQuery = useQuery({
    queryKey: ['node-interfaces'],
    queryFn: () => nodeInterfacesApi.list(),
  })

  const nodes = useMemo(() => interfacesQuery.data?.nodes ?? [], [interfacesQuery.data])
  const [activeNode, setActiveNode] = useState<string>()
  const currentNode = activeNode ?? nodes[0]?.node_name ?? ''

  const configQuery = useQuery({
    queryKey: ['network-config', currentNode],
    queryFn: () => networkConfigApi.get(currentNode),
    enabled: currentNode !== '',
  })

  const serverDesired = useMemo(() => normalizeDesired(configQuery.data?.desired), [configQuery.data])
  const status = configQuery.data?.status ?? null
  // 服务端返回本网关默认节点名；缺省时回落首个上报节点（兼容旧版接口）
  const defaultNode = configQuery.data?.default_node?.trim() || nodes[0]?.node_name || ''
  const isNonDefaultNode = Boolean(currentNode && defaultNode && currentNode !== defaultNode)
  const remoteEditable = configQuery.data?.remote_editable === true
  const isReadOnlyRemoteNode = isNonDefaultNode && !remoteEditable
  const canEditCurrentNode = canUpdate && !isReadOnlyRemoteNode
  const hasSuppressedLinkPair = useMemo(
    () => (status?.link_pairs ?? []).some((lp) => lp.state === 'SUPPRESSED'),
    [status],
  )

  // 本地未保存的期望配置修改（仅跟踪当前节点；保存成功或放弃后清空）
  const [edit, setEdit] = useState<{ nodeName: string; desired: NetworkDesiredConfig } | null>(null)
  const desired = edit && edit.nodeName === currentNode ? edit.desired : serverDesired
  const dirty = edit != null && edit.nodeName === currentNode
  const updateDesired = (next: NetworkDesiredConfig) => {
    if (!canEditCurrentNode) return
    setEdit({ nodeName: currentNode, desired: next })
  }

  // 新建网桥表单（bridgeName 为 null 表示未手动输入，展示自动建议名）
  const [bridgeName, setBridgeName] = useState<string | null>(null)
  const [bridgePorts, setBridgePorts] = useState<string[]>([])
  // 新建静态路由表单
  const [routeDst, setRouteDst] = useState('')
  const [routeVia, setRouteVia] = useState('')

  // 双击行查看详情（5 张表共用一个只读详情抽屉）
  const [detailRecord, setDetailRecord] = useState<
    | NetworkBridgeConfig
    | NetworkRouteConfig
    | NetworkBridgeStatus
    | NetworkRouteStatus
    | NetworkLinkPairStatus
    | null
  >(null)

  /** 已分配给现有网桥的成员口映射（ifname -> 所属网桥名） */
  const usedBridgePorts = useMemo(() => {
    const map = new Map<string, string>()
    for (const b of desired.bridges) {
      for (const p of b.ports) {
        map.set(p, b.name)
      }
    }
    return map
  }, [desired.bridges])

  /** 可选成员口：该节点在线（present）、非管理口且非镜像口；已加入其他网桥的端口禁用并标注 */
  const portOptions = useMemo(() => {
    const node = nodes.find((n) => n.node_name === currentNode)
    return (node?.interfaces ?? [])
      .filter((it) => it.present && it.role !== 'MANAGEMENT' && it.role !== 'MIRROR')
      .map((it) => {
        const meta = MEDIA_TYPE_META[it.media_type] ?? MEDIA_TYPE_META.UNKNOWN
        const usedBy = usedBridgePorts.get(it.ifname)
        return {
          value: it.ifname,
          label: usedBy
            ? `${it.ifname}（${meta.label} · 已用于 ${usedBy}）`
            : `${it.ifname}（${meta.label}）`,
          disabled: Boolean(usedBy),
        }
      })
  }, [nodes, currentNode, usedBridgePorts])

  const suggestedBridgeName = suggestBridgeName(desired.bridges)

  const addBridge = () => {
    if (!canEditCurrentNode) return
    const name = (bridgeName ?? suggestedBridgeName).trim()
    if (!BRIDGE_NAME_PATTERN.test(name)) {
      message.error('网桥名称仅允许 br0 ~ br99（如 br0、br1）')
      return
    }
    if (desired.bridges.some((b) => b.name === name)) {
      message.error(`网桥 ${name} 已存在`)
      return
    }
    if (bridgePorts.length < 2) {
      message.error('成员口至少选择 2 个')
      return
    }
    const conflictPort = bridgePorts.find((p) => usedBridgePorts.has(p))
    if (conflictPort) {
      message.error(`接口 ${conflictPort} 已分配给网桥 ${usedBridgePorts.get(conflictPort)}，不可重复加入`)
      return
    }
    updateDesired({ ...desired, bridges: [...desired.bridges, { name, ports: [...bridgePorts] }] })
    setBridgeName(null)
    setBridgePorts([])
  }

  const removeBridge = (name: string) => {
    if (!canEditCurrentNode) return
    updateDesired({ ...desired, bridges: desired.bridges.filter((b) => b.name !== name) })
  }

  /** 开启/关闭/调整指定网桥的端口联动配置 */
  const setBridgeLinkPair = (name: string, lp: NetworkLinkPairConfig | null) => {
    if (!canEditCurrentNode) return
    updateDesired({
      ...desired,
      bridges: desired.bridges.map((b) => (b.name === name ? { ...b, link_pair: lp } : b)),
    })
  }

  const addRoute = () => {
    if (!canEditCurrentNode) return
    const dst = routeDst.trim()
    const via = routeVia.trim()
    if (!isIPv4CIDR(dst)) {
      message.error('目的网段必须为合法 IPv4 CIDR（仅支持 IPv4，如 10.10.0.0/16）')
      return
    }
    if (!isValidIPv4(via)) {
      message.error('下一跳必须为合法 IPv4 地址（仅支持 IPv4，不支持 IPv6/域名/端口）')
      return
    }
    if (desired.routes.some((r) => r.dst === dst)) {
      message.error(`目的网段 ${dst} 的路由已存在`)
      return
    }
    updateDesired({ ...desired, routes: [...desired.routes, { dst, via }] })
    setRouteDst('')
    setRouteVia('')
  }

  const removeRoute = (dst: string) => {
    if (!canEditCurrentNode) return
    updateDesired({ ...desired, routes: desired.routes.filter((r) => r.dst !== dst) })
  }

  const saveMutation = useMutation({
    mutationFn: () => networkConfigApi.save(desired, currentNode),
    onSuccess: () => {
      message.success(
        isNonDefaultNode && remoteEditable
          ? `网络配置已保存并下发至远端节点「${currentNode}」`
          : '网络配置已保存',
      )
      setEdit(null)
      void queryClient.invalidateQueries({ queryKey: ['network-config'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '保存网络配置失败')
    },
  })

  /** 保存前二次确认（高危：保存即下发网关节点执行，错误配置可致流量中断） */
  const confirmSave = () => {
    if (!canEditCurrentNode) return
    const isResetSuppressed = !dirty && hasSuppressedLinkPair
    const targetDesc =
      isNonDefaultNode && remoteEditable
        ? `将通过节点协同代理（hasyncd）下发到远端节点「${currentNode}」立即执行`
        : `下发到节点「${currentNode}」立即执行`
    modal.confirm({
      title: '高风险操作确认',
      content: isResetSuppressed
        ? `当前存在处于抑制态（SUPPRESSED）的端口联动网桥，重新保存将刷新配置时间戳并${targetDesc}（网桥 ${desired.bridges.length} 个、静态路由 ${desired.routes.length} 条、内核三层转发${desired.ip_forward ? '开启' : '关闭'}），以复位端口联动抑制态。确定重新下发吗？`
        : `保存将把当前期望配置（网桥 ${desired.bridges.length} 个、静态路由 ${desired.routes.length} 条、内核三层转发${desired.ip_forward ? '开启' : '关闭'}）${targetDesc}，错误配置可能导致业务流量中断。确定保存吗？`,
      okText: '确认保存',
      cancelText: '取消',
      okButtonProps: { danger: true },
      onOk: () => saveMutation.mutate(),
    })
  }

  /** 有未保存修改时切换节点需确认（确认后丢弃本地修改与表单内容） */
  const switchNode = (key: string) => {
    if (key === currentNode) return
    const doSwitch = () => {
      setEdit(null)
      setBridgeName(null)
      setBridgePorts([])
      setRouteDst('')
      setRouteVia('')
      setActiveNode(key)
    }
    if (!dirty) {
      doSwitch()
      return
    }
    modal.confirm({
      title: '放弃未保存的修改？',
      content: '当前节点有未保存的网络配置修改，切换节点将丢弃这些修改。',
      okText: '放弃修改',
      cancelText: '继续编辑',
      okButtonProps: { danger: true },
      onOk: doSwitch,
    })
  }

  const bridgeColumns: ColumnsType<NetworkBridgeConfig> = [
    {
      title: '网桥名称',
      dataIndex: 'name',
      width: 160,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '成员口',
      dataIndex: 'ports',
      render: (ports: string[]) => (
        <Space size={4} wrap>
          {ports.map((p) => (
            <Tag key={p}>{p}</Tag>
          ))}
        </Space>
      ),
    },
    {
      title: '端口联动',
      key: 'link_pair',
      width: 300,
      render: (_, record) => {
        const lp = record.link_pair
        const enabled = lp?.enabled === true
        const updateParam = (patch: Partial<NetworkLinkPairConfig>) => {
          if (lp) setBridgeLinkPair(record.name, { ...lp, ...patch })
        }
        return (
          <Space size={8} wrap>
            <Switch
              size="small"
              checked={enabled}
              disabled={!canEditCurrentNode || (!enabled && record.ports.length !== 2)}
              onChange={(v) =>
                setBridgeLinkPair(record.name, v ? { ...DEFAULT_LINK_PAIR } : null)
              }
              aria-label={`端口联动-${record.name}`}
            />
            {enabled && lp ? (
              <Popover
                trigger="click"
                title="联动参数"
                content={
                  <Space direction="vertical" size={8} style={{ width: 260 }}>
                    <Space>
                      <Typography.Text style={{ width: 140 }}>故障判定（ms）</Typography.Text>
                      <InputNumber
                        size="small"
                        min={200}
                        max={10000}
                        step={100}
                        disabled={!canEditCurrentNode}
                        value={lp.hold_down_ms}
                        onChange={(v) => updateParam({ hold_down_ms: v ?? 1000 })}
                        aria-label={`故障判定-${record.name}`}
                      />
                    </Space>
                    <Space>
                      <Typography.Text style={{ width: 140 }}>恢复判定（ms）</Typography.Text>
                      <InputNumber
                        size="small"
                        min={1000}
                        max={60000}
                        step={500}
                        disabled={!canEditCurrentNode}
                        value={lp.hold_up_ms}
                        onChange={(v) => updateParam({ hold_up_ms: v ?? 5000 })}
                        aria-label={`恢复判定-${record.name}`}
                      />
                    </Space>
                    <Space>
                      <Typography.Text style={{ width: 140 }}>每小时联动上限</Typography.Text>
                      <InputNumber
                        size="small"
                        min={1}
                        max={200}
                        disabled={!canEditCurrentNode}
                        value={lp.max_flaps_per_hour}
                        onChange={(v) => updateParam({ max_flaps_per_hour: v ?? 20 })}
                        aria-label={`每小时联动上限-${record.name}`}
                      />
                    </Space>
                  </Space>
                }
              >
                <Button size="small" type="link" icon={<SettingOutlined />} style={{ padding: 0 }}>
                  {`${lp.hold_down_ms}ms / ${lp.hold_up_ms}ms / ${lp.max_flaps_per_hour}次/h`}
                </Button>
              </Popover>
            ) : (
              !enabled &&
              record.ports.length !== 2 && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  需恰好 2 个成员口
                </Typography.Text>
              )
            )}
          </Space>
        )
      },
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          danger
          icon={<DeleteOutlined />}
          aria-label={`删除网桥-${record.name}`}
          disabled={!canEditCurrentNode}
          onClick={() => removeBridge(record.name)}
        />
      ),
    },
  ]

  const routeColumns: ColumnsType<NetworkRouteConfig> = [
    {
      title: '目的网段',
      dataIndex: 'dst',
      width: 200,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '下一跳',
      dataIndex: 'via',
      width: 180,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '操作',
      key: 'action',
      width: 90,
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          danger
          icon={<DeleteOutlined />}
          aria-label={`删除路由-${record.dst}`}
          disabled={!canEditCurrentNode}
          onClick={() => removeRoute(record.dst)}
        />
      ),
    },
  ]

  const bridgeStatusColumns: ColumnsType<NetworkBridgeStatus> = [
    { title: '网桥名称', dataIndex: 'name', width: 160 },
    { title: '状态', dataIndex: 'state', width: 100, render: (v: string) => stateTag(v) },
    { title: '信息', dataIndex: 'message', render: (_, record) => statusMessage(record) },
  ]

  const routeStatusColumns: ColumnsType<NetworkRouteStatus> = [
    { title: '目的网段', dataIndex: 'dst', width: 200, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '下一跳', dataIndex: 'via', width: 180, render: (v?: string) => v || '-' },
    { title: '状态', dataIndex: 'state', width: 100, render: (v: string) => stateTag(v) },
    { title: '信息', dataIndex: 'message', render: (_, record) => statusMessage(record) },
  ]

  const linkPairStatusColumns: ColumnsType<NetworkLinkPairStatus> = [
    { title: '网桥', dataIndex: 'bridge', width: 120 },
    {
      title: '联动状态',
      dataIndex: 'state',
      width: 130,
      render: (v: string) => {
        const meta = LINK_PAIR_STATE_META[v] ?? { label: v || '未知' }
        return <Tag color={meta.color}>{meta.label}</Tag>
      },
    },
    {
      title: '故障口 / 配对口',
      key: 'ports',
      width: 180,
      render: (_, record) =>
        record.down_port
          ? `${record.down_port} / ${record.propagated_port || '-'}`
          : '-',
    },
    { title: '近 1h 联动', dataIndex: 'flap_count_hour', width: 110, render: (v?: number) => `${v ?? 0} 次` },
    {
      title: '最近事件',
      dataIndex: 'last_event_at',
      width: 170,
      render: (v?: string) => (v ? dayjs(v).format('YYYY-MM-DD HH:mm:ss') : '-'),
    },
    { title: '信息', dataIndex: 'message', render: (v?: string) => v || '-' },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card>
        <Space wrap>
          <Typography.Text>节点</Typography.Text>
          <Select
            style={{ minWidth: 220 }}
            placeholder="选择节点"
            loading={interfacesQuery.isLoading}
            value={currentNode || undefined}
            options={nodes.map((n) => ({ value: n.node_name, label: n.node_name }))}
            onChange={switchNode}
            aria-label="节点"
          />
          {dirty && <Typography.Text type="warning">有未保存的修改</Typography.Text>}
          {canUpdate && (
            <Button
              type="primary"
              icon={<SaveOutlined />}
              disabled={!canEditCurrentNode || (!dirty && !hasSuppressedLinkPair)}
              loading={saveMutation.isPending}
              onClick={confirmSave}
            >
              保存配置
            </Button>
          )}
          {canEditCurrentNode && hasSuppressedLinkPair && !dirty && (
            <Button
              icon={<ReloadOutlined />}
              loading={saveMutation.isPending}
              onClick={confirmSave}
            >
              重新下发 / 复位抑制
            </Button>
          )}
          <TableRefreshControl
            storageKey="network-config"
            loading={configQuery.isFetching || interfacesQuery.isFetching}
            onRefresh={() => Promise.all([configQuery.refetch(), interfacesQuery.refetch()])}
          />
        </Space>
        {isReadOnlyRemoteNode && (
          <Alert
            style={{ marginTop: 12 }}
            type="info"
            showIcon
            message={`当前节点「${currentNode}」仅支持只读查看`}
            description={`该远端节点尚未配置或启用节点协同代理（hasyncd），暂不支持远程编辑下发；请先在节点管理页配置协同代理地址并启用同步，或切换回本网关节点「${defaultNode}」。`}
            action={
              nodes.some((n) => n.node_name === defaultNode) ? (
                <Button size="small" type="link" onClick={() => switchNode(defaultNode)}>
                  切换到本网关节点
                </Button>
              ) : undefined
            }
          />
        )}
        {isNonDefaultNode && remoteEditable && (
          <Alert
            style={{ marginTop: 12 }}
            type="info"
            showIcon
            message={`正在编辑远端节点「${currentNode}」的网络配置`}
            description="该节点已启用节点协同代理（hasyncd），保存后将自动推送 network.json 至远端节点生效，并在此页汇聚展示其执行状态与端口联动明细。"
          />
        )}
        <Alert
          style={{ marginTop: 12 }}
          type="warning"
          showIcon
          message="网络配置属高危操作"
          description="网桥与路由牵引配置保存后将下发到网关节点执行，错误配置可能导致业务流量中断，请确认无误后再保存。"
        />
        {interfacesQuery.isError && (
          <div style={{ marginTop: 12 }}>
            <QueryErrorAlert error={interfacesQuery.error} message="加载网口清单失败" />
          </div>
        )}
      </Card>

      {configQuery.isError ? (
        <Card>
          <QueryErrorAlert error={configQuery.error} message="加载网络配置失败" />
        </Card>
      ) : (
        <Card title="网桥">
          <Table<NetworkBridgeConfig>
            rowKey="name"
            size="small"
            loading={configQuery.isLoading}
            columns={bridgeColumns}
            dataSource={desired.bridges}
            pagination={false}
            locale={{ emptyText: '尚未配置网桥' }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
          />
          {canUpdate && (
            <Space wrap style={{ marginTop: 16 }}>
              <Input
                style={{ width: 160 }}
                value={bridgeName ?? suggestedBridgeName}
                disabled={!canEditCurrentNode}
                onChange={(e) => setBridgeName(e.target.value)}
                aria-label="网桥名称"
              />
              <Select
                mode="multiple"
                style={{ minWidth: 280 }}
                placeholder="选择成员口（至少 2 个，不含管理口/镜像口）"
                disabled={!canEditCurrentNode}
                value={bridgePorts}
                options={portOptions}
                onChange={(values: string[]) => setBridgePorts(values)}
                aria-label="成员口"
              />
              <Button icon={<PlusOutlined />} disabled={!canEditCurrentNode} onClick={addBridge}>
                新建网桥
              </Button>
            </Space>
          )}
          <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0, fontSize: 12 }}>
            网桥用于透明串接等二层部署模式（桥名仅允许 br0 ~ br99）；成员口仅可选该节点在线、未分配为管理口或镜像口且未加入其他网桥的物理网口。
            开启端口联动后：任一成员口链路故障时将联动断开配对口，引导上游设备切换链路；
            故障恢复后配对口自动恢复连通；联动频率超限将进入抑制态（点击「重新下发 / 复位抑制」或重启 netmgrd 复位）。
          </Typography.Paragraph>
        </Card>
      )}

      {!configQuery.isError && (
        <Card title="路由牵引">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Space>
              <Typography.Text>内核三层转发</Typography.Text>
              <Switch
                checked={desired.ip_forward}
                disabled={!canEditCurrentNode}
                onChange={(v) => updateDesired({ ...desired, ip_forward: v })}
                aria-label="内核三层转发"
              />
            </Space>
            <Table<NetworkRouteConfig>
              rowKey="dst"
              size="small"
              loading={configQuery.isLoading}
              columns={routeColumns}
              dataSource={desired.routes}
              pagination={false}
              locale={{ emptyText: '尚未配置静态路由' }}
              onRow={(record) => ({
                onDoubleClick: () => setDetailRecord(record),
                style: { cursor: 'pointer' },
              })}
            />
            {canUpdate && (
              <Space wrap>
                <Input
                  style={{ width: 220 }}
                  placeholder="IPv4 目的网段 CIDR，如 10.10.0.0/16"
                  disabled={!canEditCurrentNode}
                  value={routeDst}
                  onChange={(e) => setRouteDst(e.target.value)}
                  aria-label="目的网段"
                />
                <Input
                  style={{ width: 200 }}
                  placeholder="IPv4 下一跳网关，如 172.30.10.2"
                  disabled={!canEditCurrentNode}
                  value={routeVia}
                  onChange={(e) => setRouteVia(e.target.value)}
                  aria-label="下一跳"
                />
                <Button icon={<PlusOutlined />} disabled={!canEditCurrentNode} onClick={addRoute}>
                  添加路由
                </Button>
              </Space>
            )}
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12 }}>
              路由牵引模式下，客户端/交换机将目的网段路由指向本节点，需开启内核三层转发并规划回程路由，避免三角传输（静态路由仅支持 IPv4）。
            </Typography.Paragraph>
          </Space>
        </Card>
      )}

      {!configQuery.isError && (
        <Card
          title={
            <Space size={8}>
              <span>执行状态</span>
              {isNonDefaultNode && status != null && <Tag color="blue">远端汇聚</Tag>}
            </Space>
          }
        >
          {status == null ? (
            isReadOnlyRemoteNode ? (
              <Alert
                type="info"
                showIcon
                message="非本网关节点暂不支持通过本地边车卷读取执行状态"
                description={`当前执行状态仅采集本网关节点「${defaultNode}」的本地边车状态文件（network-status.json）；如需远程汇聚状态，请先为该节点配置协同代理（hasyncd）。`}
              />
            ) : isNonDefaultNode && remoteEditable ? (
              <Alert
                type="info"
                showIcon
                message="远端节点尚未上报网络执行状态"
                description="请确认该远端节点的 hasyncd 协同代理与 netmgrd 边车正常运行，遥测周期汇聚后将在此展示。"
              />
            ) : (
              <Alert type="info" showIcon message="节点尚未上报执行状态" />
            )
          ) : (
            <Space direction="vertical" size={16} style={{ width: '100%' }}>
              <Space wrap>
                <Badge
                  status={status.ok ? 'success' : 'error'}
                  text={status.ok ? '整体执行成功' : '整体执行失败'}
                />
                {status.applied_at && (
                  <Typography.Text type="secondary">
                    应用时间：{dayjs(status.applied_at).format('YYYY-MM-DD HH:mm:ss')}
                  </Typography.Text>
                )}
              </Space>
              {status.message && (
                <Alert type={status.ok ? 'info' : 'error'} showIcon message={status.message} />
              )}
              <div>
                <Typography.Text strong>内核三层转发：</Typography.Text>
                {stateTag(status.ip_forward ?? 'skipped')}
              </div>
              {status.transparent &&
                (() => {
                  const tp = status.transparent
                  // 未启用（INACTIVE 或 enabled=false）时 netmgrd 未执行探活，不展示未探测的红色异常标签
                  const showProbeHealth = tp.state !== 'INACTIVE' && tp.enabled !== false
                  const meta = TRANSPARENT_STATE_META[tp.state] ?? {
                    label: tp.state || '未知',
                  }
                  return (
                    <Card size="small" title="透明串接牵引">
                      <Space direction="vertical" size={8} style={{ width: '100%' }}>
                        <Space wrap size={8}>
                          <Tag color={meta.color}>{meta.label}</Tag>
                          {showProbeHealth && typeof tp.redirect_active === 'boolean' && (
                            <Tag color={tp.redirect_active ? 'green' : 'default'}>
                              {tp.redirect_active ? 'REDIRECT 已生效' : 'REDIRECT 未生效'}
                            </Tag>
                          )}
                          {(tp.bridges?.length ?? 0) > 0 && (
                            <Typography.Text type="secondary">
                              网桥：{tp.bridges?.join('、')}
                            </Typography.Text>
                          )}
                          {(tp.ports?.length ?? 0) > 0 && (
                            <Typography.Text type="secondary">
                              牵引端口：{tp.ports?.join(', ')}
                            </Typography.Text>
                          )}
                          {tp.listen_port ? (
                            <Typography.Text type="secondary">
                              监听端口：{tp.listen_port}
                            </Typography.Text>
                          ) : null}
                          {showProbeHealth && typeof tp.tproxyd_healthy === 'boolean' && (
                            <Tag color={tp.tproxyd_healthy ? 'green' : 'red'}>
                              tproxyd {tp.tproxyd_healthy ? '正常' : '异常'}
                            </Tag>
                          )}
                          {showProbeHealth && typeof tp.caddy_healthy === 'boolean' && (
                            <Tag color={tp.caddy_healthy ? 'green' : 'red'}>
                              Caddy {tp.caddy_healthy ? '正常' : '异常'}
                            </Tag>
                          )}
                          {showProbeHealth && typeof tp.bridge_nf_ready === 'boolean' && (
                            <Tag color={tp.bridge_nf_ready ? 'green' : 'red'}>
                              br_netfilter {tp.bridge_nf_ready ? '就绪' : '未就绪'}
                            </Tag>
                          )}
                          {tp.updated_at && (
                            <Typography.Text type="secondary">
                              更新时间：{dayjs(tp.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                            </Typography.Text>
                          )}
                        </Space>
                        {tp.message &&
                          (tp.state === 'DEGRADED' ? (
                            <Alert type="error" showIcon message={tp.message} />
                          ) : (
                            <Typography.Text type="secondary">{tp.message}</Typography.Text>
                          ))}
                      </Space>
                    </Card>
                  )
                })()}
              <Table<NetworkBridgeStatus>
                rowKey="name"
                size="small"
                columns={bridgeStatusColumns}
                dataSource={status.bridges ?? []}
                pagination={false}
                locale={{ emptyText: '无网桥执行记录' }}
                onRow={(record) => ({
                  onDoubleClick: () => setDetailRecord(record),
                  style: { cursor: 'pointer' },
                })}
              />
              <Table<NetworkRouteStatus>
                rowKey="dst"
                size="small"
                columns={routeStatusColumns}
                dataSource={status.routes ?? []}
                pagination={false}
                locale={{ emptyText: '无路由执行记录' }}
                onRow={(record) => ({
                  onDoubleClick: () => setDetailRecord(record),
                  style: { cursor: 'pointer' },
                })}
              />
              {(status.link_pairs?.length ?? 0) > 0 && (
                <>
                  <Typography.Text strong>端口联动</Typography.Text>
                  {hasSuppressedLinkPair && (
                    <Alert
                      type="warning"
                      showIcon
                      message="存在处于抑制态（SUPPRESSED）的端口联动网桥"
                      description="可点击上方「重新下发 / 复位抑制」或「保存配置」刷新配置时间戳以复位抑制态。"
                    />
                  )}
                  <Table<NetworkLinkPairStatus>
                    rowKey="bridge"
                    size="small"
                    columns={linkPairStatusColumns}
                    dataSource={status.link_pairs ?? []}
                    pagination={false}
                    onRow={(record) => ({
                      onDoubleClick: () => setDetailRecord(record),
                      style: { cursor: 'pointer' },
                    })}
                  />
                </>
              )}
            </Space>
          )}
        </Card>
      )}
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
