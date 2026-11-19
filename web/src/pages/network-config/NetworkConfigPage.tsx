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
import { DeleteOutlined, PlusOutlined, SaveOutlined, SettingOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { networkConfigApi } from '../../api/networkConfig'
import { nodeInterfacesApi } from '../../api/nodeInterfaces'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import TableRefreshControl from '../../components/TableRefreshControl'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { isCIDRAddress, isValidIPLiteral } from '../../utils/stage5'
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

/** 端口联动参数缺省值（与服务端/netmgrd 一致，开启时预填） */
const DEFAULT_LINK_PAIR: NetworkLinkPairConfig = {
  enabled: true,
  hold_down_ms: 1000,
  hold_up_ms: 5000,
  max_flaps_per_hour: 20,
}

/** 网桥名校验：Linux 接口名（字母数字/下划线/连字符，最长 15 字符） */
const BRIDGE_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,15}$/

/** 取最小未使用的 brN 编号作为新建网桥的建议名 */
function suggestBridgeName(bridges: NetworkBridgeConfig[]): string {
  const used = new Set(bridges.map((b) => b.name))
  for (let i = 0; ; i++) {
    const name = `br${i}`
    if (!used.has(name)) return name
  }
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

  // 本地未保存的期望配置修改（仅跟踪当前节点；保存成功或放弃后清空）
  const [edit, setEdit] = useState<{ nodeName: string; desired: NetworkDesiredConfig } | null>(null)
  const desired = edit && edit.nodeName === currentNode ? edit.desired : serverDesired
  const dirty = edit != null && edit.nodeName === currentNode
  const updateDesired = (next: NetworkDesiredConfig) => setEdit({ nodeName: currentNode, desired: next })

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

  /** 可选成员口：该节点在线（present）且非管理口，标注介质类型 */
  const portOptions = useMemo(() => {
    const node = nodes.find((n) => n.node_name === currentNode)
    return (node?.interfaces ?? [])
      .filter((it) => it.present && it.role !== 'MANAGEMENT')
      .map((it) => {
        const meta = MEDIA_TYPE_META[it.media_type] ?? MEDIA_TYPE_META.UNKNOWN
        return { value: it.ifname, label: `${it.ifname}（${meta.label}）` }
      })
  }, [nodes, currentNode])

  const suggestedBridgeName = suggestBridgeName(desired.bridges)

  const addBridge = () => {
    const name = (bridgeName ?? suggestedBridgeName).trim()
    if (!BRIDGE_NAME_PATTERN.test(name)) {
      message.error('网桥名称仅允许字母、数字、下划线与连字符，且不超过 15 字符')
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
    updateDesired({ ...desired, bridges: [...desired.bridges, { name, ports: [...bridgePorts] }] })
    setBridgeName(null)
    setBridgePorts([])
  }

  const removeBridge = (name: string) => {
    updateDesired({ ...desired, bridges: desired.bridges.filter((b) => b.name !== name) })
  }

  /** 开启/关闭/调整指定网桥的端口联动配置 */
  const setBridgeLinkPair = (name: string, lp: NetworkLinkPairConfig | null) => {
    updateDesired({
      ...desired,
      bridges: desired.bridges.map((b) => (b.name === name ? { ...b, link_pair: lp } : b)),
    })
  }

  const addRoute = () => {
    const dst = routeDst.trim()
    const via = routeVia.trim()
    if (!isCIDRAddress(dst)) {
      message.error('目的网段必须为合法 CIDR（如 10.10.0.0/16）')
      return
    }
    if (!isValidIPLiteral(via)) {
      message.error('下一跳必须为合法 IP 地址（不支持域名/端口/协议前缀）')
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
    updateDesired({ ...desired, routes: desired.routes.filter((r) => r.dst !== dst) })
  }

  const saveMutation = useMutation({
    mutationFn: () => networkConfigApi.save(desired, currentNode),
    onSuccess: (data) => {
      message.success(data.message || '网络配置已保存')
      setEdit(null)
      void queryClient.invalidateQueries({ queryKey: ['network-config'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '保存网络配置失败')
    },
  })

  /** 保存前二次确认（高危：保存即下发网关节点执行，错误配置可致流量中断） */
  const confirmSave = () => {
    modal.confirm({
      title: '高风险操作确认',
      content: `保存将把当前期望配置（网桥 ${desired.bridges.length} 个、静态路由 ${desired.routes.length} 条、内核三层转发${desired.ip_forward ? '开启' : '关闭'}）下发到节点「${currentNode}」立即执行，错误配置可能导致业务流量中断。确定保存吗？`,
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
              disabled={!canUpdate || (!enabled && record.ports.length !== 2)}
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
          disabled={!canUpdate}
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
          disabled={!canUpdate}
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
              disabled={!dirty}
              loading={saveMutation.isPending}
              onClick={confirmSave}
            >
              保存配置
            </Button>
          )}
          <TableRefreshControl
            storageKey="network-config"
            loading={configQuery.isFetching || interfacesQuery.isFetching}
            onRefresh={() => Promise.all([configQuery.refetch(), interfacesQuery.refetch()])}
          />
        </Space>
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
                onChange={(e) => setBridgeName(e.target.value)}
                aria-label="网桥名称"
              />
              <Select
                mode="multiple"
                style={{ minWidth: 280 }}
                placeholder="选择成员口（至少 2 个，不含管理口）"
                value={bridgePorts}
                options={portOptions}
                onChange={(values: string[]) => setBridgePorts(values)}
                aria-label="成员口"
              />
              <Button icon={<PlusOutlined />} onClick={addBridge}>
                新建网桥
              </Button>
            </Space>
          )}
          <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0, fontSize: 12 }}>
            网桥用于透明串接等二层部署模式；成员口仅可选该节点在线且未分配为管理口的物理网口。
            开启端口联动后：任一成员口链路故障时将联动断开配对口，引导上游设备切换链路；
            故障恢复后配对口自动恢复连通；联动频率超限将进入抑制态（保存一次配置或重启 netmgrd 复位）。
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
                disabled={!canUpdate}
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
                  placeholder="目的网段 CIDR，如 10.10.0.0/16"
                  value={routeDst}
                  onChange={(e) => setRouteDst(e.target.value)}
                  aria-label="目的网段"
                />
                <Input
                  style={{ width: 200 }}
                  placeholder="下一跳网关，如 172.30.10.2"
                  value={routeVia}
                  onChange={(e) => setRouteVia(e.target.value)}
                  aria-label="下一跳"
                />
                <Button icon={<PlusOutlined />} onClick={addRoute}>
                  添加路由
                </Button>
              </Space>
            )}
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0, fontSize: 12 }}>
              路由牵引模式下，客户端/交换机将目的网段路由指向本节点，需开启内核三层转发并规划回程路由，避免三角传输。
            </Typography.Paragraph>
          </Space>
        </Card>
      )}

      {!configQuery.isError && (
        <Card title="执行状态">
          {status == null ? (
            <Alert type="info" showIcon message="节点尚未上报执行状态" />
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
