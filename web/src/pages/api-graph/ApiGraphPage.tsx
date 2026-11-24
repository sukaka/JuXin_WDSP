import { useCallback, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ApiOutlined,
  BranchesOutlined,
  ClearOutlined,
  ReloadOutlined,
  SearchOutlined,
} from '@ant-design/icons'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Input,
  InputNumber,
  Radio,
  Segmented,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import {
  apiGraphApi,
  type ApiGraphEdge,
  type ApiGraphFilter,
  type ServiceRPCEdge,
  type ServiceRPCGraphFilter,
  type ServiceRPCNode,
} from '../../api/apiSecurity'
import { applicationsApi } from '../../api/applications'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'
import {
  RPC_EVIDENCE_META,
  RPC_SOURCE_STATUS_META,
  buildEndpointDisplayLabel,
  buildIdentityGraphOption,
  buildServiceRpcGraphOption,
  formatErrorRate,
  formatLatencyMs,
  prepareIdentityGraph,
  truncateMiddle,
  type GraphLayoutMode,
} from './graphUtils'

type GraphMode = 'service-rpc' | 'identity-trajectory'
type RpcRangePreset = '15m' | '1h' | '6h' | '24h'
type IdentityRangePreset = 'all' | '1h' | '24h' | '7d'

const RPC_RANGE_OPTIONS: Array<{ value: RpcRangePreset; label: string }> = [
  { value: '15m', label: '近 15 分钟' },
  { value: '1h', label: '近 1 小时' },
  { value: '6h', label: '近 6 小时' },
  { value: '24h', label: '近 24 小时' },
]

const RPC_PROTOCOL_OPTIONS = [
  { value: 'ALL', label: '全部服务间调用' },
  { value: 'RPC', label: '仅 RPC（gRPC/Dubbo/Thrift）' },
  { value: 'GRPC', label: '仅 gRPC' },
  { value: 'DUBBO', label: '仅 Dubbo' },
  { value: 'THRIFT', label: '仅 Thrift' },
  { value: 'HTTP', label: '仅服务间 HTTP' },
]

const IDENTITY_RANGE_OPTIONS: Array<{ value: IdentityRangePreset; label: string }> = [
  { value: 'all', label: '全部时间' },
  { value: '1h', label: '近 1 小时' },
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
]

const IDENTITY_MAX_NODE_OPTIONS = [
  { value: 40, label: '画布最多 40 节点' },
  { value: 60, label: '画布最多 60 节点' },
  { value: 120, label: '画布最多 120 节点' },
  { value: 0, label: '画布不限制' },
]

const STATUS_OPTIONS = Object.entries(API_ENDPOINT_STATUS_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

function computeRpcWindow(preset: RpcRangePreset): { start: string; end: string } {
  const end = dayjs()
  const start =
    preset === '15m'
      ? end.subtract(15, 'minute')
      : preset === '1h'
        ? end.subtract(1, 'hour')
        : preset === '6h'
          ? end.subtract(6, 'hour')
          : end.subtract(24, 'hour')
  return { start: start.toISOString(), end: end.toISOString() }
}

function computeIdentityWindow(preset: IdentityRangePreset): Pick<ApiGraphFilter, 'start' | 'end'> {
  if (preset === 'all') return {}
  const end = dayjs()
  const start =
    preset === '1h'
      ? end.subtract(1, 'hour')
      : preset === '24h'
        ? end.subtract(24, 'hour')
        : end.subtract(7, 'day')
  return { start: start.toISOString(), end: end.toISOString() }
}

/**
 * API 安全图谱（WDSP / 阶段8）：
 * 双视图清晰分离：
 *   1) 后端微服务真实 RPC / 服务间调用（默认主视图，汇聚 OTel 双端 Span 配对 + Sensor 数据流 + Agent gRPC）；
 *   2) 同一已识别用户身份 10 分钟窗口连续路径访问轨迹（默认自动过滤静态资源、已忽略与孤立节点，支持应用/Host 消歧与同向边合并）。
 */
export default function ApiGraphPage() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<GraphMode>('service-rpc')
  const [layout, setLayout] = useState<GraphLayoutMode>('force')

  // ---------- 模式一：后端微服务真实 RPC / 服务间调用 ----------
  const [rpcRange, setRpcRange] = useState<RpcRangePreset>('1h')
  const [rpcWindow, setRpcWindow] = useState(() => computeRpcWindow('1h'))
  const [rpcProtocol, setRpcProtocol] = useState<string>('ALL')
  const [rpcServiceInput, setRpcServiceInput] = useState('')
  const [rpcService, setRpcService] = useState('')
  const [rpcPairedOnly, setRpcPairedOnly] = useState(false)
  const [rpcIncludeExternal, setRpcIncludeExternal] = useState(false)
  const [rpcMinCalls, setRpcMinCalls] = useState<number>(0)
  const [selectedRpcEdge, setSelectedRpcEdge] = useState<ServiceRPCEdge | null>(null)
  const [selectedRpcNode, setSelectedRpcNode] = useState<ServiceRPCNode | null>(null)

  const rpcParams = useMemo<ServiceRPCGraphFilter>(() => {
    const p: ServiceRPCGraphFilter = {
      start: rpcWindow.start,
      end: rpcWindow.end,
      protocol: rpcProtocol,
      paired_only: rpcPairedOnly,
      include_external: rpcIncludeExternal,
    }
    if (rpcService.trim()) p.service = rpcService.trim()
    if (rpcMinCalls > 0) p.min_calls = rpcMinCalls
    return p
  }, [rpcWindow, rpcProtocol, rpcService, rpcPairedOnly, rpcIncludeExternal, rpcMinCalls])

  const rpcQuery = useQuery({
    queryKey: ['api-service-rpc-graph', rpcParams],
    queryFn: () => apiGraphApi.serviceRpcGraph(rpcParams),
    enabled: mode === 'service-rpc',
  })

  const rpcGraph = rpcQuery.data
  const rpcNodes = useMemo(() => rpcGraph?.nodes ?? [], [rpcGraph])
  const rpcEdges = useMemo(() => rpcGraph?.edges ?? [], [rpcGraph])
  const rpcSources = useMemo(() => rpcGraph?.sources ?? [], [rpcGraph])

  const rpcChartOption = useMemo(
    () => buildServiceRpcGraphOption(rpcNodes, rpcEdges, layout),
    [rpcNodes, rpcEdges, layout],
  )

  const handleRpcChartClick = useCallback(
    (params: unknown) => {
      const p = params as { dataType?: string; name?: string; data?: { name?: string } }
      if (p.dataType === 'edge' && p.data?.name) {
        const edge = rpcEdges.find((e) => `${e.source}->${e.target}|${e.protocol}` === p.data?.name)
        if (edge) {
          setSelectedRpcNode(null)
          setSelectedRpcEdge(edge)
        }
      } else if (p.dataType === 'node' && p.name) {
        const node = rpcNodes.find((n) => n.name === p.name)
        if (node) {
          setSelectedRpcEdge(null)
          setSelectedRpcNode(node)
        }
      }
    },
    [rpcEdges, rpcNodes],
  )

  const rpcChartEvents = useMemo(() => ({ click: handleRpcChartClick }), [handleRpcChartClick])

  // ---------- 模式二：用户身份 10 分钟连续访问轨迹 ----------
  const [idRange, setIdRange] = useState<IdentityRangePreset>('all')
  const [idWindow, setIdWindow] = useState<Pick<ApiGraphFilter, 'start' | 'end'>>({})
  const [idAppId, setIdAppId] = useState<string | undefined>()
  const [idStatus, setIdStatus] = useState<string | undefined>()
  const [idKeywordInput, setIdKeywordInput] = useState('')
  const [idKeyword, setIdKeyword] = useState('')
  const [idMinCount, setIdMinCount] = useState<number>(0)
  const [idExcludeStatic, setIdExcludeStatic] = useState(true)
  const [idOnlyConnected, setIdOnlyConnected] = useState(true)
  const [idExcludeIgnored, setIdExcludeIgnored] = useState(true)
  const [idMaxNodes, setIdMaxNodes] = useState<number>(60)
  const [detailIdentityEdge, setDetailIdentityEdge] = useState<ApiGraphEdge | null>(null)

  const appsQuery = useQuery({
    queryKey: ['applications', 'api-graph-filter-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: mode === 'identity-trajectory',
    retry: false,
  })

  const idParams = useMemo<ApiGraphFilter>(() => {
    const p: ApiGraphFilter = {
      exclude_static: idExcludeStatic,
      exclude_ignored: idExcludeIgnored,
      only_connected: idOnlyConnected,
    }
    if (idWindow.start) p.start = idWindow.start
    if (idWindow.end) p.end = idWindow.end
    if (idAppId) p.application_id = idAppId
    if (idStatus) p.status = idStatus
    if (idKeyword.trim()) p.keyword = idKeyword.trim()
    if (idMinCount > 0) p.min_count = idMinCount
    return p
  }, [
    idWindow,
    idAppId,
    idStatus,
    idKeyword,
    idMinCount,
    idExcludeStatic,
    idExcludeIgnored,
    idOnlyConnected,
  ])

  const idQuery = useQuery({
    queryKey: ['api-graph', idParams],
    queryFn: () => apiGraphApi.graph(idParams),
    enabled: mode === 'identity-trajectory',
  })

  const idNodes = useMemo(() => idQuery.data?.nodes ?? [], [idQuery.data])
  const idEdges = useMemo(() => idQuery.data?.edges ?? [], [idQuery.data])
  const idSummary = idQuery.data?.summary
  const idNodeById = useMemo(() => new Map(idNodes.map((n) => [n.id, n])), [idNodes])

  const preparedIdGraph = useMemo(
    () => prepareIdentityGraph(idNodes, idEdges, idMaxNodes),
    [idNodes, idEdges, idMaxNodes],
  )

  const idChartOption = useMemo(
    () => buildIdentityGraphOption(preparedIdGraph, layout),
    [preparedIdGraph, layout],
  )

  const handleIdentityChartClick = useCallback(
    (params: unknown) => {
      const p = params as { dataType?: string; data?: { name?: string } }
      if (p.dataType === 'edge' && p.data?.name) {
        const agg = preparedIdGraph.aggregatedEdges.find((e) => e.key === p.data?.name)
        if (agg?.edgeRows[0]) {
          setDetailIdentityEdge(agg.edgeRows[0])
        }
      }
    },
    [preparedIdGraph.aggregatedEdges],
  )

  const idChartEvents = useMemo(() => ({ click: handleIdentityChartClick }), [handleIdentityChartClick])

  const appOptions = useMemo(() => {
    const items = appsQuery.data?.items ?? []
    return items.map((app) => ({
      value: app.id,
      label: app.name || app.code || app.id,
    }))
  }, [appsQuery.data])

  // ---------- 表格列定义 ----------
  const rpcColumns: ColumnsType<ServiceRPCEdge> = [
    {
      title: '调用方服务',
      dataIndex: 'source',
      width: 180,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '被调方服务',
      dataIndex: 'target',
      width: 190,
      ellipsis: true,
      render: (v: string, rec) => (
        <Space size={4}>
          <Typography.Text code>{v}</Typography.Text>
          {rec.target_type === 'EXTERNAL' && <Tag>外部</Tag>}
        </Space>
      ),
    },
    {
      title: '协议',
      dataIndex: 'protocol',
      width: 96,
      render: (v: string, rec) => (
        <Tag color={rec.call_category === 'RPC' ? 'blue' : 'cyan'}>{v}</Tag>
      ),
    },
    {
      title: '证据口径',
      dataIndex: 'evidence_type',
      width: 136,
      render: (v: string) => {
        const meta = RPC_EVIDENCE_META[v]
        return (
          <Tooltip title={meta?.description ?? v}>
            <Tag color={meta?.color ?? 'default'}>{meta?.label ?? v}</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '代表 RPC 方法 / 接口',
      dataIndex: 'operations',
      ellipsis: true,
      render: (ops: string[]) => {
        if (!ops?.length) return <Typography.Text type="secondary">-</Typography.Text>
        return (
          <Space size={4} wrap>
            <Typography.Text code style={{ fontSize: 12 }}>
              {ops[0]}
            </Typography.Text>
            {ops.length > 1 && <Tag>+{ops.length - 1}</Tag>}
          </Space>
        )
      },
    },
    { title: '调用数', dataIndex: 'calls', width: 90 },
    {
      title: '错误率',
      dataIndex: 'error_rate',
      width: 90,
      render: (v: number) => (
        <Typography.Text type={v >= 0.05 ? 'danger' : undefined}>{formatErrorRate(v)}</Typography.Text>
      ),
    },
    {
      title: '平均 / P95',
      key: 'latency',
      width: 145,
      render: (_, rec) => `${formatLatencyMs(rec.avg_ms)} / ${formatLatencyMs(rec.p95_ms)}`,
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen_at',
      width: 160,
      render: (v?: string) => (v ? formatDateTime(v) : '-'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 72,
      fixed: 'right',
      render: (_, rec) => (
        <Button
          type="link"
          size="small"
          onClick={() => {
            setSelectedRpcNode(null)
            setSelectedRpcEdge(rec)
          }}
        >
          详情
        </Button>
      ),
    },
  ]

  const idEdgeColumns: ColumnsType<ApiGraphEdge> = [
    {
      title: '调用方身份指纹',
      dataIndex: 'caller_fingerprint',
      width: 180,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{truncateMiddle(v, 10, 6)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '前序接口（10 分钟窗内）',
      dataIndex: 'source_endpoint_id',
      ellipsis: true,
      render: (v?: string | null) => {
        if (!v) return <Tag>外部调用方</Tag>
        const node = idNodeById.get(v)
        if (!node) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
        return (
          <Typography.Text code>
            {buildEndpointDisplayLabel(node, preparedIdGraph.duplicateKeySet)}
          </Typography.Text>
        )
      },
    },
    {
      title: '后继目标接口',
      dataIndex: 'target_endpoint_id',
      ellipsis: true,
      render: (v: string) => {
        const node = idNodeById.get(v)
        if (!node) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
        return (
          <Typography.Text code>
            {buildEndpointDisplayLabel(node, preparedIdGraph.duplicateKeySet)}
          </Typography.Text>
        )
      },
    },
    { title: '连续访问次数', dataIndex: 'call_count', width: 120 },
    {
      title: '最近观测',
      dataIndex: 'last_seen_at',
      width: 165,
      render: (v?: string) => (v ? formatDateTime(v) : '-'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 72,
      fixed: 'right',
      render: (_, rec) => (
        <Button type="link" size="small" onClick={() => setDetailIdentityEdge(rec)}>
          详情
        </Button>
      ),
    },
  ]

  const handleRefresh = () => {
    if (mode === 'service-rpc') {
      setRpcWindow(computeRpcWindow(rpcRange))
    } else {
      setIdWindow(computeIdentityWindow(idRange))
      void idQuery.refetch()
    }
  }

  return (
    <Card
      title="API 安全图谱"
      extra={
        <Space wrap>
          <Segmented<GraphMode>
            value={mode}
            onChange={(v) => setMode(v)}
            options={[
              {
                value: 'service-rpc',
                label: (
                  <Space size={4}>
                    <ApiOutlined />
                    <span>后端微服务 RPC 调用</span>
                  </Space>
                ),
              },
              {
                value: 'identity-trajectory',
                label: (
                  <Space size={4}>
                    <BranchesOutlined />
                    <span>用户身份访问轨迹（10 分钟窗口）</span>
                  </Space>
                ),
              },
            ]}
          />
          <Radio.Group
            size="small"
            optionType="button"
            value={layout}
            onChange={(e) => setLayout(e.target.value as GraphLayoutMode)}
            options={[
              { value: 'force', label: '力导向' },
              { value: 'circular', label: '环形布局' },
            ]}
          />
          <Button icon={<ReloadOutlined />} size="small" onClick={handleRefresh}>
            刷新
          </Button>
        </Space>
      }
    >
      {mode === 'service-rpc' ? (
        <>
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 14 }}
            title="后端微服务真实 RPC / 服务间调用图谱"
            description={
              <Space orientation="vertical" size={6} style={{ width: '100%' }}>
                <span>
                  {rpcGraph?.note ||
                    '展示后端微服务之间的真实 RPC（gRPC / Dubbo / Thrift 等）与服务间调用链路；实线为 Client↔Server 双端确凿配对，虚线为单侧观测，红色高亮表示错误率 ≥ 5%。'}
                </span>
                {rpcSources.length > 0 && (
                  <Space size={6} wrap>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      数据源状态：
                    </Typography.Text>
                    {rpcSources.map((s) => {
                      const meta = RPC_SOURCE_STATUS_META[s.status] ?? { label: s.status, color: 'default' }
                      return (
                        <Tooltip key={s.source} title={s.message || `${s.label}：${meta.label}`}>
                          <Tag color={meta.color}>
                            {s.label}：{meta.label}
                            {s.status === 'READY' ? ` (${s.edge_count} 边)` : ''}
                          </Tag>
                        </Tooltip>
                      )
                    })}
                  </Space>
                )}
              </Space>
            }
          />

          <Space wrap style={{ marginBottom: 16 }}>
            <Radio.Group
              size="small"
              optionType="button"
              value={rpcRange}
              onChange={(e) => {
                const next = e.target.value as RpcRangePreset
                setRpcRange(next)
                setRpcWindow(computeRpcWindow(next))
              }}
              options={RPC_RANGE_OPTIONS}
            />
            <Select
              size="small"
              style={{ width: 215 }}
              value={rpcProtocol}
              onChange={setRpcProtocol}
              options={RPC_PROTOCOL_OPTIONS}
            />
            <Input
              size="small"
              allowClear
              placeholder="按微服务名筛选"
              prefix={<SearchOutlined />}
              style={{ width: 180 }}
              value={rpcServiceInput}
              onChange={(e) => {
                setRpcServiceInput(e.target.value)
                if (!e.target.value) setRpcService('')
              }}
              onPressEnter={() => setRpcService(rpcServiceInput)}
              onBlur={() => setRpcService(rpcServiceInput)}
            />
            <Space size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                最小调用数
              </Typography.Text>
              <InputNumber
                size="small"
                min={0}
                style={{ width: 78 }}
                value={rpcMinCalls}
                onChange={(v) => setRpcMinCalls(Number(v ?? 0))}
              />
            </Space>
            <Space size={6}>
              <Switch size="small" checked={rpcPairedOnly} onChange={setRpcPairedOnly} />
              <Tooltip title="仅显示 Client Span 与对端 Server Span 确凿配对的微服务调用，隐藏单视角推断边">
                <Typography.Text style={{ fontSize: 12 }}>仅双端配对</Typography.Text>
              </Tooltip>
            </Space>
            <Space size={6}>
              <Switch size="small" checked={rpcIncludeExternal} onChange={setRpcIncludeExternal} />
              <Typography.Text style={{ fontSize: 12 }}>含外部目标</Typography.Text>
            </Space>
          </Space>

          <QueryErrorAlert error={rpcQuery.error} message="加载微服务 RPC 调用图谱失败" />

          <Space size="large" wrap style={{ marginBottom: 16 }}>
            <Statistic
              title="微服务节点"
              value={rpcGraph?.summary.service_nodes ?? 0}
              loading={rpcQuery.isLoading}
            />
            <Statistic
              title="调用边数"
              value={rpcGraph?.summary.total_edges ?? 0}
              loading={rpcQuery.isLoading}
            />
            <Statistic
              title="RPC 协议边"
              value={rpcGraph?.summary.rpc_edges ?? 0}
              loading={rpcQuery.isLoading}
            />
            <Statistic
              title="双端已配对"
              value={rpcGraph?.summary.paired_edges ?? 0}
              loading={rpcQuery.isLoading}
            />
            <Statistic
              title="总调用次数"
              value={rpcGraph?.summary.total_calls ?? 0}
              loading={rpcQuery.isLoading}
            />
            <Statistic
              title="高错误率边 (≥5%)"
              value={rpcGraph?.summary.error_edges ?? 0}
              styles={(rpcGraph?.summary.error_edges ?? 0) > 0 ? { content: { color: '#cf1322' } } : undefined}
              loading={rpcQuery.isLoading}
            />
          </Space>

          <Spin spinning={rpcQuery.isLoading}>
            {rpcEdges.length > 0 ? (
              <EChart
                option={rpcChartOption}
                height={480}
                ariaLabel="后端微服务真实 RPC 调用关系图"
                events={rpcChartEvents}
              />
            ) : (
              <Empty
                style={{ padding: '44px 16px' }}
                description={
                  <Space orientation="vertical" size={6}>
                    <Typography.Text strong>
                      当前时间窗内暂未采集到后端微服务 RPC / 服务间调用链路
                    </Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 13 }}>
                      该视图仅展示来自 OTel 探针、云 API Sensor 或流量 Agent 的真实微服务间调用，不会用浏览器访问路径或模拟数据充数。
                    </Typography.Text>
                  </Space>
                }
              >
                <Space wrap>
                  <Button type="primary" size="small" onClick={() => navigate('/apm-agents')}>
                    前往 APM 探针接入
                  </Button>
                  <Button size="small" onClick={() => navigate('/traffic-agents')}>
                    前往分布式 Agent
                  </Button>
                  <Button size="small" onClick={() => setMode('identity-trajectory')}>
                    查看用户身份访问轨迹
                  </Button>
                </Space>
              </Empty>
            )}
          </Spin>

          <Typography.Title level={5} style={{ marginTop: 16 }}>
            微服务 RPC / 服务间调用边明细
          </Typography.Title>
          <SmartTable<ServiceRPCEdge>
            storageKey="api-service-rpc-graph"
            rowKey="id"
            size="small"
            loading={rpcQuery.isLoading}
            columns={rpcColumns}
            dataSource={rpcEdges}
            scroll={{ x: 1120 }}
            locale={{ emptyText: '当前筛选条件下暂无微服务调用边' }}
            onRow={(record) => ({
              onDoubleClick: () => {
                setSelectedRpcNode(null)
                setSelectedRpcEdge(record)
              },
              style: { cursor: 'pointer' },
            })}
            pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true, showTotal: (t) => `共 ${t} 条` }}
          />

          <Drawer
            open={selectedRpcEdge !== null}
            title="微服务调用边详情"
            size={540}
            onClose={() => setSelectedRpcEdge(null)}
          >
            {selectedRpcEdge && (
              <Space orientation="vertical" size={16} style={{ width: '100%' }}>
                <Descriptions column={1} bordered size="small">
                  <Descriptions.Item label="调用链路">
                    <Typography.Text code>{selectedRpcEdge.source}</Typography.Text>
                    {' → '}
                    <Typography.Text code>{selectedRpcEdge.target}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="协议 / 分类">
                    <Tag color={selectedRpcEdge.call_category === 'RPC' ? 'blue' : 'cyan'}>
                      {selectedRpcEdge.protocol}
                    </Tag>
                    <Tag>{selectedRpcEdge.call_category}</Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="证据口径">
                    <Tag color={RPC_EVIDENCE_META[selectedRpcEdge.evidence_type]?.color ?? 'default'}>
                      {RPC_EVIDENCE_META[selectedRpcEdge.evidence_type]?.label ?? selectedRpcEdge.evidence_type}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="调用量 / 错误">
                    {selectedRpcEdge.calls} 次（错误 {selectedRpcEdge.error_count} 次 · 错误率{' '}
                    {formatErrorRate(selectedRpcEdge.error_rate)}）
                  </Descriptions.Item>
                  <Descriptions.Item label="耗时统计">
                    平均 {formatLatencyMs(selectedRpcEdge.avg_ms)} · P95 {formatLatencyMs(selectedRpcEdge.p95_ms)}
                  </Descriptions.Item>
                  <Descriptions.Item label="观测时间窗">
                    {selectedRpcEdge.first_seen_at ? formatDateTime(selectedRpcEdge.first_seen_at) : '-'} ~{' '}
                    {selectedRpcEdge.last_seen_at ? formatDateTime(selectedRpcEdge.last_seen_at) : '-'}
                  </Descriptions.Item>
                </Descriptions>

                <div>
                  <Typography.Title level={5} style={{ marginTop: 0 }}>
                    观测到的 RPC 方法 / 接口（{selectedRpcEdge.operations.length}）
                  </Typography.Title>
                  {selectedRpcEdge.operations.length > 0 ? (
                    <Space size={[6, 6]} wrap>
                      {selectedRpcEdge.operations.map((op) => (
                        <Tag key={op} style={{ fontFamily: 'monospace' }}>
                          {op}
                        </Tag>
                      ))}
                    </Space>
                  ) : (
                    <Typography.Text type="secondary">无具体方法名</Typography.Text>
                  )}
                </div>

                <div>
                  <Typography.Title level={5} style={{ marginTop: 0 }}>
                    采样链路 Trace ID（{selectedRpcEdge.sample_trace_ids.length}）
                  </Typography.Title>
                  {selectedRpcEdge.sample_trace_ids.length > 0 ? (
                    <Space size={[6, 6]} wrap>
                      {selectedRpcEdge.sample_trace_ids.map((tid) => (
                        <Button
                          key={tid}
                          size="small"
                          type="link"
                          style={{ padding: 0, fontFamily: 'monospace' }}
                          onClick={() => navigate(`/apm-traces?trace_id=${encodeURIComponent(tid)}`)}
                        >
                          {tid}
                        </Button>
                      ))}
                    </Space>
                  ) : (
                    <Typography.Text type="secondary">当前数据源未携带 Trace ID</Typography.Text>
                  )}
                </div>
              </Space>
            )}
          </Drawer>

          <Drawer
            open={selectedRpcNode !== null}
            title="微服务节点详情"
            size={480}
            onClose={() => setSelectedRpcNode(null)}
          >
            {selectedRpcNode && (
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="服务名称">
                  <Typography.Text code>{selectedRpcNode.name}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label="节点类型">
                  <Tag color={selectedRpcNode.node_type === 'SERVICE' ? 'blue' : 'default'}>
                    {selectedRpcNode.node_type === 'SERVICE' ? '后端微服务' : '外部目标'}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="涉及协议">
                  {selectedRpcNode.protocols.map((p) => (
                    <Tag key={p}>{p}</Tag>
                  ))}
                </Descriptions.Item>
                <Descriptions.Item label="出站调用">
                  {selectedRpcNode.outbound_calls} 次（{selectedRpcNode.outbound_edges} 条出边）
                </Descriptions.Item>
                <Descriptions.Item label="入站调用">
                  {selectedRpcNode.inbound_calls} 次（{selectedRpcNode.inbound_edges} 条入边）
                </Descriptions.Item>
                <Descriptions.Item label="入站错误率 / 平均耗时">
                  {formatErrorRate(selectedRpcNode.error_rate)} / {formatLatencyMs(selectedRpcNode.avg_ms)}
                </Descriptions.Item>
                <Descriptions.Item label="观测方法数">{selectedRpcNode.operations_count}</Descriptions.Item>
              </Descriptions>
            )}
          </Drawer>
        </>
      ) : (
        <>
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 14 }}
            title="用户身份连续访问轨迹（10 分钟会话窗口）"
            description="本视图展示同一个已识别用户身份（非匿名 identity_fingerprint）在 10 分钟窗口内先后连续访问不同 API 路径的轨迹（并非后端微服务 RPC 调用）。画布已自动按「源→目标」合并多身份重复连线，并对同名接口附带应用/Host 消歧。"
            action={
              idSummary && idSummary.static_noise_nodes > 0 ? (
                <Button
                  size="small"
                  icon={<ClearOutlined />}
                  onClick={() => navigate('/api-endpoints')}
                >
                  去清理 {idSummary.static_noise_nodes} 个存量静态噪声
                </Button>
              ) : undefined
            }
          />

          <Space wrap style={{ marginBottom: 14 }}>
            <Radio.Group
              size="small"
              optionType="button"
              value={idRange}
              onChange={(e) => {
                const next = e.target.value as IdentityRangePreset
                setIdRange(next)
                setIdWindow(computeIdentityWindow(next))
              }}
              options={IDENTITY_RANGE_OPTIONS}
            />
            <Select
              size="small"
              allowClear
              showSearch
              optionFilterProp="label"
              placeholder="全部应用"
              style={{ width: 170 }}
              value={idAppId}
              onChange={setIdAppId}
              options={appOptions}
              loading={appsQuery.isLoading}
            />
            <Select
              size="small"
              allowClear
              placeholder="全部资产状态"
              style={{ width: 135 }}
              value={idStatus}
              onChange={setIdStatus}
              options={STATUS_OPTIONS}
            />
            <Input
              size="small"
              allowClear
              placeholder="搜索路径 / 应用 / Host"
              prefix={<SearchOutlined />}
              style={{ width: 185 }}
              value={idKeywordInput}
              onChange={(e) => {
                setIdKeywordInput(e.target.value)
                if (!e.target.value) setIdKeyword('')
              }}
              onPressEnter={() => setIdKeyword(idKeywordInput)}
              onBlur={() => setIdKeyword(idKeywordInput)}
            />
            <Space size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                最小次数
              </Typography.Text>
              <InputNumber
                size="small"
                min={0}
                style={{ width: 72 }}
                value={idMinCount}
                onChange={(v) => setIdMinCount(Number(v ?? 0))}
              />
            </Space>
            <Select
              size="small"
              style={{ width: 148 }}
              value={idMaxNodes}
              onChange={setIdMaxNodes}
              options={IDENTITY_MAX_NODE_OPTIONS}
            />
          </Space>

          <Space wrap style={{ marginBottom: 16 }}>
            <Space size={6}>
              <Switch size="small" checked={idExcludeStatic} onChange={setIdExcludeStatic} />
              <Typography.Text style={{ fontSize: 12 }}>过滤静态资源/非 API</Typography.Text>
            </Space>
            <Space size={6}>
              <Switch size="small" checked={idOnlyConnected} onChange={setIdOnlyConnected} />
              <Typography.Text style={{ fontSize: 12 }}>仅看有连线接口</Typography.Text>
            </Space>
            <Space size={6}>
              <Switch size="small" checked={idExcludeIgnored} onChange={setIdExcludeIgnored} />
              <Typography.Text style={{ fontSize: 12 }}>隐藏已忽略接口</Typography.Text>
            </Space>
            {preparedIdGraph.truncatedNodeCount > 0 && (
              <Tag color="processing">
                画布聚焦高频 Top {preparedIdGraph.visibleNodes.length} 个接口（折叠其余 {preparedIdGraph.truncatedNodeCount} 个）
              </Tag>
            )}
          </Space>

          <QueryErrorAlert error={idQuery.error} message="加载身份访问轨迹图谱失败" />

          <Space size="large" wrap style={{ marginBottom: 16 }}>
            <Statistic
              title="展示接口节点"
              value={preparedIdGraph.visibleNodes.length}
              suffix={idSummary ? `/ 共 ${idSummary.total_nodes}` : undefined}
              loading={idQuery.isLoading}
            />
            <Statistic
              title="合并轨迹边"
              value={preparedIdGraph.aggregatedEdges.length}
              suffix={idEdges.length > preparedIdGraph.aggregatedEdges.length ? `（原始 ${idEdges.length}）` : undefined}
              loading={idQuery.isLoading}
            />
            <Statistic
              title="涉及已识别身份"
              value={preparedIdGraph.distinctCallers}
              loading={idQuery.isLoading}
            />
            <Statistic
              title="已识别静态噪声"
              value={idSummary?.static_noise_nodes ?? 0}
              loading={idQuery.isLoading}
            />
            <Statistic
              title="无连线孤立接口"
              value={idSummary?.isolated_nodes ?? 0}
              loading={idQuery.isLoading}
            />
          </Space>

          <Spin spinning={idQuery.isLoading}>
            {preparedIdGraph.visibleNodes.length > 0 ? (
              <EChart
                option={idChartOption}
                height={480}
                ariaLabel="用户身份 10 分钟连续访问轨迹图"
                events={idChartEvents}
              />
            ) : (
              <Empty
                style={{ padding: '44px 16px' }}
                description="当前筛选条件下暂无符合条件的 API 连续访问轨迹（可尝试关闭「仅看有连线接口」或放宽时间窗）"
              />
            )}
          </Spin>

          <Typography.Title level={5} style={{ marginTop: 16 }}>
            身份访问轨迹明细（按身份指纹）
          </Typography.Title>
          <SmartTable<ApiGraphEdge>
            storageKey="api-graph"
            rowKey="id"
            size="small"
            loading={idQuery.isLoading}
            columns={idEdgeColumns}
            dataSource={idEdges}
            scroll={{ x: 960 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailIdentityEdge(record),
              style: { cursor: 'pointer' },
            })}
            pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true, showTotal: (t) => `共 ${t} 条` }}
          />
          <RecordDetailDrawer
            open={detailIdentityEdge !== null}
            title="调用边详情"
            record={detailIdentityEdge as Record<string, unknown> | null}
            onClose={() => setDetailIdentityEdge(null)}
          />
        </>
      )}
    </Card>
  )
}
