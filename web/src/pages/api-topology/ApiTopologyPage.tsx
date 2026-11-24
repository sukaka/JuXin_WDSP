import { useCallback, useMemo, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import {
  AppstoreOutlined,
  BranchesOutlined,
  CaretDownOutlined,
  CaretRightOutlined,
  FolderOutlined,
  ReloadOutlined,
  RollbackOutlined,
  SearchOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons'
import {
  Button,
  Card,
  Empty,
  Input,
  InputNumber,
  Radio,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import {
  apiGraphApi,
  type ApiGraphEdge,
  type ApiGraphEdgeFilter,
} from '../../api/apiSecurity'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_ENDPOINT_STATUS_META, API_LEARNING_STATUS_META } from '../../utils/stage8'
import EndpointTopologyDrawer from './TopologyDetailDrawers'
import {
  ALL_APPS_KEY,
  ALL_PREFIX_KEY,
  EDGE_DETAIL_FIELD_LABELS,
  HTTP_METHOD_COLOR,
  ROOT_PREFIX_KEY,
  STATUS_COLOR_MAP,
  buildPathPrefixTree,
  buildTopologyGraphOption,
  buildTopologyIndex,
  endpointSignature,
  matchesPathPrefix,
  truncateMiddle,
  type AppTopologySummary,
  type IndexedTopologyNode,
  type PathPrefixNode,
  type TopologyGraphDatum,
} from './topologyUtils'
import './api-topology.css'

type TimeWindowPreset = 'all' | '1h' | '24h' | '7d'
type EndpointSortKey = 'hits' | 'edges' | 'risk' | 'path'
type WorkspaceViewMode = 'list' | 'graph'

const TIME_WINDOW_OPTIONS: Array<{ value: TimeWindowPreset; label: string }> = [
  { value: 'all', label: '全部时间' },
  { value: '1h', label: '近 1 小时' },
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
]

const SORT_OPTIONS: Array<{ value: EndpointSortKey; label: string }> = [
  { value: 'hits', label: '按命中降序' },
  { value: 'edges', label: '按调用边降序' },
  { value: 'risk', label: '按风险降序' },
  { value: 'path', label: '按路径升序' },
]

const STATUS_FILTER_OPTIONS = Object.entries(API_ENDPOINT_STATUS_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

function computeWindowBounds(preset: TimeWindowPreset): Pick<ApiGraphEdgeFilter, 'start' | 'end'> {
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

function renderStatusBar(statusCounts: Record<string, number>, total: number) {
  if (total <= 0) return <div className="api-topology-status-bar" />
  const segments = Object.entries(API_ENDPOINT_STATUS_META)
    .map(([status, meta]) => ({
      status,
      label: meta.label,
      count: statusCounts[status] ?? 0,
      color: STATUS_COLOR_MAP[status] ?? '#2f6fed',
    }))
    .filter((s) => s.count > 0)
  const tooltipText = segments.map((s) => `${s.label} ${s.count}`).join(' · ')
  return (
    <Tooltip title={tooltipText}>
      <div className="api-topology-status-bar" aria-label={tooltipText}>
        {segments.map((seg) => (
          <span
            key={seg.status}
            style={{
              width: `${(seg.count / total) * 100}%`,
              background: seg.color,
            }}
          />
        ))}
      </div>
    </Tooltip>
  )
}

/** API 调用拓扑（WDSP / 阶段8）：应用与路径分层拓扑浏览 + 交互关系图 + 调用边明细 */
export default function ApiTopologyPage() {
  const [timeWindow, setTimeWindow] = useState<TimeWindowPreset>('all')
  const [windowBounds, setWindowBounds] = useState<Pick<ApiGraphEdgeFilter, 'start' | 'end'>>({})
  const [minEdgeCount, setMinEdgeCount] = useState<number>(0)

  const [selectedAppKey, setSelectedAppKey] = useState<string>(ALL_APPS_KEY)
  const [selectedPrefix, setSelectedPrefix] = useState<string>(ALL_PREFIX_KEY)
  const [toggledPrefixes, setToggledPrefixes] = useState<Record<string, boolean>>({})
  const [treeSearch, setTreeSearch] = useState('')

  const [viewMode, setViewMode] = useState<WorkspaceViewMode>('list')
  const [keyword, setKeyword] = useState('')
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [methodFilter, setMethodFilter] = useState<string | undefined>()
  const [onlyWithEdges, setOnlyWithEdges] = useState(false)
  const [onlyRisky, setOnlyRisky] = useState(false)
  const [sortBy, setSortBy] = useState<EndpointSortKey>('hits')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [edgeKeyword, setEdgeKeyword] = useState('')
  const [edgeScopeToApp, setEdgeScopeToApp] = useState(true)

  const [selectedEndpoint, setSelectedEndpoint] = useState<IndexedTopologyNode | null>(null)
  const [detailEdge, setDetailEdge] = useState<ApiGraphEdge | null>(null)

  const queryParams = useMemo<ApiGraphEdgeFilter | undefined>(() => {
    const next: ApiGraphEdgeFilter = {}
    if (windowBounds.start) next.start = windowBounds.start
    if (windowBounds.end) next.end = windowBounds.end
    if (minEdgeCount > 0) next.min_count = minEdgeCount
    return Object.keys(next).length > 0 ? next : undefined
  }, [windowBounds, minEdgeCount])

  const topologyQuery = useQuery({
    queryKey: ['api-topology', queryParams ?? null],
    queryFn: () => apiGraphApi.topology(queryParams),
    placeholderData: keepPreviousData,
  })

  const groups = useMemo(() => topologyQuery.data?.applications ?? [], [topologyQuery.data])
  const edges = useMemo(() => topologyQuery.data?.edges ?? [], [topologyQuery.data])

  const index = useMemo(() => buildTopologyIndex(groups, edges), [groups, edges])

  // 当仅存在 1 个应用时直接聚焦该应用；多应用时保留用户选择（若失效则回退全部应用）
  const activeAppKey = useMemo(() => {
    if (index.appSummaries.length === 1) return index.appSummaries[0].key
    if (selectedAppKey === ALL_APPS_KEY) return ALL_APPS_KEY
    return index.appSummaries.some((a) => a.key === selectedAppKey)
      ? selectedAppKey
      : ALL_APPS_KEY
  }, [index.appSummaries, selectedAppKey])

  const activeApp: AppTopologySummary | null = useMemo(() => {
    if (activeAppKey === ALL_APPS_KEY) return null
    return index.appSummaries.find((a) => a.key === activeAppKey) ?? null
  }, [index.appSummaries, activeAppKey])

  const scopedEndpoints = useMemo(
    () => (activeApp ? activeApp.endpoints : index.allEndpoints),
    [activeApp, index.allEndpoints],
  )

  const prefixTree = useMemo(
    () => buildPathPrefixTree(scopedEndpoints, index.endpointStats),
    [scopedEndpoints, index.endpointStats],
  )

  // 当前选中的前缀在新作用域中不存在时自动回退全部接口
  const activePrefix = useMemo(() => {
    if (selectedPrefix === ALL_PREFIX_KEY) return ALL_PREFIX_KEY
    for (const node of prefixTree.nodes) {
      if (node.key === selectedPrefix) return selectedPrefix
      if (node.children.some((c) => c.key === selectedPrefix)) return selectedPrefix
    }
    return ALL_PREFIX_KEY
  }, [prefixTree.nodes, selectedPrefix])

  const methodOptions = useMemo(() => {
    const set = new Set<string>()
    for (const ep of scopedEndpoints) {
      if (ep.http_method) set.add(ep.http_method.toUpperCase())
    }
    return [...set].sort().map((m) => ({ value: m, label: m }))
  }, [scopedEndpoints])

  const filteredEndpoints = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    const list = scopedEndpoints.filter((ep) => {
      if (!matchesPathPrefix(ep, activePrefix, prefixTree.rootEndpointIds)) return false
      if (statusFilter && ep.asset_status !== statusFilter) return false
      if (methodFilter && ep.http_method.toUpperCase() !== methodFilter) return false
      const stat = index.endpointStats.get(ep.id)
      if (onlyWithEdges && (stat?.edgeCount ?? 0) === 0) return false
      if (onlyRisky && (ep.open_findings_count ?? 0) === 0) return false
      if (kw) {
        const hay = `${ep.http_method} ${ep.normalized_path} ${ep.endpoint_key} ${ep.applicationName}`.toLowerCase()
        if (!hay.includes(kw)) return false
      }
      return true
    })

    return list.sort((a, b) => {
      if (sortBy === 'hits') {
        const diff = (b.hit_count ?? 0) - (a.hit_count ?? 0)
        if (diff !== 0) return diff
        const edgeDiff =
          (index.endpointStats.get(b.id)?.callCount ?? 0) -
          (index.endpointStats.get(a.id)?.callCount ?? 0)
        if (edgeDiff !== 0) return edgeDiff
      } else if (sortBy === 'edges') {
        const sa = index.endpointStats.get(a.id)
        const sb = index.endpointStats.get(b.id)
        const diff = (sb?.edgeCount ?? 0) - (sa?.edgeCount ?? 0)
        if (diff !== 0) return diff
        const callDiff = (sb?.callCount ?? 0) - (sa?.callCount ?? 0)
        if (callDiff !== 0) return callDiff
      } else if (sortBy === 'risk') {
        const diff = (b.open_findings_count ?? 0) - (a.open_findings_count ?? 0)
        if (diff !== 0) return diff
      }
      return a.endpoint_key.localeCompare(b.endpoint_key)
    })
  }, [
    scopedEndpoints,
    activePrefix,
    prefixTree.rootEndpointIds,
    statusFilter,
    methodFilter,
    onlyWithEdges,
    onlyRisky,
    keyword,
    sortBy,
    index.endpointStats,
  ])

  const filteredTreeNodes = useMemo<PathPrefixNode[]>(() => {
    const q = treeSearch.trim().toLowerCase()
    if (!q) return prefixTree.nodes
    const out: PathPrefixNode[] = []
    for (const node of prefixTree.nodes) {
      const selfMatch =
        node.label.toLowerCase().includes(q) || node.key.toLowerCase().includes(q)
      const matchedChildren = node.children.filter(
        (c) => c.label.toLowerCase().includes(q) || c.key.toLowerCase().includes(q),
      )
      if (selfMatch || matchedChildren.length > 0) {
        out.push({
          ...node,
          children: selfMatch ? node.children : matchedChildren,
        })
      }
    }
    return out
  }, [prefixTree.nodes, treeSearch])

  const scopeLabel = useMemo(() => {
    const appPart = activeApp ? activeApp.applicationName : '全部应用'
    if (activePrefix === ALL_PREFIX_KEY) return appPart
    if (activePrefix === ROOT_PREFIX_KEY) return `${appPart} · 根路径与单段`
    return `${appPart} · ${activePrefix}`
  }, [activeApp, activePrefix])

  const graphResult = useMemo(
    () =>
      buildTopologyGraphOption({
        scopeLabel,
        selectedPrefix: activePrefix,
        endpoints: filteredEndpoints,
        edges,
        prefixTree,
        endpointStats: index.endpointStats,
      }),
    [scopeLabel, activePrefix, filteredEndpoints, edges, prefixTree, index.endpointStats],
  )

  const handleGraphClick = useCallback((raw: unknown) => {
    const params = raw as { dataType?: string; data?: Partial<TopologyGraphDatum> }
    if (params.dataType !== 'node' || !params.data) return
    if (params.data.kind === 'prefix' && params.data.prefixKey) {
      setSelectedPrefix(params.data.prefixKey)
      setPage(1)
      return
    }
    if (params.data.kind === 'endpoint' && params.data.endpoint) {
      setSelectedEndpoint(params.data.endpoint)
    }
  }, [])

  const graphEvents = useMemo(() => ({ click: handleGraphClick }), [handleGraphClick])

  const filteredEdges = useMemo(() => {
    const q = edgeKeyword.trim().toLowerCase()
    return edges.filter((edge) => {
      const target = index.nodeById.get(edge.target_endpoint_id)
      const source = edge.source_endpoint_id ? index.nodeById.get(edge.source_endpoint_id) : undefined
      if (activeApp && edgeScopeToApp) {
        const matchesApp =
          target?.applicationKey === activeApp.key || source?.applicationKey === activeApp.key
        if (!matchesApp) return false
      }
      if (q) {
        const hay = `${edge.caller_fingerprint} ${source?.endpoint_key ?? ''} ${target?.endpoint_key ?? ''} ${target?.applicationName ?? ''}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [edges, index.nodeById, activeApp, edgeScopeToApp, edgeKeyword])

  const hasEndpointFilters = Boolean(
    keyword.trim() || statusFilter || methodFilter || onlyWithEdges || onlyRisky || activePrefix !== ALL_PREFIX_KEY,
  )

  const resetEndpointFilters = () => {
    setKeyword('')
    setStatusFilter(undefined)
    setMethodFilter(undefined)
    setOnlyWithEdges(false)
    setOnlyRisky(false)
    setSelectedPrefix(ALL_PREFIX_KEY)
    setPage(1)
  }

  const handleTimeWindowChange = (preset: TimeWindowPreset) => {
    setTimeWindow(preset)
    setWindowBounds(computeWindowBounds(preset))
  }

  const handleSelectApp = (appKey: string) => {
    setSelectedAppKey(appKey)
    setSelectedPrefix(ALL_PREFIX_KEY)
    setToggledPrefixes({})
    setTreeSearch('')
    setPage(1)
  }

  const isPrefixExpanded = (node: PathPrefixNode, idx: number): boolean => {
    if (treeSearch.trim()) return true
    if (toggledPrefixes[node.key] !== undefined) return toggledPrefixes[node.key]
    return idx === 0
  }

  const togglePrefixExpanded = (key: string, current: boolean) => {
    setToggledPrefixes((prev) => ({ ...prev, [key]: !current }))
  }

  const activePrefixLabel = useMemo(() => {
    if (activePrefix === ALL_PREFIX_KEY) return '全部接口'
    if (activePrefix === ROOT_PREFIX_KEY) return '根路径与单段'
    return activePrefix
  }, [activePrefix])

  const endpointColumns: ColumnsType<IndexedTopologyNode> = useMemo(
    () => [
      {
        title: '接口路径',
        key: 'path',
        render: (_, record) => {
          const method = (record.http_method || 'ANY').toUpperCase()
          const methodStyle = HTTP_METHOD_COLOR[method]
          const fullPath = record.normalized_path || '/'
          const dupCount =
            index.duplicateCountBySignature.get(
              endpointSignature(record.applicationKey, method, fullPath),
            ) ?? 1
          return (
            <div className="api-topology-endpoint-cell">
              <span
                className="api-topology-method-badge"
                style={
                  methodStyle
                    ? {
                        background: methodStyle.bg,
                        borderColor: methodStyle.border,
                        color: methodStyle.text,
                      }
                    : undefined
                }
              >
                {method}
              </span>
              <Tooltip
                title={
                  <div style={{ wordBreak: 'break-all' }}>
                    {method} {fullPath}
                  </div>
                }
              >
                <span className="api-topology-path-text">{fullPath}</span>
              </Tooltip>
              {activeAppKey === ALL_APPS_KEY && index.appSummaries.length > 1 && (
                <Tooltip title={`所属应用：${record.applicationName}`}>
                  <span className="api-topology-app-pill">{record.applicationName}</span>
                </Tooltip>
              )}
              {dupCount > 1 && (
                <Tooltip title={`同应用下存在 ${dupCount} 条同路径记录（不同域名或协议）`}>
                  <span className="api-topology-dup-pill">×{dupCount}</span>
                </Tooltip>
              )}
            </div>
          )
        },
      },
      {
        title: '资产状态',
        dataIndex: 'asset_status',
        width: 84,
        render: (v: string) => <StatusTag value={v} map={API_ENDPOINT_STATUS_META} />,
      },
      {
        title: '学习状态',
        dataIndex: 'learning_status',
        width: 80,
        render: (v?: string) =>
          v ? (
            <StatusTag value={v} map={API_LEARNING_STATUS_META} />
          ) : (
            <Typography.Text type="secondary">-</Typography.Text>
          ),
      },
      {
        title: '命中数',
        dataIndex: 'hit_count',
        width: 74,
        align: 'right',
        render: (v?: number) => (
          <span className="api-topology-num">{(v ?? 0).toLocaleString()}</span>
        ),
      },
      {
        title: '调用边',
        key: 'edges',
        width: 68,
        align: 'right',
        render: (_, record) => {
          const stat = index.endpointStats.get(record.id)
          const count = stat?.edgeCount ?? 0
          if (count === 0) return <Typography.Text type="secondary">0</Typography.Text>
          return (
            <Tooltip
              title={`上游 ${stat?.incomingEdges.length ?? 0} 条 · 下游 ${stat?.outgoingEdges.length ?? 0} 条 · 调用 ${(stat?.callCount ?? 0).toLocaleString()} 次`}
            >
              <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                {count}
              </Tag>
            </Tooltip>
          )
        },
      },
      {
        title: '风险',
        dataIndex: 'open_findings_count',
        width: 62,
        align: 'right',
        render: (v?: number) =>
          (v ?? 0) > 0 ? (
            <Tag color="red" style={{ marginInlineEnd: 0 }}>
              {v}
            </Tag>
          ) : (
            <Typography.Text type="secondary">-</Typography.Text>
          ),
      },
      {
        title: '操作',
        key: 'actions',
        width: 56,
        align: 'center',
        render: (_, record) => (
          <Button type="link" size="small" onClick={() => setSelectedEndpoint(record)}>
            详情
          </Button>
        ),
      },
    ],
    [index.duplicateCountBySignature, index.appSummaries.length, index.endpointStats, activeAppKey],
  )

  const edgeColumns: ColumnsType<ApiGraphEdge> = useMemo(
    () => [
      {
        title: '调用方指纹',
        dataIndex: 'caller_fingerprint',
        width: 196,
        ellipsis: true,
        render: (v: string) => (
          <Tooltip title={v}>
            <Typography.Text code>{truncateMiddle(v, 12, 6)}</Typography.Text>
          </Tooltip>
        ),
      },
      {
        title: '源接口',
        dataIndex: 'source_endpoint_id',
        width: 220,
        ellipsis: true,
        render: (v?: string | null) => {
          if (!v) return <Tag>外部调用方</Tag>
          const source = index.nodeById.get(v)
          if (!source) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
          return (
            <Tooltip title={<div style={{ wordBreak: 'break-all' }}>{source.endpoint_key}</div>}>
              <Typography.Link
                className="api-topology-code-ellipsis"
                onClick={() => setSelectedEndpoint(source)}
              >
                {source.endpoint_key}
              </Typography.Link>
            </Tooltip>
          )
        },
      },
      {
        title: '目标接口',
        dataIndex: 'target_endpoint_id',
        ellipsis: true,
        render: (v: string) => {
          const target = index.nodeById.get(v)
          if (!target) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
          return (
            <div className="api-topology-endpoint-cell">
              <Tooltip title={<div style={{ wordBreak: 'break-all' }}>{target.endpoint_key}</div>}>
                <Typography.Link
                  className="api-topology-code-ellipsis"
                  onClick={() => setSelectedEndpoint(target)}
                >
                  {target.endpoint_key}
                </Typography.Link>
              </Tooltip>
              {index.appSummaries.length > 1 && (
                <span className="api-topology-app-pill">{target.applicationName}</span>
              )}
            </div>
          )
        },
      },
      {
        title: '调用次数',
        dataIndex: 'call_count',
        width: 100,
        align: 'right',
        sorter: (a, b) => a.call_count - b.call_count,
        render: (v: number) => <span className="api-topology-num">{v.toLocaleString()}</span>,
      },
      {
        title: '涉及身份',
        dataIndex: 'identity_count',
        width: 92,
        align: 'right',
        render: (v?: number) => (
          <span className="api-topology-num">{v !== undefined ? v.toLocaleString() : '-'}</span>
        ),
      },
      {
        title: '最近观测',
        dataIndex: 'last_seen_at',
        width: 164,
        render: (v?: string) => formatDateTime(v),
      },
      {
        title: '操作',
        key: 'actions',
        width: 70,
        align: 'center',
        render: (_, record) => (
          <Button type="link" size="small" onClick={() => setDetailEdge(record)}>
            详情
          </Button>
        ),
      },
    ],
    [index.nodeById, index.appSummaries.length],
  )

  const detailEdgeRecord = useMemo(() => {
    if (!detailEdge) return null
    const src = detailEdge.source_endpoint_id
      ? index.nodeById.get(detailEdge.source_endpoint_id)
      : undefined
    const dst = index.nodeById.get(detailEdge.target_endpoint_id)
    return {
      id: detailEdge.id,
      caller_fingerprint: detailEdge.caller_fingerprint,
      source_endpoint_key: src ? src.endpoint_key : '外部调用方',
      source_endpoint_id: detailEdge.source_endpoint_id ?? null,
      target_endpoint_key: dst ? dst.endpoint_key : detailEdge.target_endpoint_id,
      target_application_name: dst?.applicationName ?? '-',
      target_endpoint_id: detailEdge.target_endpoint_id,
      call_count: detailEdge.call_count,
      identity_count: detailEdge.identity_count,
      first_seen_at: detailEdge.first_seen_at,
      last_seen_at: detailEdge.last_seen_at,
    }
  }, [detailEdge, index.nodeById])

  const statusLegendItems = useMemo(
    () =>
      Object.entries(API_ENDPOINT_STATUS_META).map(([status, meta]) => ({
        status,
        label: meta.label,
        color: STATUS_COLOR_MAP[status] ?? '#2f6fed',
        count: index.totals.statusCounts[status] ?? 0,
      })),
    [index.totals.statusCounts],
  )

  return (
    <Card
      className="api-topology-page"
      title="API 调用拓扑"
      extra={
        <div className="api-topology-header-extra">
          <Radio.Group
            size="small"
            optionType="button"
            value={timeWindow}
            onChange={(e) => handleTimeWindowChange(e.target.value as TimeWindowPreset)}
            options={TIME_WINDOW_OPTIONS}
          />
          <Button
            size="small"
            icon={<ReloadOutlined />}
            loading={topologyQuery.isFetching}
            onClick={() => topologyQuery.refetch()}
          >
            刷新
          </Button>
        </div>
      }
    >
      <p className="api-topology-intro">
        按应用与路径层级聚合展示 API 资产拓扑与运行时调用关系；支持按路径目录逐级下钻、筛选高活跃/高风险接口及查看上下游调用边。
      </p>

      <QueryErrorAlert error={topologyQuery.error} />

      <Spin spinning={topologyQuery.isLoading}>
        {/* 顶部 KPI 概览带 */}
        <div className="api-topology-summary-strip" aria-label="拓扑汇总指标">
          <span className="api-topology-metric">
            应用 <strong>{index.totals.appCount.toLocaleString()}</strong>
          </span>
          <span className="api-topology-metric-divider" />
          <span className="api-topology-metric">
            接口总数 <strong>{index.totals.endpointCount.toLocaleString()}</strong>
          </span>
          <span className="api-topology-metric-divider" />
          <span className="api-topology-metric">
            风险接口{' '}
            <strong className={index.totals.riskyEndpointCount > 0 ? 'is-danger' : undefined}>
              {index.totals.riskyEndpointCount.toLocaleString()}
            </strong>
          </span>
          <span className="api-topology-metric-divider" />
          <span className="api-topology-metric">
            调用边 <strong>{index.totals.edgeCount.toLocaleString()}</strong>
          </span>
          <span className="api-topology-metric">
            累计调用 <strong>{index.totals.totalCalls.toLocaleString()}</strong>
          </span>
          {index.totals.callerCount > 0 && (
            <span className="api-topology-metric">
              调用方 <strong>{index.totals.callerCount.toLocaleString()}</strong>
            </span>
          )}
          <div className="api-topology-status-legend">
            {statusLegendItems.map((item) => (
              <span key={item.status} className="api-topology-legend-item">
                <span
                  className="api-topology-legend-dot"
                  style={{ background: item.color }}
                />
                {item.label} {item.count}
              </span>
            ))}
          </div>
        </div>

        {/* 应用概览区：单应用占满整行，多应用以紧凑卡片网格切换 */}
        {index.appSummaries.length === 0 ? (
          <Empty
            description="暂无 API 拓扑资产数据"
            style={{ padding: '40px 0', border: '1px solid #dce5ee', borderRadius: 8, background: '#fff' }}
          />
        ) : (
          <>
            {index.appSummaries.length === 1 ? (
              <div className="api-topology-app-banner">
                <div className="api-topology-app-banner-title">
                  <AppstoreOutlined style={{ color: '#1d5bd6' }} />
                  <Tooltip title={index.appSummaries[0].applicationName}>
                    <span className="api-topology-app-banner-name">
                      {index.appSummaries[0].applicationName}
                    </span>
                  </Tooltip>
                  <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                    {index.appSummaries[0].endpointCount.toLocaleString()} 个接口
                  </Tag>
                </div>
                <div className="api-topology-app-banner-stats">
                  <span>
                    路径分组 <strong>{prefixTree.nodes.length}</strong>
                  </span>
                  <span>
                    累计命中 <strong>{index.appSummaries[0].totalHits.toLocaleString()}</strong>
                  </span>
                  <span>
                    调用边 <strong>{index.appSummaries[0].edgeCount.toLocaleString()}</strong>
                  </span>
                  <span>
                    风险接口{' '}
                    <strong
                      style={
                        index.appSummaries[0].riskyEndpointCount > 0
                          ? { color: '#cf2e36' }
                          : undefined
                      }
                    >
                      {index.appSummaries[0].riskyEndpointCount}
                    </strong>
                  </span>
                </div>
                <div className="api-topology-app-banner-bar">
                  {renderStatusBar(
                    index.appSummaries[0].statusCounts,
                    index.appSummaries[0].endpointCount,
                  )}
                </div>
              </div>
            ) : (
              <div className="api-topology-apps-grid" role="tablist" aria-label="应用筛选">
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeAppKey === ALL_APPS_KEY}
                  className={`api-topology-app-card ${activeAppKey === ALL_APPS_KEY ? 'is-active' : ''}`}
                  onClick={() => handleSelectApp(ALL_APPS_KEY)}
                >
                  <div className="api-topology-app-card-head">
                    <span className="api-topology-app-card-name">全部应用</span>
                    <span className="api-topology-app-card-count">
                      {index.totals.endpointCount.toLocaleString()} 个接口
                    </span>
                  </div>
                  {renderStatusBar(index.totals.statusCounts, index.totals.endpointCount)}
                  <div className="api-topology-app-card-meta">
                    <span>{index.totals.appCount} 个应用</span>
                    <span>边 {index.totals.edgeCount}</span>
                    {index.totals.riskyEndpointCount > 0 && (
                      <span style={{ color: '#cf2e36' }}>
                        风险 {index.totals.riskyEndpointCount}
                      </span>
                    )}
                  </div>
                </button>
                {index.appSummaries.map((app) => (
                  <button
                    key={app.key}
                    type="button"
                    role="tab"
                    aria-selected={activeAppKey === app.key}
                    className={`api-topology-app-card ${activeAppKey === app.key ? 'is-active' : ''}`}
                    onClick={() => handleSelectApp(app.key)}
                  >
                    <div className="api-topology-app-card-head">
                      <Tooltip title={app.applicationName}>
                        <span className="api-topology-app-card-name">{app.applicationName}</span>
                      </Tooltip>
                      <span className="api-topology-app-card-count">
                        {app.endpointCount.toLocaleString()} 个接口
                      </span>
                    </div>
                    {renderStatusBar(app.statusCounts, app.endpointCount)}
                    <div className="api-topology-app-card-meta">
                      <span>命中 {app.totalHits.toLocaleString()}</span>
                      <span>边 {app.edgeCount}</span>
                      {app.riskyEndpointCount > 0 && (
                        <span style={{ color: '#cf2e36' }}>风险 {app.riskyEndpointCount}</span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* 主从有界拓扑工作区：左路径分组树 + 右列表/拓扑画布 */}
            <div className="api-topology-workspace">
              <aside className="api-topology-tree-pane" aria-label="路径分组导航">
                <div className="api-topology-tree-header">
                  <span>
                    <FolderOutlined style={{ marginRight: 6, color: '#4d6580' }} />
                    路径分组
                  </span>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {prefixTree.nodes.length} 组
                  </Typography.Text>
                </div>

                {prefixTree.nodes.length > 8 && (
                  <div className="api-topology-tree-search">
                    <Input
                      size="small"
                      allowClear
                      prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                      placeholder="筛选路径前缀"
                      value={treeSearch}
                      onChange={(e) => setTreeSearch(e.target.value)}
                    />
                  </div>
                )}

                <div className="api-topology-tree-scroll">
                  <div className="api-topology-tree-row">
                    <span className="api-topology-tree-toggle-placeholder" />
                    <button
                      type="button"
                      className={`api-topology-tree-btn ${activePrefix === ALL_PREFIX_KEY ? 'is-active' : ''}`}
                      onClick={() => {
                        setSelectedPrefix(ALL_PREFIX_KEY)
                        setPage(1)
                      }}
                    >
                      <span className="api-topology-tree-label">全部接口</span>
                      <span className="api-topology-tree-count">
                        {scopedEndpoints.length.toLocaleString()}
                      </span>
                    </button>
                  </div>

                  {filteredTreeNodes.map((node, idx) => {
                    const hasChildren = node.children.length > 0
                    const expanded = hasChildren && isPrefixExpanded(node, idx)
                    const isMono = node.key !== ROOT_PREFIX_KEY
                    return (
                      <div key={node.key}>
                        <div className="api-topology-tree-row">
                          {hasChildren ? (
                            <button
                              type="button"
                              aria-label={expanded ? `收起 ${node.label}` : `展开 ${node.label}`}
                              className="api-topology-tree-toggle"
                              onClick={() => togglePrefixExpanded(node.key, expanded)}
                            >
                              {expanded ? (
                                <CaretDownOutlined style={{ fontSize: 10 }} />
                              ) : (
                                <CaretRightOutlined style={{ fontSize: 10 }} />
                              )}
                            </button>
                          ) : (
                            <span className="api-topology-tree-toggle-placeholder" />
                          )}
                          <Tooltip title={`${node.label}（${node.count} 个接口）`} placement="right">
                            <button
                              type="button"
                              className={`api-topology-tree-btn ${activePrefix === node.key ? 'is-active' : ''}`}
                              onClick={() => {
                                setSelectedPrefix(node.key)
                                setPage(1)
                              }}
                            >
                              <span
                                className={`api-topology-tree-label ${isMono ? 'is-mono' : ''}`}
                              >
                                {node.label}
                              </span>
                              {node.riskEndpointCount > 0 && (
                                <span
                                  className="api-topology-tree-risk-dot"
                                  title={`${node.riskEndpointCount} 个风险接口`}
                                />
                              )}
                              <span className="api-topology-tree-count">{node.count}</span>
                            </button>
                          </Tooltip>
                        </div>

                        {expanded &&
                          node.children.map((child) => (
                            <div key={child.key} className="api-topology-tree-row is-child">
                              <span className="api-topology-tree-toggle-placeholder" />
                              <Tooltip
                                title={`${child.key}（${child.count} 个接口）`}
                                placement="right"
                              >
                                <button
                                  type="button"
                                  className={`api-topology-tree-btn ${activePrefix === child.key ? 'is-active' : ''}`}
                                  onClick={() => {
                                    setSelectedPrefix(child.key)
                                    setPage(1)
                                  }}
                                >
                                  <span className="api-topology-tree-label is-mono">
                                    {child.label}
                                  </span>
                                  {child.riskEndpointCount > 0 && (
                                    <span
                                      className="api-topology-tree-risk-dot"
                                      title={`${child.riskEndpointCount} 个风险接口`}
                                    />
                                  )}
                                  <span className="api-topology-tree-count">{child.count}</span>
                                </button>
                              </Tooltip>
                            </div>
                          ))}
                      </div>
                    )
                  })}
                </div>
              </aside>

              <section className="api-topology-main-pane" aria-label="接口与拓扑展示区">
                <div className="api-topology-main-head">
                  <div className="api-topology-scope-crumb">
                    <strong>{activeApp ? activeApp.applicationName : '全部应用'}</strong>
                    <Typography.Text type="secondary">/</Typography.Text>
                    <Tooltip title={activePrefixLabel}>
                      <span className="api-topology-scope-prefix">{activePrefixLabel}</span>
                    </Tooltip>
                    <Tag style={{ marginInlineEnd: 0 }}>
                      {filteredEndpoints.length.toLocaleString()} /{' '}
                      {scopedEndpoints.length.toLocaleString()} 个接口
                    </Tag>
                    {activePrefix !== ALL_PREFIX_KEY && (
                      <Button
                        type="link"
                        size="small"
                        icon={<RollbackOutlined />}
                        onClick={() => {
                          setSelectedPrefix(ALL_PREFIX_KEY)
                          setPage(1)
                        }}
                      >
                        返回全部
                      </Button>
                    )}
                  </div>
                  <Radio.Group
                    size="small"
                    optionType="button"
                    value={viewMode}
                    onChange={(e) => setViewMode(e.target.value as WorkspaceViewMode)}
                    options={[
                      {
                        value: 'list',
                        label: (
                          <span>
                            <UnorderedListOutlined style={{ marginRight: 4 }} />
                            接口列表
                          </span>
                        ),
                      },
                      {
                        value: 'graph',
                        label: (
                          <span>
                            <BranchesOutlined style={{ marginRight: 4 }} />
                            拓扑图
                          </span>
                        ),
                      },
                    ]}
                  />
                </div>

                <div className="api-topology-toolbar">
                  <Input
                    className="api-topology-toolbar-search"
                    size="small"
                    allowClear
                    prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
                    placeholder="搜索路径 / 方法 / 端点键"
                    value={keyword}
                    onChange={(e) => {
                      setKeyword(e.target.value)
                      setPage(1)
                    }}
                  />
                  <Select
                    size="small"
                    allowClear
                    placeholder="资产状态"
                    style={{ width: 112 }}
                    value={statusFilter}
                    onChange={(v) => {
                      setStatusFilter(v)
                      setPage(1)
                    }}
                    options={STATUS_FILTER_OPTIONS}
                  />
                  <Select
                    size="small"
                    allowClear
                    placeholder="请求方法"
                    style={{ width: 108 }}
                    value={methodFilter}
                    onChange={(v) => {
                      setMethodFilter(v)
                      setPage(1)
                    }}
                    options={methodOptions}
                  />
                  <Select
                    size="small"
                    style={{ width: 124 }}
                    value={sortBy}
                    onChange={(v) => {
                      setSortBy(v as EndpointSortKey)
                      setPage(1)
                    }}
                    options={SORT_OPTIONS}
                  />
                  <Space size={6}>
                    <Button
                      size="small"
                      type={onlyWithEdges ? 'primary' : 'default'}
                      ghost={onlyWithEdges}
                      onClick={() => {
                        setOnlyWithEdges((v) => !v)
                        setPage(1)
                      }}
                    >
                      仅有调用边
                    </Button>
                    <Button
                      size="small"
                      danger={onlyRisky}
                      type={onlyRisky ? 'primary' : 'default'}
                      ghost={onlyRisky}
                      onClick={() => {
                        setOnlyRisky((v) => !v)
                        setPage(1)
                      }}
                    >
                      仅有风险
                    </Button>
                    {hasEndpointFilters && (
                      <Button size="small" type="link" onClick={resetEndpointFilters}>
                        重置筛选
                      </Button>
                    )}
                  </Space>
                </div>

                {viewMode === 'list' ? (
                  <div className="api-topology-table-wrap">
                    <Table<IndexedTopologyNode>
                      rowKey="id"
                      size="small"
                      tableLayout="fixed"
                      scroll={{ x: 680 }}
                      columns={endpointColumns}
                      dataSource={filteredEndpoints}
                      locale={{
                        emptyText: (
                          <Empty
                            image={Empty.PRESENTED_IMAGE_SIMPLE}
                            description={
                              hasEndpointFilters ? '当前筛选条件下无匹配接口' : '暂无接口数据'
                            }
                          />
                        ),
                      }}
                      onRow={(record) => ({
                        onClick: (event) => {
                          if ((event.target as HTMLElement).closest('button, a')) return
                          setSelectedEndpoint(record)
                        },
                        style: { cursor: 'pointer' },
                      })}
                      pagination={{
                        current: page,
                        pageSize,
                        pageSizeOptions: ['10', '20', '50'],
                        showSizeChanger: true,
                        showQuickJumper: filteredEndpoints.length > 50,
                        size: 'small',
                        showTotal: (total) => `共 ${total.toLocaleString()} 个接口`,
                        onChange: (nextPage, nextSize) => {
                          setPage(nextPage)
                          setPageSize(nextSize)
                        },
                      }}
                    />
                  </div>
                ) : (
                  <div className="api-topology-canvas-wrap">
                    <div className="api-topology-canvas-bar">
                      <span>
                        {graphResult.mode === 'module' ? (
                          <>
                            <strong>模块聚合拓扑</strong> · 展示前 {graphResult.displayedModules}/
                            {graphResult.totalModules} 个路径模块（覆盖{' '}
                            {graphResult.totalEndpoints.toLocaleString()} 个接口）·
                            点击模块节点可下钻查看子接口
                          </>
                        ) : (
                          <>
                            <strong>接口明细拓扑</strong> · 展示重点 {graphResult.displayedEndpoints}
                            /{graphResult.totalEndpoints.toLocaleString()} 个接口
                            {graphResult.displayedCallers > 0
                              ? ` · 关联 ${graphResult.displayedCallers} 个调用方`
                              : ''}
                            · 点击接口节点查看上下游调用
                          </>
                        )}
                      </span>
                      {edges.length === 0 && (
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          当前时间窗未观测到调用边，展示应用与路径层级结构
                        </Typography.Text>
                      )}
                    </div>
                    {filteredEndpoints.length === 0 ? (
                      <Empty
                        description="当前筛选条件下无匹配接口"
                        style={{ padding: '120px 0' }}
                      />
                    ) : (
                      <EChart
                        option={graphResult.option}
                        height={460}
                        ariaLabel="API 调用拓扑图"
                        events={graphEvents}
                      />
                    )}
                  </div>
                )}
              </section>
            </div>
          </>
        )}
      </Spin>

      {/* 下方调用边明细表 */}
      <div className="api-topology-edges-section">
        <div className="api-topology-edges-head">
          <div className="api-topology-edges-title">
            <span>调用边明细</span>
            <Tag style={{ marginInlineEnd: 0 }}>{filteredEdges.length.toLocaleString()} 条</Tag>
          </div>
          <div className="api-topology-edges-controls">
            <Input
              size="small"
              allowClear
              style={{ width: 220 }}
              prefix={<SearchOutlined style={{ color: '#94a3b8' }} />}
              placeholder="搜索调用方指纹 / 接口路径"
              value={edgeKeyword}
              onChange={(e) => setEdgeKeyword(e.target.value)}
            />
            <Space size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                最小调用数
              </Typography.Text>
              <InputNumber
                size="small"
                aria-label="最小调用数"
                min={0}
                max={1_000_000}
                style={{ width: 88 }}
                value={minEdgeCount}
                onChange={(v) => setMinEdgeCount(typeof v === 'number' && v >= 0 ? v : 0)}
              />
            </Space>
            {index.appSummaries.length > 1 && activeApp && (
              <Space size={6}>
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  仅看当前应用
                </Typography.Text>
                <Switch
                  size="small"
                  checked={edgeScopeToApp}
                  onChange={setEdgeScopeToApp}
                />
              </Space>
            )}
          </div>
        </div>

        <SmartTable<ApiGraphEdge>
          storageKey="api-topology"
          refreshQueryKeys={[['api-topology']]}
          rowKey="id"
          size="small"
          tableLayout="fixed"
          scroll={{ x: 860 }}
          loading={topologyQuery.isLoading}
          columns={edgeColumns}
          dataSource={filteredEdges}
          onRow={(record) => ({
            onDoubleClick: () => setDetailEdge(record),
            style: { cursor: 'pointer' },
          })}
          pagination={{
            pageSize: 8,
            showSizeChanger: false,
            hideOnSinglePage: true,
            showTotal: (t) => `共 ${t} 条`,
          }}
        />
      </div>

      <EndpointTopologyDrawer
        endpoint={selectedEndpoint}
        stats={selectedEndpoint ? index.endpointStats.get(selectedEndpoint.id) : undefined}
        nodeById={index.nodeById}
        onClose={() => setSelectedEndpoint(null)}
        onSelectEndpoint={(node) => setSelectedEndpoint(node)}
        onSelectEdge={(edge) => {
          setSelectedEndpoint(null)
          setDetailEdge(edge)
        }}
      />

      <RecordDetailDrawer
        open={detailEdge !== null}
        title="调用边详情"
        record={detailEdgeRecord}
        fieldLabels={EDGE_DETAIL_FIELD_LABELS}
        onClose={() => setDetailEdge(null)}
      />
    </Card>
  )
}
