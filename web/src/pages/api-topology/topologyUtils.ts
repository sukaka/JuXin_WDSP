import type { GraphSeriesOption } from 'echarts/charts'
import type { EChartOption } from '../../components/EChart'
import type { ApiGraphEdge, ApiGraphNode, ApiTopologyGroup } from '../../api/apiSecurity'
import { escapeHtml } from '../../utils/format'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'

export const ALL_APPS_KEY = '__all__'
export const UNASSIGNED_APP_KEY = '__unassigned__'
export const ALL_PREFIX_KEY = '__all__'
export const ROOT_PREFIX_KEY = '__root__'

/** 图谱在超过该接口数时自动收敛为路径模块级视图，避免海量节点重叠不可读 */
export const MODULE_VIEW_THRESHOLD = 28
/** 端点级图谱单屏最多展示的重点接口数 */
export const MAX_ENDPOINT_GRAPH_NODES = 40
/** 模块级图谱最多展示的一级/子级路径模块数 */
export const MAX_MODULE_GRAPH_NODES = 16
/** 图谱中最多展示的外部调用方节点数 */
export const MAX_CALLER_GRAPH_NODES = 12

export const STATUS_COLOR_MAP: Record<string, string> = {
  DISCOVERED: '#2f6fed',
  CONFIRMED: '#248c67',
  IGNORED: '#98a6b5',
  DEPRECATED: '#d98218',
  ZOMBIE: '#7c4dff',
}

export const EDGE_DETAIL_FIELD_LABELS: Record<string, string> = {
  id: '边 ID',
  caller_fingerprint: '调用方指纹',
  source_endpoint_key: '源接口',
  source_endpoint_id: '源接口 ID',
  target_endpoint_key: '目标接口',
  target_application_name: '目标所属应用',
  target_endpoint_id: '目标接口 ID',
  call_count: '调用次数',
  identity_count: '涉及身份数',
  first_seen_at: '首次观测时间',
  last_seen_at: '最近观测时间',
}

export const HTTP_METHOD_COLOR: Record<string, { bg: string; border: string; text: string }> = {
  GET: { bg: '#edf4ff', border: '#bfd6ff', text: '#1d5bd6' },
  POST: { bg: '#eaf8f1', border: '#b3e4cc', text: '#18794e' },
  PUT: { bg: '#fff6e8', border: '#f5d29c', text: '#b8620a' },
  PATCH: { bg: '#f4efff', border: '#d4c1ff', text: '#6338c7' },
  DELETE: { bg: '#fff0f0', border: '#f7baba', text: '#c42b33' },
  HEAD: { bg: '#f2f5f8', border: '#d2dce6', text: '#4a5f75' },
  OPTIONS: { bg: '#f2f5f8', border: '#d2dce6', text: '#4a5f75' },
}

export interface IndexedTopologyNode extends ApiGraphNode {
  applicationKey: string
  applicationName: string
}

export interface EndpointEdgeStats {
  incomingEdges: ApiGraphEdge[]
  outgoingEdges: ApiGraphEdge[]
  edgeCount: number
  callCount: number
  callerCount: number
}

export interface AppTopologySummary {
  key: string
  applicationId: string | null
  applicationName: string
  endpointCount: number
  statusCounts: Record<string, number>
  totalHits: number
  riskyEndpointCount: number
  openFindingsTotal: number
  edgeCount: number
  totalCalls: number
  callerCount: number
  endpoints: IndexedTopologyNode[]
}

export interface TopologyIndex {
  nodeById: Map<string, IndexedTopologyNode>
  endpointStats: Map<string, EndpointEdgeStats>
  appSummaries: AppTopologySummary[]
  allEndpoints: IndexedTopologyNode[]
  duplicateCountBySignature: Map<string, number>
  totals: {
    appCount: number
    endpointCount: number
    statusCounts: Record<string, number>
    riskyEndpointCount: number
    openFindingsTotal: number
    edgeCount: number
    totalCalls: number
    callerCount: number
  }
}

export interface PathPrefixNode {
  key: string
  label: string
  count: number
  riskEndpointCount: number
  openFindingsTotal: number
  edgeEndpointCount: number
  hitTotal: number
  children: PathPrefixNode[]
}

export interface PathPrefixTreeResult {
  nodes: PathPrefixNode[]
  rootEndpointIds: Set<string>
  totalCount: number
}

export interface TopologyGraphDatum {
  kind: 'hub' | 'prefix' | 'endpoint' | 'caller' | 'overflow'
  id: string
  name: string
  prefixKey?: string
  endpoint?: IndexedTopologyNode
  count?: number
  riskCount?: number
  callCount?: number
  hitCount?: number
  assetStatus?: string
}

export interface TopologyGraphBuildResult {
  option: EChartOption
  mode: 'module' | 'endpoint'
  displayedEndpoints: number
  totalEndpoints: number
  displayedModules: number
  totalModules: number
  displayedCallers: number
}

/** 指纹/ID 截断展示：保留首尾，中间省略 */
export function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** 路径尾部紧凑展示：用于图谱节点短标签，避免长路径撑爆画布 */
export function compactEndpointLabel(method: string, normalizedPath: string, maxLen = 28): string {
  const full = `${method} ${normalizedPath || '/'}`
  if (full.length <= maxLen) return full
  const segs = normalizePathSegments(normalizedPath)
  if (segs.length >= 2) {
    const tail = `…/${segs.slice(-2).join('/')}`
    const candidate = `${method} ${tail}`
    if (candidate.length <= maxLen) return candidate
  }
  const budget = Math.max(8, maxLen - method.length - 2)
  return `${method} …${(normalizedPath || '/').slice(-budget)}`
}

export function getAppKey(applicationId?: string | null): string {
  return applicationId || UNASSIGNED_APP_KEY
}

export function getAppDisplayName(group: Pick<ApiTopologyGroup, 'application_name'>): string {
  const name = (group.application_name ?? '').trim()
  return name || '未分组'
}

export function endpointSignature(appKey: string, method: string, normalizedPath: string): string {
  return `${appKey}\0${method.toUpperCase()}\0${normalizedPath}`
}

/** 提取规范路径的有效段（保留原大小写，剔除空段） */
export function normalizePathSegments(normalizedPath: string): string[] {
  if (!normalizedPath) return []
  return normalizedPath.split('/').filter(Boolean)
}

/** 构造应用、端点、调用边的全量索引，供列表、路径树与拓扑画布共用 */
export function buildTopologyIndex(
  groups: ApiTopologyGroup[],
  edges: ApiGraphEdge[],
): TopologyIndex {
  const nodeById = new Map<string, IndexedTopologyNode>()
  const endpointStats = new Map<string, EndpointEdgeStats>()
  const duplicateCountBySignature = new Map<string, number>()
  const allEndpoints: IndexedTopologyNode[] = []
  const overallStatusCounts: Record<string, number> = {}
  const overallCallers = new Set<string>()

  const appBuckets = new Map<
    string,
    {
      applicationId: string | null
      applicationName: string
      endpoints: IndexedTopologyNode[]
      statusCounts: Record<string, number>
      totalHits: number
      riskyEndpointCount: number
      openFindingsTotal: number
      edgeIds: Set<string>
      totalCalls: number
      callers: Set<string>
    }
  >()
  const appOrder: string[] = []

  for (const g of groups) {
    const appKey = getAppKey(g.application_id)
    const appName = getAppDisplayName(g)
    let bucket = appBuckets.get(appKey)
    if (!bucket) {
      bucket = {
        applicationId: g.application_id ?? null,
        applicationName: appName,
        endpoints: [],
        statusCounts: {},
        totalHits: 0,
        riskyEndpointCount: 0,
        openFindingsTotal: 0,
        edgeIds: new Set(),
        totalCalls: 0,
        callers: new Set(),
      }
      appBuckets.set(appKey, bucket)
      appOrder.push(appKey)
    }

    for (const raw of g.endpoints ?? []) {
      const node: IndexedTopologyNode = {
        ...raw,
        applicationKey: appKey,
        applicationName: appName,
      }
      nodeById.set(node.id, node)
      allEndpoints.push(node)
      bucket.endpoints.push(node)

      const status = node.asset_status || 'DISCOVERED'
      bucket.statusCounts[status] = (bucket.statusCounts[status] ?? 0) + 1
      overallStatusCounts[status] = (overallStatusCounts[status] ?? 0) + 1

      const hits = node.hit_count ?? 0
      const findings = node.open_findings_count ?? 0
      bucket.totalHits += hits
      if (findings > 0) {
        bucket.riskyEndpointCount += 1
        bucket.openFindingsTotal += findings
      }

      const sig = endpointSignature(appKey, node.http_method, node.normalized_path)
      duplicateCountBySignature.set(sig, (duplicateCountBySignature.get(sig) ?? 0) + 1)
    }
  }

  const ensureEndpointStat = (endpointId: string): EndpointEdgeStats => {
    let stat = endpointStats.get(endpointId)
    if (!stat) {
      stat = {
        incomingEdges: [],
        outgoingEdges: [],
        edgeCount: 0,
        callCount: 0,
        callerCount: 0,
      }
      endpointStats.set(endpointId, stat)
    }
    return stat
  }

  const callersByEndpoint = new Map<string, Set<string>>()
  let overallTotalCalls = 0

  for (const edge of edges) {
    overallTotalCalls += edge.call_count ?? 0
    if (edge.caller_fingerprint) overallCallers.add(edge.caller_fingerprint)

    const targetNode = nodeById.get(edge.target_endpoint_id)
    if (targetNode) {
      const stat = ensureEndpointStat(targetNode.id)
      stat.incomingEdges.push(edge)
      stat.edgeCount += 1
      stat.callCount += edge.call_count ?? 0
      let set = callersByEndpoint.get(targetNode.id)
      if (!set) {
        set = new Set<string>()
        callersByEndpoint.set(targetNode.id, set)
      }
      if (edge.caller_fingerprint) set.add(edge.caller_fingerprint)

      const bucket = appBuckets.get(targetNode.applicationKey)
      if (bucket && !bucket.edgeIds.has(edge.id)) {
        bucket.edgeIds.add(edge.id)
        bucket.totalCalls += edge.call_count ?? 0
        if (edge.caller_fingerprint) bucket.callers.add(edge.caller_fingerprint)
      }
    }

    if (edge.source_endpoint_id && nodeById.has(edge.source_endpoint_id)) {
      const sourceNode = nodeById.get(edge.source_endpoint_id)!
      const stat = ensureEndpointStat(sourceNode.id)
      stat.outgoingEdges.push(edge)
      if (edge.source_endpoint_id !== edge.target_endpoint_id) {
        stat.edgeCount += 1
      }
      const bucket = appBuckets.get(sourceNode.applicationKey)
      if (bucket && !bucket.edgeIds.has(edge.id)) {
        bucket.edgeIds.add(edge.id)
        bucket.totalCalls += edge.call_count ?? 0
        if (edge.caller_fingerprint) bucket.callers.add(edge.caller_fingerprint)
      }
    }
  }

  for (const [endpointId, callers] of callersByEndpoint.entries()) {
    const stat = endpointStats.get(endpointId)
    if (stat) stat.callerCount = callers.size
  }

  let overallRiskyEndpoints = 0
  let overallOpenFindings = 0
  const appSummaries: AppTopologySummary[] = appOrder.map((key) => {
    const b = appBuckets.get(key)!
    overallRiskyEndpoints += b.riskyEndpointCount
    overallOpenFindings += b.openFindingsTotal
    return {
      key,
      applicationId: b.applicationId,
      applicationName: b.applicationName,
      endpointCount: b.endpoints.length,
      statusCounts: b.statusCounts,
      totalHits: b.totalHits,
      riskyEndpointCount: b.riskyEndpointCount,
      openFindingsTotal: b.openFindingsTotal,
      edgeCount: b.edgeIds.size,
      totalCalls: b.totalCalls,
      callerCount: b.callers.size,
      endpoints: b.endpoints,
    }
  })

  return {
    nodeById,
    endpointStats,
    appSummaries,
    allEndpoints,
    duplicateCountBySignature,
    totals: {
      appCount: appSummaries.length,
      endpointCount: allEndpoints.length,
      statusCounts: overallStatusCounts,
      riskyEndpointCount: overallRiskyEndpoints,
      openFindingsTotal: overallOpenFindings,
      edgeCount: edges.length,
      totalCalls: overallTotalCalls,
      callerCount: overallCallers.size,
    },
  }
}

/**
 * 将平铺的接口列表聚合成 2 级路径前缀树：
 * - `/` 以及没有任何子路径的单段路径（如 `/.env`、`/admin`）统一归入「根路径与单段」桶，
 *   避免扫描探测路径把左侧树撑成几十个单条叶节点；
 * - 存在子路径的一级段（如 `/admin-api`、`/.git`）作为一级分组，按接口数降序排列；
 * - 二级段在拥有更深子路径或 ≥2 个接口时展开为子分组，保持目录层次紧凑可读。
 */
export function buildPathPrefixTree(
  endpoints: IndexedTopologyNode[],
  endpointStats: Map<string, EndpointEdgeStats>,
): PathPrefixTreeResult {
  const hasChildrenSeg0 = new Set<string>()
  const parsed = endpoints.map((ep) => {
    const segs = normalizePathSegments(ep.normalized_path)
    if (segs.length >= 2) hasChildrenSeg0.add(segs[0])
    return { ep, segs }
  })

  interface MutablePrefix {
    key: string
    label: string
    count: number
    riskEndpointCount: number
    openFindingsTotal: number
    edgeEndpointCount: number
    hitTotal: number
    hasDeeperChild: boolean
    children: Map<string, MutablePrefix>
  }

  const createBucket = (key: string, label: string): MutablePrefix => ({
    key,
    label,
    count: 0,
    riskEndpointCount: 0,
    openFindingsTotal: 0,
    edgeEndpointCount: 0,
    hitTotal: 0,
    hasDeeperChild: false,
    children: new Map(),
  })

  const accumulate = (bucket: MutablePrefix, ep: IndexedTopologyNode) => {
    const findings = ep.open_findings_count ?? 0
    const stat = endpointStats.get(ep.id)
    bucket.count += 1
    bucket.hitTotal += ep.hit_count ?? 0
    if (findings > 0) {
      bucket.riskEndpointCount += 1
      bucket.openFindingsTotal += findings
    }
    if ((stat?.edgeCount ?? 0) > 0) {
      bucket.edgeEndpointCount += 1
    }
  }

  const rootBucket = createBucket(ROOT_PREFIX_KEY, '根路径与单段')
  const rootEndpointIds = new Set<string>()
  const topBuckets = new Map<string, MutablePrefix>()

  for (const { ep, segs } of parsed) {
    if (segs.length === 0 || (segs.length === 1 && !hasChildrenSeg0.has(segs[0]))) {
      rootEndpointIds.add(ep.id)
      accumulate(rootBucket, ep)
      continue
    }

    const topKey = `/${segs[0]}`
    let top = topBuckets.get(topKey)
    if (!top) {
      top = createBucket(topKey, topKey)
      topBuckets.set(topKey, top)
    }
    accumulate(top, ep)

    if (segs.length >= 2) {
      const subKey = `/${segs[0]}/${segs[1]}`
      let sub = top.children.get(subKey)
      if (!sub) {
        sub = createBucket(subKey, `/${segs[1]}`)
        top.children.set(subKey, sub)
      }
      accumulate(sub, ep)
      if (segs.length >= 3) sub.hasDeeperChild = true
    }
  }

  const sortPrefixNodes = (a: PathPrefixNode, b: PathPrefixNode) => {
    if (b.count !== a.count) return b.count - a.count
    return a.key.localeCompare(b.key)
  }

  const nodes: PathPrefixNode[] = []
  for (const top of topBuckets.values()) {
    const children: PathPrefixNode[] = []
    for (const sub of top.children.values()) {
      if (sub.hasDeeperChild || sub.count >= 2) {
        children.push({
          key: sub.key,
          label: sub.label,
          count: sub.count,
          riskEndpointCount: sub.riskEndpointCount,
          openFindingsTotal: sub.openFindingsTotal,
          edgeEndpointCount: sub.edgeEndpointCount,
          hitTotal: sub.hitTotal,
          children: [],
        })
      }
    }
    children.sort(sortPrefixNodes)
    nodes.push({
      key: top.key,
      label: top.label,
      count: top.count,
      riskEndpointCount: top.riskEndpointCount,
      openFindingsTotal: top.openFindingsTotal,
      edgeEndpointCount: top.edgeEndpointCount,
      hitTotal: top.hitTotal,
      children,
    })
  }

  if (rootBucket.count > 0) {
    nodes.push({
      key: rootBucket.key,
      label: rootBucket.label,
      count: rootBucket.count,
      riskEndpointCount: rootBucket.riskEndpointCount,
      openFindingsTotal: rootBucket.openFindingsTotal,
      edgeEndpointCount: rootBucket.edgeEndpointCount,
      hitTotal: rootBucket.hitTotal,
      children: [],
    })
  }

  nodes.sort(sortPrefixNodes)

  return {
    nodes,
    rootEndpointIds,
    totalCount: endpoints.length,
  }
}

/** 按路径段边界精确匹配选中前缀，避免 /admin 误命中 /admin-api */
export function matchesPathPrefix(
  endpoint: Pick<ApiGraphNode, 'id' | 'normalized_path'>,
  selectedPrefix: string,
  rootEndpointIds: Set<string>,
): boolean {
  if (!selectedPrefix || selectedPrefix === ALL_PREFIX_KEY) return true
  if (selectedPrefix === ROOT_PREFIX_KEY) return rootEndpointIds.has(endpoint.id)
  const canonical = `/${normalizePathSegments(endpoint.normalized_path).join('/')}`
  return canonical === selectedPrefix || canonical.startsWith(`${selectedPrefix}/`)
}

/** 返回接口归属的顶层模块键（用于模块级拓扑画布聚合边） */
function resolveModuleKey(
  endpoint: IndexedTopologyNode,
  prefixTree: PathPrefixTreeResult,
  selectedPrefix: string,
): string {
  if (selectedPrefix === ALL_PREFIX_KEY) {
    if (prefixTree.rootEndpointIds.has(endpoint.id)) return ROOT_PREFIX_KEY
    const segs = normalizePathSegments(endpoint.normalized_path)
    return segs.length > 0 ? `/${segs[0]}` : ROOT_PREFIX_KEY
  }
  const segs = normalizePathSegments(endpoint.normalized_path)
  if (segs.length >= 2) return `/${segs[0]}/${segs[1]}`
  return selectedPrefix
}

export interface BuildTopologyGraphInput {
  scopeLabel: string
  selectedPrefix: string
  endpoints: IndexedTopologyNode[]
  edges: ApiGraphEdge[]
  prefixTree: PathPrefixTreeResult
  endpointStats: Map<string, EndpointEdgeStats>
}

/**
 * 构建有界拓扑图配置：
 * - 当当前作用域接口数超过 MODULE_VIEW_THRESHOLD 且存在多个子路径模块时，展示「应用/前缀 → 路径模块 ← 调用方」聚合拓扑，
 *   点击模块节点即可下钻到对应目录；
 * - 否则展示「应用/前缀 → 接口节点 ← 调用方 / 前置接口」明细拓扑（最多取重点 Top 40 接口防重叠）。
 * 所有进入 ECharts HTML Tooltip 的不可信字段均经 escapeHtml 转义。
 */
export function buildTopologyGraphOption(
  input: BuildTopologyGraphInput,
): TopologyGraphBuildResult {
  const { scopeLabel, selectedPrefix, endpoints, edges, prefixTree, endpointStats } = input
  const endpointSet = new Set(endpoints.map((ep) => ep.id))

  // 判断当前前缀是否可以按子模块聚合
  let candidateModules: PathPrefixNode[] = []
  if (selectedPrefix === ALL_PREFIX_KEY) {
    candidateModules = prefixTree.nodes
  } else if (selectedPrefix !== ROOT_PREFIX_KEY) {
    const matchedTop = prefixTree.nodes.find((n) => n.key === selectedPrefix)
    if (matchedTop && matchedTop.children.length > 1) {
      candidateModules = matchedTop.children
    }
  }

  const useModuleMode =
    endpoints.length > MODULE_VIEW_THRESHOLD && candidateModules.length > 1

  if (useModuleMode) {
    const visibleModules = candidateModules.slice(0, MAX_MODULE_GRAPH_NODES)
    const overflowModules = candidateModules.slice(MAX_MODULE_GRAPH_NODES)
    const visibleKeys = new Set(visibleModules.map((m) => m.key))

    // 按当前过滤后的接口集合重算每个可见模块的展示计数，确保筛选条件与画布一致
    const moduleStats = new Map<
      string,
      { label: string; count: number; riskCount: number; hitTotal: number }
    >()
    for (const m of visibleModules) {
      moduleStats.set(m.key, { label: m.label, count: 0, riskCount: 0, hitTotal: 0 })
    }
    let overflowCount = 0
    let overflowRisk = 0

    const endpointToGraphModule = new Map<string, string>()
    for (const ep of endpoints) {
      const mKey = resolveModuleKey(ep, prefixTree, selectedPrefix)
      if (visibleKeys.has(mKey)) {
        endpointToGraphModule.set(ep.id, mKey)
        const st = moduleStats.get(mKey)!
        st.count += 1
        st.hitTotal += ep.hit_count ?? 0
        if ((ep.open_findings_count ?? 0) > 0) st.riskCount += 1
      } else {
        endpointToGraphModule.set(ep.id, '__overflow__')
        overflowCount += 1
        if ((ep.open_findings_count ?? 0) > 0) overflowRisk += 1
      }
    }

    const categories = [
      { name: '当前作用域', itemStyle: { color: '#21344d' } },
      { name: '路径模块', itemStyle: { color: '#2f6fed' } },
      { name: '含风险模块', itemStyle: { color: '#d9534f' } },
      { name: '调用方', itemStyle: { color: '#6b7e92' } },
    ]

    const data: Array<Record<string, unknown>> = [
      {
        id: 'hub',
        kind: 'hub',
        name: scopeLabel,
        count: endpoints.length,
        category: 0,
        symbolSize: 44,
        label: { show: true, fontSize: 12, fontWeight: 600, color: '#21344d', position: 'bottom' },
      },
    ]

    const links: NonNullable<GraphSeriesOption['links']> = []
    let displayedModules = 0

    for (const [mKey, st] of moduleStats.entries()) {
      if (st.count === 0) continue
      displayedModules += 1
      const size = Math.min(38, Math.max(18, Math.round(14 + Math.log2(st.count + 1) * 4.5)))
      data.push({
        id: `mod:${mKey}`,
        kind: 'prefix',
        prefixKey: mKey,
        name: `${st.label} (${st.count})`,
        count: st.count,
        riskCount: st.riskCount,
        hitCount: st.hitTotal,
        category: st.riskCount > 0 ? 2 : 1,
        symbolSize: size,
        label: { show: true, fontSize: 11, color: '#2f455e', position: 'right' },
      })
      links.push({
        source: 'hub',
        target: `mod:${mKey}`,
        value: st.count,
        lineStyle: { color: '#b7c7d9', width: 1.5, curveness: 0.08, opacity: 0.75 },
      })
    }

    if (overflowCount > 0) {
      const overflowName =
        overflowModules.length > 0
          ? `其余 ${overflowModules.length} 个模块 (${overflowCount})`
          : `其他直属接口 (${overflowCount})`
      data.push({
        id: 'mod:__overflow__',
        kind: 'overflow',
        name: overflowName,
        count: overflowCount,
        riskCount: overflowRisk,
        category: overflowRisk > 0 ? 2 : 1,
        symbolSize: 20,
        itemStyle: { borderType: 'dashed' },
        label: { show: true, fontSize: 11, color: '#63768b', position: 'right' },
      })
      links.push({
        source: 'hub',
        target: 'mod:__overflow__',
        value: overflowCount,
        lineStyle: { color: '#cbd5e1', width: 1.2, type: 'dashed', curveness: 0.08 },
      })
    }

    // 聚合调用方 → 路径模块边（仅取调用量 Top MAX_CALLER_GRAPH_NODES 个调用方）
    const callerTotals = new Map<string, number>()
    const callerModuleCalls = new Map<string, Map<string, number>>()
    for (const edge of edges) {
      const modKey = endpointToGraphModule.get(edge.target_endpoint_id)
      if (!modKey) continue
      const caller = edge.caller_fingerprint || 'unknown'
      callerTotals.set(caller, (callerTotals.get(caller) ?? 0) + edge.call_count)
      let modMap = callerModuleCalls.get(caller)
      if (!modMap) {
        modMap = new Map()
        callerModuleCalls.set(caller, modMap)
      }
      modMap.set(modKey, (modMap.get(modKey) ?? 0) + edge.call_count)
    }

    const topCallers = [...callerTotals.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_CALLER_GRAPH_NODES)
    const maxCall = Math.max(1, ...topCallers.map(([, total]) => total))

    for (const [caller, total] of topCallers) {
      const callerId = `caller:${caller}`
      data.push({
        id: callerId,
        kind: 'caller',
        name: truncateMiddle(caller, 8, 4),
        callCount: total,
        category: 3,
        symbol: 'diamond',
        symbolSize: 16,
        label: { show: true, fontSize: 10, color: '#63768b', position: 'left' },
      })
      const targets = callerModuleCalls.get(caller)
      if (targets) {
        for (const [modKey, count] of targets.entries()) {
          links.push({
            source: callerId,
            target: `mod:${modKey}`,
            value: count,
            symbol: ['none', 'arrow'],
            symbolSize: [4, 8],
            lineStyle: {
              color: '#5b8ff9',
              width: 1.2 + (count / maxCall) * 4,
              curveness: 0.16,
              opacity: 0.72,
            },
          })
        }
      }
    }

    const option: EChartOption = {
      tooltip: {
        trigger: 'item',
        formatter: (params: unknown) => {
          const p = params as {
            dataType?: string
            data?: Partial<TopologyGraphDatum> & { value?: number; source?: string; target?: string }
          }
          if (p.dataType === 'edge') {
            const isHierarchy = p.data?.source === 'hub'
            return isHierarchy
              ? `包含接口：<strong>${p.data?.value ?? 0}</strong> 个`
              : `累计调用：<strong>${(p.data?.value ?? 0).toLocaleString()}</strong> 次`
          }
          const d = p.data
          if (!d) return ''
          const safeName = escapeHtml(d.name ?? '')
          if (d.kind === 'hub') {
            return `<strong>${safeName}</strong><br/>当前筛选接口：${(d.count ?? 0).toLocaleString()} 个`
          }
          if (d.kind === 'prefix') {
            return (
              `<strong>${safeName}</strong><br/>` +
              `接口数：${(d.count ?? 0).toLocaleString()}<br/>` +
              `风险接口：${d.riskCount ?? 0}<br/>` +
              `累计命中：${(d.hitCount ?? 0).toLocaleString()}<br/>` +
              `<span style="color:#63768b">点击节点下钻查看该分组接口</span>`
            )
          }
          if (d.kind === 'caller') {
            return `<strong>调用方 ${safeName}</strong><br/>累计调用：${(d.callCount ?? 0).toLocaleString()} 次`
          }
          return `<strong>${safeName}</strong><br/>接口数：${d.count ?? 0}`
        },
      },
      legend: {
        data: categories.map((c) => c.name),
        top: 6,
        left: 12,
        textStyle: { color: '#52677e', fontSize: 12 },
      },
      series: [
        {
          type: 'graph',
          layout: 'force',
          roam: true,
          draggable: true,
          top: 40,
          categories,
          data: data as GraphSeriesOption['data'],
          links,
          force: {
            repulsion: 260,
            edgeLength: [70, 145],
            gravity: 0.08,
          },
          emphasis: { focus: 'adjacency' },
        },
      ],
    }

    return {
      option,
      mode: 'module',
      displayedEndpoints: endpoints.length,
      totalEndpoints: endpoints.length,
      displayedModules,
      totalModules: candidateModules.length,
      displayedCallers: topCallers.length,
    }
  }

  // 端点级图谱（接口数 ≤ 28 或无更多子模块可聚合时取重点 Top MAX_ENDPOINT_GRAPH_NODES）
  const rankedEndpoints = [...endpoints]
    .sort((a, b) => {
      const sa = endpointStats.get(a.id)
      const sb = endpointStats.get(b.id)
      const scoreA = (sa?.callCount ?? 0) * 10 + (a.open_findings_count ?? 0) * 100 + (a.hit_count ?? 0)
      const scoreB = (sb?.callCount ?? 0) * 10 + (b.open_findings_count ?? 0) * 100 + (b.hit_count ?? 0)
      if (scoreB !== scoreA) return scoreB - scoreA
      return a.endpoint_key.localeCompare(b.endpoint_key)
    })
    .slice(0, MAX_ENDPOINT_GRAPH_NODES)

  const visibleEndpointIds = new Set(rankedEndpoints.map((ep) => ep.id))
  const statusKeys = Object.keys(API_ENDPOINT_STATUS_META)
  const categories = [
    { name: '当前作用域', itemStyle: { color: '#21344d' } },
    ...statusKeys.map((status) => ({
      name: API_ENDPOINT_STATUS_META[status].label,
      itemStyle: { color: STATUS_COLOR_MAP[status] ?? '#2f6fed' },
    })),
    { name: '外部调用方', itemStyle: { color: '#6b7e92' } },
  ]
  const callerCategoryIdx = categories.length - 1

  const data: Array<Record<string, unknown>> = [
    {
      id: 'hub',
      kind: 'hub',
      name: scopeLabel,
      count: endpoints.length,
      category: 0,
      symbolSize: 38,
      label: { show: true, fontSize: 12, fontWeight: 600, color: '#21344d', position: 'bottom' },
    },
  ]

  const links: NonNullable<GraphSeriesOption['links']> = []

  for (const ep of rankedEndpoints) {
    const stat = endpointStats.get(ep.id)
    const statusIdx = statusKeys.indexOf(ep.asset_status)
    const hasRisk = (ep.open_findings_count ?? 0) > 0
    const weight = (stat?.callCount ?? 0) + (ep.hit_count ?? 0)
    const symbolSize = Math.min(30, Math.max(15, Math.round(14 + Math.log2(weight + 1) * 2.4)))

    data.push({
      id: ep.id,
      kind: 'endpoint',
      name: compactEndpointLabel(ep.http_method, ep.normalized_path),
      endpoint: ep,
      hitCount: ep.hit_count ?? 0,
      riskCount: ep.open_findings_count ?? 0,
      callCount: stat?.callCount ?? 0,
      assetStatus: ep.asset_status,
      category: statusIdx >= 0 ? statusIdx + 1 : 1,
      symbolSize,
      itemStyle: hasRisk
        ? { borderColor: '#d9363e', borderWidth: 2.5, shadowBlur: 8, shadowColor: 'rgba(217, 54, 62, 0.35)' }
        : undefined,
      label: {
        show: rankedEndpoints.length <= 24,
        fontSize: 10,
        color: '#2f455e',
        position: 'right',
      },
    })

    links.push({
      source: 'hub',
      target: ep.id,
      value: ep.hit_count ?? 0,
      lineStyle: { color: '#cfdbe8', width: 1, opacity: 0.55 },
    })
  }

  // 叠加调用边（API → API 与 外部调用方 → API）
  const relevantEdges = edges.filter(
    (e) =>
      visibleEndpointIds.has(e.target_endpoint_id) &&
      (endpointSet.has(e.target_endpoint_id)),
  )
  const callerTotals = new Map<string, number>()
  for (const e of relevantEdges) {
    if (!e.source_endpoint_id || !visibleEndpointIds.has(e.source_endpoint_id)) {
      const caller = e.caller_fingerprint || 'unknown'
      callerTotals.set(caller, (callerTotals.get(caller) ?? 0) + e.call_count)
    }
  }
  const topCallerSet = new Set(
    [...callerTotals.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_CALLER_GRAPH_NODES)
      .map(([c]) => c),
  )

  const maxCallCount = Math.max(1, ...relevantEdges.map((e) => e.call_count))
  const addedCallers = new Set<string>()

  for (const e of relevantEdges) {
    let source = e.source_endpoint_id && visibleEndpointIds.has(e.source_endpoint_id)
      ? e.source_endpoint_id
      : undefined
    if (!source) {
      const caller = e.caller_fingerprint || 'unknown'
      if (!topCallerSet.has(caller)) continue
      source = `caller:${caller}`
      if (!addedCallers.has(source)) {
        addedCallers.add(source)
        data.push({
          id: source,
          kind: 'caller',
          name: truncateMiddle(caller, 8, 4),
          callCount: callerTotals.get(caller) ?? e.call_count,
          category: callerCategoryIdx,
          symbol: 'diamond',
          symbolSize: 15,
          label: { show: true, fontSize: 10, color: '#63768b', position: 'left' },
        })
      }
    }

    links.push({
      source,
      target: e.target_endpoint_id,
      value: e.call_count,
      symbol: ['none', 'arrow'],
      symbolSize: [4, 8],
      lineStyle: {
        color: '#2f6fed',
        width: 1.2 + (e.call_count / maxCallCount) * 4.5,
        curveness: 0.16,
        opacity: 0.78,
      },
    })
  }

  const option: EChartOption = {
    tooltip: {
      trigger: 'item',
      formatter: (params: unknown) => {
        const p = params as {
          dataType?: string
          data?: Partial<TopologyGraphDatum> & { value?: number; source?: string }
        }
        if (p.dataType === 'edge') {
          if (p.data?.source === 'hub') {
            return `归属接口 · 累计命中 ${(p.data?.value ?? 0).toLocaleString()} 次`
          }
          return `调用次数：<strong>${(p.data?.value ?? 0).toLocaleString()}</strong>`
        }
        const d = p.data
        if (!d) return ''
        if (d.kind === 'endpoint' && d.endpoint) {
          const statusMeta = API_ENDPOINT_STATUS_META[d.endpoint.asset_status]
          const fullKey = escapeHtml(d.endpoint.endpoint_key || `${d.endpoint.http_method} ${d.endpoint.normalized_path}`)
          const statusLabel = escapeHtml(statusMeta?.label ?? d.endpoint.asset_status)
          return (
            `<div style="max-width:420px;word-break:break-all">` +
            `<strong>${fullKey}</strong><br/>` +
            `状态：${statusLabel}<br/>` +
            `命中次数：${(d.hitCount ?? 0).toLocaleString()} ｜ 关联调用：${(d.callCount ?? 0).toLocaleString()}<br/>` +
            `未闭环风险：${d.riskCount ?? 0}<br/>` +
            `<span style="color:#63768b">点击节点查看上下游调用详情</span>` +
            `</div>`
          )
        }
        if (d.kind === 'caller') {
          return `<strong>外部调用方 ${escapeHtml(d.name ?? '')}</strong><br/>累计调用：${(d.callCount ?? 0).toLocaleString()} 次`
        }
        return `<strong>${escapeHtml(d.name ?? '')}</strong><br/>接口数：${d.count ?? 0}`
      },
    },
    legend: {
      data: categories.map((c) => c.name),
      top: 6,
      left: 12,
      textStyle: { color: '#52677e', fontSize: 12 },
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        draggable: true,
        top: 42,
        categories,
        data: data as GraphSeriesOption['data'],
        links,
        force: {
          repulsion: rankedEndpoints.length > 20 ? 180 : 240,
          edgeLength: [56, 130],
          gravity: 0.09,
        },
        emphasis: { focus: 'adjacency' },
      },
    ],
  }

  return {
    option,
    mode: 'endpoint',
    displayedEndpoints: rankedEndpoints.length,
    totalEndpoints: endpoints.length,
    displayedModules: 0,
    totalModules: candidateModules.length,
    displayedCallers: addedCallers.size,
  }
}
