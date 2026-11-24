import type { GraphSeriesOption } from 'echarts/charts'
import type { EChartOption } from '../../components/EChart'
import type {
  ApiGraphEdge,
  ApiGraphNode,
  ServiceRPCEdge,
  ServiceRPCNode,
} from '../../api/apiSecurity'
import { escapeHtml } from '../../utils/format'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'

export type GraphLayoutMode = 'force' | 'circular'

/** 接口资产状态 → 图谱节点配色 */
export const IDENTITY_NODE_COLOR_BY_STATUS: Record<string, string> = {
  DISCOVERED: '#1677ff',
  CONFIRMED: '#52c41a',
  IGNORED: '#bfbfbf',
  DEPRECATED: '#fa8c16',
  ZOMBIE: '#722ed1',
}

export const EXTERNAL_CALLER_COLOR = '#8c8c8c'

/** 微服务 RPC 证据类型中文词表 */
export const RPC_EVIDENCE_META: Record<string, { label: string; color: string; description: string }> = {
  OTEL_SPAN_PAIRED: {
    label: 'OTel 双端配对',
    color: 'green',
    description: '同一 TraceId 下 Client Span 与对端 Server Span 精确配对',
  },
  AGENT_TRACE_PAIRED: {
    label: 'Sensor 双端配对',
    color: 'cyan',
    description: '云 API Sensor 捕获的 Client↔Server 真实链路配对',
  },
  OTEL_CLIENT_SPAN: {
    label: 'OTel 客户端视角',
    color: 'blue',
    description: '基于客户端 Span 的 peer.service / rpc.service / server.address 派生',
  },
  AGENT_GRPC_OBSERVED: {
    label: 'Agent gRPC 观测',
    color: 'purple',
    description: '分布式流量 Agent 捕获的 gRPC 协议调用元数据',
  },
  AGENT_CLIENT_OBSERVED: {
    label: 'Sensor 单侧观测',
    color: 'geekblue',
    description: '云 API Sensor 单侧观测到的服务出向调用',
  },
}

/** 数据源可用状态标签 */
export const RPC_SOURCE_STATUS_META: Record<string, { label: string; color: string }> = {
  READY: { label: '已接入', color: 'success' },
  EMPTY: { label: '暂无数据', color: 'default' },
  NOT_CONFIGURED: { label: '未配置', color: 'warning' },
  UNAVAILABLE: { label: '暂不可用', color: 'error' },
}

export function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export function formatLatencyMs(ms: number | undefined): string {
  if (ms === undefined || Number.isNaN(ms)) return '-'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`
  return `${ms.toFixed(1)} ms`
}

export function formatErrorRate(rate: number | undefined): string {
  if (rate === undefined || Number.isNaN(rate)) return '0.0%'
  return `${(rate * 100).toFixed(1)}%`
}

/** 节点名称区分：当同 endpoint_key 出现多次时附带应用名/Host，彻底避免重名混淆 */
export function buildEndpointDisplayLabel(
  node: ApiGraphNode,
  duplicateKeySet: Set<string>,
): string {
  if (!duplicateKeySet.has(node.endpoint_key)) {
    return node.endpoint_key
  }
  const scopeParts = [node.application_name, node.host].filter(Boolean)
  if (scopeParts.length === 0) {
    return `${node.endpoint_key} (${node.id.slice(0, 6)})`
  }
  return `${node.endpoint_key} [${scopeParts.join(' · ')}]`
}

export interface AggregatedIdentityEdge {
  key: string
  sourceId: string
  targetId: string
  sourceLabel: string
  targetLabel: string
  isExternalCaller: boolean
  totalCalls: number
  callerCount: number
  edgeRows: ApiGraphEdge[]
}

export interface PreparedIdentityGraph {
  visibleNodes: ApiGraphNode[]
  truncatedNodeCount: number
  aggregatedEdges: AggregatedIdentityEdge[]
  duplicateKeySet: Set<string>
  distinctCallers: number
}

/**
 * 预处理身份 10 分钟轨迹图谱数据：
 * 1) 识别同名 endpoint_key 集合用于标签消歧；
 * 2) 当节点数超过 maxNodes 时按调用量/连接度保留重点 Top N，防止画布挤成一团；
 * 3) 按 (source -> target) 合并多身份重复连线，避免两点之间叠画大量重复弧线。
 */
export function prepareIdentityGraph(
  nodes: ApiGraphNode[],
  edges: ApiGraphEdge[],
  maxNodes: number,
): PreparedIdentityGraph {
  const callerSet = new Set<string>()
  const nodeCalls = new Map<string, number>()
  const nodeDegree = new Map<string, number>()
  for (const e of edges) {
    if (e.caller_fingerprint) callerSet.add(e.caller_fingerprint)
    nodeCalls.set(e.target_endpoint_id, (nodeCalls.get(e.target_endpoint_id) ?? 0) + e.call_count)
    nodeDegree.set(e.target_endpoint_id, (nodeDegree.get(e.target_endpoint_id) ?? 0) + 1)
    if (e.source_endpoint_id) {
      nodeCalls.set(e.source_endpoint_id, (nodeCalls.get(e.source_endpoint_id) ?? 0) + e.call_count)
      nodeDegree.set(e.source_endpoint_id, (nodeDegree.get(e.source_endpoint_id) ?? 0) + 1)
    }
  }

  let visibleNodes = [...nodes]
  let truncatedNodeCount = 0
  if (maxNodes > 0 && visibleNodes.length > maxNodes) {
    visibleNodes.sort((a, b) => {
      const cDiff = (nodeCalls.get(b.id) ?? 0) - (nodeCalls.get(a.id) ?? 0)
      if (cDiff !== 0) return cDiff
      const dDiff = (nodeDegree.get(b.id) ?? 0) - (nodeDegree.get(a.id) ?? 0)
      if (dDiff !== 0) return dDiff
      return (b.hit_count ?? 0) - (a.hit_count ?? 0)
    })
    truncatedNodeCount = visibleNodes.length - maxNodes
    visibleNodes = visibleNodes.slice(0, maxNodes)
  }

  const keyCounts = new Map<string, number>()
  for (const n of visibleNodes) {
    keyCounts.set(n.endpoint_key, (keyCounts.get(n.endpoint_key) ?? 0) + 1)
  }
  const duplicateKeySet = new Set<string>()
  for (const [k, count] of keyCounts) {
    if (count > 1) duplicateKeySet.add(k)
  }

  const visibleNodeMap = new Map(visibleNodes.map((n) => [n.id, n]))
  const aggMap = new Map<string, { edge: AggregatedIdentityEdge; callers: Set<string> }>()

  for (const e of edges) {
    const targetNode = visibleNodeMap.get(e.target_endpoint_id)
    if (!targetNode) continue

    let sourceId = e.source_endpoint_id ?? ''
    let sourceLabel = ''
    let isExternalCaller = false
    if (!sourceId || !visibleNodeMap.has(sourceId)) {
      if (e.source_endpoint_id) {
        // 源节点因 Top-N 截断不在当前画布内，跳过该半边保持画布整洁
        continue
      }
      sourceId = `caller:${e.caller_fingerprint}`
      sourceLabel = truncateMiddle(e.caller_fingerprint)
      isExternalCaller = true
    } else {
      sourceLabel = buildEndpointDisplayLabel(visibleNodeMap.get(sourceId)!, duplicateKeySet)
    }

    if (sourceId === e.target_endpoint_id) continue

    const targetLabel = buildEndpointDisplayLabel(targetNode, duplicateKeySet)
    const aggKey = `${sourceId}->${e.target_endpoint_id}`
    let acc = aggMap.get(aggKey)
    if (!acc) {
      acc = {
        edge: {
          key: aggKey,
          sourceId,
          targetId: e.target_endpoint_id,
          sourceLabel,
          targetLabel,
          isExternalCaller,
          totalCalls: 0,
          callerCount: 0,
          edgeRows: [],
        },
        callers: new Set<string>(),
      }
      aggMap.set(aggKey, acc)
    }
    acc.edge.totalCalls += e.call_count
    if (e.caller_fingerprint) acc.callers.add(e.caller_fingerprint)
    acc.edge.edgeRows.push(e)
  }

  const aggregatedEdges = Array.from(aggMap.values())
    .map(({ edge, callers }) => ({
      ...edge,
      callerCount: Math.max(callers.size, edge.edgeRows.length),
    }))
    .sort((a, b) => b.totalCalls - a.totalCalls)

  return {
    visibleNodes,
    truncatedNodeCount,
    aggregatedEdges,
    duplicateKeySet,
    distinctCallers: callerSet.size,
  }
}

/** 构造「后端微服务真实 RPC / 服务间调用」ECharts 图谱配置 */
export function buildServiceRpcGraphOption(
  nodes: ServiceRPCNode[],
  edges: ServiceRPCEdge[],
  layout: GraphLayoutMode,
): EChartOption {
  const categories = [
    { name: '后端微服务', itemStyle: { color: '#1677ff' } },
    { name: '异常服务（错误率≥5%）', itemStyle: { color: '#ff4d4f' } },
    { name: '外部目标', itemStyle: { color: '#8c8c8c' } },
  ]
  const nodeByName = new Map(nodes.map((n) => [n.name, n]))
  const maxCalls = Math.max(1, ...edges.map((e) => e.calls))
  const maxNodeTraffic = Math.max(1, ...nodes.map((n) => n.inbound_calls + n.outbound_calls))

  const graphNodes: NonNullable<GraphSeriesOption['data']> = nodes.map((n) => {
    const traffic = n.inbound_calls + n.outbound_calls
    const ratio = Math.log1p(traffic) / Math.log1p(maxNodeTraffic)
    const symbolSize = Math.round(24 + ratio * 20)
    const category =
      n.node_type !== 'SERVICE' ? 2 : n.error_rate >= 0.05 ? 1 : 0
    return {
      id: n.id,
      name: n.name,
      category,
      symbolSize,
      value: traffic,
      label: {
        show: true,
        position: layout === 'circular' ? 'right' : 'bottom',
        fontSize: 12,
        fontWeight: 500,
        color: '#1f2937',
      },
    }
  })

  const edgeByKey = new Map<string, ServiceRPCEdge>()
  const graphLinks: NonNullable<GraphSeriesOption['links']> = edges.map((e) => {
    const linkKey = `${e.source}->${e.target}|${e.protocol}`
    edgeByKey.set(linkKey, e)
    const isErr = e.error_rate >= 0.05
    const color = isErr
      ? '#ff4d4f'
      : e.call_category === 'RPC'
        ? '#1677ff'
        : '#13c2c2'
    const width = Number((1.8 + (e.calls / maxCalls) * 4.8).toFixed(2))
    return {
      source: e.source,
      target: e.target,
      value: e.calls,
      name: linkKey,
      lineStyle: {
        color,
        width,
        type: e.paired ? 'solid' : 'dashed',
        curveness: 0.16,
        opacity: 0.85,
      },
      label: {
        show: edges.length <= 24,
        formatter: `${e.protocol} (${e.calls})`,
        fontSize: 10,
        color: isErr ? '#cf1322' : '#4b5563',
      },
    }
  })

  return {
    tooltip: {
      trigger: 'item',
      confine: true,
      formatter: (params) => {
        const p = params as {
          dataType?: string
          name?: string
          data?: { name?: string; source?: string; target?: string }
        }
        if (p.dataType === 'edge') {
          const edge = p.data?.name ? edgeByKey.get(p.data.name) : undefined
          if (!edge) return escapeHtml(`${p.data?.source ?? ''} → ${p.data?.target ?? ''}`)
          const evMeta = RPC_EVIDENCE_META[edge.evidence_type]?.label ?? edge.evidence_type
          const topOps = edge.operations.slice(0, 3).map((op) => `<code>${escapeHtml(op)}</code>`).join('<br/>')
          return [
            `<strong>${escapeHtml(edge.source)} → ${escapeHtml(edge.target)}</strong>`,
            `协议：${escapeHtml(edge.protocol)} · ${escapeHtml(evMeta)}`,
            `调用次数：${edge.calls} · 错误率：${formatErrorRate(edge.error_rate)}`,
            `平均耗时：${formatLatencyMs(edge.avg_ms)} · P95：${formatLatencyMs(edge.p95_ms)}`,
            topOps ? `代表方法：<br/>${topOps}` : '',
          ]
            .filter(Boolean)
            .join('<br/>')
        }
        const node = p.name ? nodeByName.get(p.name) : undefined
        if (!node) return escapeHtml(p.name ?? '')
        const typeLabel = node.node_type === 'SERVICE' ? '后端微服务' : '外部目标'
        return [
          `<strong>${escapeHtml(node.name)}</strong>（${typeLabel}）`,
          `协议：${escapeHtml(node.protocols.join(' / ') || '-')}`,
          `出站调用：${node.outbound_calls} 次（${node.outbound_edges} 条边）`,
          `入站调用：${node.inbound_calls} 次（${node.inbound_edges} 条边）`,
          `错误率：${formatErrorRate(node.error_rate)} · 平均耗时：${formatLatencyMs(node.avg_ms)}`,
        ].join('<br/>')
      },
    },
    legend: [{ data: categories.map((c) => c.name), top: 0 }],
    series: [
      {
        type: 'graph',
        layout,
        roam: true,
        draggable: layout === 'force',
        top: 40,
        bottom: 24,
        categories,
        data: graphNodes,
        links: graphLinks,
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: [4, 10],
        circular: { rotateLabel: false },
        force: {
          repulsion: 480,
          edgeLength: [120, 220],
          gravity: 0.08,
          friction: 0.6,
        },
        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 4 },
        },
      },
    ],
  }
}

/** 构造「同一已识别身份 10 分钟连续访问轨迹」ECharts 图谱配置 */
export function buildIdentityGraphOption(
  prepared: PreparedIdentityGraph,
  layout: GraphLayoutMode,
): EChartOption {
  const categories = [
    ...Object.entries(API_ENDPOINT_STATUS_META).map(([status, meta]) => ({
      name: meta.label,
      itemStyle: { color: IDENTITY_NODE_COLOR_BY_STATUS[status] ?? EXTERNAL_CALLER_COLOR },
    })),
    { name: '外部调用方', itemStyle: { color: EXTERNAL_CALLER_COLOR } },
  ]
  const statusKeys = Object.keys(API_ENDPOINT_STATUS_META)
  const categoryIndex = (status: string) => {
    const idx = statusKeys.indexOf(status)
    return idx >= 0 ? idx : categories.length - 1
  }

  const nodeById = new Map(prepared.visibleNodes.map((n) => [n.id, n]))
  const maxCalls = Math.max(1, ...prepared.aggregatedEdges.map((e) => e.totalCalls))
  const degreeMap = new Map<string, number>()
  for (const e of prepared.aggregatedEdges) {
    degreeMap.set(e.sourceId, (degreeMap.get(e.sourceId) ?? 0) + e.totalCalls)
    degreeMap.set(e.targetId, (degreeMap.get(e.targetId) ?? 0) + e.totalCalls)
  }
  const maxDegree = Math.max(1, ...degreeMap.values())

  const data: NonNullable<GraphSeriesOption['data']> = prepared.visibleNodes.map((n) => {
    const label = buildEndpointDisplayLabel(n, prepared.duplicateKeySet)
    const weight = degreeMap.get(n.id) ?? 0
    const size = Math.round(16 + (Math.log1p(weight) / Math.log1p(maxDegree)) * 14)
    return {
      id: n.id,
      name: label,
      category: categoryIndex(n.asset_status),
      symbolSize: size,
      label: {
        show: prepared.visibleNodes.length <= 45,
        position: 'right',
        fontSize: 11,
        color: '#374151',
      },
    }
  })

  const addedCallers = new Set<string>()
  const edgeByKey = new Map<string, AggregatedIdentityEdge>()
  const links: NonNullable<GraphSeriesOption['links']> = []

  for (const e of prepared.aggregatedEdges) {
    if (e.isExternalCaller && !addedCallers.has(e.sourceId)) {
      addedCallers.add(e.sourceId)
      data.push({
        id: e.sourceId,
        name: e.sourceLabel,
        category: categories.length - 1,
        symbolSize: 12,
        label: { show: prepared.visibleNodes.length <= 45, position: 'right', fontSize: 10 },
      })
    }
    edgeByKey.set(e.key, e)
    links.push({
      source: e.sourceId,
      target: e.targetId,
      name: e.key,
      value: e.totalCalls,
      lineStyle: {
        width: Number((1.4 + (e.totalCalls / maxCalls) * 4.6).toFixed(2)),
        curveness: 0.14,
        opacity: 0.72,
      },
    })
  }

  return {
    tooltip: {
      trigger: 'item',
      confine: true,
      formatter: (params) => {
        const p = params as {
          dataType?: string
          data?: { id?: string; name?: string }
        }
        if (p.dataType === 'edge') {
          const agg = p.data?.name ? edgeByKey.get(p.data.name) : undefined
          if (!agg) return ''
          return [
            `<strong>${escapeHtml(agg.sourceLabel)} → ${escapeHtml(agg.targetLabel)}</strong>`,
            `连续访问次数：${agg.totalCalls} 次`,
            `涉及已识别身份：${agg.callerCount} 个（10 分钟窗口内相邻路径）`,
          ].join('<br/>')
        }
        const id = p.data?.id ?? ''
        const node = nodeById.get(id)
        if (!node) {
          return `外部调用方：${escapeHtml(p.data?.name ?? '')}`
        }
        const statusLabel = API_ENDPOINT_STATUS_META[node.asset_status]?.label ?? node.asset_status
        return [
          `<strong>${escapeHtml(node.endpoint_key)}</strong>`,
          node.application_name ? `所属应用：${escapeHtml(node.application_name)}` : '',
          node.host ? `Host：${escapeHtml(node.host)}` : '',
          `状态：${escapeHtml(statusLabel)} · 协议：${escapeHtml(node.protocol_type || 'REST')}`,
          `累计命中：${node.hit_count ?? 0} · 未闭环风险：${node.open_findings_count ?? 0}`,
        ]
          .filter(Boolean)
          .join('<br/>')
      },
    },
    legend: [{ data: categories.map((c) => c.name), top: 0 }],
    series: [
      {
        type: 'graph',
        layout,
        roam: true,
        draggable: layout === 'force',
        top: 38,
        bottom: 16,
        categories,
        data,
        links,
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: [4, 9],
        force: {
          repulsion: 360,
          edgeLength: [95, 180],
          gravity: 0.09,
          friction: 0.6,
        },
        lineStyle: { color: 'source', curveness: 0.14, opacity: 0.72 },
        emphasis: {
          focus: 'adjacency',
          label: { show: true },
        },
      },
    ],
  }
}
