import type { EChartOption } from '../components/EChart'
import type { CustomSeriesOption } from 'echarts/charts'
import type { DataFlowEdge, DataFlowGraph, DataFlowNode } from '../api/apiDataFlow'
import { escapeHtml } from './format'

export interface FlowPoint {
  x: number
  y: number
}

export interface DataFlowLayoutOptions {
  positions?: Record<string, FlowPoint>
  collapsedGroups?: string[]
  maxDepth?: number
  dragging?: boolean
  viewportWidth?: number
  viewportHeight?: number
}

const NODE_WIDTH = 224
const NODE_HEIGHT = 86
const COLUMN_GAP = 324
const ROW_GAP = 138
const GROUP_PAD = 20
const GROUP_HEADER = 32
const GROUP_GAP_X = 56
const GROUP_GAP_Y = 48
const CANVAS_PAD = 40
const TRACK_GAP = 14
const TRACK_RADIUS = 8
const TRACK_NEUTRAL = '#b6c1ce'
const TYPE_COLORS: Record<string, string> = {
  SERVICE: '#3568b8',
  ENDPOINT: '#3568b8',
  KAFKA: '#16836d',
  CLIENT: '#607d8b',
  EXTERNAL: '#687386',
}
const FIELD_COLORS: Record<string, string> = {
  PHONE: '#f2c894',
  CN_ID: '#d8bfe8',
  ACCOUNT: '#a9cbe8',
  EMAIL: '#a9ddd6',
  ADDRESS: '#b8d9b4',
  ID: '#c5ceda',
  BANK_CARD: '#eab8a8',
  PASSPORT: '#b8c4e8',
  TOKEN: '#e7b3c2',
  PASSWORD: '#d4b4cd',
}
const FIELD_LABEL_COLORS: Record<string, string> = {
  PHONE: '#765015',
  CN_ID: '#654477',
  ACCOUNT: '#365f7d',
  EMAIL: '#286a6c',
  ADDRESS: '#3c6b50',
  ID: '#465564',
  BANK_CARD: '#7b4c3d',
  PASSPORT: '#4c5a7f',
  TOKEN: '#7a4149',
  PASSWORD: '#6b4561',
}
const GROUP_COLORS = ['#edf2f8', '#eef5f1', '#f4f1ec', '#f1eff7', '#eff3f5']
const GROUP_STROKES = ['#a6b9cf', '#a3c2b2', '#c8bda7', '#b6a9c8', '#a9b8c3']

export const DATA_TYPE_LABELS: Record<string, string> = {
  PHONE: '手机号',
  CN_ID: '身份证号',
  ACCOUNT: '账号',
  EMAIL: '邮箱',
  ADDRESS: '地址',
  ID: '用户标识',
  BANK_CARD: '银行卡号',
  PASSPORT: '护照号',
  TOKEN: '访问令牌',
  PASSWORD: '密码',
}

export function dataFlowDataTypes(edge: DataFlowEdge, side?: 'REQUEST' | 'RESPONSE' | 'MESSAGE'): string[] {
  if (!side) return edge.data_types
  const observed = new Set((edge.fields ?? []).filter((field) => field.side === side && field.data_type !== '').map((field) => field.data_type))
  const ordered = edge.data_types.filter((type) => observed.has(type))
  for (const type of observed) {
    if (!ordered.includes(type)) ordered.push(type)
  }
  return ordered
}

export function dataFlowNetworkZoneLabel(zone?: string): string {
  if (zone === 'PUBLIC') return '公网来源'
  if (zone === 'INTERNAL') return '内网来源'
  return '外部来源/区域未知'
}

export function dataFlowBoundaryTypeLabel(type?: string): string {
  return type === 'PUBLIC_TO_INTERNAL' ? '公网 → 内网' : '边界未知'
}

export function dataFlowBoundaryEvidenceLabel(evidence: string): string {
  const labels: Record<string, string> = {
    DIRECT_PEER: '直连对端',
    TRUSTED_PROXY: '可信代理',
    GATEWAY: '网关',
    MISSING_CLIENT_ADDRESS: '缺少客户端地址',
    MISSING_SERVER_ADDRESS: '缺少服务端地址',
    UNTRUSTED_CLIENT_SOURCE: '客户端来源不可信',
  }
  return labels[evidence] ?? '未知证据'
}

function environmentGroupName(node: DataFlowNode): string {
  if (node.group_name) return node.group_name
  if (node.type === 'KAFKA') return '消息与基础设施'
  if (node.type === 'CLIENT' || node.type === 'EXTERNAL') return '来源与外部'
  return '未分区'
}

export function dataFlowGroupNames(graph: DataFlowGraph): Map<string, string> {
  const names = new Map<string, string>()
  if (graph.view === 'network') {
    for (const node of graph.nodes) names.set(node.id, environmentGroupName(node))
    return names
  }
  const adjacency = new Map<string, Set<string>>(graph.nodes.map((node) => [node.id, new Set<string>()]))
  for (const edge of graph.edges) {
    if (!adjacency.has(edge.source_id) || !adjacency.has(edge.target_id)) continue
    adjacency.get(edge.source_id)!.add(edge.target_id)
    adjacency.get(edge.target_id)!.add(edge.source_id)
  }
  const unvisited = new Set(adjacency.keys())
  const components: DataFlowNode[][] = []
  for (const node of graph.nodes) {
    if (!unvisited.has(node.id)) continue
    const component: DataFlowNode[] = []
    const queue = [node]
    unvisited.delete(node.id)
    while (queue.length) {
      const current = queue.shift()!
      component.push(current)
      for (const neighbor of adjacency.get(current.id) ?? []) {
        if (!unvisited.has(neighbor)) continue
        unvisited.delete(neighbor)
        queue.push(graph.nodes.find((candidate) => candidate.id === neighbor)!)
      }
    }
    components.push(component)
  }
  const componentKey = (component: DataFlowNode[]) => component.map((node) => node.id).sort()[0] ?? ''
  components.sort((a, b) => b.length - a.length || componentKey(a).localeCompare(componentKey(b)))
  components.forEach((component, index) => {
    const groupName = graph.view === 'boundary' ? '内外网边界' : '独立系统交互'
    const name = `${groupName} · ${String(index + 1).padStart(2, '0')}`
    for (const node of component) names.set(node.id, name)
  })
  return names
}

export function dataFlowDepths(nodes: DataFlowNode[], edges: DataFlowEdge[]): Map<string, number> {
  const depths = new Map<string, number>()
  const indegree = new Map<string, number>()
  for (const node of nodes) {
    depths.set(node.id, node.type === 'EXTERNAL' || node.type === 'CLIENT' ? 0 : 1)
    indegree.set(node.id, 0)
  }
  for (const edge of edges) {
    if (edge.source_id !== edge.target_id && indegree.has(edge.target_id)) {
      indegree.set(edge.target_id, (indegree.get(edge.target_id) ?? 0) + 1)
    }
  }
  const queue = nodes.filter((node) => indegree.get(node.id) === 0).map((node) => node.id)
  const visited = new Set<string>()
  while (queue.length) {
    const source = queue.shift()!
    if (visited.has(source)) continue
    visited.add(source)
    for (const edge of edges) {
      if (edge.source_id !== source || !depths.has(edge.target_id)) continue
      depths.set(edge.target_id, Math.max(depths.get(edge.target_id) ?? 0, (depths.get(source) ?? 0) + 1))
      const nextDegree = (indegree.get(edge.target_id) ?? 0) - 1
      indegree.set(edge.target_id, nextDegree)
      if (nextDegree === 0) queue.push(edge.target_id)
    }
  }
  return depths
}

function text(x: number, y: number, value: string, fill: string, font: string, width?: number) {
  return {
    type: 'text' as const,
    style: { x, y, text: value, fill, font, ...(width ? { width, overflow: 'truncate' as const } : {}) },
    silent: true,
  }
}

type RenderAPI = Parameters<NonNullable<CustomSeriesOption['renderItem']>>[1]
type PixelPoint = [number, number]

function scaledSize(api: RenderAPI, value: [number, number]): [number, number] {
  const size = api.size?.(value) ?? value
  return Array.isArray(size) ? [size[0], size[1]] : [size, size]
}

function hash(value: string): number {
  let result = 0
  for (const char of value) result = (result * 31 + char.codePointAt(0)!) >>> 0
  return result
}

function orthogonalTrack(source: PixelPoint, target: PixelPoint, offset: number, nodeWidth: number, nodeHeight: number): PixelPoint[] {
  const horizontal = Math.abs(target[0] - source[0]) >= Math.abs(target[1] - source[1])
  const sign = (horizontal ? target[0] - source[0] : target[1] - source[1]) >= 0 ? 1 : -1
  if (horizontal) {
    const start: PixelPoint = [source[0] + sign * nodeWidth / 2, source[1] + offset]
    const end: PixelPoint = [target[0] - sign * nodeWidth / 2, target[1] + offset]
    if (Math.abs(source[1] - target[1]) < 0.01) return [start, end]
    const middleX = (start[0] + end[0]) / 2 + offset
    return [start, [middleX, start[1]], [middleX, end[1]], end]
  }
  const start: PixelPoint = [source[0] + offset, source[1] + sign * nodeHeight / 2]
  const end: PixelPoint = [target[0] + offset, target[1] - sign * nodeHeight / 2]
  if (Math.abs(source[0] - target[0]) < 0.01) return [start, end]
  const middleY = (start[1] + end[1]) / 2 + offset
  return [start, [start[0], middleY], [end[0], middleY], end]
}

function simplifiedOrthogonalPoints(points: PixelPoint[]): PixelPoint[] {
  const result: PixelPoint[] = []
  for (const point of points) {
    const previous = result[result.length - 1]
    if (previous && Math.abs(previous[0] - point[0]) < 0.01 && Math.abs(previous[1] - point[1]) < 0.01) continue
    if (result.length >= 2) {
      const first = result[result.length - 2]
      const incoming: PixelPoint = [previous[0] - first[0], previous[1] - first[1]]
      const outgoing: PixelPoint = [point[0] - previous[0], point[1] - previous[1]]
      const collinear = Math.abs(incoming[0] * outgoing[1] - incoming[1] * outgoing[0]) < 0.01
      if (collinear && incoming[0] * outgoing[0] + incoming[1] * outgoing[1] > 0) {
        result[result.length - 1] = point
        continue
      }
    }
    result.push(point)
  }
  return result
}

function roundedOrthogonalPath(points: PixelPoint[], radius: number): string {
  const simplified = simplifiedOrthogonalPoints(points)
  if (!simplified.length) return ''
  const format = (point: PixelPoint) => `${point[0].toFixed(2)} ${point[1].toFixed(2)}`
  let path = `M ${format(simplified[0])}`
  for (let index = 1; index < simplified.length - 1; index += 1) {
    const previous = simplified[index - 1]
    const current = simplified[index]
    const next = simplified[index + 1]
    const incoming: PixelPoint = [current[0] - previous[0], current[1] - previous[1]]
    const outgoing: PixelPoint = [next[0] - current[0], next[1] - current[1]]
    const incomingLength = Math.hypot(...incoming)
    const outgoingLength = Math.hypot(...outgoing)
    const corner = Math.min(radius, incomingLength / 2, outgoingLength / 2)
    const entry: PixelPoint = [current[0] - incoming[0] / incomingLength * corner, current[1] - incoming[1] / incomingLength * corner]
    const exit: PixelPoint = [current[0] + outgoing[0] / outgoingLength * corner, current[1] + outgoing[1] / outgoingLength * corner]
    path += ` L ${format(entry)} Q ${format(current)} ${format(exit)}`
  }
  return `${path} L ${format(simplified[simplified.length - 1])}`
}

function trackLabelPoint(points: PixelPoint[], phase: number): PixelPoint {
  let start = points[0]
  let end = points[points.length - 1]
  let longest = -1
  for (let index = 1; index < points.length; index += 1) {
    const length = Math.hypot(points[index][0] - points[index - 1][0], points[index][1] - points[index - 1][1])
    if (length > longest) {
      longest = length
      start = points[index - 1]
      end = points[index]
    }
  }
  const horizontal = Math.abs(end[0] - start[0]) >= Math.abs(end[1] - start[1])
  return [start[0] + (end[0] - start[0]) * phase + (horizontal ? 0 : 9), start[1] + (end[1] - start[1]) * phase + (horizontal ? -8 : 0)]
}

function trackColor(dataType: string): string {
  return FIELD_COLORS[dataType] ?? TRACK_NEUTRAL
}

function trackLabelColor(dataType: string): string {
  return FIELD_LABEL_COLORS[dataType] ?? '#405164'
}

interface ServiceGroupLayout {
  points: Map<string, FlowPoint>
  width: number
  height: number
  rowCount: number
}

function createServiceGroupLayout(nodes: DataFlowNode[], depths: Map<string, number>, normalizeDepth: boolean): ServiceGroupLayout {
  const byDepth = new Map<number, DataFlowNode[]>()
  for (const node of nodes) {
    const depth = depths.get(node.id) ?? 0
    byDepth.set(depth, [...(byDepth.get(depth) ?? []), node])
  }
  const minDepth = normalizeDepth ? Math.min(...byDepth.keys()) : 0
  const maxDepth = Math.max(...byDepth.keys())
  const points = new Map<string, FlowPoint>()
  let rowCount = 1
  for (const [depth, depthNodes] of [...byDepth.entries()].sort(([a], [b]) => a - b)) {
    depthNodes.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN') || a.id.localeCompare(b.id))
    depthNodes.forEach((node, index) => points.set(node.id, { x: (depth - minDepth) * COLUMN_GAP, y: index * ROW_GAP }))
    rowCount = Math.max(rowCount, depthNodes.length)
  }
  return {
    points,
    width: (maxDepth - minDepth) * COLUMN_GAP + NODE_WIDTH + GROUP_PAD * 2,
    height: (rowCount - 1) * ROW_GAP + NODE_HEIGHT + GROUP_HEADER + GROUP_PAD,
    rowCount,
  }
}

function layoutServiceGroups(orderedGroups: Array<[string, DataFlowNode[]]>, depths: Map<string, number>, viewportWidth: number, positions?: Record<string, FlowPoint>) {
  const coordinates = new Map<string, FlowPoint>()
  if (!orderedGroups.length) return { coordinates, rowCount: 0 }
  if (orderedGroups.length === 1) {
    const layout = createServiceGroupLayout(orderedGroups[0][1], depths, false)
    for (const [id, point] of layout.points) coordinates.set(id, positions?.[id] ?? point)
    return { coordinates, rowCount: layout.rowCount }
  }
  const layouts = orderedGroups.map(([, nodes]) => createServiceGroupLayout(nodes, depths, true))
  const availableWidth = Math.max(NODE_WIDTH + GROUP_PAD * 2, viewportWidth / 0.85 - CANVAS_PAD * 2)
  const rows: Array<{ layouts: ServiceGroupLayout[]; width: number }> = []
  for (const layout of layouts) {
    const current = rows[rows.length - 1]
    if (!current) {
      rows.push({ layouts: [layout], width: layout.width })
      continue
    }
    const nextWidth = current.width + GROUP_GAP_X + layout.width
    if (nextWidth > availableWidth) rows.push({ layouts: [layout], width: layout.width })
    else {
      current.layouts.push(layout)
      current.width = nextWidth
    }
  }
  const maxRowWidth = Math.max(...rows.map((row) => row.width))
  let top = 0
  let rowCount = 0
  for (const row of rows) {
    const rowHeight = Math.max(...row.layouts.map((layout) => layout.height))
    let left = (maxRowWidth - row.width) / 2
    for (const layout of row.layouts) {
      const originX = left + NODE_WIDTH / 2 + GROUP_PAD
      const originY = top + NODE_HEIGHT / 2 + GROUP_HEADER
      for (const [id, point] of layout.points) {
        coordinates.set(id, positions?.[id] ?? { x: point.x + originX, y: point.y + originY })
      }
      left += layout.width + GROUP_GAP_X
    }
    top += rowHeight + GROUP_GAP_Y
    rowCount += Math.max(...row.layouts.map((layout) => layout.rowCount))
  }
  return { coordinates, rowCount }
}

export function dataFlowLayoutRowCount(graph: DataFlowGraph, viewportWidth: number): number {
  const depths = dataFlowDepths(graph.nodes, graph.edges)
  if (graph.view === 'network') {
    const rows = new Map<number, number>()
    for (const depth of depths.values()) rows.set(depth, (rows.get(depth) ?? 0) + 1)
    return Math.max(1, ...rows.values())
  }
  const groupNames = dataFlowGroupNames(graph)
  const groups = new Map<string, DataFlowNode[]>()
  for (const node of graph.nodes) {
    const name = groupNames.get(node.id)!
    groups.set(name, [...(groups.get(name) ?? []), node])
  }
  const orderedGroups = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))
  return Math.max(1, layoutServiceGroups(orderedGroups, depths, viewportWidth).rowCount)
}

export function dataFlowGraphOption(graph: DataFlowGraph, options: DataFlowLayoutOptions = {}): EChartOption {
  const depths = dataFlowDepths(graph.nodes, graph.edges)
  const collapsed = new Set(options.collapsedGroups ?? [])
  const groupNames = dataFlowGroupNames(graph)
  const visibleNodes = graph.nodes.filter((node) => !collapsed.has(groupNames.get(node.id) ?? '') && (options.maxDepth === undefined || (depths.get(node.id) ?? 0) <= options.maxDepth))
  const visibleIDs = new Set(visibleNodes.map((node) => node.id))
  const groups = new Map<string, DataFlowNode[]>()
  for (const node of graph.nodes) {
    const name = groupNames.get(node.id)!
    groups.set(name, [...(groups.get(name) ?? []), node])
  }
  const orderedGroups = graph.view === 'network' ? [...groups.entries()] : [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))
  let coordinates = new Map<string, FlowPoint>()
  if (graph.view === 'network') {
    const byDepth = new Map<number, DataFlowNode[]>()
    for (const node of graph.nodes) {
      const depth = depths.get(node.id) ?? 0
      byDepth.set(depth, [...(byDepth.get(depth) ?? []), node])
    }
    for (const [depth, nodes] of byDepth) {
      nodes.sort((a, b) => groupNames.get(a.id)!.localeCompare(groupNames.get(b.id)!, 'zh-CN') || a.name.localeCompare(b.name))
      nodes.forEach((node, index) => {
        coordinates.set(node.id, options.positions?.[node.id] ?? { x: depth * COLUMN_GAP, y: index * ROW_GAP })
      })
    }
  } else {
    coordinates = layoutServiceGroups(orderedGroups, depths, options.viewportWidth ?? 1000, options.positions).coordinates
  }
  const renderNode: NonNullable<CustomSeriesOption['renderItem']> = (_params, api) => {
    const node = visibleNodes[_params.dataIndex]
    const point = api.coord([api.value(0), api.value(1)])
    const size = scaledSize(api, [NODE_WIDTH, NODE_HEIGHT])
    const width = size[0]
    const height = size[1]
    const color = TYPE_COLORS[node.type] ?? TYPE_COLORS.SERVICE
    const health = node.health === 'ERROR' ? '#bd3f46' : node.health === 'DEGRADED' ? '#bd841b' : '#248c67'
    const activity = graph.view === 'boundary'
      ? `${dataFlowNetworkZoneLabel(node.network_zone)} · ${node.calls.toLocaleString()} 次 · ${node.api_count} API`
      : `${node.calls.toLocaleString()} 次  ·  ${node.api_count} API`
    return {
      type: 'group',
      x: point[0],
      y: point[1],
      children: [
        { type: 'rect', shape: { x: -width / 2, y: -height / 2, width, height, r: 6 }, style: { fill: '#fcfdff', stroke: '#cbd7e4', lineWidth: 1, shadowBlur: 6, shadowColor: 'rgba(32,55,78,0.08)', shadowOffsetY: 2 } },
        { type: 'rect', shape: { x: -width / 2 + 1, y: -height / 2, width: width - 2, height: Math.max(1, scaledSize(api, [0, 2])[1]), r: [5, 5, 0, 0] }, style: { fill: color }, silent: true },
        { type: 'circle', shape: { cx: -width / 2 + scaledSize(api, [17, 0])[0], cy: -height / 2 + scaledSize(api, [0, 20])[1], r: Math.max(2, scaledSize(api, [3, 0])[0]) }, style: { fill: health }, silent: true },
        text(-width / 2 + scaledSize(api, [28, 0])[0], -height / 2 + scaledSize(api, [0, 13])[1], node.name, '#182b43', '600 13px "PingFang SC", "Microsoft YaHei", sans-serif', width * 0.84),
        text(-width / 2 + scaledSize(api, [16, 0])[0], -height / 2 + scaledSize(api, [0, 39])[1], activity, '#40536b', `${graph.view === 'boundary' ? 11 : 12}px "PingFang SC", "Microsoft YaHei", sans-serif`),
        text(-width / 2 + scaledSize(api, [16, 0])[0], -height / 2 + scaledSize(api, [0, 62])[1], `均 ${node.avg_latency_ms.toFixed(1)} ms  ·  峰值 ${node.max_latency_ms.toFixed(0)} ms`, '#68788c', '11px "PingFang SC", "Microsoft YaHei", sans-serif'),
      ],
    }
  }
  const renderEdge: NonNullable<CustomSeriesOption['renderItem']> = (_params, api) => {
    const datum = edges[_params.dataIndex]
    const source = api.coord([datum.source.x, datum.source.y]) as PixelPoint
    const target = api.coord([datum.target.x, datum.target.y]) as PixelPoint
    const [nodeWidth, nodeHeight] = scaledSize(api, [NODE_WIDTH, NODE_HEIGHT])
    const dataTypes = [...new Set(datum.edge.data_types)]
    const tracks = dataTypes.length ? dataTypes : ['']
    const trackGap = Math.max(8, scaledSize(api, [0, TRACK_GAP])[1])
    const radius = Math.max(3, Math.min(9, scaledSize(api, [TRACK_RADIUS, 0])[0]))
    const arrowSize = Math.max(3, Math.min(5, scaledSize(api, [4, 0])[0]))
    const lineWidth = Math.min(2.8, 1.1 + Math.log10(Math.max(1, datum.edge.calls)) * 0.35)
    const uncertain = datum.edge.evidence_type.includes('INFERRED') || (graph.view === 'boundary' && datum.edge.boundary_type !== 'PUBLIC_TO_INTERNAL')
    return {
      type: 'group',
      children: tracks.flatMap((dataType, index) => {
        const offset = (index - (tracks.length - 1) / 2) * trackGap
        const points = orthogonalTrack(source, target, offset, nodeWidth, nodeHeight)
        const pathData = roundedOrthogonalPath(points, radius)
        const color = trackColor(dataType)
        const end = points[points.length - 1]
        const previous = points[points.length - 2]
        const angle = Math.atan2(end[1] - previous[1], end[0] - previous[0])
        const fieldLabel = DATA_TYPE_LABELS[dataType] ?? dataType
        const labelValue = fieldLabel || (graph.view === 'boundary' ? dataFlowBoundaryTypeLabel(datum.edge.boundary_type) : '')
        const labelPhase = 0.22 + hash(`${datum.edge.id}:${dataType}`) % 5 * 0.14
        const labelAt = trackLabelPoint(points, labelPhase)
        const label = labelValue ? text(labelAt[0], labelAt[1], labelValue, trackLabelColor(dataType), '600 11px "PingFang SC", "Microsoft YaHei", sans-serif') : null
        return [
          { type: 'path' as const, name: 'flow-track-hitbox', shape: { pathData }, style: { fill: 'none', stroke: 'rgba(0,0,0,0)', lineWidth: Math.max(14, lineWidth + 12), lineCap: 'round' as const, lineJoin: 'round' as const } },
          { type: 'path' as const, name: 'flow-track-casing', shape: { pathData }, style: { fill: 'none', stroke: color, lineWidth: lineWidth + 9, opacity: 0.12, lineCap: 'round' as const, lineJoin: 'round' as const }, silent: true },
          { type: 'path' as const, name: 'flow-track-body', shape: { pathData }, style: { fill: 'none', stroke: color, lineWidth: lineWidth + 5, opacity: 0.22, lineCap: 'round' as const, lineJoin: 'round' as const }, silent: true },
          { type: 'path' as const, name: 'flow-track-rail', shape: { pathData }, style: { fill: 'none', stroke: color, lineWidth: lineWidth + 1.8, opacity: 0.42, lineCap: 'round' as const, lineJoin: 'round' as const }, silent: true },
          { type: 'path' as const, name: 'flow-track-core', shape: { pathData }, style: { fill: 'none', stroke: color, lineWidth, opacity: 0.82, lineDash: uncertain ? [6, 5] : [], lineCap: 'round' as const, lineJoin: 'round' as const }, silent: true },
          {
            type: 'path' as const,
            name: 'flow-track-stream',
            shape: { pathData },
            style: { fill: 'none', stroke: '#fdfdff', lineWidth: Math.max(1.8, lineWidth * 0.85), lineDash: [1.5, 18], lineDashOffset: 0, opacity: uncertain ? 0.46 : 0.92, lineCap: 'round' as const, lineJoin: 'round' as const },
            keyframeAnimation: reducedMotion ? undefined : {
              duration: 1700 + hash(`${datum.edge.id}:${dataType}`) % 500,
              loop: true,
              keyframes: [
                { percent: 0, shape: { pathData }, style: { lineDashOffset: 0 } },
                { percent: 1, shape: { pathData }, style: { lineDashOffset: -39 } },
              ],
            },
            silent: true,
          },
          {
            type: 'polygon' as const,
            shape: { points: [
              end,
              [end[0] - arrowSize * Math.cos(angle - Math.PI / 6), end[1] - arrowSize * Math.sin(angle - Math.PI / 6)],
              [end[0] - arrowSize * Math.cos(angle + Math.PI / 6), end[1] - arrowSize * Math.sin(angle + Math.PI / 6)],
            ] },
            style: { fill: color, opacity: 0.82 },
            silent: true,
          },
          ...(label ? [label] : []),
        ]
      }),
    }
  }
  const groupData = orderedGroups.map(([name, nodes]) => {
    const points = nodes.map((node) => options.positions?.[node.id] ?? coordinates.get(node.id) ?? { x: (depths.get(node.id) ?? 0) * COLUMN_GAP, y: 0 })
    const minX = Math.min(...points.map((point) => point.x)) - NODE_WIDTH / 2 - GROUP_PAD
    const maxX = Math.max(...points.map((point) => point.x)) + NODE_WIDTH / 2 + GROUP_PAD
    const minY = Math.min(...points.map((point) => point.y)) - NODE_HEIGHT / 2 - GROUP_HEADER
    const maxY = Math.max(...points.map((point) => point.y)) + NODE_HEIGHT / 2 + GROUP_PAD
    const visibleCount = nodes.filter((node) => visibleIDs.has(node.id)).length
    return { value: [(minX + maxX) / 2, (minY + maxY) / 2], width: maxX - minX, height: maxY - minY, kind: 'group', id: name, groupKey: name, nodeCount: nodes.length, visibleCount, collapsed: collapsed.has(name) }
  })
  const renderGroup: NonNullable<CustomSeriesOption['renderItem']> = (_params, api) => {
    const datum = groupData[_params.dataIndex]
    const center = api.coord([api.value(0), api.value(1)])
    const size = scaledSize(api, [datum.width, datum.height])
    const index = hash(datum.groupKey) % GROUP_COLORS.length
    return {
      type: 'group',
      x: center[0],
      y: center[1],
      children: [
        { type: 'rect', shape: { x: -size[0] / 2, y: -size[1] / 2, width: size[0], height: size[1], r: 7 }, style: { fill: GROUP_COLORS[index], stroke: GROUP_STROKES[index], lineWidth: 1, lineDash: [3, 4] } },
        text(-size[0] / 2 + scaledSize(api, [12, 0])[0], -size[1] / 2 + scaledSize(api, [0, 10])[1], `${datum.groupKey}  ·  ${datum.nodeCount} 节点${datum.collapsed ? ' · 已折叠，点击展开' : ''}`, '#506078', '600 11px "PingFang SC", "Microsoft YaHei", sans-serif', size[0] * 0.9),
      ],
    }
  }
  const edges = graph.edges.filter((edge) => visibleIDs.has(edge.source_id) && visibleIDs.has(edge.target_id)).map((edge) => ({
    value: [0, 0],
    kind: 'edge',
    id: edge.id,
    edge,
    source: coordinates.get(edge.source_id)!,
    target: coordinates.get(edge.target_id)!,
  }))
  const multipleServiceGroups = graph.view !== 'network' && orderedGroups.length > 1
  let minX = Math.min(...[...coordinates.values()].map((point) => point.x), 0) - 180
  let maxX = Math.max(...[...coordinates.values()].map((point) => point.x), 0) + 180
  let minY = Math.min(...[...coordinates.values()].map((point) => point.y), 0) - 120
  let maxY = Math.max(...[...coordinates.values()].map((point) => point.y), 0) + 120
  if (multipleServiceGroups) {
    minX = Math.min(...groupData.map((datum) => datum.value[0] - datum.width / 2)) - CANVAS_PAD
    maxX = Math.max(...groupData.map((datum) => datum.value[0] + datum.width / 2)) + CANVAS_PAD
    minY = Math.min(...groupData.map((datum) => datum.value[1] - datum.height / 2)) - CANVAS_PAD
    maxY = Math.max(...groupData.map((datum) => datum.value[1] + datum.height / 2)) + CANVAS_PAD
  }
  const viewportWidth = options.viewportWidth ?? 1000
  const viewportHeight = options.viewportHeight ?? 620
  const xSpan = Math.max(maxX - minX, viewportWidth / 0.85, (maxY - minY) * viewportWidth / viewportHeight)
  const ySpan = xSpan * viewportHeight / viewportWidth
  const xCenter = (minX + maxX) / 2
  const yCenter = (minY + maxY) / 2
  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  return {
    animation: !reducedMotion,
    animationDuration: 280,
    animationDurationUpdate: 180,
    animationEasing: 'cubicOut',
    grid: { left: 0, right: 0, top: 0, bottom: 0 },
    xAxis: { type: 'value', min: xCenter - xSpan / 2, max: xCenter + xSpan / 2, show: false },
    yAxis: { type: 'value', min: yCenter - ySpan / 2, max: yCenter + ySpan / 2, inverse: true, show: false },
    dataZoom: [
      { id: 'flow-x', type: 'inside', xAxisIndex: 0, filterMode: 'none', zoomOnMouseWheel: true, moveOnMouseMove: true, moveOnMouseWheel: false, disabled: options.dragging },
      { id: 'flow-y', type: 'inside', yAxisIndex: 0, filterMode: 'none', zoomOnMouseWheel: true, moveOnMouseMove: true, moveOnMouseWheel: false, disabled: options.dragging },
    ],
    tooltip: {
      trigger: 'item',
      confine: true,
      backgroundColor: '#fbfcfe',
      borderColor: '#d5dee8',
      textStyle: { color: '#263a50', fontSize: 12 },
      formatter: (params: unknown) => {
        const datum = (params as { data?: { kind?: string; node?: DataFlowNode; edge?: DataFlowEdge } }).data
        if (datum?.kind === 'node' && datum.node) {
          const zone = graph.view === 'boundary' ? `<br/>区域：${dataFlowNetworkZoneLabel(datum.node.network_zone)}` : ''
          return `${escapeHtml(datum.node.name)}${zone}<br/>调用 ${datum.node.calls.toLocaleString()} 次 · ${datum.node.api_count} API<br/>点击查看直接上下游`
        }
        if (datum?.kind === 'edge' && datum.edge) {
          const edge = datum.edge
          const requestLabels = dataFlowDataTypes(edge, 'REQUEST').map((item) => DATA_TYPE_LABELS[item] ?? item).join('、') || '未识别'
          const responseLabels = dataFlowDataTypes(edge, 'RESPONSE').map((item) => DATA_TYPE_LABELS[item] ?? item).join('、') || '未识别'
          const messageLabels = dataFlowDataTypes(edge, 'MESSAGE').map((item) => DATA_TYPE_LABELS[item] ?? item).join('、')
          const apis = edge.apis.slice(0, 5).map(escapeHtml).join('<br/>') || '未知'
          const evidence = edge.boundary_evidence
            ? `${dataFlowBoundaryEvidenceLabel(edge.boundary_evidence)}（${edge.boundary_evidence}）`
            : '证据未提供'
          const boundary = graph.view === 'boundary'
            ? `<br/>区域：${dataFlowNetworkZoneLabel(edge.source_zone)} → ${dataFlowNetworkZoneLabel(edge.target_zone)}<br/>边界：${dataFlowBoundaryTypeLabel(edge.boundary_type)} · ${escapeHtml(evidence)}`
            : ''
          return `${escapeHtml(edge.source_name)} → ${escapeHtml(edge.target_name)}${boundary}<br/>调用 ${edge.calls.toLocaleString()} 次<br/>API：<br/>${apis}<br/>请求敏感数据：${escapeHtml(requestLabels)}<br/>响应敏感数据：${escapeHtml(responseLabels)}${messageLabels ? `<br/>消息敏感数据：${escapeHtml(messageLabels)}` : ''}<br/>点击查看字段与脱敏证据`
        }
        return ''
      },
    },
    series: [
      { id: 'dataflow-groups', type: 'custom', coordinateSystem: 'cartesian2d', data: groupData, renderItem: renderGroup, z: 1, clip: false },
      { id: 'dataflow-edges', type: 'custom', coordinateSystem: 'cartesian2d', data: edges, renderItem: renderEdge, z: 2, clip: false },
      { id: 'dataflow-nodes', type: 'custom', coordinateSystem: 'cartesian2d', data: visibleNodes.map((node) => ({ value: [coordinates.get(node.id)!.x, coordinates.get(node.id)!.y], kind: 'node', id: node.id, node })), renderItem: renderNode, z: 3, clip: false },
    ],
  }
}
