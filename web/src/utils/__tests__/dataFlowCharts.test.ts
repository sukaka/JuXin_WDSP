import { describe, expect, it } from 'vitest'
import type { DataFlowGraph } from '../../api/apiDataFlow'
import { dataFlowBoundaryEvidenceLabel, dataFlowBoundaryTypeLabel, dataFlowDataTypes, dataFlowDepths, dataFlowGraphOption, dataFlowNetworkZoneLabel } from '../dataFlowCharts'

const graph: DataFlowGraph = {
  nodes: [
    { id: 'client:192.0.2.10', name: '192.0.2.10', type: 'CLIENT', calls: 1, api_count: 0, avg_latency_ms: 0, max_latency_ms: 0, error_rate: 0, health: 'HEALTHY', incoming_count: 0, outgoing_count: 1 },
    { id: 'service:orders', name: 'orders', type: 'SERVICE', group_name: 'prod / shop', calls: 1, api_count: 1, avg_latency_ms: 12, max_latency_ms: 20, error_rate: 0, health: 'HEALTHY', incoming_count: 1, outgoing_count: 1 },
    { id: 'service:profile', name: 'profile', type: 'SERVICE', group_name: 'prod / shop', calls: 1, api_count: 1, avg_latency_ms: 10, max_latency_ms: 15, error_rate: 0, health: 'HEALTHY', incoming_count: 1, outgoing_count: 0 },
  ],
  edges: [{ id: 'edge-1', source_id: 'service:orders', target_id: 'service:profile', source_name: 'orders', target_name: 'profile', protocol: 'HTTP', method: 'POST', path_template: '/profiles/{id}', apis: ['POST /profiles/{id}'], calls: 1, errors: 0, avg_latency_ms: 12, max_latency_ms: 20, data_types: ['PHONE'], fields: [], evidence_type: 'OBSERVED_TRACE', confidence: 0.98, first_seen_at: '2026-11-06T00:00:00Z', last_seen_at: '2026-11-06T00:00:00Z', sample_trace_ids: ['a'.repeat(32)] }],
  truncated: false,
  view: 'service',
  quality: { observations: 2, trace_linked: 2, trace_coverage: 1, truncated: 0, data_source: 'clickhouse', partial: false, message: '' },
}

type Series = { id: string; data: Array<{ value: number[]; id?: string; kind?: string; collapsed?: boolean; groupKey?: string; nodeCount?: number; width?: number; height?: number }>; renderItem?: (params: { dataIndex: number }, api: unknown) => unknown }
type RenderedElement = {
  type?: string
  name?: string
  silent?: boolean
  shape?: { pathData?: string; points?: number[][] }
  style?: { text?: string; stroke?: string; lineWidth?: number; lineDash?: number[]; lineDashOffset?: number; backgroundColor?: string; fill?: string; font?: string }
  keyframeAnimation?: { duration?: number; loop?: boolean; keyframes?: Array<{ percent: number; style: { lineDashOffset: number } }> }
  children?: RenderedElement[]
}

function seriesOf(option: ReturnType<typeof dataFlowGraphOption>): Series[] {
  return (option.series ?? []) as unknown as Series[]
}

const renderAPI = {
  coord: (value: number[]) => value,
  size: (value: number[]) => value,
  value: (index: number) => index,
}

function renderEdge(option: ReturnType<typeof dataFlowGraphOption>, dataIndex = 0): RenderedElement {
  const edges = seriesOf(option).find((item) => item.id === 'dataflow-edges')!
  return edges.renderItem?.({ dataIndex }, renderAPI) as RenderedElement
}

function renderNode(option: ReturnType<typeof dataFlowGraphOption>, dataIndex = 0): RenderedElement {
  const nodes = seriesOf(option).find((item) => item.id === 'dataflow-nodes')!
  return nodes.renderItem?.({ dataIndex }, renderAPI) as RenderedElement
}

function independentSystemsGraph(): DataFlowGraph {
  const names = ['风险控制系统', '客户关系系统', '数据分析系统', '人力资源系统', 'OA办公系统', '统一认证系统', '电商订单系统', '支付结算系统']
  const prefixes = ['a-risk', 'a-customer', 'a-analytics', 'b-hr', 'b-oa', 'b-auth', 'c-order', 'c-payment']
  const nodes = names.map((name, index) => ({ ...graph.nodes[1], id: `service:${prefixes[index]}`, name }))
  const links = [[0, 2], [1, 2], [3, 5], [4, 5], [6, 7]]
  const edges = links.map(([source, target], index) => ({
    ...graph.edges[0],
    id: `edge-${index + 1}`,
    source_id: nodes[source].id,
    target_id: nodes[target].id,
    source_name: nodes[source].name,
    target_name: nodes[target].name,
  }))
  return { ...graph, nodes, edges }
}

describe('dataFlowCharts', () => {
  it('服务主图按真实无向连通分量分区，不使用环境命名空间', () => {
    const option = dataFlowGraphOption(graph)
    const series = seriesOf(option)
    const groups = series.find((item) => item.id === 'dataflow-groups')!.data
    expect(groups.map((item) => item.groupKey)).toEqual(['独立系统交互 · 01', '独立系统交互 · 02'])
    expect(groups[0]).toMatchObject({ groupKey: '独立系统交互 · 01', nodeCount: 2 })
    expect(JSON.stringify(groups)).not.toContain('prod / shop')

    const collapsed = dataFlowGraphOption(graph, { collapsedGroups: ['独立系统交互 · 01'] })
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-nodes')?.data.map((item) => item.id)).toEqual(['client:192.0.2.10'])
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-edges')?.data).toHaveLength(0)
    const rendered = renderEdge(option)
    expect(JSON.stringify(rendered)).toContain('手机号')
    expect(JSON.stringify(rendered)).toContain('polygon')
    expect(JSON.stringify(rendered)).not.toContain('bezierCurve')
  })

  it('宽屏多分区按编号进行二维排布，利用宽度并保持间距与节点比例', () => {
    const option = dataFlowGraphOption(independentSystemsGraph(), { viewportWidth: 1156, viewportHeight: 420 })
    const groups = seriesOf(option).find((item) => item.id === 'dataflow-groups')!.data
    expect(groups.map((item) => item.groupKey)).toEqual(['独立系统交互 · 01', '独立系统交互 · 02', '独立系统交互 · 03'])
    const [first, second, third] = groups
    expect(first.value[0]).toBeLessThan(second.value[0])
    expect(first.value[1] - first.height! / 2).toBeCloseTo(second.value[1] - second.height! / 2)
    expect(third.value[0]).toBeGreaterThan(first.value[0])
    expect(third.value[0]).toBeLessThan(second.value[0])
    expect(third.value[1]).toBeGreaterThan(first.value[1])
    expect(first.height).toBe(276)
    expect(third.height).toBe(138)
    expect(second.value[0] - second.width! / 2 - (first.value[0] + first.width! / 2)).toBeCloseTo(56)
    expect(third.value[1] - third.height! / 2 - (first.value[1] + first.height! / 2)).toBeCloseTo(48)

    const xAxis = option.xAxis as { min: number; max: number }
    const yAxis = option.yAxis as { min: number; max: number }
    const xSpan = xAxis.max - xAxis.min
    const occupiedWidth = second.value[0] + second.width! / 2 - (first.value[0] - first.width! / 2)
    expect(occupiedWidth / xSpan).toBeGreaterThan(0.8)
    expect(xSpan / (yAxis.max - yAxis.min)).toBeCloseTo(1156 / 420, 6)
  })

  it('窄屏按真实分区高度逐行换行，保持编号顺序和行间距', () => {
    const option = dataFlowGraphOption(independentSystemsGraph(), { viewportWidth: 720, viewportHeight: 560 })
    const groups = seriesOf(option).find((item) => item.id === 'dataflow-groups')!.data
    const [first, second, third] = groups
    expect(first.value[0]).toBeCloseTo(second.value[0])
    expect(second.value[0]).toBeCloseTo(third.value[0])
    expect(second.value[1] - second.height! / 2 - (first.value[1] + first.height! / 2)).toBeCloseTo(48)
    expect(third.value[1] - third.height! / 2 - (second.value[1] + second.height! / 2)).toBeCloseTo(48)
  })

  it('单连通分量保留原始节点坐标和居中边界', () => {
    const single = { ...graph, nodes: graph.nodes.slice(1) }
    const option = dataFlowGraphOption(single, { viewportWidth: 1000, viewportHeight: 620 })
    const nodes = seriesOf(option).find((item) => item.id === 'dataflow-nodes')!.data
    expect(nodes.map((item) => item.value)).toEqual([[324, 0], [648, 0]])
    const xAxis = option.xAxis as { min: number; max: number }
    const yAxis = option.yAxis as { min: number; max: number }
    const expectedXSpan = 1000 / 0.85
    const expectedYSpan = expectedXSpan * 620 / 1000
    expect(xAxis.min).toBeCloseTo(324 - expectedXSpan / 2)
    expect(xAxis.max).toBeCloseTo(324 + expectedXSpan / 2)
    expect(yAxis.min).toBeCloseTo(-expectedYSpan / 2)
    expect(yAxis.max).toBeCloseTo(expectedYSpan / 2)
  })

  it('拖拽坐标同步到系统，兼容网络视图分组折叠', () => {
    const moved = dataFlowGraphOption(graph, { positions: { 'service:orders': { x: 500, y: 260 } } })
    const nodes = seriesOf(moved).find((item) => item.id === 'dataflow-nodes')!
    expect(nodes.data.find((item) => item.id === 'service:orders')?.value).toEqual([500, 260])
    const collapsed = dataFlowGraphOption({ ...graph, view: 'network' }, { collapsedGroups: ['prod / shop'] })
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-nodes')?.data.map((item) => item.id)).toEqual(['client:192.0.2.10'])
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-edges')?.data).toHaveLength(0)
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-groups')?.data.some((item) => item.collapsed)).toBe(true)
  })

  it('A→B、B→C 与 A→C 三条系统关系同时保留', () => {
    const identity = { ...graph.nodes[2], id: 'service:identity', name: 'identity', incoming_count: 2, outgoing_count: 0 }
    const bc = { ...graph.edges[0], id: 'edge-2', source_id: 'service:profile', target_id: 'service:identity', source_name: 'profile', target_name: 'identity' }
    const ac = { ...graph.edges[0], id: 'edge-3', source_id: 'service:orders', target_id: 'service:identity', source_name: 'orders', target_name: 'identity' }
    const option = dataFlowGraphOption({ ...graph, nodes: [graph.nodes[1], graph.nodes[2], identity], edges: [graph.edges[0], bc, ac] })
    const edges = seriesOf(option).find((item) => item.id === 'dataflow-edges')!
    expect(edges.data.map((item) => item.id)).toEqual(['edge-1', 'edge-2', 'edge-3'])
  })

  it('按字段证据区分请求、响应和消息敏感数据，并保留完整 tooltip', () => {
    const edge = {
      ...graph.edges[0],
      data_types: ['PHONE', 'CN_ID', 'EMAIL'],
      fields: [
        { side: 'REQUEST' as const, path: '$.mobile', data_type: 'PHONE', match: 'OBSERVED' },
        { side: 'REQUEST' as const, path: '$.remark', data_type: '', match: 'OBSERVED' },
        { side: 'RESPONSE' as const, path: '$.identity_no', data_type: 'CN_ID', match: 'OBSERVED' },
        { side: 'MESSAGE' as const, path: '$.email', data_type: 'EMAIL', match: 'OBSERVED' },
      ],
    }
    expect(dataFlowDataTypes(edge, 'REQUEST')).toEqual(['PHONE'])
    expect(dataFlowDataTypes(edge, 'RESPONSE')).toEqual(['CN_ID'])
    expect(dataFlowDataTypes(edge, 'MESSAGE')).toEqual(['EMAIL'])
    const option = dataFlowGraphOption({ ...graph, edges: [edge] })
    const tooltip = (option.tooltip as { formatter: (params: unknown) => string }).formatter({ data: { kind: 'edge', edge } })
    expect(tooltip).toContain('请求敏感数据：手机号')
    expect(tooltip).toContain('响应敏感数据：身份证号')
    expect(tooltip).toContain('消息敏感数据：邮箱')
    expect(tooltip).toContain('点击查看字段与脱敏证据')
  })

  it('每种敏感数据类型使用平行圆角管道，管体分层且流光沿调用方向运动', () => {
    const multitype = { ...graph, edges: [{ ...graph.edges[0], data_types: ['PHONE', 'CN_ID', 'EMAIL'] }] }
    const crossRow = dataFlowGraphOption(multitype, { positions: { 'service:orders': { x: 0, y: 0 }, 'service:profile': { x: 400, y: 180 } } })
    const rendered = renderEdge(crossRow)
    const tracks = rendered.children?.filter((item) => item.name === 'flow-track-core') ?? []
    expect(tracks).toHaveLength(3)
    expect(new Set(tracks.map((item) => item.style?.stroke)).size).toBe(3)
    for (const track of tracks) {
      expect(track.shape?.pathData).toContain(' Q ')
      expect(track.shape?.pathData).not.toContain(' C ')
      expect(track.shape?.pathData).not.toContain('NaN')
      expect(track.style?.lineWidth).toBeLessThanOrEqual(2.8)
    }
    for (const layer of ['flow-track-casing', 'flow-track-body', 'flow-track-rail']) {
      expect(rendered.children?.filter((item) => item.name === layer)).toHaveLength(3)
    }
    const streams = rendered.children?.filter((item) => item.name === 'flow-track-stream') ?? []
    expect(streams).toHaveLength(3)
    for (const stream of streams) {
      expect(new Set(tracks.map((track) => track.shape?.pathData))).toContain(stream.shape?.pathData)
      expect(stream.style?.lineDash).toEqual([1.5, 18])
      expect(stream.keyframeAnimation?.loop).toBe(true)
      expect(stream.keyframeAnimation?.keyframes?.[1].style.lineDashOffset).toBeLessThan(0)
    }
    const labelElements = rendered.children?.filter((item) => item.type === 'text') ?? []
    const labels = labelElements.map((item) => item.style?.text)
    expect(labels).toEqual(expect.arrayContaining(['手机号', '身份证号', '邮箱']))
    for (const label of labelElements) {
      expect(label.style?.backgroundColor).toBeUndefined()
      expect(label.style?.font).toContain('600 11px')
      expect(label.style?.fill).toMatch(/^#[0-9a-f]{6}$/)
    }
    const arrows = rendered.children?.filter((item) => item.type === 'polygon') ?? []
    expect(arrows).toHaveLength(3)
    for (const arrow of arrows) {
      const [tip, ...wings] = arrow.shape?.points ?? []
      for (const wing of wings) expect(Math.hypot(wing[0] - tip[0], wing[1] - tip[1])).toBeLessThanOrEqual(5.01)
    }

    const sameRow = dataFlowGraphOption(multitype, { positions: { 'service:orders': { x: 500, y: 260 }, 'service:profile': { x: 100, y: 260 } } })
    const sameRowTracks = renderEdge(sameRow).children?.filter((item) => item.name === 'flow-track-core') ?? []
    expect(sameRowTracks).toHaveLength(3)
    const startYs = sameRowTracks.map((item) => Number(item.shape?.pathData?.match(/^M (-?[\d.]+) (-?[\d.]+)/)?.[2]))
    expect(new Set(startYs).size).toBe(3)
    expect(startYs[1] - startYs[0]).toBeCloseTo(14)
    expect(startYs[2] - startYs[1]).toBeCloseTo(14)
    for (const track of sameRowTracks) expect(track.shape?.pathData).not.toContain(' Q ')
  })

  it('节点直接展示真实中文名称', () => {
    const node = { ...graph.nodes[1], name: '统一订单中心' }
    const option = dataFlowGraphOption({ ...graph, nodes: [node], edges: [] })
    const nodes = seriesOf(option).find((item) => item.id === 'dataflow-nodes')!
    const rendered = nodes.renderItem?.({ dataIndex: 0 }, {
      coord: (value: number[]) => value,
      size: (value: number[]) => value,
      value: (index: number) => index,
    }) as RenderedElement
    expect(rendered.children?.some((item) => item.style?.text === '统一订单中心')).toBe(true)
  })

  it('多分区和不同视口下保持统一的节点宽高比', () => {
    const isolated = ['a', 'b', 'c', 'd'].map((name) => ({ ...graph.nodes[1], id: `service:${name}`, name }))
    const option = dataFlowGraphOption({ ...graph, nodes: [...graph.nodes, ...isolated], edges: [] }, { viewportWidth: 1440, viewportHeight: 620 })
    const xAxis = option.xAxis as { min: number; max: number }
    const yAxis = option.yAxis as { min: number; max: number }
    expect((xAxis.max - xAxis.min) / (yAxis.max - yAxis.min)).toBeCloseTo(1440 / 620, 6)
  })

  it('循环依赖布局有界，按层展开不会虚构节点', () => {
    const cyclic = [...graph.edges, { ...graph.edges[0], id: 'edge-2', source_id: 'service:profile', target_id: 'service:orders' }]
    const depths = dataFlowDepths(graph.nodes, cyclic)
    expect(depths.size).toBe(graph.nodes.length)
    const limited = dataFlowGraphOption(graph, { maxDepth: 1 })
    expect(seriesOf(limited).find((item) => item.id === 'dataflow-nodes')?.data.map((item) => item.id)).toEqual(['client:192.0.2.10', 'service:orders'])
  })

  it('边界标签只映射契约代码，不从应用名或 GeoIP 推断', () => {
    expect(dataFlowNetworkZoneLabel('PUBLIC')).toBe('公网来源')
    expect(dataFlowNetworkZoneLabel('INTERNAL')).toBe('内网来源')
    expect(dataFlowNetworkZoneLabel('UNKNOWN')).toBe('外部来源/区域未知')
    expect(dataFlowNetworkZoneLabel(undefined)).toBe('外部来源/区域未知')
    expect(dataFlowBoundaryTypeLabel('PUBLIC_TO_INTERNAL')).toBe('公网 → 内网')
    expect(dataFlowBoundaryTypeLabel('UNKNOWN')).toBe('边界未知')
    expect(dataFlowBoundaryTypeLabel(undefined)).toBe('边界未知')
    expect(dataFlowBoundaryEvidenceLabel('TRUSTED_PROXY')).toBe('可信代理')
    expect(dataFlowBoundaryEvidenceLabel('UNTRUSTED_CLIENT_SOURCE')).toBe('客户端来源不可信')
  })

  it('内外网边界保留中文名和真实连通分区，公网与未知方向及证据不混淆', () => {
    const boundaryGraph: DataFlowGraph = {
      ...graph,
      view: 'boundary',
      nodes: [
        { ...graph.nodes[0], name: '外部调用方', network_zone: 'PUBLIC' },
        { ...graph.nodes[1], name: '统一订单中心', network_zone: 'INTERNAL' },
        { ...graph.nodes[0], id: 'client:unknown', name: '公网代理出口', network_zone: 'UNKNOWN' },
      ],
      edges: [
        {
          ...graph.edges[0],
          source_id: 'client:192.0.2.10',
          target_id: 'service:orders',
          source_name: '外部调用方',
          target_name: '统一订单中心',
          data_types: [],
          fields: [],
          source_zone: 'PUBLIC',
          target_zone: 'INTERNAL',
          boundary_type: 'PUBLIC_TO_INTERNAL',
          boundary_evidence: 'DIRECT_PEER',
        },
        {
          ...graph.edges[0],
          id: 'edge-unknown',
          source_id: 'client:unknown',
          target_id: 'service:orders',
          source_name: '公网代理出口',
          target_name: '统一订单中心',
          data_types: [],
          fields: [],
          source_zone: 'UNKNOWN',
          target_zone: 'INTERNAL',
          boundary_type: 'UNKNOWN',
          boundary_evidence: 'UNTRUSTED_CLIENT_SOURCE',
        },
      ],
    }
    const option = dataFlowGraphOption(boundaryGraph)
    expect(seriesOf(option).find((item) => item.id === 'dataflow-groups')?.data.map((item) => item.groupKey)).toEqual(['内外网边界 · 01'])
    expect(JSON.stringify(renderNode(option, 0))).toContain('外部调用方')
    expect(JSON.stringify(renderNode(option, 0))).toContain('公网来源')
    expect(JSON.stringify(renderNode(option, 1))).toContain('统一订单中心')
    expect(JSON.stringify(renderNode(option, 1))).toContain('内网来源')
    expect(JSON.stringify(renderNode(option, 2))).toContain('外部来源/区域未知')

    const publicTracks = renderEdge(option).children?.filter((item) => item.name === 'flow-track-core') ?? []
    const unknownTracks = renderEdge(option, 1).children?.filter((item) => item.name === 'flow-track-core') ?? []
    expect(publicTracks[0].style?.lineDash).toEqual([])
    expect(unknownTracks[0].style?.lineDash).toEqual([6, 5])
    expect(JSON.stringify(renderEdge(option))).toContain('公网 → 内网')
    expect(JSON.stringify(renderEdge(option, 1))).toContain('边界未知')
    expect(publicTracks[0].shape?.pathData).not.toContain(' C ')

    const tooltip = (option.tooltip as { formatter: (params: unknown) => string }).formatter
    const publicTooltip = tooltip({ data: { kind: 'edge', edge: boundaryGraph.edges[0] } })
    const unknownTooltip = tooltip({ data: { kind: 'edge', edge: boundaryGraph.edges[1] } })
    expect(publicTooltip).toContain('边界：公网 → 内网 · 直连对端（DIRECT_PEER）')
    expect(unknownTooltip).toContain('边界：边界未知 · 客户端来源不可信（UNTRUSTED_CLIENT_SOURCE）')
    expect(unknownTooltip).not.toContain('边界：公网 → 内网')

    const collapsed = dataFlowGraphOption(boundaryGraph, { collapsedGroups: ['内外网边界 · 01'] })
    expect(seriesOf(collapsed).find((item) => item.id === 'dataflow-nodes')?.data).toHaveLength(0)
    const moved = dataFlowGraphOption(boundaryGraph, { positions: { 'client:unknown': { x: 88, y: 66 } } })
    expect(seriesOf(moved).find((item) => item.id === 'dataflow-nodes')?.data.find((item) => item.id === 'client:unknown')?.value).toEqual([88, 66])
  })
})
