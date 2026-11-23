import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Button, Space, Tooltip } from 'antd'
import { ExpandOutlined, FullscreenExitOutlined, FullscreenOutlined, MinusOutlined, PlusOutlined, RedoOutlined } from '@ant-design/icons'
import type { ECharts } from 'echarts/core'
import EChart from '../../components/EChart'
import type { DataFlowEdge, DataFlowGraph, DataFlowNode } from '../../api/apiDataFlow'
import { DATA_TYPE_LABELS, dataFlowDepths, dataFlowGraphOption, dataFlowGroupNames, dataFlowLayoutRowCount, type FlowPoint } from '../../utils/dataFlowCharts'

interface DataFlowCanvasProps {
  graph: DataFlowGraph
  onNode: (node: DataFlowNode) => void
  onEdge: (edge: DataFlowEdge) => void
}

interface DragState {
  nodeID: string
  offsetX: number
  offsetY: number
  moved: boolean
}

interface ChartDatum {
  kind?: 'node' | 'edge' | 'group'
  id?: string
  value?: [number, number]
  node?: DataFlowNode
  edge?: DataFlowEdge
  groupKey?: string
}

export default function DataFlowCanvas({ graph, onNode, onEdge }: DataFlowCanvasProps) {
  const chartRef = useRef<ECharts | null>(null)
  const containerRef = useRef<HTMLElement | null>(null)
  const dragging = useRef<DragState | null>(null)
  const suppressClickUntil = useRef(0)
  const [viewportWidth, setViewportWidth] = useState(1000)
  const [viewportHeight, setViewportHeight] = useState(400)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [positions, setPositions] = useState<Record<string, FlowPoint>>({})
  const [collapsedGroups, setCollapsedGroups] = useState<string[]>([])
  const [depthLimit, setDepthLimit] = useState<number>()
  const depths = useMemo(() => dataFlowDepths(graph.nodes, graph.edges), [graph])
  const groupNames = useMemo(() => dataFlowGroupNames(graph), [graph])
  const rowCount = useMemo(() => dataFlowLayoutRowCount(graph, viewportWidth), [graph, viewportWidth])
  const contentHeight = viewportWidth < 720 ? 560 : Math.max(400, Math.min(760, 180 + rowCount * 80))
  const height = Math.max(contentHeight, viewportHeight)
  const maxDepth = Math.max(0, ...depths.values())
  const hiddenCount = graph.nodes.filter((node) => collapsedGroups.includes(groupNames.get(node.id) ?? '') || (depthLimit !== undefined && (depths.get(node.id) ?? 0) > depthLimit)).length
  const option = useMemo(() => dataFlowGraphOption(graph, {
    positions,
    collapsedGroups,
    maxDepth: depthLimit,
    dragging: dragging.current !== null,
    viewportWidth,
    viewportHeight: height,
  }), [graph, positions, collapsedGroups, depthLimit, viewportWidth, height])

  useEffect(() => {
    const element = containerRef.current
    if (!element) return
    const update = () => {
      setViewportWidth(element.clientWidth || 1000)
      const top = isFullscreen ? 0 : Math.max(0, element.getBoundingClientRect().top)
      const bottomGap = isFullscreen ? 0 : 16
      setViewportHeight(Math.max(320, Math.floor(window.innerHeight - top - 42 - bottomGap)))
    }
    update()
    window.addEventListener('resize', update)
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(update)
    observer?.observe(element)
    return () => {
      window.removeEventListener('resize', update)
      observer?.disconnect()
    }
  }, [graph, isFullscreen])

  useEffect(() => {
    if (!isFullscreen) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const exit = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setIsFullscreen(false)
    }
    document.addEventListener('keydown', exit)
    return () => {
      document.body.style.overflow = previousOverflow
      document.removeEventListener('keydown', exit)
    }
  }, [isFullscreen])

  useEffect(() => {
    setPositions({})
    setCollapsedGroups([])
    setDepthLimit(undefined)
  }, [graph])

  const onChartReady = useCallback((chart: ECharts) => {
    chartRef.current = chart
    let syncingZoom = false
    chart.on('dataZoom', (raw: unknown) => {
      if (syncingZoom) return
      const event = raw as { batch?: Array<{ dataZoomId?: string; start?: number; end?: number }>; dataZoomId?: string; start?: number; end?: number }
      const zooms = (chart.getOption().dataZoom ?? []) as Array<{ id?: string; start?: number; end?: number }>
      const source = event.batch?.[0] ?? event
      if (zooms.length < 2 || zooms.every((item) => item.start === zooms[0].start && item.end === zooms[0].end)) return
      syncingZoom = true
      chart.dispatchAction({ type: 'dataZoom', id: source.dataZoomId === 'flow-x' ? 'flow-y' : 'flow-x', start: source.start, end: source.end })
      syncingZoom = false
    })
    const finishDrag = () => {
      if (dragging.current?.moved) suppressClickUntil.current = Date.now() + 150
      dragging.current = null
      chart.setOption({ dataZoom: [{ id: 'flow-x', disabled: false }, { id: 'flow-y', disabled: false }] })
    }
    chart.on('mousedown', (raw: unknown) => {
      const params = raw as { data?: ChartDatum; event?: { stop?: () => void; offsetX?: number; offsetY?: number } }
      const datum = params.data
      if (datum?.kind !== 'node' || !datum.id || !datum.value) return
      const point = chart.convertFromPixel({ xAxisIndex: 0, yAxisIndex: 0 }, [Number(params.event?.offsetX ?? 0), Number(params.event?.offsetY ?? 0)])
      dragging.current = { nodeID: datum.id, offsetX: point[0] - datum.value[0], offsetY: point[1] - datum.value[1], moved: false }
      params.event?.stop?.()
      chart.setOption({ dataZoom: [{ id: 'flow-x', disabled: true }, { id: 'flow-y', disabled: true }] })
    })
    chart.getZr().on('mousemove', (event) => {
      const current = dragging.current
      if (!current) return
      const point = chart.convertFromPixel({ xAxisIndex: 0, yAxisIndex: 0 }, [event.offsetX, event.offsetY])
      if (!Number.isFinite(point[0]) || !Number.isFinite(point[1])) return
      current.moved = true
      setPositions((previous) => ({ ...previous, [current.nodeID]: { x: point[0] - current.offsetX, y: point[1] - current.offsetY } }))
    })
    chart.getZr().on('mouseup', finishDrag)
    chart.getZr().on('globalout', finishDrag)
  }, [])

  const events = useMemo(() => ({
    click: (raw: unknown) => {
      if (Date.now() < suppressClickUntil.current) return
      const datum = (raw as { data?: ChartDatum }).data
      if (datum?.kind === 'node' && datum.node) onNode(datum.node)
      if (datum?.kind === 'edge' && datum.edge) onEdge(datum.edge)
      if (datum?.kind === 'group' && datum.groupKey) {
        const key = datum.groupKey
        setCollapsedGroups((previous) => previous.includes(key) ? previous.filter((item) => item !== key) : [...previous, key])
      }
    },
  }), [onNode, onEdge])

  const zoom = (factor: number) => {
    const chart = chartRef.current
    if (!chart) return
    const current = (chart.getOption().dataZoom ?? []) as Array<{ start?: number; end?: number }>
    for (const [index, id] of ['flow-x', 'flow-y'].entries()) {
      const start = current[index]?.start ?? 0
      const end = current[index]?.end ?? 100
      const center = (start + end) / 2
      const span = Math.max(5, Math.min(100, (end - start) * factor))
      chart.dispatchAction({ type: 'dataZoom', id, start: Math.max(0, center - span / 2), end: Math.min(100, center + span / 2) })
    }
  }

  const reset = () => {
    setPositions({})
    setCollapsedGroups([])
    setDepthLimit(undefined)
    for (const id of ['flow-x', 'flow-y']) chartRef.current?.dispatchAction({ type: 'dataZoom', id, start: 0, end: 100 })
  }

  const fieldTypes = [...new Set(graph.edges.flatMap((edge) => edge.data_types))]
  const isBoundary = graph.view === 'boundary'
  const regionLabel = isBoundary ? '内外网边界调用图' : graph.view === 'network' ? '应用观测网络端点图' : '应用数据流向图'
  const metaLabel = isBoundary ? '内外网边界' : graph.view === 'network' ? '观测网络' : '独立系统交互'
  const ariaLabel = isBoundary
    ? '基于地址范围与来源证据的内外网边界调用图'
    : graph.view === 'network' ? '基于真实 API 观测的网络端点流向图' : '独立业务系统之间的 API 调用与敏感数据流向图'
  return (
    <section ref={containerRef} className={`data-flow-canvas${isFullscreen ? ' is-fullscreen' : ''}`} aria-label={regionLabel}>
      <div className="data-flow-canvas-meta">
        <span>{metaLabel}</span>
        <span>{graph.nodes.length} 个{graph.view === 'service' || !graph.view ? '系统' : '节点'} · {graph.edges.length} 条关系</span>
      </div>
      <div className="data-flow-canvas-tools">
        <Space size={4} wrap>
          <Tooltip title="放大" placement="bottom"><Button aria-label="放大图" icon={<PlusOutlined />} onClick={() => zoom(0.8)} /></Tooltip>
          <Tooltip title="缩小" placement="bottom"><Button aria-label="缩小图" icon={<MinusOutlined />} onClick={() => zoom(1.25)} /></Tooltip>
          <Tooltip title="还原布局与视口" placement="bottom"><Button aria-label="还原图" icon={<RedoOutlined />} onClick={reset} /></Tooltip>
          <Tooltip title={isFullscreen ? '退出全屏（Esc）' : '全屏画布'} placement="bottom"><Button aria-label={isFullscreen ? '退出全屏' : '全屏画布'} aria-pressed={isFullscreen} icon={isFullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />} onClick={() => setIsFullscreen((value) => !value)} /></Tooltip>
          {depthLimit === undefined ? (
            <Button disabled={maxDepth <= 2} icon={<ExpandOutlined />} onClick={() => setDepthLimit(2)}>收起下游</Button>
          ) : (
            <Button icon={<ExpandOutlined />} onClick={() => setDepthLimit((value) => Math.min(maxDepth, (value ?? 0) + 1))}>展开下一层</Button>
          )}
        </Space>
      </div>
      <EChart
        option={option}
        height={height}
        merge
        events={events}
        onChartReady={onChartReady}
        ariaLabel={ariaLabel}
        summary={isBoundary
          ? `${graph.nodes.length} 个节点，${graph.edges.length} 条调用关系，按真实连通关系分区。公网到内网与边界未知分开标识，可拖拽、缩放、折叠并查看边界证据。`
          : graph.view === 'network'
            ? `${graph.nodes.length} 个网络节点，${graph.edges.length} 条 API 调用关系。可拖拽节点、缩放画布，点击轨道查看 API 与敏感字段证据。`
            : `${graph.nodes.length} 个业务系统，${graph.edges.length} 条 API 调用关系，按真实调用连通关系分区。可拖拽系统、缩放画布，点击轨道查看 API 与敏感字段证据。`}
      />
      <div className="data-flow-canvas-footer">
        <span>{isBoundary ? '每种敏感数据类型一条平行轨道 · 实线为公网 → 内网，虚线为边界未知 · 点击节点或轨道查看证据' : '每种敏感数据类型一条平行轨道 · 流动光点与箭头指示 API 调用方向 · 点击系统或轨道查看详情'}</span>
        <span className="data-flow-health-legend"><i className="is-healthy" />健康<i className="is-degraded" />降级<i className="is-error" />异常</span>
        {fieldTypes.map((type) => <span className="data-flow-field-legend" data-field-type={type} key={type}>{DATA_TYPE_LABELS[type] ?? type}</span>)}
        {hiddenCount > 0 && <span className="data-flow-hidden-note" role="status">已收起 {hiddenCount} 个节点，当前仅显示部分系统交互</span>}
      </div>
    </section>
  )
}
