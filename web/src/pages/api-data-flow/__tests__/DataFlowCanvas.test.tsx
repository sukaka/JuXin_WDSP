import { act, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { ComponentProps } from 'react'
import type { ECharts } from 'echarts/core'
import type { DataFlowGraph } from '../../../api/apiDataFlow'
import DataFlowCanvas from '../DataFlowCanvas'
import type EChart from '../../../components/EChart'

let latestProps: ComponentProps<typeof EChart> | undefined

vi.mock('../../../components/EChart', () => ({
  default: (props: ComponentProps<typeof EChart>) => {
    latestProps = props
    return <div data-testid="flow-canvas" />
  },
}))

const graph: DataFlowGraph = {
  nodes: [{ id: 'service:orders', name: 'orders', type: 'SERVICE', group_name: 'prod', calls: 1, api_count: 1, avg_latency_ms: 10, max_latency_ms: 12, error_rate: 0, health: 'HEALTHY', incoming_count: 0, outgoing_count: 0 }],
  edges: [],
  truncated: false,
  view: 'service',
  quality: { observations: 1, trace_linked: 1, trace_coverage: 1, truncated: 0, data_source: 'clickhouse', partial: false, message: '' },
}

describe('DataFlowCanvas', () => {
  it('节点与轨道下钻、连通分量折叠和拖拽只改变本地布局', () => {
    const onNode = vi.fn()
    const onEdge = vi.fn()
    const edge = { id: 'edge-1' } as DataFlowGraph['edges'][number]
    render(<DataFlowCanvas graph={graph} onNode={onNode} onEdge={onEdge} />)
    expect(screen.getByRole('region', { name: '应用数据流向图' })).toBeTruthy()
    act(() => latestProps?.events?.click({ data: { kind: 'node', node: graph.nodes[0] } }))
    expect(onNode).toHaveBeenCalledWith(graph.nodes[0])
    act(() => latestProps?.events?.click({ data: { kind: 'edge', edge } }))
    expect(onEdge).toHaveBeenCalledWith(edge)
    expect(screen.getByText(/每种敏感数据类型一条平行轨道/)).toBeTruthy()

    act(() => latestProps?.events?.click({ data: { kind: 'group', groupKey: '独立系统交互 · 01' } }))
    let option = latestProps!.option
    let series = (option.series ?? []) as Array<{ id: string; data: Array<{ value: number[]; collapsed?: boolean; groupKey?: string }> }>
    expect(series.find((item) => item.id === 'dataflow-nodes')?.data).toHaveLength(0)
    expect(series.find((item) => item.id === 'dataflow-groups')?.data[0]).toMatchObject({ groupKey: '独立系统交互 · 01', collapsed: true })
    act(() => latestProps?.events?.click({ data: { kind: 'group', groupKey: '独立系统交互 · 01' } }))
    expect(screen.getByText('独立系统交互')).toBeTruthy()

    const chartEvents: Record<string, (event: unknown) => void> = {}
    const pointerEvents: Record<string, (event: { offsetX: number; offsetY: number }) => void> = {}
    const chart = {
      on: (name: string, handler: (event: unknown) => void) => { chartEvents[name] = handler },
      getZr: () => ({ on: (name: string, handler: (event: { offsetX: number; offsetY: number }) => void) => { pointerEvents[name] = handler } }),
      convertFromPixel: (_finder: unknown, point: [number, number]) => point,
      setOption: vi.fn(),
    }
    latestProps?.onChartReady?.(chart as unknown as ECharts)
    act(() => chartEvents.mousedown({ data: { kind: 'node', id: 'service:orders', value: [0, 0] }, event: { offsetX: 10, offsetY: 20, stop: vi.fn() } }))
    act(() => pointerEvents.mousemove({ offsetX: 40, offsetY: 60 }))
    option = latestProps!.option
    series = (option.series ?? []) as Array<{ id: string; data: Array<{ value: number[]; collapsed?: boolean; groupKey?: string }> }>
    expect(series.find((item) => item.id === 'dataflow-nodes')?.data[0].value).toEqual([30, 40])
    act(() => pointerEvents.mouseup({ offsetX: 40, offsetY: 60 }))
    expect(chart.setOption).toHaveBeenCalled()
  })

  it('画布至少填满当前浏览器剩余高度', () => {
    const clients = ['a', 'b', 'c'].map((name) => ({ ...graph.nodes[0], id: `client:${name}`, name, type: 'CLIENT' }))
    render(<DataFlowCanvas graph={{ ...graph, nodes: [...graph.nodes, ...clients] }} onNode={vi.fn()} onEdge={vi.fn()} />)
    expect(latestProps?.height).toBeGreaterThan(400)
  })

  it('全屏画布覆盖视口并支持 Esc 退出', () => {
    render(<DataFlowCanvas graph={graph} onNode={vi.fn()} onEdge={vi.fn()} />)
    const region = screen.getByRole('region', { name: '应用数据流向图' })
    act(() => screen.getByRole('button', { name: '全屏画布' }).click())
    expect(region.classList.contains('is-fullscreen')).toBe(true)
    expect(screen.getByRole('button', { name: '退出全屏' }).getAttribute('aria-pressed')).toBe('true')
    expect(document.body.style.overflow).toBe('hidden')
    expect(latestProps?.height).toBe(window.innerHeight - 42)
    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })))
    expect(region.classList.contains('is-fullscreen')).toBe(false)
    expect(document.body.style.overflow).not.toBe('hidden')
  })

  it('边界视图使用独立可访问名称并明确未知边界', () => {
    render(<DataFlowCanvas graph={{ ...graph, view: 'boundary' }} onNode={vi.fn()} onEdge={vi.fn()} />)
    expect(screen.getByRole('region', { name: '内外网边界调用图' })).toBeTruthy()
    expect(screen.getByText('内外网边界')).toBeTruthy()
    expect(screen.getByText(/实线为公网 → 内网，虚线为边界未知/)).toBeTruthy()
    expect(latestProps?.ariaLabel).toBe('基于地址范围与来源证据的内外网边界调用图')
    expect(latestProps?.summary).toContain('公网到内网与边界未知分开标识')
  })
})
