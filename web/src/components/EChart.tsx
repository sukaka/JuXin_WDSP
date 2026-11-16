import { useEffect, useId, useMemo, useRef, type CSSProperties } from 'react'
import * as echarts from 'echarts/core'
import { BarChart, CustomChart, GraphChart, LineChart, PieChart } from 'echarts/charts'
import {
  AriaComponent,
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { ComposeOption } from 'echarts/core'
import type { XAXisComponentOption, YAXisComponentOption } from 'echarts'
import type { BarSeriesOption, CustomSeriesOption, GraphSeriesOption, LineSeriesOption, PieSeriesOption } from 'echarts/charts'
import type {
  AriaComponentOption,
  DataZoomComponentOption,
  GridComponentOption,
  LegendComponentOption,
  TooltipComponentOption,
} from 'echarts/components'
import { buildAccessibleSummary } from './EChartAccessibleSummary'

// 按需注册，避免全量引入 echarts 增加包体积
echarts.use([
  BarChart,
  LineChart,
  PieChart,
  // APM 依赖关系图（/apm-dependencies）追加；既有注册保持不变
  GraphChart,
  CustomChart,
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  AriaComponent,
  CanvasRenderer,
])

/** 已注册部件对应的图表配置类型 */
export type EChartOption = ComposeOption<
  | BarSeriesOption
  | LineSeriesOption
  | PieSeriesOption
  | GraphSeriesOption
  | CustomSeriesOption
  | DataZoomComponentOption
  | XAXisComponentOption
  | YAXisComponentOption
  | GridComponentOption
  | LegendComponentOption
  | TooltipComponentOption
  | AriaComponentOption
>

export interface EChartProps {
  option: EChartOption
  height?: number
  /** 图表可访问名称（必填）：容器 role="img" 的 aria-label，也是 ECharts aria 描述文案 */
  ariaLabel: string
  /** 可选文字数据摘要：建议包含时间范围、主要趋势、异常值和单位，视觉隐藏、屏幕阅读器可读 */
  summary?: string
  events?: Record<string, (params: unknown) => void>
  onChartReady?: (chart: echarts.ECharts) => void
  merge?: boolean
}

const visuallyHiddenStyle: CSSProperties = {
  position: 'absolute',
  width: 1,
  height: 1,
  margin: -1,
  padding: 0,
  overflow: 'hidden',
  clip: 'rect(0 0 0 0)',
  whiteSpace: 'nowrap',
  border: 0,
}

/**
 * ECharts 轻封装：负责初始化、option 更新、容器尺寸自适应与销毁。
 * 默认整体重绘；merge 模式按 series 替换并保留视口，供拖拽图使用。
 * 可访问性：容器带 role="img" 与 aria-label；setOption 时默认启用 aria 组件，
 * 调用方传入的 option.aria 字段优先，仅未提供的子项使用默认值。
 */
export default function EChart({ option, height = 320, ariaLabel, summary, events, onChartReady, merge }: EChartProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const summaryId = useId()
  const accessibleSummary = useMemo(
    () => summary?.trim() || buildAccessibleSummary(option, ariaLabel),
    [summary, option, ariaLabel],
  )

  useEffect(() => {
    if (!containerRef.current) return
    const chart = echarts.init(containerRef.current)
    chartRef.current = chart
    const observer = new ResizeObserver(() => chart.resize())
    observer.observe(containerRef.current)
    onChartReady?.(chart)
    return () => {
      observer.disconnect()
      chart.dispose()
      chartRef.current = null
    }
  }, [onChartReady])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart || !events) return
    const entries = Object.entries(events)
    for (const [name, handler] of entries) chart.on(name, handler)
    return () => {
      for (const [name, handler] of entries) chart.off(name, handler)
    }
  }, [events])

  useEffect(() => {
    // aria 配置允许数组形态（AriaComponentOption = Arrayable<AriaOption>），仅对象形态做默认合并
    const aria = Array.isArray(option.aria) ? undefined : option.aria
    const chart = chartRef.current
    if (!chart) return
    const nextOption = {
      ...option,
      aria: {
        ...aria,
        enabled: aria?.enabled ?? true,
        label: {
          ...aria?.label,
          enabled: aria?.label?.enabled ?? true,
          description: aria?.label?.description ?? accessibleSummary,
        },
      },
    }
    if (merge) chart.setOption(nextOption, { replaceMerge: ['series'] })
    else chart.setOption(nextOption, true)
  }, [option, accessibleSummary, merge])

  return (
    <>
      <div
        ref={containerRef}
        role="img"
        aria-label={ariaLabel}
        aria-describedby={summaryId}
        style={{ width: '100%', height }}
      />
      <p id={summaryId} style={visuallyHiddenStyle}>{accessibleSummary}</p>
    </>
  )
}
