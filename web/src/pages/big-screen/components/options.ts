import * as echarts from 'echarts/core'
import type { EChartsCoreOption } from 'echarts/core'
import dayjs from 'dayjs'
import { BS_AXIS_BASE, BS_COLORS, BS_TOOLTIP } from './theme'

export interface TrendSeries {
  name: string
  data: number[]
  color: string
  /** 是否填充渐变面积，默认 true */
  area?: boolean
}

/** 渐变面积折线趋势图 */
export function trendOption(times: string[], series: TrendSeries[], timeFormat = 'HH:mm'): EChartsCoreOption {
  return {
    color: series.map((s) => s.color),
    tooltip: { trigger: 'axis', ...BS_TOOLTIP },
    legend: { top: 0, textStyle: { color: 'rgba(214, 228, 255, 0.75)' } },
    grid: { left: 56, right: 20, top: 34, bottom: 28 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: times.map((t) => dayjs(t).format(timeFormat)),
      ...BS_AXIS_BASE,
    },
    yAxis: { type: 'value', minInterval: 1, ...BS_AXIS_BASE },
    series: series.map((s) => ({
      name: s.name,
      type: 'line' as const,
      smooth: true,
      symbol: 'none',
      data: s.data,
      lineStyle: { width: 2, shadowColor: s.color, shadowBlur: 12 },
      areaStyle:
        s.area === false
          ? undefined
          : {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: `${s.color}55` },
                { offset: 1, color: `${s.color}00` },
              ]),
            },
    })),
  }
}

/** 横向条形排行图（值在条形末端发光显示） */
export function hBarOption(
  items: { name: string; value: number }[],
  color = '#00e5ff',
): EChartsCoreOption {
  const sorted = [...items].sort((a, b) => a.value - b.value)
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...BS_TOOLTIP },
    grid: { left: 8, right: 48, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: 'value', minInterval: 1, ...BS_AXIS_BASE, splitLine: { show: false } },
    yAxis: {
      type: 'category',
      data: sorted.map((i) => i.name),
      ...BS_AXIS_BASE,
      splitLine: { show: false },
      axisLabel: { color: 'rgba(214, 228, 255, 0.85)', width: 110, overflow: 'truncate' },
    },
    series: [
      {
        type: 'bar',
        data: sorted.map((i) => i.value),
        barMaxWidth: 14,
        label: { show: true, position: 'right', color, fontFamily: 'monospace' },
        itemStyle: {
          borderRadius: [0, 4, 4, 0],
          color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
            { offset: 0, color: `${color}33` },
            { offset: 1, color },
          ]),
          shadowColor: color,
          shadowBlur: 8,
        },
      },
    ],
  }
}

/** 环形占比图 */
export function donutOption(
  items: { name: string; value: number }[],
  colors: string[] = BS_COLORS,
): EChartsCoreOption {
  return {
    color: colors,
    tooltip: { trigger: 'item', ...BS_TOOLTIP },
    legend: {
      bottom: 0,
      textStyle: { color: 'rgba(214, 228, 255, 0.75)' },
      itemWidth: 12,
      itemHeight: 8,
    },
    series: [
      {
        type: 'pie',
        radius: ['48%', '72%'],
        center: ['50%', '44%'],
        avoidLabelOverlap: true,
        label: { color: 'rgba(214, 228, 255, 0.85)', formatter: '{b}\n{c}' },
        labelLine: { lineStyle: { color: 'rgba(0, 229, 255, 0.4)' } },
        itemStyle: { borderColor: '#051129', borderWidth: 2 },
        emphasis: { scaleSize: 8, itemStyle: { shadowBlur: 20, shadowColor: 'rgba(0,229,255,0.5)' } },
        data: items,
      },
    ],
  }
}

/** 仪表盘（百分比水位） */
export function gaugeOption(value: number, name: string, color = '#00e5ff'): EChartsCoreOption {
  return {
    series: [
      {
        type: 'gauge',
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max: 100,
        progress: {
          show: true,
          width: 12,
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: `${color}66` },
              { offset: 1, color },
            ]),
            shadowColor: color,
            shadowBlur: 12,
          },
        },
        axisLine: { lineStyle: { width: 12, color: [[1, 'rgba(0, 229, 255, 0.12)']] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        title: { offsetCenter: [0, '32%'], color: 'rgba(214, 228, 255, 0.7)', fontSize: 13 },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, '-4%'],
          formatter: (v: number) => `${v.toFixed(1)}%`,
          color,
          fontSize: 26,
          fontWeight: 700,
        },
        data: [{ value: Math.max(0, Math.min(100, value)), name }],
      },
    ],
  }
}

/** 雷达图 */
export function radarOption(
  indicators: { name: string; max: number }[],
  values: number[],
  color = '#b388ff',
  name = '分布',
): EChartsCoreOption {
  return {
    tooltip: { ...BS_TOOLTIP },
    radar: {
      indicator: indicators,
      radius: '62%',
      center: ['50%', '52%'],
      axisName: { color: 'rgba(214, 228, 255, 0.8)', fontSize: 12 },
      splitArea: { areaStyle: { color: ['rgba(0,229,255,0.02)', 'rgba(0,229,255,0.05)'] } },
      splitLine: { lineStyle: { color: 'rgba(0, 229, 255, 0.15)' } },
      axisLine: { lineStyle: { color: 'rgba(0, 229, 255, 0.2)' } },
    },
    series: [
      {
        type: 'radar',
        data: [
          {
            value: values,
            name,
            areaStyle: { color: `${color}44` },
            lineStyle: { color, width: 2, shadowColor: color, shadowBlur: 10 },
            itemStyle: { color },
          },
        ],
      },
    ],
  }
}
