/* ==================== 业务性能（APM 阶段1：无 Agent 模式）图表 option 构建 ==================== */

import dayjs from 'dayjs'
import type { EChartOption } from '../components/EChart'
import type { ApmDependencyEdge, ApmRuntimeMetric, ApmSloTrendBucket, ApmTrendBucket } from '../types'
import { APM_DEPENDENCY_TARGET_TYPE_META } from './apm'
import { escapeHtml } from './format'

/** 请求/错误/阻断 + P95 组合趋势（双 y 轴：请求数 / 毫秒） */
export function apmTrendOption(trend: ApmTrendBucket[]): EChartOption {
  return {
    grid: { left: 56, right: 56, top: 32, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    xAxis: {
      type: 'category',
      data: trend.map((b) => dayjs(b.bucket_start).format('MM-DD HH:mm')),
      axisLabel: { hideOverlap: true },
    },
    yAxis: [
      { type: 'value', minInterval: 1, name: '请求数' },
      { type: 'value', name: 'P95 (ms)' },
    ],
    series: [
      { name: '请求量', type: 'line', smooth: true, data: trend.map((b) => b.requests), itemStyle: { color: '#2f54eb' } },
      { name: '错误数', type: 'line', smooth: true, data: trend.map((b) => b.errors), itemStyle: { color: '#cf1322' } },
      { name: '阻断量', type: 'line', smooth: true, data: trend.map((b) => b.blocked), itemStyle: { color: '#fa8c16' } },
      { name: 'P95 时延', type: 'line', smooth: true, yAxisIndex: 1, data: trend.map((b) => b.p95), itemStyle: { color: '#722ed1' } },
    ],
  }
}

/** 键值饼图（状态码分布 / WAF 动作分布） */
export function apmKvPieOption(items: { name: string; value: number }[]): EChartOption {
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        data: items,
        label: { formatter: '{b}: {c}' },
      },
    ],
  }
}

/** 运行时单指标折线（/apm-runtime 指标小卡；points ≤200，x 轴 HH:mm:ss） */
export function apmRuntimeMetricOption(metric: ApmRuntimeMetric): EChartOption {
  const points = metric.points ?? []
  return {
    grid: { left: 48, right: 16, top: 16, bottom: 24 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: points.map((p) => dayjs(p.ts).format('HH:mm:ss')),
      axisLabel: { hideOverlap: true },
    },
    yAxis: { type: 'value', name: metric.unit || '' },
    series: [
      {
        name: metric.name,
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: points.map((p) => p.value),
        itemStyle: { color: '#2f54eb' },
      },
    ],
  }
}

/** SLO 达标率趋势（/apm-slos 详情 Drawer；y 轴百分比 0-100） */
export function apmSloTrendOption(trend: ApmSloTrendBucket[]): EChartOption {
  return {
    grid: { left: 48, right: 16, top: 16, bottom: 28 },
    tooltip: { trigger: 'axis', valueFormatter: (v) => `${Number(v).toFixed(2)}%` },
    xAxis: {
      type: 'category',
      data: trend.map((b) => dayjs(b.bucket_start).format('MM-DD HH:mm')),
      axisLabel: { hideOverlap: true },
    },
    yAxis: { type: 'value', min: 0, max: 100, name: '达标率 (%)' },
    series: [
      {
        name: '达标率',
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: trend.map((b) => +(b.compliance_ratio * 100).toFixed(4)),
        itemStyle: { color: '#389e0d' },
      },
    ],
  }
}

/** 依赖关系图（/apm-dependencies 关系图视图；节点按目标类型着色，边为调用关系，force 布局） */
export function apmDependencyGraphOption(edges: ApmDependencyEdge[]): EChartOption {
  // 类别词表与 APM_DEPENDENCY_TARGET_TYPE_META 对齐；source 一律按服务（类别 0）
  const categories = ['service', 'db', 'messaging', 'external'].map((k) => ({
    name: APM_DEPENDENCY_TARGET_TYPE_META[k]?.label ?? k,
  }))
  const categoryOf = (t: string) =>
    Math.max(0, ['service', 'db', 'messaging', 'external'].indexOf(t))
  const nodeIndex = new Map<string, number>()
  const nodes: { name: string; category: number }[] = []
  const addNode = (name: string, category: number) => {
    if (!nodeIndex.has(name)) {
      nodeIndex.set(name, nodes.length)
      nodes.push({ name, category })
    }
  }
  for (const e of edges) {
    addNode(e.source, 0)
    addNode(e.target, categoryOf(e.target_type))
  }
  return {
    tooltip: {
      trigger: 'item',
      // 节点名来自依赖边的 source/target（外部目标主机名等可被外部输入影响）：
      // 默认 tooltip 为 html 渲染模式，显式 formatter 并对节点名转义防存储型 XSS
      formatter: (params) => {
        const p = params as { dataType?: string; name?: string; value?: number }
        if (p.dataType === 'edge') return `调用次数：${p.value ?? 0}`
        return escapeHtml(p.name ?? '')
      },
    },
    legend: { top: 0, data: categories.map((c) => c.name) },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        top: 32,
        categories,
        data: nodes,
        links: edges.map((e) => ({
          source: e.source,
          target: e.target,
          // GraphEdgeItemOption.value 仅接受数值：填调用数，tooltip 默认展示
          value: e.calls,
        })),
        force: { repulsion: 240, edgeLength: [80, 160] },
        label: { show: true, position: 'right', fontSize: 11 },
        lineStyle: { color: 'source', curveness: 0.1 },
        emphasis: { focus: 'adjacency' },
      },
    ],
  }
}
