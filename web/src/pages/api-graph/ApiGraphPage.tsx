import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Space, Spin, Statistic, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { ComposeOption } from 'echarts/core'
import type { GraphSeriesOption } from 'echarts/charts'
import type { LegendComponentOption, TooltipComponentOption } from 'echarts/components'
import { apiGraphApi, type ApiGraphEdge, type ApiGraphNode } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'
import { escapeHtml } from '../../utils/format'

// 按需注册 graph 图所需部件（共享 EChart 组件未注册 GraphChart，本页自带轻封装避免改动公共组件）
echarts.use([GraphChart, TooltipComponent, LegendComponent, CanvasRenderer])

type GraphOption = ComposeOption<GraphSeriesOption | TooltipComponentOption | LegendComponentOption>

/** 接口资产状态 → 图谱节点配色（与 antd 语义色板一致） */
const NODE_COLOR_BY_STATUS: Record<string, string> = {
  DISCOVERED: '#1677ff',
  CONFIRMED: '#52c41a',
  IGNORED: '#bfbfbf',
  DEPRECATED: '#fa8c16',
}

/** 外部调用方（非已发现接口）节点配色 */
const EXTERNAL_CALLER_COLOR = '#8c8c8c'

/** 指纹/ID 截断展示：保留首尾，中间省略 */
function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** Graph 轻封装：与 components/EChart 同职责，option 类型换为 graph 系列 */
function GraphChartView({ option, height = 480 }: { option: GraphOption; height?: number }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    if (!containerRef.current) return
    const chart = echarts.init(containerRef.current)
    chartRef.current = chart
    const observer = new ResizeObserver(() => chart.resize())
    observer.observe(containerRef.current)
    return () => {
      observer.disconnect()
      chart.dispose()
      chartRef.current = null
    }
  }, [])

  useEffect(() => {
    chartRef.current?.setOption(option, true)
  }, [option])

  return <div ref={containerRef} style={{ width: '100%', height }} />
}

/** API 安全图谱（WDSP / 阶段8）：接口节点 + 调用边，节点按资产状态上色，边宽按调用次数 */
export default function ApiGraphPage() {
  const [detailRecord, setDetailRecord] = useState<ApiGraphEdge | null>(null)

  const graphQuery = useQuery({
    queryKey: ['api-graph'],
    queryFn: () => apiGraphApi.graph(),
  })

  const nodes = useMemo(() => graphQuery.data?.nodes ?? [], [graphQuery.data])
  const edges = useMemo(() => graphQuery.data?.edges ?? [], [graphQuery.data])
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])

  const option = useMemo<GraphOption>(() => {
    const maxCallCount = Math.max(1, ...edges.map((e) => e.call_count))
    const categories = [
      ...Object.entries(API_ENDPOINT_STATUS_META).map(([status, meta]) => ({
        name: meta.label,
        itemStyle: { color: NODE_COLOR_BY_STATUS[status] ?? EXTERNAL_CALLER_COLOR },
      })),
      { name: '外部调用方', itemStyle: { color: EXTERNAL_CALLER_COLOR } },
    ]
    const categoryIndex = (node: ApiGraphNode) =>
      Object.keys(API_ENDPOINT_STATUS_META).indexOf(node.asset_status)

    const data = nodes.map((n) => ({
      id: n.id,
      name: n.endpoint_key,
      category: categoryIndex(n) >= 0 ? categoryIndex(n) : categories.length - 1,
      symbolSize: 18,
      label: { show: true, position: 'right' as const, fontSize: 11 },
    }))
    const links: NonNullable<GraphSeriesOption['links']> = []
    for (const e of edges) {
      // 源接口未知（外部调用方）时合成灰色节点；目标接口必须存在，否则跳过该边
      let source = e.source_endpoint_id ?? undefined
      if (!source || !nodeById.has(source)) {
        source = `caller:${e.caller_fingerprint}`
        if (!data.some((d) => d.id === source)) {
          data.push({
            id: source,
            name: truncateMiddle(e.caller_fingerprint),
            category: categories.length - 1,
            symbolSize: 12,
            label: { show: true, position: 'right' as const, fontSize: 11 },
          })
        }
      }
      if (!nodeById.has(e.target_endpoint_id)) continue
      links.push({
        source,
        target: e.target_endpoint_id,
        value: e.call_count,
        lineStyle: { width: 1 + (e.call_count / maxCallCount) * 6 },
      })
    }

    return {
      tooltip: {
        formatter: (params) => {
          const p = params as { dataType: string; data: { name?: string; value?: number } }
          if (p.dataType === 'edge') return `调用次数：${p.data.value ?? 0}`
          // name 为 endpoint_key（攻击者可通过恶意请求路径注入 HTML）：
          // tooltip 默认 html 渲染模式将返回值作为 HTML 插入 DOM，必须转义防存储型 XSS
          return escapeHtml(p.data.name ?? '')
        },
      },
      legend: [{ data: categories.map((c) => c.name), top: 0 }],
      series: [
        {
          type: 'graph',
          layout: 'force',
          roam: true,
          draggable: true,
          top: 32,
          categories,
          data,
          links,
          force: { repulsion: 220, edgeLength: [48, 140] },
          lineStyle: { color: 'source', curveness: 0.1, opacity: 0.7 },
          emphasis: { focus: 'adjacency' },
        },
      ],
    }
  }, [nodes, edges, nodeById])

  const edgeColumns: ColumnsType<ApiGraphEdge> = [
    {
      title: '调用方指纹',
      dataIndex: 'caller_fingerprint',
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{truncateMiddle(v, 12, 6)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '目标接口',
      dataIndex: 'target_endpoint_id',
      ellipsis: true,
      render: (v: string) => {
        const target = nodeById.get(v)
        return target ? <Typography.Text code>{target.endpoint_key}</Typography.Text> : truncateMiddle(v)
      },
    },
    { title: '调用次数', dataIndex: 'call_count', width: 110 },
  ]

  return (
    <Card title="API 安全图谱">
      <Typography.Paragraph type="secondary">
        节点为 API 接口（按资产状态上色：蓝=已发现、绿=已确认、灰=已忽略、橙=已废弃），边为运行时观测到的调用关系，边宽随调用次数增加；灰色小节点为未匹配到接口的外部调用方。
      </Typography.Paragraph>
      <QueryErrorAlert error={graphQuery.error} />
      <Space size="large" style={{ marginBottom: 16 }}>
        <Statistic title="节点数" value={nodes.length} loading={graphQuery.isLoading} />
        <Statistic title="调用边数" value={edges.length} loading={graphQuery.isLoading} />
      </Space>
      <Spin spinning={graphQuery.isLoading}>
        <GraphChartView option={option} height={480} />
      </Spin>
      <Typography.Title level={5}>调用边明细</Typography.Title>
      <SmartTable<ApiGraphEdge>
        storageKey="api-graph"
        rowKey="id"
        size="small"
        loading={graphQuery.isLoading}
        columns={edgeColumns}
        dataSource={edges}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        pagination={{ pageSize: 8, showSizeChanger: false, hideOnSinglePage: true, showTotal: (t) => `共 ${t} 条` }}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="调用边详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
