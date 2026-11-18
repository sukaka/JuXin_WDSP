import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Checkbox, Empty, Space, Tag, Typography } from 'antd'
import { accessLogsApi, type AccessLogFlowParams, type FlowNode } from '../../api/accessLogs'
import { ApiError } from '../../api/client'
import EChart, { type EChartOption } from '../../components/EChart'

const kinds: Array<{ key: FlowNode['kind']; label: string; column: number; color: string }> = [
  { key: 'SOURCE', label: '来源 IP', column: 0, color: '#3b6ea5' },
  { key: 'ACCOUNT', label: '身份指纹', column: 1, color: '#766a98' },
  { key: 'REQUEST_FIELD', label: '请求敏感字段', column: 2, color: '#ad6544' },
  { key: 'APPLICATION', label: '应用', column: 3, color: '#53745b' },
  { key: 'API', label: 'API', column: 4, color: '#3f7881' },
  { key: 'RESPONSE_FIELD', label: '响应敏感字段', column: 5, color: '#9a5d6b' },
]

function drillFilters(filters: Record<string, string>, requestIds: string[]): AccessLogFlowParams {
  const result = { ...filters, request_ids: requestIds.join(',') } as AccessLogFlowParams
  if (requestIds.length > 0) result.request_id = undefined
  return result
}

function truncatedLabel(name: string): string {
  return name.length > 32 ? name.slice(0, 31) + '…' : name
}

function tooltip(node: FlowNode): string {
  return `${node.name}<br/>去重请求：${node.request_count}<br/>字段命中：${node.field_hits}${node.other ? `<br/>合并节点：${node.aggregated_nodes ?? 0}` : ''}${node.drill_exact ? '<br/>点击查看对应请求' : '<br/>集合较大，下钻使用所示筛选条件'}`
}

export default function AccessLogFlow({ filters, onDrill }: { filters: AccessLogFlowParams; onDrill: (filters: AccessLogFlowParams) => void }) {
  const [visibleKinds, setVisibleKinds] = useState<Set<FlowNode['kind']>>(() => new Set(kinds.map((kind) => kind.key)))
  const flow = useQuery({
    queryKey: ['access-log-audit-flow', filters],
    queryFn: () => accessLogsApi.flow(filters),
    retry: false,
  })
  const nodes = useMemo(() => flow.data?.nodes.filter((node) => visibleKinds.has(node.kind)) ?? [], [flow.data, visibleKinds])
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes])
  const edges = useMemo(() => (flow.data?.edges ?? []).filter((edge) => nodeMap.has(edge.source_id) && nodeMap.has(edge.target_id)), [flow.data, nodeMap])
  const positions = useMemo(() => {
    const rows = new Map<FlowNode['kind'], number>()
    return new Map(nodes.map((node) => {
      const row = rows.get(node.kind) ?? 0
      rows.set(node.kind, row + 1)
      const kind = kinds.find((item) => item.key === node.kind)
      return [node.id, { x: 85 + (kind?.column ?? 0) * 185, y: 64 + row * 62 }]
    }))
  }, [nodes])
  const option = useMemo(() => ({
    animationDuration: 240,
    tooltip: {
      trigger: 'item',
      formatter: (params: unknown) => {
        const item = params as { dataType?: string; data?: { id?: string; source?: string; target?: string } }
        if (item.dataType === 'edge') {
          const edge = flow.data?.edges.find((candidate) => candidate.source_id === item.data?.source && candidate.target_id === item.data?.target)
          return edge ? `去重请求：${edge.request_count}<br/>字段命中：${edge.field_hits}` : ''
        }
        const node = item.data?.id ? nodeMap.get(item.data.id) : undefined
        return node ? tooltip(node) : ''
      },
    },
    series: [{
      type: 'graph', layout: 'none', roam: true, left: 0, top: 0, width: 1010,
      height: Math.max(420, nodes.length * 35), edgeSymbol: ['none', 'arrow'], edgeSymbolSize: [0, 7],
      emphasis: { focus: 'adjacency' },
      label: { show: true, position: 'bottom', distance: 6, fontSize: 11, color: '#243247', formatter: (params: unknown) => truncatedLabel(String((params as { name?: string }).name ?? '')) },
      data: nodes.map((node) => ({
        id: node.id, name: node.name, x: positions.get(node.id)?.x, y: positions.get(node.id)?.y,
        symbolSize: Math.min(42, 25 + Math.sqrt(node.request_count) * 3),
        itemStyle: { color: kinds.find((kind) => kind.key === node.kind)?.color, borderColor: '#f7f9fb', borderWidth: 2 },
      })),
      links: edges.map((edge) => ({
        source: edge.source_id, target: edge.target_id,
        lineStyle: { color: '#a5b2c0', width: Math.min(3, 1 + Math.log10(edge.request_count + 1)), curveness: 0.08, opacity: 0.75 },
      })),
    }],
  }) as EChartOption, [nodes, edges, positions, nodeMap, flow.data])
  const events = useMemo(() => ({
    click: (params: unknown) => {
      const item = params as { dataType?: string; data?: { id?: string; source?: string; target?: string } }
      if (item.dataType === 'edge') {
        const edge = flow.data?.edges.find((candidate) => candidate.source_id === item.data?.source && candidate.target_id === item.data?.target)
        if (edge) onDrill(drillFilters(edge.filters, edge.request_ids))
        return
      }
      const node = item.data?.id ? nodeMap.get(item.data.id) : undefined
      if (node) onDrill(drillFilters(node.filters, node.request_ids))
    },
  }), [flow.data, nodeMap, onDrill])

  if (flow.isLoading) return <Typography.Text type="secondary">正在聚合真实请求流向...</Typography.Text>
  if (flow.isError) return <Alert type="error" showIcon message="审计流向加载失败" description={flow.error instanceof ApiError ? flow.error.message : '网络异常'} />
  if (!flow.data || flow.data.nodes.length === 0) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前筛选范围内没有真实请求，未生成流向节点" />

  return (
    <section aria-label="审计流向图">
      <Space direction="vertical" size={12} style={{ width: '100%', marginBottom: 16 }}>
        <Space wrap size={16}>
          <Typography.Text strong>去重请求 {flow.data.request_count}</Typography.Text>
          <Typography.Text>涉敏请求 {flow.data.sensitive_request_count}</Typography.Text>
          <Typography.Text type="secondary">字段命中 {flow.data.nodes.reduce((sum, node) => sum + node.field_hits, 0)}</Typography.Text>
          <Tag>真实访问日志 + 运行时字段证据</Tag>
        </Space>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          流向为 来源/身份 → 请求字段 → 应用 → API → 响应字段。响应字段不表示反向调用，图中不含字段原值。
        </Typography.Text>
        <Checkbox.Group
          aria-label="显示节点类型"
          options={kinds.map((kind) => ({ label: kind.label, value: kind.key }))}
          value={[...visibleKinds]}
          onChange={(values) => setVisibleKinds(new Set(values as FlowNode['kind'][]))}
        />
        {flow.data.truncated && <Alert type="info" showIcon message="结果已按 Top N 聚合" description="“其他”保留真实去重数量；大集合下钻若不能精确列出请求 ID，会按节点筛选条件执行。" />}
      </Space>
      <div style={{ overflowX: 'auto', borderTop: '1px solid #e8edf3', paddingTop: 8 }}>
        <div style={{ minWidth: 1060, position: 'relative' }}>
          {kinds.map((kind) => <Typography.Text key={kind.key} type="secondary" style={{ position: 'absolute', left: 35 + kind.column * 185, top: 0, fontSize: 12 }}>{kind.label}</Typography.Text>)}
          <EChart option={option} events={events} height={Math.max(430, Math.max(...kinds.map((kind) => nodes.filter((node) => node.kind === kind.key).length)) * 62 + 100)} ariaLabel="按真实请求聚合的来源、身份、应用、API和敏感字段流向图" summary={`共${flow.data.request_count}个去重请求，其中${flow.data.sensitive_request_count}个包含敏感字段`} />
        </div>
      </div>
      <details style={{ marginTop: 8 }}>
        <summary style={{ cursor: 'pointer', color: '#3b6ea5' }}>查看节点计数表</summary>
        <table style={{ width: '100%', marginTop: 12, borderCollapse: 'collapse', fontSize: 12 }}>
          <thead><tr><th style={{ textAlign: 'left', padding: 8 }}>类型 / 节点</th><th style={{ textAlign: 'right', padding: 8 }}>去重请求</th><th style={{ textAlign: 'right', padding: 8 }}>字段命中</th></tr></thead>
          <tbody>{flow.data.nodes.map((node) => <tr key={node.id}>
            <td style={{ padding: 8, borderTop: '1px solid #edf0f4' }}>
              <ButtonLink node={node} onDrill={onDrill} />
              {node.kind === 'ACCOUNT' && <Tag color={node.verified ? 'success' : 'default'} style={{ marginLeft: 6 }}>{node.verified ? '已验证' : '已识别'}</Tag>}
            </td>
            <td style={{ padding: 8, textAlign: 'right', borderTop: '1px solid #edf0f4' }}>{node.request_count}</td>
            <td style={{ padding: 8, textAlign: 'right', borderTop: '1px solid #edf0f4' }}>{node.field_hits}</td>
          </tr>)}</tbody>
        </table>
      </details>
    </section>
  )
}

function ButtonLink({ node, onDrill }: { node: FlowNode; onDrill: (filters: AccessLogFlowParams) => void }) {
  return <button type="button" style={{ border: 0, background: 'transparent', padding: 0, color: '#3b6ea5', cursor: 'pointer', textAlign: 'left' }} onClick={() => onDrill(drillFilters(node.filters, node.request_ids))}>{kinds.find((kind) => kind.key === node.kind)?.label} / {node.name}</button>
}
