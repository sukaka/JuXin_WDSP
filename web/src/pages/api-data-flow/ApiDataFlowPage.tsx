import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  DatePicker,
  Empty,
  Input,
  InputNumber,
  Radio,
  Select,
  Spin,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs, { type Dayjs } from 'dayjs'
import { apiDataFlowApi, type DataFlowEdge, type DataFlowNode, type DataFlowQuery } from '../../api/apiDataFlow'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import DataFlowCanvas from './DataFlowCanvas'
import { EvidenceDrawer, NodeDetailDrawer } from './DataFlowDetails'
import { DATA_TYPE_LABELS, dataFlowDataTypes, dataFlowFields } from '../../utils/dataFlowCharts'
import './api-data-flow.css'

function percent(value: number): string {
  return `${(value * 100).toFixed(2)}%`
}

export default function ApiDataFlowPage() {
  const [range, setRange] = useState<[Dayjs, Dayjs]>(() => [dayjs().subtract(1, 'hour'), dayjs()])
  const [applicationId, setApplicationId] = useState<string>()
  const [method, setMethod] = useState<string>()
  const [dataType, setDataType] = useState('')
  const [maxEdges, setMaxEdges] = useState(50)
  const [presentation, setPresentation] = useState<'graph' | 'table'>('graph')
  const [topology, setTopology] = useState<NonNullable<DataFlowQuery['view']>>('service')
  const [applied, setApplied] = useState<DataFlowQuery>(() => ({
    start: dayjs().subtract(1, 'hour').toISOString(),
    end: dayjs().toISOString(),
    max_edges: 50,
    view: 'service',
  }))
  const [selectedNode, setSelectedNode] = useState<DataFlowNode | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<DataFlowEdge | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'api-data-flow-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const graphQuery = useQuery({
    queryKey: ['api-data-flow', applied],
    queryFn: () => apiDataFlowApi.graph(applied),
  })
  const nodeQuery = useQuery({
    queryKey: ['api-data-flow-node', selectedNode?.id, applied],
    queryFn: () => apiDataFlowApi.node(selectedNode!.id, applied),
    enabled: selectedNode !== null,
  })
  const evidenceQuery = useQuery({
    queryKey: ['api-data-flow-evidence', selectedEdge?.id, applied],
    queryFn: () => apiDataFlowApi.evidence(selectedEdge!.id, { ...applied, limit: 100 }),
    enabled: selectedEdge !== null,
  })
  const graph = graphQuery.data

  const applyFilters = () => {
    setSelectedNode(null)
    setSelectedEdge(null)
    setApplied({
      start: range[0].toISOString(),
      end: range[1].toISOString(),
      application_id: applicationId || undefined,
      method: method || undefined,
      data_type: dataType.trim() || undefined,
      max_edges: maxEdges,
      view: topology,
    })
  }
  const resetFilters = () => {
    const nextRange: [Dayjs, Dayjs] = [dayjs().subtract(1, 'hour'), dayjs()]
    setRange(nextRange)
    setApplicationId(undefined)
    setMethod(undefined)
    setDataType('')
    setMaxEdges(50)
    setTopology('service')
    setSelectedNode(null)
    setSelectedEdge(null)
    setApplied({ start: nextRange[0].toISOString(), end: nextRange[1].toISOString(), max_edges: 50, view: 'service' })
  }

  const sensitiveTags = (edge: DataFlowEdge, side: 'REQUEST' | 'RESPONSE' | 'MESSAGE') => {
    const color = side === 'MESSAGE' ? 'green' : side === 'REQUEST' ? 'gold' : 'purple'
    const fields = dataFlowFields(edge, side)
    if (fields.length) {
      return <div className="data-flow-sensitive-fields">{fields.map((field, index) => (
        <Tag key={`${field.data_type}:${field.path}:${index}`} color={color}>
          <span>{DATA_TYPE_LABELS[field.data_type] ?? field.data_type}</span>
          <Typography.Text code>{field.path}</Typography.Text>
        </Tag>
      ))}</div>
    }
    const types = dataFlowDataTypes(edge, side)
    return types.length
      ? types.map((value) => <Tag key={value} color={color}>{DATA_TYPE_LABELS[value] ?? value}</Tag>)
      : <Typography.Text type="secondary">未识别</Typography.Text>
  }
  const hasMessageFields = (graph?.edges ?? []).some((edge) => dataFlowDataTypes(edge, 'MESSAGE').length > 0)
  const columns: ColumnsType<DataFlowEdge> = [
    { title: '调用系统', dataIndex: 'source_name', ellipsis: true },
    { title: '被调用系统', dataIndex: 'target_name', ellipsis: true },
    {
      title: 'API',
      dataIndex: 'apis',
      render: (values: string[]) => values.length
        ? <div className="data-flow-api-list">{values.map((value) => <Typography.Text code key={value}>{value}</Typography.Text>)}</div>
        : <Typography.Text type="secondary">未知</Typography.Text>,
    },
    { title: '调用量', dataIndex: 'calls', width: 90 },
    { title: '请求敏感数据', key: 'request_data', render: (_, record) => sensitiveTags(record, 'REQUEST') },
    { title: '响应敏感数据', key: 'response_data', render: (_, record) => sensitiveTags(record, 'RESPONSE') },
    { title: '消息敏感数据', key: 'message_data', hidden: !hasMessageFields, render: (_, record) => sensitiveTags(record, 'MESSAGE') },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      render: (_, record) => <Button type="link" size="small" onClick={() => setSelectedEdge(record)}>查看详情</Button>,
    },
  ]

  return (
    <Card
      className="api-data-flow-page"
      title="数据流向"
      extra={
        <Radio.Group
          className="data-flow-presentation"
          value={presentation}
          onChange={(event) => setPresentation(event.target.value as 'graph' | 'table')}
          options={[{ value: 'graph', label: '应用流向' }, { value: 'table', label: '边明细' }]}
          optionType="button"
          size="small"
        />
      }
    >
      <div className="data-flow-scope">
        <Typography.Text type="secondary">{graph?.view === 'boundary'
          ? '内外网边界仅依据观测地址范围与客户端来源证据展示方向；代理、NAT 或证据不足时显示边界未知，不猜测真实公网客户端。点击节点或调用关系可查看地址与证据。'
          : '基于 Agent 的 HTTP 配对观测，展示独立业务系统之间的 API 调用与敏感数据流向；每个节点代表一个独立系统，点击系统或调用关系可查看上下游 API 与字段证据。'}</Typography.Text>
      </div>
      <div className="data-flow-filters">
        <label className="data-flow-filter data-flow-filter-range">
          <span className="data-flow-filter-label">观测时间</span>
          <DatePicker.RangePicker
            showTime
            value={range}
            onChange={(value) => {
              if (value?.[0] && value[1]) setRange([value[0], value[1]])
            }}
          />
        </label>
        <label className="data-flow-filter">
          <span className="data-flow-filter-label">拓扑视图</span>
          <Select
            aria-label="拓扑视图"
            value={topology}
            onChange={setTopology}
            options={[{ value: 'service', label: '独立系统视图' }, { value: 'network', label: '网络拓扑' }, { value: 'boundary', label: '内外网边界' }]}
          />
        </label>
        <label className="data-flow-filter">
          <span className="data-flow-filter-label">应用</span>
          <Select
            aria-label="应用"
            value={applicationId}
            onChange={setApplicationId}
            allowClear
            showSearch
            optionFilterProp="label"
            loading={applicationsQuery.isLoading}
            placeholder="全部应用"
            options={(applicationsQuery.data?.items ?? []).map((application) => ({ value: application.id, label: `${application.name} (${application.code})` }))}
          />
        </label>
        <label className="data-flow-filter">
          <span className="data-flow-filter-label">请求方法</span>
          <Select
            aria-label="Method"
            value={method}
            onChange={setMethod}
            allowClear
            placeholder="全部 Method"
            options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((value) => ({ value, label: value }))}
          />
        </label>
        <label className="data-flow-filter">
          <span className="data-flow-filter-label">数据类型</span>
          <Input
            aria-label="数据类型"
            value={dataType}
            onChange={(event) => setDataType(event.target.value)}
            placeholder="如 PHONE"
            maxLength={64}
          />
        </label>
        <label className="data-flow-filter">
          <span className="data-flow-filter-label">最大边数</span>
          <InputNumber aria-label="最大边数" value={maxEdges} onChange={(value) => setMaxEdges(value ?? 50)} min={1} max={200} />
        </label>
        <div className="data-flow-filter-actions">
          <Button onClick={resetFilters}>重置</Button>
          <Button type="primary" loading={graphQuery.isFetching} onClick={applyFilters}>查询</Button>
        </div>
      </div>

      <QueryErrorAlert error={applicationsQuery.error} message="加载应用列表失败" />
      <QueryErrorAlert error={graphQuery.error} message="加载系统间 API 调用失败" />
      {graph && (
        <div className="data-flow-quality-strip" aria-label="数据质量概览">
          <span>业务观测 <strong>{graph.quality.observations.toLocaleString()}</strong></span>
          <span>Trace 关联 <strong>{percent(graph.quality.trace_coverage)}</strong></span>
          <span>字段截断 <strong>{graph.quality.truncated.toLocaleString()}</strong></span>
        </div>
      )}
      {graph?.quality.partial && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="调用证据不完整"
          description={`${graph.quality.message}；Trace 关联覆盖率 ${percent(graph.quality.trace_coverage)}，未关联部分不会被推断为确定的系统间 API 调用。`}
        />
      )}
      {graph?.truncated && <Alert type="info" showIcon style={{ marginBottom: 12 }} message={`仅展示前 ${maxEdges} 条系统间 API 调用关系，请缩小时间窗或增加过滤条件。`} />}
      {graphQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 80 }}><Spin /></div>
      ) : !graph || graph.edges.length === 0 ? (
        <Empty description={graph?.quality.message || '当前时间窗暂无独立系统之间的 API 调用证据'} style={{ padding: 64 }}>
          <Typography.Text type="secondary">请至少在调用方系统接入 Agent 并完成应用绑定；只有具备可靠的 HTTP 配对与 Trace 证据时，才展示系统间调用关系。</Typography.Text>
        </Empty>
      ) : presentation === 'graph' ? (
        <DataFlowCanvas graph={graph} onNode={setSelectedNode} onEdge={setSelectedEdge} />
      ) : (
        <SmartTable<DataFlowEdge>
          storageKey="api-data-flow"
          rowKey="id"
          loading={graphQuery.isFetching}
          columns={columns}
          dataSource={graph.edges}
          scroll={{ x: 1320 }}
          onRow={(record) => ({
            onDoubleClick: (event) => {
              if ((event.target as HTMLElement).closest('button')) return
              const source = graph.nodes.find((node) => node.id === record.source_id)
              if (source) setSelectedNode(source)
            },
          })}
          pagination={{ pageSize: 20, showSizeChanger: false, showTotal: (total) => `共 ${total} 条` }}
        />
      )}
      {presentation === 'graph' && graph && graph.edges.length > 0 && (
        <div className="data-flow-node-index">
          <span className="data-flow-node-index-label">系统索引</span>
          {graph.nodes.map((node) => (
            <Button key={node.id} size="small" onClick={() => setSelectedNode(node)}>
              {node.name} · {node.calls} 次
            </Button>
          ))}
        </div>
      )}

      <NodeDetailDrawer
        node={selectedNode}
        detail={nodeQuery.data}
        error={nodeQuery.error}
        onClose={() => setSelectedNode(null)}
        onEdge={(edge) => {
          setSelectedNode(null)
          setSelectedEdge(edge)
        }}
      />
      <EvidenceDrawer edge={selectedEdge} items={evidenceQuery.data?.items} loading={evidenceQuery.isLoading} error={evidenceQuery.error} onClose={() => setSelectedEdge(null)} />
    </Card>
  )
}
