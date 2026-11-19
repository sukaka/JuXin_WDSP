import { Button, Descriptions, Drawer, List, Tabs, Tag, Typography } from 'antd'
import type { DataFlowEdge, DataFlowEvidenceRecord, DataFlowFieldEvidence, DataFlowNode, DataFlowNodeDetail } from '../../api/apiDataFlow'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { DATA_TYPE_LABELS, dataFlowBoundaryEvidenceLabel, dataFlowBoundaryTypeLabel, dataFlowDataTypes, dataFlowNetworkZoneLabel } from '../../utils/dataFlowCharts'
import {
  CLIENT_ADDRESS_SOURCE_LABELS,
  DATA_FLOW_EVIDENCE_TYPE_LABELS,
  DATA_FLOW_MATCH_LABELS,
  formatEnvironment,
} from '../../utils/i18nLabels'

const FIELD_MATCH_LABELS: Record<string, string> = {
  ...DATA_FLOW_MATCH_LABELS,
  CORRELATED_FIELD: '关联字段命中',
  EXACT: '精确匹配',
}

function evidenceTypeLabel(type?: string): string {
  if (!type) return '-'
  return DATA_FLOW_EVIDENCE_TYPE_LABELS[type] ?? type
}

function percentage(value: number): string {
  return `${(value * 100).toFixed(2)}%`
}

function fieldDirection(field: DataFlowFieldEvidence, edge: DataFlowEdge): string {
  if (field.side === 'RESPONSE') return `响应：${edge.target_name} → ${edge.source_name}`
  if (field.side === 'MESSAGE') return `消息：${edge.source_name} → ${edge.target_name}`
  return `请求：${edge.source_name} → ${edge.target_name}`
}

function SensitiveTypes({ edge, side }: { edge: DataFlowEdge; side: 'REQUEST' | 'RESPONSE' | 'MESSAGE' }) {
  const types = dataFlowDataTypes(edge, side)
  return types.length
    ? <>{types.map((type) => <Tag key={type} color={side === 'MESSAGE' ? 'green' : side === 'REQUEST' ? 'gold' : 'purple'}>{DATA_TYPE_LABELS[type] ?? type}</Tag>)}</>
    : <Typography.Text type="secondary">未识别</Typography.Text>
}

function BoundaryTypeValue({ type }: { type?: string }) {
  if (!type) return null
  return <Tag className={`data-flow-boundary-type ${type === 'PUBLIC_TO_INTERNAL' ? 'is-public' : 'is-unknown'}`} color={type === 'PUBLIC_TO_INTERNAL' ? 'volcano' : 'default'}>{dataFlowBoundaryTypeLabel(type)}</Tag>
}

function BoundaryEvidenceFields({ record }: { record: DataFlowEvidenceRecord }) {
  const addresses = [
    { key: 'client_address', label: '客户端地址', value: record.client_address, isCode: true },
    { key: 'peer_address', label: '对端地址', value: record.peer_address, isCode: true },
    { key: 'server_address', label: '服务端地址', value: record.server_address, isCode: true },
    {
      key: 'client_address_source',
      label: '客户端地址来源',
      value: record.client_address_source
        ? (CLIENT_ADDRESS_SOURCE_LABELS[record.client_address_source] ?? record.client_address_source)
        : undefined,
      isCode: false,
    },
  ]
  if (!record.boundary_type && !record.boundary_evidence && !record.source_zone && !record.target_zone && !addresses.some((field) => field.value)) return null
  return (
    <div className="data-flow-boundary-record" aria-label="边界地址证据">
      {record.boundary_type && <div className="data-flow-boundary-field"><span>边界类型</span><BoundaryTypeValue type={record.boundary_type} /></div>}
      {(record.source_zone || record.target_zone) && (
        <div className="data-flow-boundary-field">
          <span>区域方向</span>
          <Typography.Text>{dataFlowNetworkZoneLabel(record.source_zone)} → {dataFlowNetworkZoneLabel(record.target_zone)}</Typography.Text>
        </div>
      )}
      {addresses.map((field) => field.value && (
        <div className="data-flow-boundary-field" key={field.key}>
          <span>{field.label}</span>
          {field.isCode ? <Typography.Text code>{field.value}</Typography.Text> : <Typography.Text>{field.value}</Typography.Text>}
        </div>
      ))}
      {record.boundary_evidence && (
        <div className="data-flow-boundary-field">
          <span>边界依据</span>
          <Typography.Text>{dataFlowBoundaryEvidenceLabel(record.boundary_evidence)}</Typography.Text>
        </div>
      )}
    </div>
  )
}

function RelationItem({ edge, onEdge }: { edge: DataFlowEdge; onEdge: (edge: DataFlowEdge) => void }) {
  return (
    <List.Item actions={[<Button key="detail" type="link" size="small" onClick={() => onEdge(edge)}>API 与字段</Button>]}>
      <List.Item.Meta
        title={`${edge.source_name} → ${edge.target_name}（${edge.calls} 次）`}
        description={
          <div className="data-flow-relation">
            <div>{(edge.apis ?? []).length ? edge.apis.map((api) => <Typography.Text code key={api}>{api}</Typography.Text>) : 'API 未知'}</div>
            <div><Typography.Text type="secondary">请求：</Typography.Text><SensitiveTypes edge={edge} side="REQUEST" /></div>
            <div><Typography.Text type="secondary">响应：</Typography.Text><SensitiveTypes edge={edge} side="RESPONSE" /></div>
            {dataFlowDataTypes(edge, 'MESSAGE').length > 0 && <div><Typography.Text type="secondary">消息：</Typography.Text><SensitiveTypes edge={edge} side="MESSAGE" /></div>}
          </div>
        }
      />
    </List.Item>
  )
}

interface NodeDetailDrawerProps {
  node: DataFlowNode | null
  detail?: DataFlowNodeDetail
  error: Error | null
  onClose: () => void
  onEdge: (edge: DataFlowEdge) => void
}

export function NodeDetailDrawer({ node, detail, error, onClose, onEdge }: NodeDetailDrawerProps) {
  const addresses = node?.addresses ?? []
  return (
    <Drawer className="data-flow-detail-drawer" open={node !== null} width={560} title={node ? `${node.name} · 系统详情` : ''} onClose={onClose}>
      {node && (
        <>
          <div className="data-flow-node-summary">
            <span className="data-flow-node-type">{node.network_zone ? dataFlowNetworkZoneLabel(node.network_zone) : node.type === 'EXTERNAL' ? '外部 API 接收方' : '独立业务系统'}</span>
            <div className="data-flow-node-metrics">
              <div><span>调用量</span><strong>{node.calls.toLocaleString()}</strong></div>
              <div><span>API 数量</span><strong>{node.api_count}</strong></div>
              <div><span>直接上游</span><strong>{node.incoming_count}</strong></div>
              <div><span>直接下游</span><strong>{node.outgoing_count}</strong></div>
            </div>
            <Descriptions column={2} size="small">
              <Descriptions.Item label="平均耗时">{node.avg_latency_ms.toFixed(1)} ms</Descriptions.Item>
              <Descriptions.Item label="最大耗时">{node.max_latency_ms.toFixed(0)} ms</Descriptions.Item>
            </Descriptions>
          </div>
          <Tabs
            items={[
              {
                key: 'relations',
                label: '上下游 API',
                children: (
                  <>
                    <QueryErrorAlert error={error} message="加载系统详情失败" />
                    <Typography.Title level={5}>调用的下游（{detail?.dependencies.length ?? 0}）</Typography.Title>
                    <List size="small" dataSource={detail?.dependencies ?? []} renderItem={(edge) => <RelationItem edge={edge} onEdge={onEdge} />} />
                    <Typography.Title level={5}>调用我的上游（{detail?.called_by.length ?? 0}）</Typography.Title>
                    <List size="small" dataSource={detail?.called_by ?? []} renderItem={(edge) => <RelationItem edge={edge} onEdge={onEdge} />} />
                  </>
                ),
              },
              {
                key: 'infrastructure',
                label: '采集信息',
                children: (
                  <Descriptions column={1} bordered size="small">
                    <Descriptions.Item label="系统标识">{node.service_name || (node.type === 'SERVICE' ? node.name : '外部 API 接收方')}</Descriptions.Item>
                    <Descriptions.Item label="观测地址">
                      {addresses.length ? addresses.map((address) => <div key={address}><Typography.Text code>{address}</Typography.Text></div>) : '未知'}
                    </Descriptions.Item>
                    {node.network_zone && <Descriptions.Item label="网络区域">{dataFlowNetworkZoneLabel(node.network_zone)}</Descriptions.Item>}
                    <Descriptions.Item label="环境">{node.environment ? formatEnvironment(node.environment) : '未知'}</Descriptions.Item>
                    <Descriptions.Item label="命名空间">{node.namespace || '未知'}</Descriptions.Item>
                    <Descriptions.Item label="集群">{node.cluster || '未知'}</Descriptions.Item>
                  </Descriptions>
                ),
              },
            ]}
          />
        </>
      )}
    </Drawer>
  )
}

interface EvidenceDrawerProps {
  edge: DataFlowEdge | null
  items?: DataFlowEvidenceRecord[]
  loading: boolean
  error: Error | null
  onClose: () => void
}

export function EvidenceDrawer({ edge, items, loading, error, onClose }: EvidenceDrawerProps) {
  return (
    <Drawer className="data-flow-detail-drawer" open={edge !== null} width={560} title={edge ? `${edge.source_name} → ${edge.target_name}` : ''} onClose={onClose}>
      {edge && (
        <>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="调用量">{edge.calls}</Descriptions.Item>
            <Descriptions.Item label="API（按系统间调用关系统计）">
              <div className="data-flow-api-list">{(edge.apis ?? []).length ? edge.apis.map((api) => <Typography.Text code key={api}>{api}</Typography.Text>) : '未知'}</div>
            </Descriptions.Item>
            {edge.boundary_type && <Descriptions.Item label="边界类型"><BoundaryTypeValue type={edge.boundary_type} /></Descriptions.Item>}
            {(edge.source_zone || edge.target_zone) && (
              <Descriptions.Item label="区域方向">{dataFlowNetworkZoneLabel(edge.source_zone)} → {dataFlowNetworkZoneLabel(edge.target_zone)}</Descriptions.Item>
            )}
            {edge.boundary_evidence && <Descriptions.Item label="边界依据">{dataFlowBoundaryEvidenceLabel(edge.boundary_evidence)}</Descriptions.Item>}
            <Descriptions.Item label={`请求敏感数据（${edge.source_name} → ${edge.target_name}）`}><SensitiveTypes edge={edge} side="REQUEST" /></Descriptions.Item>
            <Descriptions.Item label={`响应敏感数据（${edge.target_name} → ${edge.source_name}）`}><SensitiveTypes edge={edge} side="RESPONSE" /></Descriptions.Item>
            {dataFlowDataTypes(edge, 'MESSAGE').length > 0 && <Descriptions.Item label={`消息敏感数据（${edge.source_name} → ${edge.target_name}）`}><SensitiveTypes edge={edge} side="MESSAGE" /></Descriptions.Item>}
            <Descriptions.Item label="证据类型">{evidenceTypeLabel(edge.evidence_type)}</Descriptions.Item>
            <Descriptions.Item label="置信度">{percentage(edge.confidence)}</Descriptions.Item>
            <Descriptions.Item label="样本 Trace">
              {edge.sample_trace_ids.length ? edge.sample_trace_ids.map((id) => <div key={id}><Typography.Text code>{id}</Typography.Text></div>) : '无'}
            </Descriptions.Item>
          </Descriptions>
          <QueryErrorAlert error={error} message="加载字段证据失败" />
          <Typography.Title level={5} style={{ marginTop: 16 }}>字段级脱敏证据</Typography.Title>
          <List
            loading={loading}
            dataSource={items ?? []}
            renderItem={(record) => (
              <List.Item>
                <List.Item.Meta
                  title={`${record.service_name} · ${evidenceTypeLabel(record.evidence_type)}`}
                  description={
                    <div className="data-flow-evidence-record">
                      <BoundaryEvidenceFields record={record} />
                      {record.fields.map((field, index) => (
                        <div key={`${field.path}-${index}`}>
                          <Tag color={field.side === 'MESSAGE' ? 'green' : field.side === 'RESPONSE' ? 'purple' : 'gold'}>{DATA_TYPE_LABELS[field.data_type] ?? field.data_type}</Tag>
                          <Typography.Text code>{field.path}</Typography.Text>
                          <div><Typography.Text type="secondary">{fieldDirection(field, edge)} · {FIELD_MATCH_LABELS[field.match] ?? field.match}</Typography.Text></div>
                          {field.value_hmac && <Typography.Text type="secondary" copyable={{ text: field.value_hmac }}>{field.value_hmac}</Typography.Text>}
                        </div>
                      ))}
                      {record.trace_id && <Typography.Text code>Trace: {record.trace_id}</Typography.Text>}
                    </div>
                  }
                />
              </List.Item>
            )}
          />
        </>
      )}
    </Drawer>
  )
}
