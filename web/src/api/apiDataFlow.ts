import { request } from './client'

export type DataFlowView = 'service' | 'network' | 'boundary'
export type DataFlowNetworkZone = 'PUBLIC' | 'INTERNAL' | 'UNKNOWN'
export type DataFlowClientAddressSource = 'DIRECT_PEER' | 'TRUSTED_PROXY' | 'GATEWAY' | 'UNKNOWN'
export type DataFlowBoundaryType = 'PUBLIC_TO_INTERNAL' | 'UNKNOWN'
export type DataFlowBoundaryEvidence = 'DIRECT_PEER' | 'TRUSTED_PROXY' | 'GATEWAY' | 'MISSING_CLIENT_ADDRESS' | 'MISSING_SERVER_ADDRESS' | 'UNTRUSTED_CLIENT_SOURCE'

export interface DataFlowQuery {
  start?: string
  end?: string
  application_id?: string
  method?: string
  data_type?: string
  max_edges?: number
  view?: DataFlowView
}

export interface DataFlowNode {
  id: string
  name: string
  type: string
  service_name?: string
  group_name?: string
  addresses?: string[]
  environment?: string
  namespace?: string
  cluster?: string
  network_zone?: DataFlowNetworkZone
  calls: number
  api_count: number
  avg_latency_ms: number
  max_latency_ms: number
  error_rate: number
  health: string
  incoming_count: number
  outgoing_count: number
}

export interface DataFlowFieldEvidence {
  side: string
  path: string
  data_type: string
  value_hmac?: string
  hmac_key_id?: string
  match: string
}

export interface DataFlowEdge {
  id: string
  source_id: string
  target_id: string
  source_name: string
  target_name: string
  protocol: string
  method: string
  path_template: string
  apis: string[]
  calls: number
  errors: number
  avg_latency_ms: number
  max_latency_ms: number
  data_types: string[]
  fields: DataFlowFieldEvidence[]
  evidence_type: string
  confidence: number
  first_seen_at: string
  last_seen_at: string
  sample_trace_ids: string[]
  source_zone?: DataFlowNetworkZone
  target_zone?: DataFlowNetworkZone
  boundary_type?: DataFlowBoundaryType
  boundary_evidence?: DataFlowBoundaryEvidence
}

export interface DataFlowQuality {
  observations: number
  trace_linked: number
  trace_coverage: number
  truncated: number
  data_source: string
  partial: boolean
  message: string
}

export interface DataFlowGraph {
  nodes: DataFlowNode[]
  edges: DataFlowEdge[]
  truncated: boolean
  view?: DataFlowView
  quality: DataFlowQuality
}

export interface DataFlowNodeDetail {
  node: DataFlowNode
  dependencies: DataFlowEdge[]
  called_by: DataFlowEdge[]
}

export interface DataFlowEvidenceRecord {
  agent_id: string
  event_id: string
  edge_id: string
  occurred_at: string
  service_name: string
  trace_id: string
  span_id: string
  fields: DataFlowFieldEvidence[]
  evidence_type: string
  confidence: number
  peer_address?: string
  client_address?: string
  client_address_source?: DataFlowClientAddressSource
  server_address?: string
  source_zone?: DataFlowNetworkZone
  target_zone?: DataFlowNetworkZone
  boundary_type?: DataFlowBoundaryType
  boundary_evidence?: DataFlowBoundaryEvidence
}

const PATH = '/api-security/data-flow'

function normalizeEdge(edge: DataFlowEdge): DataFlowEdge {
  return {
    ...edge,
    apis: edge.apis ?? (edge.method || edge.path_template ? [`${edge.method} ${edge.path_template}`.trim()] : []),
    data_types: edge.data_types ?? [],
    fields: edge.fields ?? [],
    sample_trace_ids: edge.sample_trace_ids ?? [],
  }
}

function normalizeEvidenceRecord(record: DataFlowEvidenceRecord): DataFlowEvidenceRecord {
  const peerAddress = record.peer_address || undefined
  const clientAddressSource = record.client_address_source || (peerAddress ? 'DIRECT_PEER' : undefined)
  const clientAddress = record.client_address || (clientAddressSource === 'DIRECT_PEER' ? peerAddress : undefined)
  return { ...record, peer_address: peerAddress, client_address: clientAddress, client_address_source: clientAddressSource }
}

export const apiDataFlowApi = {
  graph: async (params: DataFlowQuery) => {
    const data = await request<DataFlowGraph>(`${PATH}/graph`, { query: { ...params } })
    return { ...data, nodes: data.nodes ?? [], edges: (data.edges ?? []).map(normalizeEdge) }
  },
  node: async (id: string, params: DataFlowQuery) => {
    const data = await request<DataFlowNodeDetail>(`${PATH}/nodes/${encodeURIComponent(id)}`, { query: { ...params } })
    return { ...data, dependencies: (data.dependencies ?? []).map(normalizeEdge), called_by: (data.called_by ?? []).map(normalizeEdge) }
  },
  evidence: async (edgeID: string, params: DataFlowQuery & { limit?: number }) => {
    const data = await request<{ items: DataFlowEvidenceRecord[]; total: number }>(`${PATH}/evidence`, {
      query: { ...params, edge_id: edgeID },
    })
    return { ...data, items: (data.items ?? []).map(normalizeEvidenceRecord) }
  },
  quality: (params: DataFlowQuery) => request<DataFlowQuality>(`${PATH}/quality`, { query: { ...params } }),
}
