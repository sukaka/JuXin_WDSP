import { request } from './client'
import type { HaVipStatus, NetworkConfigStatus } from '../types'

/* ==================== 节点版本校验与跨节点协同管理（server/internal/apinodes） ==================== */

/** 节点状态词表（按最近事件距当前时刻的时长判定） */
export type ApiNodeStatus = 'ACTIVE' | 'STALE' | 'SILENT'

/** 网关节点版本视图行（与 server/internal/apinodes.Node 一致） */
export interface ApiNode {
  id: string
  node_name: string
  first_seen_at: string
  /** 最近活性时间（业务事件与心跳取新；状态判定基准） */
  last_seen_at: string
  /** 最近上报策略版本（空串 = 未上报，旧版网关） */
  last_policy_version: string
  /** 最近上报模型版本（空串 = 未上报） */
  last_model_version: string
  /** 业务事件总数（心跳不计数） */
  event_count: number
  status: ApiNodeStatus
  /** Caddy Admin 通道标识；空串 = 未登记 */
  admin_addr: string
  /** 是否参与发布扇出 */
  sync_enabled: boolean
  /** 节点 hasyncd 协同代理地址（内网 http(s)://host:port）；空串 = 未配置 */
  sync_agent_addr?: string
  /** 是否已配置 hasyncd HMAC 同步密钥（密文落库，永不回显明文） */
  has_sync_secret?: boolean
  /** 节点上报的当前系统版本；空串 = 未知 */
  reported_version?: string
  /** 节点最新汇聚的 ha-vip-status.json 快照 */
  ha_vip_status?: HaVipStatus | null
  ha_vip_status_at?: string | null
  /** 节点最新汇聚的 network-status.json 快照 */
  network_status?: NetworkConfigStatus | null
  network_status_at?: string | null
  /** 最近同步尝试时间；null = 从未同步 */
  last_sync_at: string | null
  /** SUCCESS/FAILED/HASH_MISMATCH；空串 = 从未同步 */
  last_sync_result: string
  /** 最近失败原因（截断）；空串 = 无错误 */
  last_sync_error: string
  /** 最近同步尝试的配置版本；null = 从未同步 */
  last_sync_version_id: string | null
  /** 策略版本是否与活跃多数派一致；null = 未参与判定（SILENT 离线或未上报版本） */
  version_consistent: boolean | null
  created_at: string
  updated_at: string
}

/** 节点列表出参（与 apinodes.NodesResponse 一致；非分页接口） */
export interface ApiNodeListResult {
  items: ApiNode[]
  total: number
  /** 总体一致性标记（口径同 /nodes/consistency） */
  consistent: boolean
  /** 参与判定节点数（0 = 无版本数据可比） */
  evaluated_nodes: number
}

/** 一致性分组（与 apinodes.VersionGroup 一致；policy_version 空串 = 未上报组） */
export interface ApiNodeVersionGroup {
  policy_version: string
  node_count: number
  nodes: string[]
}

/** 一致性报告（与 apinodes.ConsistencyReport 一致） */
export interface ApiNodeConsistency {
  consistent: boolean
  evaluated_nodes: number
  /** 多数派版本（无参与节点时为空串） */
  dominant_version: string
  /** 活跃节点按策略版本分组（含未上报空串组） */
  groups: ApiNodeVersionGroup[]
  /** SILENT 节点（离线不参与判定，如实列出） */
  silent_nodes: string[]
  generated_at: string
}

/** 新增/预注册网关节点请求体（POST /api-security/nodes） */
export interface CreateApiNodeBody {
  node_name: string
  admin_addr?: string
  sync_agent_addr?: string
  sync_secret?: string
  sync_enabled?: boolean
}

/** 更新网关节点同步配置请求体（PATCH /api-security/nodes/{id}；sync_secret：省略=不变更，''=清除） */
export interface UpdateApiNodeBody {
  admin_addr?: string
  sync_agent_addr?: string
  sync_secret?: string
  sync_enabled?: boolean
}

/** 节点连通性探测响应（POST /api-security/nodes/{id}/test） */
export interface ApiNodeTestResult {
  ok: boolean
  channel: 'hasyncd' | 'caddy_admin' | 'none' | string
  latency_ms: number
  version?: string
  caddy_reachable?: boolean
  hostctl_ready?: boolean
  upgrade_ready?: boolean
  error?: string
}

/** 配置版本次要节点重试同步响应（POST /config-versions/{id}/retry-sync） */
export interface NodeSyncRetryResult {
  version_id: string
  node_id?: string
  attempted: number
  succeeded: number
  failed: number
  record_failures: number
}

export const apiNodesApi = {
  /** 节点列表（状态+版本+同步登记/结果+逐项一致性标记+总体标记） */
  list: async () => {
    const data = await request<ApiNodeListResult>('/api-security/nodes')
    return { ...data, items: data.items ?? [] }
  },
  /** 版本分组对比（明确回答所有节点版本是否一致） */
  consistency: async () => {
    const data = await request<ApiNodeConsistency>('/api-security/nodes/consistency')
    return { ...data, groups: data.groups ?? [], silent_nodes: data.silent_nodes ?? [] }
  },
  /** 手动登记/预注册网关节点 */
  create: (body: CreateApiNodeBody) =>
    request<ApiNode>('/api-security/nodes', { method: 'POST', body }),
  /** 编辑节点同步登记配置 */
  update: (id: string, body: UpdateApiNodeBody) =>
    request<ApiNode>(`/api-security/nodes/${id}`, { method: 'PATCH', body }),
  /** 删除离网节点（被 HA 组引用时服务端返回 409） */
  remove: (id: string) =>
    request<{ message?: string }>(`/api-security/nodes/${id}`, { method: 'DELETE' }),
  /** 探测节点 hasyncd 或 Caddy Admin 连通性 */
  testConnection: (id: string) =>
    request<ApiNodeTestResult>(`/api-security/nodes/${id}/test`, { method: 'POST' }),
  /** 对已发布配置版本重试节点同步（可选 nodeId 定向单节点重试） */
  retrySync: (versionId: string, nodeId?: string) =>
    request<NodeSyncRetryResult>(`/config-versions/${versionId}/retry-sync`, {
      method: 'POST',
      body: nodeId ? { node_id: nodeId } : {},
    }),
}
