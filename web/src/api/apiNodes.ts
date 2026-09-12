import { request } from './client'

/* ==================== 节点版本校验（server/internal/apinodes）：节点列表 + 策略版本一致性 ==================== */

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

export const apiNodesApi = {
  /** 节点列表（状态+版本+逐项一致性标记+总体标记） */
  list: async () => {
    const data = await request<ApiNodeListResult>('/api-security/nodes')
    return { ...data, items: data.items ?? [] }
  },
  /** 版本分组对比（明确回答所有节点版本是否一致） */
  consistency: async () => {
    const data = await request<ApiNodeConsistency>('/api-security/nodes/consistency')
    return { ...data, groups: data.groups ?? [], silent_nodes: data.silent_nodes ?? [] }
  },
}
