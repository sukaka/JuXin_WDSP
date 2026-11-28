import { request, upload, type UploadProgress } from './client'
import type {
  PageResult,
  RulePackApplyRequest,
  RulePackCurrentStatus,
  RulePackItem,
  RulePackJob,
} from '../types'

export interface RulePackListParams {
  page?: number
  page_size?: number
}

/**
 * 纯离线 WAF 规则包热更新 API（docs/OFFLINE_RULEPACK_UPDATE_DESIGN.md §7.1）。
 * - 读权限：waf_rules.read（current / list / get / getJob）
 * - 写权限：waf_rules.pack.manage（upload / apply / rollback / retryNodeSync）
 */
export const rulePacksApi = {
  /** 查询当前激活规则包版本、CRS 版本、存储模式与 HA 节点对齐态 */
  current: async (): Promise<RulePackCurrentStatus> => {
    const data = await request<RulePackCurrentStatus>('/rule-packs/current')
    return { ...data, nodes: data.nodes ?? [] }
  },

  /** 分页查询离线规则包历史记录 */
  list: async (params: RulePackListParams = {}): Promise<PageResult<RulePackItem>> => {
    const data = await request<PageResult<RulePackItem>>('/rule-packs', {
      query: { page: params.page ?? 1, page_size: params.page_size ?? 20 },
    })
    return { ...data, items: data.items ?? [] }
  },

  /** 查询单个规则包详情、manifest 与差异预检报告 */
  get: (id: string): Promise<RulePackItem> => request<RulePackItem>(`/rule-packs/${id}`),

  /**
   * 上传纯离线规则包（.tar.gz）并立即执行 Ed25519 验签、静态门禁与差异预检（零现网副作用）。
   * 复用 client.ts upload()，自带 X-CSRF-Token、credentials、真实 XHR 上传进度与统一信封解析。
   */
  upload: (
    file: File,
    onProgress?: (progress: UploadProgress) => void,
  ): Promise<RulePackItem> => {
    const form = new FormData()
    form.append('file', file)
    return upload<RulePackItem>('/rule-packs/upload', form, { onProgress })
  },

  /** 管理员二次确认后一键生效已验证的规则包，异步返回执行任务 */
  apply: (id: string, body?: RulePackApplyRequest): Promise<RulePackJob> =>
    request<RulePackJob>(`/rule-packs/${id}/apply`, {
      method: 'POST',
      body: body ?? { allow_degraded_ha: false, degraded_reason: '' },
    }),

  /** 一键回滚至保留的历史规则包快照或内置基线，异步返回执行任务 */
  rollback: (id: string, body?: RulePackApplyRequest): Promise<RulePackJob> =>
    request<RulePackJob>(`/rule-packs/${id}/rollback`, {
      method: 'POST',
      body: body ?? { allow_degraded_ha: false, degraded_reason: '' },
    }),

  /** 轮询应用/回滚任务进度、关联发布任务、同步报告与 HA 逐节点状态 */
  getJob: async (jobId: string): Promise<RulePackJob> => {
    const data = await request<RulePackJob>(`/rule-packs/jobs/${jobId}`)
    return { ...data, node_states: data.node_states ?? [] }
  },

  /** HA 备节点恢复在线后，手工触发补发当前激活规则包并重同步配置 */
  retryNodeSync: (nodeId: string): Promise<{ message: string }> =>
    request<{ message: string }>(`/rule-packs/nodes/${nodeId}/retry-sync`, { method: 'POST' }),
}
