import { request } from './client'
import type { PageResult } from '../types'

/**
 * 端点级运行时策略版本（/api-security/runtime-policies，
 * 字段与 server/internal/apimodels.RuntimePolicy 一致，迁移 000037）。
 * 状态机：DRAFT → VALIDATED →（整站发布）→ ACTIVE / FAILED；曾生效退出为 ROLLED_BACK（已知良好版本，供回滚溯源）。
 */
export interface ApiRuntimePolicy {
  id: string
  endpoint_id: string
  /** JOIN api_endpoints 带出（展示用） */
  endpoint_key: string
  source_model_version_id: string
  /** 端点内自增 "vN" */
  runtime_version: string
  compiler_version: string
  /** CompiledEndpointPolicy 规范序列化（详情展示按需取用） */
  content?: Record<string, unknown>
  content_hash: string
  status: string
  error?: string
  created_at: string
  published_at?: string | null
  activated_at?: string | null
}

/** 运行时策略状态展示（与 server/internal/apimodels 策略状态机一致；DRAFT/VALIDATED 为待发布集合） */
export const API_RUNTIME_POLICY_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'default', label: '草稿' },
  VALIDATED: { color: 'processing', label: '待发布' },
  PUBLISHED: { color: 'blue', label: '已发布' },
  ACTIVE: { color: 'green', label: '生效中' },
  ROLLED_BACK: { color: 'orange', label: '已退出' },
  FAILED: { color: 'red', label: '发布失败' },
}

export const apiRuntimePoliciesApi = {  /** 策略版本列表：endpoint_id / status 过滤 + 分页（按创建时间倒序） */
  list: async (params: { endpoint_id?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiRuntimePolicy>>('/api-security/runtime-policies', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 模型 → 策略溯源：列出由该模型版本编译产生的全部策略 */
  listByModel: async (modelVersionId: string) => {
    const data = await request<{ items: ApiRuntimePolicy[] }>(
      `/api-security/models/${modelVersionId}/runtime`,
    )
    return data.items ?? []
  },
  /** 回滚到上一已知良好版本：克隆其编译内容创建新 DRAFT 并重触发整站发布（仅 ACTIVE/FAILED 可操作） */
  rollback: (id: string) =>
    request<{ policy: ApiRuntimePolicy; task_id: string; status: string; message: string }>(
      `/api-security/runtime-policies/${id}/rollback`,
      { method: 'POST', body: {} },
    ),
}
