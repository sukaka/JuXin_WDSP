import { request } from './client'
import type {
  PageResult,
  PublishTaskItem,
  RateLimitPolicyItem,
  RateLimitTestResult,
  RateLimitValidateResult,
} from '../types'

export interface RateLimitPolicyListParams {
  scope_type?: string
  status?: string
  action?: string
  keyword?: string
  application_id?: string
  page: number
  page_size: number
}

export interface RateLimitPolicyBody {
  name: string
  description: string
  scope_type: string
  application_id?: string | null
  uri_match_type: string
  uri_pattern: string
  dimension: string
  algorithm: string
  requests_limit: number
  window_seconds: number
  burst_capacity: number
  action: string
  block_duration_seconds: number
  observe_only: boolean
  priority: number
  effective_from?: string | null
  effective_until?: string | null
}

export interface UpdateRateLimitPolicyBody extends RateLimitPolicyBody {
  /** 乐观锁版本号（后端校验不一致返回 409） */
  version: number
}

export interface RateLimitTestBody {
  requests: number
  client_ips: string[]
  uri: string
}

export const rateLimitPoliciesApi = {
  list: async (params: RateLimitPolicyListParams) => {
    const data = await request<PageResult<RateLimitPolicyItem>>('/rate-limit-policies', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  // 后端详情直接返回策略对象（非包裹结构）
  get: (id: string) => request<RateLimitPolicyItem>(`/rate-limit-policies/${id}`),
  create: (body: RateLimitPolicyBody) =>
    request<RateLimitPolicyItem>('/rate-limit-policies', { method: 'POST', body }),
  update: (id: string, body: UpdateRateLimitPolicyBody) =>
    request<RateLimitPolicyItem>(`/rate-limit-policies/${id}`, { method: 'PUT', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/rate-limit-policies/${id}`, { method: 'DELETE' }),
  enable: (id: string) =>
    request<{ message: string }>(`/rate-limit-policies/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/rate-limit-policies/${id}/disable`, { method: 'POST' }),
  validate: (id: string, body: RateLimitPolicyBody) =>
    request<RateLimitValidateResult>(`/rate-limit-policies/${id}/validate`, {
      method: 'POST',
      body,
    }),
  test: (id: string, body: RateLimitTestBody) =>
    request<RateLimitTestResult>(`/rate-limit-policies/${id}/test`, { method: 'POST', body }),
  /** 发布 CC 防护配置到网关（与配置发布共用发布任务） */
  publish: (idempotencyKey: string) =>
    request<PublishTaskItem>('/rate-limit-policies/publish', {
      method: 'POST',
      body: { idempotency_key: idempotencyKey },
    }),
}
