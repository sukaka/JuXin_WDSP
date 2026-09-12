import { request } from './client'
import type {
  L7RuleActionConfig,
  L7RuleCondition,
  L7RuleDetail,
  L7RuleItem,
  L7RuleTestRequest,
  L7RuleTestResult,
  PageResult,
  PublishTaskItem,
} from '../types'

export interface L7RuleListParams {
  keyword?: string
  enabled?: boolean
  page: number
  page_size: number
}

/** 新建/编辑请求体（PATCH 全量提交可编辑字段） */
export interface L7RuleBody {
  name: string
  priority: number
  enabled: boolean
  conditions: L7RuleCondition[]
  action: string
  action_config: L7RuleActionConfig
}

/** L7 访问控制规则接口（权限点 l7rules.*；仅 WAF/WDSP 形态注册） */
export const l7RulesApi = {
  list: async (params: L7RuleListParams) => {
    const data = await request<PageResult<L7RuleItem>>('/l7-rules', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<L7RuleDetail>(`/l7-rules/${id}`),
  create: (body: L7RuleBody) => request<L7RuleDetail>('/l7-rules', { method: 'POST', body }),
  update: (id: string, body: L7RuleBody) =>
    request<L7RuleDetail>(`/l7-rules/${id}`, { method: 'PATCH', body }),
  remove: (id: string) => request<{ message: string }>(`/l7-rules/${id}`, { method: 'DELETE' }),
  /** 发布 L7 规则到网关（复用访问控制版本发布链） */
  publish: (idempotencyKey: string) =>
    request<PublishTaskItem>('/l7-rules/publish', {
      method: 'POST',
      body: { idempotency_key: idempotencyKey },
    }),
  /** 规则测试器：纯评估，不产生真实流量、不写事件 */
  test: (body: L7RuleTestRequest) =>
    request<L7RuleTestResult>('/l7-rules/test', { method: 'POST', body }),
}
