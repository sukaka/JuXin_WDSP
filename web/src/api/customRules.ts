import { request } from './client'
import type { CustomRuleItem, CustomRuleValidateResult, PageResult } from '../types'

export interface CustomRuleListParams {
  keyword?: string
  status?: string
  page: number
  page_size: number
}

export interface CustomRuleBody {
  rule_id: number
  name: string
  description: string
  attack_type: string
  severity: string
  phase: number
  operator: string
  operator_value: string
  target_variables: string[]
  action: string
  tags: string[]
}

export interface UpdateCustomRuleBody extends CustomRuleBody {
  version: number
}

export const customRulesApi = {
  list: async (params: CustomRuleListParams) => {
    const data = await request<PageResult<CustomRuleItem>>('/custom-rules', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<CustomRuleItem>(`/custom-rules/${id}`),
  create: (body: CustomRuleBody) => request<CustomRuleItem>('/custom-rules', { method: 'POST', body }),
  update: (id: string, body: UpdateCustomRuleBody) =>
    request<CustomRuleItem>(`/custom-rules/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/custom-rules/${id}`, { method: 'DELETE' }),
  // 校验不保存；后端忽略路径 id，新建时传 'new' 占位
  validate: (id: string, body: CustomRuleBody) =>
    request<CustomRuleValidateResult>(`/custom-rules/${id}/validate`, { method: 'POST', body }),
  enable: (id: string) => request<{ message: string }>(`/custom-rules/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/custom-rules/${id}/disable`, { method: 'POST' }),
}
