import { request } from './client'
import type { PageResult } from '../types'

export type RuleOverrideScope = 'GLOBAL' | 'POLICY' | 'APPLICATION'
export type RuleOverrideAction = 'DISABLE' | 'ENABLE' | 'SEVERITY_OVERRIDE' | 'ACTION_OVERRIDE'

export interface RuleOverrideItem {
  id: string
  rule_id: number
  scope_type: RuleOverrideScope
  scope_id?: string | null
  action: RuleOverrideAction
  severity_override: string
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  version: number
  created_at: string
  updated_at: string
}

export interface CreateRuleOverrideBody {
  rule_id: number
  scope_type: RuleOverrideScope
  scope_id?: string | null
  action: RuleOverrideAction
  severity_override?: string
  effective_from?: string | null
  effective_until?: string | null
  reason?: string
}

export const ruleOverridesApi = {
  list: async (params: {
    rule_id?: number
    scope_type?: string
    scope_id?: string
    action?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<RuleOverrideItem>>('/rule-overrides', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: (body: CreateRuleOverrideBody) =>
    request<{ override: RuleOverrideItem; message: string }>('/rule-overrides', {
      method: 'POST',
      body,
    }),
  remove: (id: string) =>
    request<{ message: string }>(`/rule-overrides/${id}`, { method: 'DELETE' }),
}
