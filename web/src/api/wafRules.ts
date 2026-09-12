import { request } from './client'
import type { PageResult, WafRuleCategory, WafRuleItem, WafRuleSyncReport } from '../types'

export interface WafRuleListParams {
  rule_id?: number | string
  keyword?: string
  attack_type?: string
  severity?: string
  rule_source?: string
  tag?: string
  page: number
  page_size: number
}

export const wafRulesApi = {
  list: async (params: WafRuleListParams) => {
    const data = await request<PageResult<WafRuleItem>>('/waf-rules', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (ruleId: number | string) => request<WafRuleItem>(`/waf-rules/${ruleId}`),
  categories: async () => {
    const data = await request<{ items: WafRuleCategory[] }>('/waf-rules/categories')
    return { items: data.items ?? [] }
  },
  versions: async () => {
    const data = await request<{ versions: string[] }>('/waf-rules/versions')
    return { versions: data.versions ?? [] }
  },
  sync: () => request<WafRuleSyncReport>('/waf-rules/sync', { method: 'POST' }),
}
