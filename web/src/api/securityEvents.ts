import { buildUrl, request } from './client'
import type {
  BlacklistPrefillResult,
  CreateExceptionFromEventResult,
  EventRemediationResult,
  PageResult,
  RelatedEventMode,
  SecurityEventDetail,
  SecurityEventItem,
  WafRuleEffectStatisticsPage,
  WhitelistPrefillResult,
} from '../types'

export interface SecurityEventListParams {
  start_time?: string
  end_time?: string
  application_id?: string
  domain?: string
  client_ip?: string
  uri?: string
  method?: string
  attack_type?: string
  severity?: string
  action?: string
  rule_id?: number | string
  disposition_status?: string
  request_id?: string
  gateway_node?: string
  page: number
  page_size: number
}

export interface DispositionBody {
  result?: string
  note?: string
}

export interface RuleEffectStatisticsParams {
  from?: string
  to?: string
  rule_id?: number | string
  rule_version?: string
  page: number
  page_size: number
}

export const securityEventsApi = {
  ruleEffectStatistics: async (params: RuleEffectStatisticsParams) => {
    const data = await request<WafRuleEffectStatisticsPage>('/waf-rules/effect-statistics', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  list: async (params: SecurityEventListParams) => {
    const data = await request<PageResult<SecurityEventItem>>('/security-events', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => {
    const data = await request<SecurityEventDetail>(`/security-events/${id}`)
    // 后端对无匹配/备注/记录返回 null（Go nil slice），统一归一化为空数组
    return {
      ...data,
      matches: data.matches ?? [],
      notes: data.notes ?? [],
      actions: data.actions ?? [],
      related: data.related ?? [],
      related_mode: data.related_mode ?? 'none',
      related_session_id: data.related_session_id ?? null,
    }
  },
  related: async (id: string) => {
    const data = await request<{ items: SecurityEventItem[]; mode?: RelatedEventMode; session_id?: string | null }>(
      `/security-events/${id}/related`,
    )
    return { items: data.items ?? [], mode: data.mode ?? 'none', session_id: data.session_id ?? null }
  },
  remediation: (id: string) =>
    request<EventRemediationResult>(`/security-events/${id}/remediation`),
  addNote: (id: string, note: string) =>
    request<{ message: string }>(`/security-events/${id}/notes`, { method: 'POST', body: { note } }),
  confirmAttack: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/confirm-attack`, { method: 'POST', body }),
  confirmFalsePositive: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/confirm-false-positive`, {
      method: 'POST',
      body,
    }),
  ignore: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/ignore`, { method: 'POST', body }),
  resolve: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/resolve`, { method: 'POST', body }),
  markAnalyzing: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/mark-analyzing`, { method: 'POST', body }),
  createException: (id: string) =>
    request<CreateExceptionFromEventResult>(`/security-events/${id}/create-exception`, {
      method: 'POST',
    }),
  /** 事件→黑名单预填（阶段5 §十一；只读不落库，权限 access_rules.manage） */
  blacklistPrefill: async (id: string) => {
    const data = await request<BlacklistPrefillResult>(`/security-events/${id}/blacklist-prefill`)
    return { ...data.prefill, hit_rules: data.prefill.hit_rules ?? [] }
  },
  /** 事件→白名单预填（支持 IP 白名单 / URL 白名单及联动 WAF 精确例外；只读不落库） */
  whitelistPrefill: async (id: string) => {
    const data = await request<WhitelistPrefillResult>(`/security-events/${id}/whitelist-prefill`)
    return {
      ...data.prefill,
      hit_rules: data.prefill.hit_rules ?? [],
      event_rule_ids: data.prefill.event_rule_ids ?? [],
    }
  },
  /** 导出 CSV（支持全部列表筛选维度及按勾选 ids 导出，上限 10000 行） */
  exportUrl: (
    params: Partial<Omit<SecurityEventListParams, 'page' | 'page_size'>> & { ids?: string },
  ) => buildUrl('/security-events/export', { ...params }),
}
