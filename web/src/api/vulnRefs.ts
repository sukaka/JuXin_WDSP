import { request } from './client'
import type { PageResult, VulnRefDetail, VulnRefItem } from '../types'

export interface VulnRefListParams {
  keyword?: string
  page: number
  page_size: number
}

export interface VulnRefBody {
  cnnvd_id: string
  cve_id?: string
  title: string
  severity: string
  published_at?: string
  url?: string
}

/** 漏洞档案（CNNVD 兼容性 P1）：读沿用 waf_rules.read，写 waf_rule.vuln_ref.edit */
export const vulnRefsApi = {
  list: async (params: VulnRefListParams) => {
    const data = await request<PageResult<VulnRefItem>>('/waf/vuln-refs', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: async (cnnvdId: string) => {
    const data = await request<VulnRefDetail>(`/waf/vuln-refs/${encodeURIComponent(cnnvdId)}`)
    // 后端对无关联规则/样例事件返回 null（Go nil slice），统一归一化为空数组
    return { ...data, rules: data.rules ?? [], sample_events: data.sample_events ?? [] }
  },
  create: (body: VulnRefBody) => request<VulnRefItem>('/waf/vuln-refs', { method: 'POST', body }),
  update: (cnnvdId: string, body: VulnRefBody) =>
    request<VulnRefItem>(`/waf/vuln-refs/${encodeURIComponent(cnnvdId)}`, { method: 'PUT', body }),
  remove: (cnnvdId: string) =>
    request<{ message: string }>(`/waf/vuln-refs/${encodeURIComponent(cnnvdId)}`, {
      method: 'DELETE',
    }),
}
