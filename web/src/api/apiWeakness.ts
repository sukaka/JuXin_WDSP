import { request } from './client'
import type { PageResult } from '../types'

/* ==================== API 弱点中心（server/internal/apiweakness）：列表/详情/生命周期流转 ==================== */

/** 弱点状态（与 server/internal/apiweakness 状态机枚举一致） */
export type ApiWeaknessStatus =
  | 'NEW'
  | 'CONFIRMED'
  | 'TO_FIX'
  | 'FIXED'
  | 'REPRODUCED'
  | 'IGNORED'
  | 'ARCHIVED'

/** 弱点分类（category 列取值） */
export type ApiWeaknessCategory = 'AUTHN' | 'LIFECYCLE' | 'SENSITIVE' | 'SCHEMA'

/** 复测结果（POST /{id}/retest 请求体 result 字段） */
export type ApiWeaknessRetestResult = 'PASS' | 'FAIL'

/** API 弱点（api_weaknesses） */
export interface ApiWeakness {
  id: string
  endpoint_id?: string | null
  /** 关联接口的「METHOD 路径模板」（后端 LEFT JOIN api_endpoints 带出；端点已删除时为空串） */
  endpoint_key: string
  weakness_code: string
  weakness_name: string
  category: string
  severity: string
  status: ApiWeaknessStatus
  /** 派生证据（JSON 对象） */
  evidence: Record<string, unknown>
  first_seen: string
  last_seen: string
  trigger_count: number
  owner: string
  due_date?: string | null
  fixed_at?: string | null
  retested_at?: string | null
  created_at: string
  updated_at: string
}

/** 整改/复测历史条目（api_weakness_actions） */
export interface ApiWeaknessAction {
  id: string
  weakness_id: string
  action: string
  actor: string
  note: string
  created_at: string
}

/** 弱点详情响应（弱点 + 整改/复测历史） */
export interface ApiWeaknessDetail {
  weakness: ApiWeakness
  actions: ApiWeaknessAction[]
}

/** 仅备注的流转请求体（confirm/fixed/ignore/archive；整体可省略） */
export interface ApiWeaknessNoteBody {
  note?: string
}

export const apiWeaknessesApi = {
  list: async (params: {
    status?: string
    severity?: string
    category?: string
    endpoint_id?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiWeakness>>(`/api-security/weaknesses`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  detail: async (id: string) => {
    const data = await request<ApiWeaknessDetail>(`/api-security/weaknesses/${id}`)
    return { ...data, actions: data.actions ?? [] }
  },
  /** 确认弱点（NEW → CONFIRMED） */
  confirm: (id: string, body?: ApiWeaknessNoteBody) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/confirm`, {
      method: 'POST',
      body,
    }),
  /** 指派/改派整改（CONFIRMED/TO_FIX/REPRODUCED → TO_FIX）；due_date 为 RFC3339 时间串 */
  assign: (id: string, body: { owner: string; due_date?: string; note?: string }) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/assign`, {
      method: 'POST',
      body,
    }),
  /** 标记整改完成（TO_FIX → FIXED） */
  fixed: (id: string, body?: ApiWeaknessNoteBody) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/fixed`, {
      method: 'POST',
      body,
    }),
  /** 复测（FIXED；PASS → ARCHIVED 关闭，FAIL → REPRODUCED 复现） */
  retest: (id: string, body: { result: ApiWeaknessRetestResult; note?: string }) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/retest`, {
      method: 'POST',
      body,
    }),
  /** 忽略（接受风险/误报 → IGNORED） */
  ignore: (id: string, body?: ApiWeaknessNoteBody) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/ignore`, {
      method: 'POST',
      body,
    }),
  /** 人工归档关闭（→ ARCHIVED，终态） */
  archive: (id: string, body?: ApiWeaknessNoteBody) =>
    request<{ weakness: ApiWeakness }>(`/api-security/weaknesses/${id}/archive`, {
      method: 'POST',
      body,
    }),
}
