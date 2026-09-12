import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 文件合规规则（server/internal/apifiles P2-03 管理面） ==================== */

/** 传输方向（api_file_compliance_rules.direction CHECK 对齐） */
export type ApiFileDirection = 'UPLOAD' | 'DOWNLOAD'

/** 匹配类型（api_file_compliance_rules.match_type CHECK 对齐） */
export type ApiFileMatchType = 'EXT' | 'MIME' | 'FILENAME_REGEX'

/** 命中动作（api_file_compliance_rules.action CHECK 对齐）：OBSERVE 仅记录 / BLOCK 阻断 */
export type ApiFileComplianceAction = 'OBSERVE' | 'BLOCK'

/** 文件合规规则（与 server/internal/apifiles.ComplianceRule 一致） */
export interface ApiFileComplianceRule {
  id: string
  direction: ApiFileDirection
  match_type: ApiFileMatchType
  match_value: string
  action: ApiFileComplianceAction
  reason: string
  enabled: boolean
  created_by?: string | null
  created_at: string
  updated_at: string
}

/** 规则新建提交体（enabled 缺省服务端归一为 true） */
export interface ApiFileComplianceRuleBody {
  direction: ApiFileDirection
  match_type: ApiFileMatchType
  match_value: string
  action: ApiFileComplianceAction
  reason: string
  enabled?: boolean
}

/** 规则编辑提交体（部分更新：仅提交的字段生效；match_type 与 match_value 服务端联动校验） */
export type ApiFileComplianceRulePatch = Partial<ApiFileComplianceRuleBody>

export const apiFileComplianceApi = {
  /** 规则明细分页（direction/match_type/action 枚举过滤 + enabled） */
  list: async (params: {
    direction?: string
    match_type?: string
    action?: string
    enabled?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiFileComplianceRule>>('/api-security/file-compliance-rules', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 新建（match_value 按类型校验，冲突 409） */
  create: (body: ApiFileComplianceRuleBody) =>
    request<ApiFileComplianceRule>('/api-security/file-compliance-rules', { method: 'POST', body }),
  /** 部分更新（合并后整体校验再落库） */
  update: (id: string, body: ApiFileComplianceRulePatch) =>
    request<ApiFileComplianceRule>(`/api-security/file-compliance-rules/${id}`, {
      method: 'PATCH',
      body,
    }),
  /** 硬删除（不可恢复） */
  remove: (id: string) =>
    request<{ status: string }>(`/api-security/file-compliance-rules/${id}`, { method: 'DELETE' }),
}
