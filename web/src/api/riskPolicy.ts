import { request } from './client'

/** 风险等级三档下限（中/高/严重），阈值全部配置化（设计文档 14.2） */
export interface RiskPolicyLevels {
  medium: number
  high: number
  critical: number
}

/**
 * 风险策略（全局单例）：处置阈值/风险等级/信号分值全量读写，version 乐观锁。
 * 与 GET/PUT /security/risk-policy 契约一致（docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md #30）。
 */
export interface RiskPolicy {
  id: string
  scope: string
  enabled: boolean
  mode: string
  version: number
  block_threshold: number
  rate_limit_threshold: number
  rate_limit_rps: number
  signal_window_seconds: number
  scores: Record<string, number>
  risk_levels: RiskPolicyLevels
  updated_by: string
  updated_at: string
}

/** PUT 全量提交体：剔除只读字段（id/updated_by/updated_at） */
export type RiskPolicyBody = Omit<RiskPolicy, 'id' | 'updated_by' | 'updated_at'>

export const riskPolicyApi = {
  get: async () => {
    // 后端响应为 { policy: {...} } 包裹（与 behavior-policy 同构），此处解包；
    // 空 map/子对象可能返回 null（Go nil），统一归一化（风险等级缺省按设计文档 14.2 默认档位）
    const data = await request<{ policy: RiskPolicy }>('/security/risk-policy')
    const p = data.policy
    return {
      ...p,
      scores: p.scores ?? {},
      risk_levels: p.risk_levels ?? { medium: 20, high: 40, critical: 70 },
    }
  },
  update: async (body: RiskPolicyBody) => {
    const data = await request<{ policy: RiskPolicy }>('/security/risk-policy', { method: 'PUT', body })
    return data.policy
  },
}
