import { request } from './client'

/** 风险等级三档下限（中/高/严重），阈值全部配置化（设计文档 14.2） */
export interface RiskPolicyLevels {
  medium: number
  high: number
  critical: number
}

/**
 * 风险策略（全局与按应用覆盖）：处置阈值/风险等级/信号分值全量读写，version 乐观锁。
 * 与 /security/risk-policy 及其 applications/{id} 覆盖接口契约一致。
 */
export interface RiskPolicy {
  id: string
  scope: string
  application_id?: string
  enabled: boolean
  mode: string
  version: number
  block_threshold: number
  rate_limit_threshold: number
  rate_limit_rps: number
  signal_window_seconds: number
  /** 应用覆盖专属：0=默认3个可信账号，自定义2-1000；只影响观察信号 */
  shared_device_account_limit?: number
  scores: Record<string, number>
  risk_levels: RiskPolicyLevels
  updated_by: string
  updated_at: string
}

/** PUT 全量提交体：剔除只读字段（id/application_id/updated_by/updated_at） */
export type RiskPolicyBody = Omit<
  RiskPolicy,
  'id' | 'application_id' | 'updated_by' | 'updated_at'
>

function normalizeRiskPolicy(policy: RiskPolicy): RiskPolicy {
  return {
    ...policy,
    shared_device_account_limit: policy.shared_device_account_limit ?? 0,
    scores: policy.scores ?? {},
    risk_levels: policy.risk_levels ?? { medium: 20, high: 40, critical: 70 },
  }
}

export const riskPolicyApi = {
  get: async () => {
    const data = await request<{ policy: RiskPolicy }>('/security/risk-policy')
    return normalizeRiskPolicy(data.policy)
  },
  update: async (body: RiskPolicyBody) => {
    const data = await request<{ policy: RiskPolicy }>(
      '/security/risk-policy',
      { method: 'PUT', body },
    )
    return normalizeRiskPolicy(data.policy)
  },
  getApplicationOverride: async (applicationId: string) => {
    const data = await request<{ policy: RiskPolicy | null }>(
      `/security/risk-policy/applications/${applicationId}`,
    )
    return data.policy ? normalizeRiskPolicy(data.policy) : null
  },
  putApplicationOverride: async (
    applicationId: string,
    body: RiskPolicyBody,
  ) => {
    const data = await request<{ policy: RiskPolicy }>(
      `/security/risk-policy/applications/${applicationId}`,
      { method: 'PUT', body },
    )
    return normalizeRiskPolicy(data.policy)
  },
  deleteApplicationOverride: (applicationId: string, version: number) =>
    request<{ message: string }>(
      `/security/risk-policy/applications/${applicationId}?version=${version}`,
      { method: 'DELETE' },
    ),
}
