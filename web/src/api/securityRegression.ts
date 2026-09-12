import { request } from './client'

/**
 * 安全回归证据登记与发布门禁管理面客户端（WDSP P1-04 R4a，契约
 * server/openapi/fragments/18-security-regression.yaml；服务端 server/internal/regression）。
 * 路由：GET /security/regressions（过滤分页）、GET {id}（摘要+gate_assessment）、
 * GET {id}/cases（分页，无原始正文）、GET/PUT /security/regression-policy。
 * 权限：security_regression.read / .import / .policy。
 * 词表纪律：declared_status 为验证服务声明（仅登记不采信），
 * verification_status 才是服务端独立核验结论——界面两者分列，不混成一个状态。
 */

export type RegressionLevel = 'SMOKE' | 'FULL' | 'RELEASE'
export type RegressionDeclaredStatus = 'PASS' | 'FAIL' | 'SKIP' | 'BLOCKED' | 'NOT_RUN'
export type RegressionVerificationStatus = 'PENDING' | 'PASSED' | 'FAILED'
export type RegressionCaseStatus = 'PASS' | 'FAIL' | 'SKIP' | 'BLOCKED' | 'NOT_RUN'
export type RegressionGateMode = 'OFF' | 'OBSERVE' | 'ENFORCE'

/** 执行计数（planned-executed=缺失数量；mandatory_failed>0 阻断 ENFORCE 发布） */
export interface RegressionCounts {
  planned: number
  executed: number
  skipped: number
  blocked: number
  not_run: number
  passed: number
  failed: number
  mandatory_total: number
  mandatory_failed: number
}

/** 回归运行摘要（不可变；policy_version 为导入时门禁策略版本） */
export interface SecurityRegressionRun {
  id: string
  run_id: string
  manifest_sha256: string
  level: RegressionLevel
  declared_status: RegressionDeclaredStatus
  verification_status: RegressionVerificationStatus
  verification_reasons: string[]
  signature_algorithm: string
  signature_key_id: string
  config_fingerprint: string
  build_digest: string
  compiler: string
  corpus_id: string
  corpus_version: number
  corpus_sha256: string
  plan_sha256: string
  counts: RegressionCounts
  run_started_at?: string | null
  run_finished_at?: string | null
  policy_version: number
  imported_by: string
  created_at: string
}

export interface SecurityRegressionRunListQuery {
  fingerprint?: string
  level?: RegressionLevel
  status?: RegressionVerificationStatus
  since?: string
  until?: string
  page?: number
  page_size?: number
}

export interface SecurityRegressionRunListResult {
  items: SecurityRegressionRun[]
  page: number
  page_size: number
  total: number
}

/** 门禁可用性实时评估（只读，不产生判定留痕；发布时由发布器门禁终判） */
export interface SecurityRegressionGateAssessment {
  usable_for_publish: boolean
  reasons: string[]
  policy_mode: RegressionGateMode
  required_level: RegressionLevel
  evidence_max_age_seconds: number
  age_seconds: number
  expired: boolean
}

export interface SecurityRegressionRunDetail {
  run: SecurityRegressionRun
  gate_assessment: SecurityRegressionGateAssessment
}

/** 用例差异摘要（不含原始请求/响应正文；diff_summary 为服务端脱敏后的自由结构） */
export interface SecurityRegressionCase {
  id: string
  case_id: string
  case_version: number
  family: string
  truth: 'BENIGN' | 'ATTACK' | 'UNKNOWN'
  criticality: 'MANDATORY' | 'OPTIONAL'
  status: RegressionCaseStatus
  diff_summary?: Record<string, unknown> | null
}

export interface SecurityRegressionCaseListResult {
  items: SecurityRegressionCase[]
  page: number
  page_size: number
  total: number
}

/** 发布门禁策略（version 乐观锁；evidence_max_age_seconds 86400~2592000） */
export interface SecurityRegressionPolicy {
  mode: RegressionGateMode
  required_level: RegressionLevel
  required_corpus_id: string
  evidence_max_age_seconds: number
  version: number
  updated_by: string
  updated_at: string
}

export interface SecurityRegressionPolicyPutBody {
  mode: RegressionGateMode
  required_level: RegressionLevel
  required_corpus_id?: string
  evidence_max_age_seconds: number
  expected_version: number
  /** 变更理由（非空，进操作审计） */
  reason: string
}

/** Go nil slice/map 序列化为 null，统一归一化（词表未知值原样保留由展示层兜底） */
function normalizeRun(r: SecurityRegressionRun): SecurityRegressionRun {
  return {
    ...r,
    verification_reasons: r.verification_reasons ?? [],
    counts: r.counts ?? {
      planned: 0,
      executed: 0,
      skipped: 0,
      blocked: 0,
      not_run: 0,
      passed: 0,
      failed: 0,
      mandatory_total: 0,
      mandatory_failed: 0,
    },
  }
}

export const securityRegressionApi = {
  list: async (
    q: SecurityRegressionRunListQuery,
  ): Promise<SecurityRegressionRunListResult> => {
    const data = await request<SecurityRegressionRunListResult>(
      '/security/regressions',
      { query: { ...q } },
    )
    return { ...data, items: (data.items ?? []).map(normalizeRun) }
  },
  get: async (id: string): Promise<SecurityRegressionRunDetail> => {
    const data = await request<SecurityRegressionRunDetail>(
      `/security/regressions/${id}`,
    )
    return {
      ...data,
      run: normalizeRun(data.run),
      gate_assessment: {
        ...data.gate_assessment,
        // Go nil slice 序列化为 null（可用证据无理由时 reasons=null），统一归一化
        reasons: data.gate_assessment?.reasons ?? [],
      },
    }
  },
  listCases: async (
    id: string,
    q: { status?: RegressionCaseStatus; page?: number; page_size?: number },
  ): Promise<SecurityRegressionCaseListResult> => {
    const data = await request<SecurityRegressionCaseListResult>(
      `/security/regressions/${id}/cases`,
      { query: { ...q } },
    )
    return { ...data, items: data.items ?? [] }
  },
  getPolicy: async (): Promise<SecurityRegressionPolicy> => {
    const data = await request<{ policy: SecurityRegressionPolicy }>(
      '/security/regression-policy',
    )
    return data.policy
  },
  updatePolicy: async (
    body: SecurityRegressionPolicyPutBody,
  ): Promise<SecurityRegressionPolicy> => {
    const data = await request<{ policy: SecurityRegressionPolicy }>(
      '/security/regression-policy',
      { method: 'PUT', body },
    )
    return data.policy
  },
}
