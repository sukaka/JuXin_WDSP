import { request } from './client'
import type {
  ApmAgentItem,
  ApmDependencyGraph,
  ApmDiagnosticCapability,
  ApmDiagnosticDryRunResult,
  ApmDiagnosticScope,
  ApmDiagnosticSession,
  ApmDiagnosticSessionDetail,
  ApmDiagnosticSessionPage,
  ApmEndpointPage,
  ApmEnrollmentTokenResult,
  ApmExceptionPage,
  ApmOverview,
  ApmPolicyDocument,
  ApmRuntimeOverview,
  ApmServiceDetail,
  ApmServiceItem,
  ApmSloDetail,
  ApmSloItem,
  ApmSloList,
  ApmSloMetricType,
  ApmSqlPage,
  ApmTraceDetail,
  ApmTraceSearchPage,
  PageResult,
} from '../types'

/** 通用时间窗参数（RFC3339） */
export interface ApmTimeRangeParams {
  start_time: string
  end_time: string
}

export interface ApmServiceListParams extends ApmTimeRangeParams {
  page: number
  page_size: number
  keyword?: string
}

/** 端点列表排序口径（后端 sort 参数词表） */
export type ApmEndpointSort = 'p95' | 'requests' | 'error_rate'

export interface ApmEndpointListParams extends ApmTimeRangeParams {
  application_id?: string
  sort?: ApmEndpointSort
  page: number
  page_size: number
}

/** 调用链检索参数（GET /apm/trace-search；error=true 表示仅错误链路，不传表示全部） */
export interface ApmTraceSearchParams extends ApmTimeRangeParams {
  service?: string
  trace_id?: string
  request_id?: string
  /** 应用约束（P1-01 A2；非法 UUID/应用不存在后端返回 400，不静默忽略） */
  application_id?: string
  min_duration_ms?: number
  error?: boolean
  page: number
  page_size: number
}

/** Trace 详情可选时间窗（GET /apm/traces/{trace_id}；两者需同时提供，缺省为点查不限时） */
export interface ApmTraceDetailParams {
  start_time?: string
  end_time?: string
}

export interface ApmAgentListParams {
  status?: string
  keyword?: string
  page: number
  page_size: number
}

/** 创建一次性注册令牌入参（POST /apm/agents/enrollment-tokens） */
export interface CreateApmEnrollmentTokenBody {
  application_id?: string | null
  environment: string
  allowed_languages: string[]
  expires_in_minutes: number
  note?: string
}

/** 更新基线策略入参（PUT /apm/policies/{scope}；expected_version 乐观锁，409=版本冲突） */
export interface PutApmPolicyBody {
  policy: Record<string, unknown>
  expected_version: number
}

/** SQL 指纹列表排序口径（后端 sort 参数词表） */
export type ApmSqlSort = 'calls' | 'avg_ms' | 'p95_ms'

export interface ApmSqlListParams extends ApmTimeRangeParams {
  service?: string
  db_system?: string
  /** trace 级定位（P1-01 A2）：非空时仅从该 trace 的 DB span 派生指纹，响应 match_mode=trace_exact */
  trace_id?: string
  sort?: ApmSqlSort
  page: number
  page_size: number
}

export interface ApmExceptionListParams extends ApmTimeRangeParams {
  service?: string
  /** trace 级定位（P1-01 A2）：非空时直读该 trace 的 exception 事件，结果在 trace_exceptions */
  trace_id?: string
  page: number
  page_size: number
}

export interface ApmDependencyParams extends ApmTimeRangeParams {
  service?: string
}

export interface ApmRuntimeParams extends ApmTimeRangeParams {
  service?: string
  instance_id?: string
}

/** 新建/更新 SLO 入参（POST /apm/slos、PUT /apm/slos/{id}；target 口径随 metric_type：availability 为 0-1 比例，latency_p95 为毫秒阈值） */
export interface ApmSloBody {
  name: string
  service: string
  metric_type: ApmSloMetricType
  target: number
  window: string
}

/** 诊断会话列表查询参数（GET /apm/diagnostic-sessions） */
export interface ApmDiagnosticSessionListParams {
  status?: string
  page: number
  page_size: number
}

/** 诊断会话基础入参（POST /apm/diagnostic-sessions；dry_run=true 仅预估开销，confirm=true 正式创建——由 dryRun/create 两个方法分别强制置位） */
export interface ApmDiagnosticSessionBody {
  scope: ApmDiagnosticScope
  capabilities: ApmDiagnosticCapability[]
  sampling_rate: number
  duration_minutes: number
}

/** 业务性能（APM）接口封装；权限：overview=apm.overview.read，services/endpoints=apm.services.read，
 *  traces/trace-search=apm.traces.read，agents/policies=apm.agents.manage，diagnostics=apm.diagnostics.manage */
export const apmApi = {
  /** GET /apm/overview：全局 RED、趋势与 Top 列表 */
  overview: (params: ApmTimeRangeParams) =>
    request<ApmOverview>('/apm/overview', { query: { ...params } }),
  /** GET /apm/services：服务（应用）性能清单 */
  services: async (params: ApmServiceListParams) => {
    const data = await request<PageResult<ApmServiceItem>>('/apm/services', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** GET /apm/services/{id}：单服务详情（趋势/状态码/WAF 动作/Top 端点） */
  service: (id: string, params: ApmTimeRangeParams) =>
    request<ApmServiceDetail>(`/apm/services/${id}`, { query: { ...params } }),
  /** GET /apm/endpoints：端点性能列表（依赖全量访问日志开关） */
  endpoints: async (params: ApmEndpointListParams) => {
    const data = await request<ApmEndpointPage>('/apm/endpoints', { query: { ...params } })
    return { ...data, list: data.list ?? [] }
  },
  /** GET /apm/traces/{trace_id}：按 trace_id 检索访问记录/OTel span 并关联 WAF 事件；
   *  可选 start_time/end_time 限窗（P1-01 A3：详情查询携带时间窗上下文，两者需同时提供） */
  trace: (traceId: string, params?: ApmTraceDetailParams) =>
    request<ApmTraceDetail>(`/apm/traces/${encodeURIComponent(traceId)}`, { query: { ...params } }),
  /** GET /apm/trace-search：调用链检索（DSN 未配置时返回空 list + data_source=agentless） */
  traceSearch: async (params: ApmTraceSearchParams) => {
    const data = await request<ApmTraceSearchPage>('/apm/trace-search', {
      query: { ...params },
    })
    return { ...data, list: data.list ?? [] }
  },
  /** POST /apm/agents/enrollment-tokens：创建一次性注册令牌（token 原文仅此一次返回） */
  createEnrollmentToken: (body: CreateApmEnrollmentTokenBody) =>
    request<ApmEnrollmentTokenResult>('/apm/agents/enrollment-tokens', {
      method: 'POST',
      body,
    }),
  /** GET /apm/agents：Agent 分页清单 */
  agents: async (params: ApmAgentListParams) => {
    const data = await request<PageResult<ApmAgentItem>>('/apm/agents', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** POST /apm/agents/{id}/revoke：撤销 Agent（撤销后其证书不再被接受） */
  revokeAgent: (id: string) =>
    request<ApmAgentItem>(`/apm/agents/${id}/revoke`, { method: 'POST' }),
  /** GET /apm/policies/{scope}：读取 scope 的基线策略文档 */
  getPolicy: (scope: string) =>
    request<ApmPolicyDocument>(`/apm/policies/${encodeURIComponent(scope)}`),
  /** PUT /apm/policies/{scope}：更新基线策略（expected_version 乐观锁；409=版本冲突，需刷新重试） */
  putPolicy: (scope: string, body: PutApmPolicyBody) =>
    request<ApmPolicyDocument>(`/apm/policies/${encodeURIComponent(scope)}`, {
      method: 'PUT',
      body,
    }),
  /** GET /apm/sql：SQL 指纹聚合（权限 apm.sql.read；只出指纹不出原始 SQL；
   *  data_source=agentless 表示未接入 OTel 数据面，页面须展示接入指引） */
  sql: async (params: ApmSqlListParams) => {
    const data = await request<ApmSqlPage>('/apm/sql', { query: { ...params } })
    return { ...data, list: data.list ?? [] }
  },
  /** GET /apm/exceptions：异常指纹聚合（权限 apm.traces.read） */
  exceptions: async (params: ApmExceptionListParams) => {
    const data = await request<ApmExceptionPage>('/apm/exceptions', { query: { ...params } })
    return { ...data, list: data.list ?? [] }
  },
  /** GET /apm/dependencies：服务依赖边（权限 apm.services.read；note 为口径说明须如实展示） */
  dependencies: async (params: ApmDependencyParams) => {
    const data = await request<ApmDependencyGraph>('/apm/dependencies', { query: { ...params } })
    return { ...data, edges: data.edges ?? [] }
  },
  /** GET /apm/runtime：实例运行时指标（权限 apm.runtime.read；不同语言指标集不同，如实展示） */
  runtime: async (params: ApmRuntimeParams) => {
    const data = await request<ApmRuntimeOverview>('/apm/runtime', { query: { ...params } })
    return { ...data, instances: data.instances ?? [] }
  },
  /** GET /apm/slos：SLO 清单（读权限 apm.overview.read） */
  slos: async () => {
    const data = await request<ApmSloList>('/apm/slos')
    return { ...data, list: data.list ?? [] }
  },
  /** GET /apm/slos/{id}：SLO 详情 + 达标率趋势 */
  slo: (id: string) => request<ApmSloDetail>(`/apm/slos/${encodeURIComponent(id)}`),
  /** POST /apm/slos：新建 SLO（写权限 apm.settings.manage） */
  createSlo: (body: ApmSloBody) => request<ApmSloItem>('/apm/slos', { method: 'POST', body }),
  /** PUT /apm/slos/{id}：更新 SLO（写权限 apm.settings.manage；409/校验错误按 ApiError 处理） */
  updateSlo: (id: string, body: ApmSloBody) =>
    request<ApmSloItem>(`/apm/slos/${encodeURIComponent(id)}`, { method: 'PUT', body }),
  /** DELETE /apm/slos/{id}：删除 SLO（写权限 apm.settings.manage） */
  deleteSlo: (id: string) =>
    request<{ message: string }>(`/apm/slos/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  /** GET /apm/diagnostic-sessions：诊断会话分页（权限 apm.diagnostics.manage；items 缺省补空数组） */
  diagnosticSessions: async (params: ApmDiagnosticSessionListParams) => {
    const data = await request<ApmDiagnosticSessionPage>('/apm/diagnostic-sessions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** GET /apm/diagnostic-sessions/{id}：会话详情 + 关联审计（audits 缺省补空数组） */
  diagnosticSession: async (id: string) => {
    const data = await request<ApmDiagnosticSessionDetail>(
      `/apm/diagnostic-sessions/${encodeURIComponent(id)}`,
    )
    return { ...data, audits: data.audits ?? [] }
  },
  /** POST /apm/diagnostic-sessions（dry_run=true）：仅预估开销，不创建会话 */
  dryRunDiagnosticSession: (body: ApmDiagnosticSessionBody) =>
    request<ApmDiagnosticDryRunResult>('/apm/diagnostic-sessions', {
      method: 'POST',
      body: { ...body, dry_run: true },
    }),
  /** POST /apm/diagnostic-sessions（confirm=true）：二次确认后正式创建会话并写审计 */
  createDiagnosticSession: (body: ApmDiagnosticSessionBody) =>
    request<ApmDiagnosticSession>('/apm/diagnostic-sessions', {
      method: 'POST',
      body: { ...body, confirm: true },
    }),
  /** POST /apm/diagnostic-sessions/{id}/stop：提前停止会话（停止后 Agent 回到基线策略） */
  stopDiagnosticSession: (id: string) =>
    request<ApmDiagnosticSession>(`/apm/diagnostic-sessions/${encodeURIComponent(id)}/stop`, {
      method: 'POST',
    }),
  /** POST /apm/diagnostics/kill-switch：全局熔断（enable=true 立即终止全部进行中会话并拒绝新建） */
  setDiagnosticKillSwitch: (enable: boolean) =>
    request<{ kill_switch_enabled: boolean }>('/apm/diagnostics/kill-switch', {
      method: 'POST',
      body: { enable },
    }),
}
