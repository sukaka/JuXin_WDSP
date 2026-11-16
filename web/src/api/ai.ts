// 阶段7 AI 安全运营中心 API 封装：会话/消息（SSE 流式）、一次性分析、草稿、
// 模型/Agent/Tool/Prompt/记忆/审计/用量/评估。字段与 server/internal/aihandlers 对齐。
import {
  ApiError,
  buildUrl,
  getCsrfToken,
  notifyLicenseInvalid,
  notifySessionExpired,
  request,
} from './client'
import type { PageResult } from '../types'

/* ==================== 会话与消息 ==================== */

export interface AiSession {
  id: string
  title: string
  status: string // ACTIVE / ARCHIVED
  context_token_count: number
}

export interface AiMessage {
  id: string
  role: string // user / assistant
  content: string
  created_at: string
}

/** SSE 事件（data: {"type":...,"text":...,"payload":...}） */
export interface AiSseEvent {
  type: string // plan / agent_start / agent_done / composing / degraded / continued / error / compressed / done
  text?: string
  payload?: unknown
}

/** 任务计划（plan 事件 payload / 分析结果 plan 字段） */
export interface AiPlan {
  task_type: string
  agents?: string[] | null
  risk_level: string
  summary: string
}

/** 证据引用项（[Ex] 编号） */
export interface AiEvidenceItem {
  id: string
  source: string
  summary: string
  detail?: unknown
}

/** done 事件 payload */
export interface AiDonePayload {
  task_id?: string
  message_id?: string
  finish_reason?: string
  /** 本轮 finish_reason=length 触发的自动续写次数 */
  auto_continues?: number
}

export interface AiSessionListParams {
  page: number
  page_size: number
  include_archived?: boolean
}

/** 流式读取 POST SSE 响应：逐行解析 data: {json}，回调事件；AbortSignal 中断。 */
async function streamPostSSE(
  path: string,
  body: unknown,
  onEvent: (e: AiSseEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const csrf = getCsrfToken()
  if (csrf) headers['X-CSRF-Token'] = csrf

  let resp: Response
  try {
    resp = await fetch(buildUrl(path), {
      method: 'POST',
      headers,
      credentials: 'include',
      body: JSON.stringify(body ?? {}),
      signal,
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0)
  }

  // SSE 为独立 fetch 封装（流式响应无法走 request() 的全量读取），
  // 401/423 全局处置须与 request() 同一纪律，显式触发全局回调
  if (resp.status === 401) notifySessionExpired()
  if (resp.status === 423) notifyLicenseInvalid()

  if (!resp.ok || !resp.body) {
    // 非流式错误响应：按统一信封提取错误信息
    let code = 'HTTP_ERROR'
    let message = `请求失败（HTTP ${resp.status}）`
    try {
      const env = (await resp.json()) as { code?: string; message?: string } | null
      if (env && typeof env.code === 'string') code = env.code
      if (env && typeof env.message === 'string') message = env.message
    } catch {
      // 保留默认错误信息
    }
    throw new ApiError(message, code, resp.status)
  }

  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  const handleLine = (line: string) => {
    const trimmed = line.replace(/\r$/, '')
    if (!trimmed.startsWith('data:')) return
    const json = trimmed.slice(5).trim()
    if (!json) return
    try {
      onEvent(JSON.parse(json) as AiSseEvent)
    } catch {
      // 单条事件解析失败不中断流
    }
  }
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += decoder.decode(value, { stream: true })
      let idx: number
      while ((idx = buf.indexOf('\n')) >= 0) {
        handleLine(buf.slice(0, idx))
        buf = buf.slice(idx + 1)
      }
    }
    buf += decoder.decode()
    if (buf.trim()) handleLine(buf)
  } finally {
    reader.releaseLock()
  }
}

/** AI 安全助手会话（ai.chat.use / ai.sessions.read_own / ai.sessions.delete_own） */
export const aiChatApi = {
  listSessions: async (params: AiSessionListParams) => {
    const data = await request<PageResult<AiSession>>('/ai/sessions', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  createSession: async (title?: string) =>
    (await request<{ session: AiSession }>('/ai/sessions', { method: 'POST', body: { title } }))
      .session,
  /** 重命名请使用 renameAiSession（后端为 PATCH 方法） */
  archiveSession: (id: string) =>
    request<{ message: string }>(`/ai/sessions/${id}/archive`, { method: 'POST' }),
  deleteSession: (id: string) =>
    request<{ message: string }>(`/ai/sessions/${id}`, { method: 'DELETE' }),
  listMessages: async (id: string, limit = 100) =>
    (
      await request<{ items: AiMessage[] }>(`/ai/sessions/${id}/messages`, {
        query: { limit },
      })
    ).items ?? [],
  stop: (id: string) =>
    request<{ message: string }>(`/ai/sessions/${id}/stop`, { method: 'POST' }),
  feedback: (messageId: string, body: { rating: 1 | -1; feedback_type?: string; comment?: string }) =>
    request<{ message: string }>(`/ai/messages/${messageId}/feedback`, { method: 'POST', body }),
  /** 发送消息（SSE 流式） */
  streamMessage: (sessionId: string, content: string, onEvent: (e: AiSseEvent) => void, signal: AbortSignal) =>
    streamPostSSE(`/ai/sessions/${sessionId}/messages`, { content }, onEvent, signal),
  /** 重试最后一问（SSE 流式） */
  streamRetry: (sessionId: string, onEvent: (e: AiSseEvent) => void, signal: AbortSignal) =>
    streamPostSSE(`/ai/sessions/${sessionId}/retry`, {}, onEvent, signal),
  /** 继续输出（SSE 流式） */
  streamContinue: (sessionId: string, onEvent: (e: AiSseEvent) => void, signal: AbortSignal) =>
    streamPostSSE(`/ai/sessions/${sessionId}/continue`, {}, onEvent, signal),
}

/** 会话重命名（PATCH 方法，走 request() 统一纪律：CSRF、401/423 全局回调、业务信封校验） */
export async function renameAiSession(id: string, title: string): Promise<void> {
  await request<unknown>(`/ai/sessions/${id}`, { method: 'PATCH', body: { title } })
}

/* ==================== 任务记录 ==================== */

export interface AiTask {
  id: string
  session_id: string
  session_title: string
  task_type: string
  status: string
  risk_level: string
  plan_summary: string
  started_at?: string | null
  finished_at?: string | null
  failure_code: string
  failure_message: string
  created_at: string
}

export interface AiTaskListParams {
  page: number
  page_size: number
  status?: string
  task_type?: string
}

/** AI 任务记录（ai.sessions.read_own，仅本人） */
export const aiTasksApi = {
  list: async (params: AiTaskListParams) => {
    const data = await request<PageResult<AiTask>>('/ai/tasks', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => (await request<{ task: AiTask }>(`/ai/tasks/${id}`)).task,
}

/* ==================== 一次性 AI 分析 ==================== */

export interface AiAnalyzeBody {
  event_id?: string
  rule_id?: number
  ip?: string
  question?: string
  period?: string
  /** 统计区间预设 1h/6h/24h/7d/30d（结构化过滤与画像、What-If 估算用） */
  time_range?: string
  /** 应用维度过滤 / 应用画像对象 */
  application_id?: string
  /** URI 维度过滤 / URI 画像对象 */
  uri?: string
  /** 网关 Request ID 维度过滤 */
  request_id?: string
  /** What-If 场景（§19.1 八种，缺省 disable_rule） */
  scenario?:
    | 'disable_rule'
    | 'enable_rule'
    | 'anomaly_threshold'
    | 'pl_switch'
    | 'add_exception'
    | 'remove_exception'
    | 'cc_threshold'
    | 'block_duration'
  /** What-If：模拟 CC 阈值（次/窗口，1-1000000） */
  cc_threshold?: number
  /** What-If：模拟封禁时长（秒，60-2592000） */
  block_duration_seconds?: number
  /** What-If anomaly_threshold：模拟入站异常阈值（1-10000） */
  anomaly_threshold?: number
  /** What-If pl_switch：模拟 CRS 执行等级（1-4） */
  paranoia_level?: number
  /** What-If remove_exception：模拟删除的例外 ID */
  exception_id?: string
}

/** 一次性分析结果（非流式，steps 为过程事件快照） */
export interface AiAnalyzeResult {
  task_id: string
  answer: string
  plan?: AiPlan | null
  steps?: AiSseEvent[] | null
  evidence?: AiEvidenceItem[] | null
}

/** 一次性分析服务端编排上限 120s、写期限放宽至 10 分钟（server analyze_handler runAnalyze），客户端留 1 分钟余量 */
const AI_ANALYZE_TIMEOUT_MS = 660_000

/** AI 分析端点（各自权限点，见路由注册） */
export const aiAnalyzeApi = {
  event: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/event', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  falsePositive: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/false-positive', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  attackProfile: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/attack-profile', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  attackChain: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/attack-chain', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  policyRecommendation: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/policy-recommendation', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  whatIf: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/what-if', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  rootCause: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/root-cause', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
  reportSummary: (body: AiAnalyzeBody) =>
    request<AiAnalyzeResult>('/ai/analyze/report-summary', { method: 'POST', body, timeoutMs: AI_ANALYZE_TIMEOUT_MS }),
}

/* ==================== 草稿 ==================== */

export interface AiDraft {
  id: string
  task_id?: string | null
  recommendation_type: string // EXCEPTION / BLACKLIST / CC_POLICY / CUSTOM_RULE / POLICY_CHANGE / REPORT_SUMMARY
  target_type: string
  target_id: string
  summary: string
  evidence_references?: unknown
  risk_level: string
  status: string // DRAFT / PENDING_REVIEW / ACCEPTED / REJECTED / EXPIRED
  draft_reference: string
  created_by_ai: boolean
  reviewed_by?: string | null
  reviewed_at?: string | null
  created_at: string
}

export interface AiDraftListParams {
  page: number
  page_size: number
  recommendation_type?: string
  status?: string
}

/** AI 草稿（任一 ai.draft.* 权限可读） */
export const aiDraftsApi = {
  list: async (params: AiDraftListParams) => {
    const data = await request<PageResult<AiDraft>>('/ai/drafts', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => (await request<{ draft: AiDraft }>(`/ai/drafts/${id}`)).draft,
  discard: (id: string) =>
    request<{ message: string }>(`/ai/drafts/${id}/discard`, { method: 'POST' }),
}

/* ==================== 模型供应商 / 模型 / 路由档位 ==================== */

export interface AiModelProvider {
  id: string
  name: string
  provider_type: string // openai_compatible / anthropic / ollama / local
  base_url: string
  /** 服务端按 BaseURL 规范化出的 scheme://host:port（前端不自行推导） */
  canonical_origin: string
  /** 管理员显式授权的附加出站目标（返回值保证为数组） */
  allowed_targets: string[]
  /** 非空 = 已配置密钥（仅存引用，不回显明文；规范 origin 变化时后端原子清除） */
  api_key_reference: string
  status: string // ENABLED / DISABLED
}

export interface AiProviderBody {
  name: string
  provider_type: string
  base_url: string
  api_key?: string
  /** 附加出站目标白名单（提交前需 trim/去空/去重） */
  allowed_targets?: string[]
  status?: string
}

export interface AiModel {
  id: string
  provider_id: string
  model_code: string
  display_name: string
  context_window: number
  max_output_tokens: number
  supports_tools: boolean
  supports_streaming: boolean
  priority: number
  timeout_seconds: number
  cost_input_unit: number
  cost_output_unit: number
  status: string
}

export interface AiModelBody {
  provider_id: string
  model_code: string
  display_name?: string
  context_window?: number
  max_output_tokens?: number
  supports_tools?: boolean
  supports_streaming?: boolean
  priority?: number
  timeout_seconds?: number
  cost_input_unit?: number
  cost_output_unit?: number
}

export interface AiModelRoutes {
  simple: string
  standard: string
  high: string
}

/** 模型管理（ai.models.read / ai.models.manage） */
export const aiModelsApi = {
  listProviders: async () =>
    (await request<{ items: AiModelProvider[] }>('/ai/models/providers')).items ?? [],
  createProvider: (body: AiProviderBody) =>
    request<{ provider: AiModelProvider }>('/ai/models/providers', { method: 'POST', body }),
  /** 更新供应商请使用 patchAiProvider（后端为 PATCH 方法） */
  deleteProvider: (id: string) =>
    request<{ message: string }>(`/ai/models/providers/${id}`, { method: 'DELETE' }),
  rotateKey: (id: string, apiKey: string) =>
    request<{ message: string }>(`/ai/models/providers/${id}/rotate-key`, {
      method: 'POST',
      body: { api_key: apiKey },
    }),
  listModels: async () => (await request<{ items: AiModel[] }>('/ai/models')).items ?? [],
  createModel: (body: AiModelBody) =>
    request<{ model: AiModel }>('/ai/models', { method: 'POST', body }),
  updateModel: (id: string, body: AiModelBody) =>
    request<{ model: AiModel }>(`/ai/models/${id}`, { method: 'PUT', body }),
  deleteModel: (id: string) =>
    request<{ message: string }>(`/ai/models/${id}`, { method: 'DELETE' }),
  enableModel: (id: string) =>
    request<{ message: string }>(`/ai/models/${id}/enable`, { method: 'POST' }),
  disableModel: (id: string) =>
    request<{ message: string }>(`/ai/models/${id}/disable`, { method: 'POST' }),
  /** 连通性健康检查（后端权限 ai.models.read，只读探测；模型自身 timeout_seconds 默认 60s，留一倍余量） */
  testModel: (id: string) =>
    request<{ ok: boolean; message: string }>(`/ai/models/${id}/test`, {
      method: 'POST',
      timeoutMs: 120_000,
    }),
  getRoutes: async () =>
    (
      await request<{ routes: AiModelRoutes; loaded_models: number }>('/ai/models/routes')
    ).routes,
  putRoutes: (body: Partial<AiModelRoutes>) =>
    request<{ message: string }>('/ai/models/routes', { method: 'PUT', body }),
}

/** 供应商更新（PATCH 方法；空字段服务端忽略；成功响应 { provider }，以响应中的 canonical_origin/api_key_reference 为准） */
export async function patchAiProvider(
  id: string,
  body: Partial<AiProviderBody & { status?: string }>,
): Promise<AiModelProvider> {
  const data = await request<{ provider: AiModelProvider }>(`/ai/models/providers/${id}`, {
    method: 'PATCH',
    body,
  })
  return data.provider
}

/** Agent 配置更新（PATCH） */
export async function patchAiAgent(
  id: string,
  body: { enabled?: boolean; allowed_tool_ids?: string[] },
): Promise<void> {
  await patchJSON(`/ai/agents/${id}`, body)
}

/** Tool 配置更新（PATCH） */
export async function patchAiTool(
  id: string,
  body: { enabled?: boolean; timeout_seconds?: number; max_results?: number },
): Promise<void> {
  await patchJSON(`/ai/tools/${id}`, body)
}

/** PATCH 请求小封装：收敛回 request() 统一纪律（CSRF、401/423 全局回调、业务信封校验） */
async function patchJSON(path: string, body: unknown): Promise<void> {
  await request<unknown>(path, { method: 'PATCH', body })
}

/* ==================== Agent / Tool 管理 ==================== */

export interface AiAgent {
  id: string
  code: string
  name: string
  description: string
  allowed_tool_ids?: string[] | null
  status: string
  version: number
  in_registry: boolean
}

export interface AiTool {
  id: string
  code: string
  name: string
  description: string
  version: string
  risk_level: string // READ_ONLY / DRAFT_ONLY / REQUIRES_CONFIRMATION / PROHIBITED
  required_permission: string
  input_schema?: unknown
  timeout_seconds: number
  max_results: number
  status: string
  in_registry: boolean
}

/** Agent / Tool 管理（ai.agents.read/manage、ai.tools.read/manage） */
export const aiAgentsToolsApi = {
  listAgents: async () => (await request<{ items: AiAgent[] }>('/ai/agents')).items ?? [],
  listTools: async () => (await request<{ items: AiTool[] }>('/ai/tools')).items ?? [],
}

/* ==================== Prompt 管理 ==================== */

export interface AiPrompt {
  id: string
  code: string
  name: string
  prompt_type: string // SYSTEM / ORCHESTRATOR / AGENT / TOOL / TASK / SAFETY / EVALUATION
  status: string
  current_version_id?: string | null
  created_at: string
}

export interface AiPromptVersion {
  id: string
  prompt_id: string
  version_number: number
  content: string
  content_hash: string
  change_summary: string
  test_result: string // '' / PASSED / FAILED
  adversarial_result: string // '' / ADVERSARIAL_PASSED / ADVERSARIAL_FAILED
  adversarial_detail?: AiPromptAdversarialCase[] | null
  created_at: string
  published_at?: string | null
  is_current: boolean
}

export interface AiPromptTestCheck {
  name: string
  passed: boolean
  message?: string
}

/** 回归测试逐用例摘要（test_detail.sets[].cases 元素；字段均可能缺省，渲染时容错） */
export interface AiPromptTestSetCase {
  id?: string
  question?: string
  passed?: boolean
  message?: string
}

/** 单个评估集的模型回归结果（test_detail.sets 元素，与后端冻结契约一致） */
export interface AiPromptTestSetResult {
  code: string
  name: string
  score: number
  threshold: number
  passed: boolean
  total: number
  passed_count: number
  model_code: string
  message?: string
  cases?: AiPromptTestSetCase[] | null
}

/** 版本测试结构化明细：sets 为真实模型回归结果，static_checks 为静态检查（两者分区展示，不得混称） */
export interface AiPromptTestDetail {
  sets?: AiPromptTestSetResult[] | null
  static_checks?: AiPromptTestCheck[] | null
}

export interface AiPromptTestResult {
  test_result: string
  checks?: AiPromptTestCheck[] | null
  test_detail?: AiPromptTestDetail | null
}

export interface AiPromptAdversarialCase {
  id: string
  category: string // PROMPT_INJECTION / PRIVILEGE_ESCALATION / DATA_EXFILTRATION
  attack: string
  passed: boolean
  reason?: string
}

export interface AiPromptAdversarialTestResult {
  adversarial_result: string // ADVERSARIAL_PASSED / ADVERSARIAL_FAILED
  cases?: AiPromptAdversarialCase[] | null
}

/** Prompt 管理（ai.prompts.*） */
export const aiPromptsApi = {
  list: async (params?: { prompt_type?: string; status?: string }) =>
    (await request<{ items: AiPrompt[] }>('/ai/prompts', { query: { ...params } })).items ?? [],
  create: (body: {
    code: string
    name: string
    prompt_type: string
    content: string
    change_summary?: string
  }) => request<{ prompt: AiPrompt; version: AiPromptVersion }>('/ai/prompts', { method: 'POST', body }),
  rename: (id: string, body: { name: string }) =>
    request<{ prompt: AiPrompt }>(`/ai/prompts/${id}`, { method: 'PATCH', body }),
  remove: (id: string) => request<{ message: string }>(`/ai/prompts/${id}`, { method: 'DELETE' }),
  listVersions: async (id: string) =>
    (await request<{ items: AiPromptVersion[] }>(`/ai/prompts/${id}/versions`)).items ?? [],
  createVersion: (id: string, body: { content: string; change_summary?: string }) =>
    request<{ version: AiPromptVersion }>(`/ai/prompts/${id}/versions`, { method: 'POST', body }),
  testVersion: (versionId: string) =>
    request<AiPromptTestResult>(`/ai/prompts/versions/${versionId}/test`, { method: 'POST' }),
  adversarialTestVersion: (versionId: string) =>
    request<AiPromptAdversarialTestResult>(`/ai/prompts/versions/${versionId}/adversarial-test`, {
      method: 'POST',
    }),
  publish: (id: string, versionId: string) =>
    request<{ message: string }>(`/ai/prompts/${id}/publish`, {
      method: 'POST',
      body: { version_id: versionId },
    }),
  rollback: (id: string, versionId: string) =>
    request<{ message: string }>(`/ai/prompts/${id}/rollback`, {
      method: 'POST',
      body: { version_id: versionId },
    }),
}

/* ==================== 记忆 ==================== */

export interface AiMemory {
  id: string
  user_id: string
  memory_scope: string // SESSION / PROJECT / LONG_TERM
  scope_reference: string
  content: string
  confidence_type: string // USER_CONFIRMED / SYSTEM_CONFIRMED / AI_INFERRED
  source_type: string
  source_reference: string
  status: string // ACTIVE / DISABLED
  last_used_at?: string | null
  created_at: string
  updated_at: string
}

export interface AiMemoryBody {
  memory_scope: string
  scope_reference?: string
  content: string
  confidence_type?: string
}

/** 记忆管理（ai.memories.read_own / ai.memories.manage_own，仅本人） */
export const aiMemoriesApi = {
  list: async (params?: { scope?: string; include_disabled?: boolean }) =>
    (await request<{ items: AiMemory[] }>('/ai/memories', { query: { ...params } })).items ?? [],
  create: (body: AiMemoryBody) =>
    request<{ memory: AiMemory }>('/ai/memories', { method: 'POST', body }),
  update: (id: string, content: string) =>
    request<{ message: string }>(`/ai/memories/${id}`, { method: 'PUT', body: { content } }),
  remove: (id: string) => request<{ message: string }>(`/ai/memories/${id}`, { method: 'DELETE' }),
  disable: (id: string) =>
    request<{ message: string }>(`/ai/memories/${id}/disable`, { method: 'POST' }),
}

/* ==================== AI 审计 ==================== */

/**
 * AI 审计记录。
 * 注意：后端 Record 无 JSON tag，序列化为 Go 字段名（PascalCase）；
 * 且 List 查询将 occurred_at 扫描进 RoleCodes 字段，前端以 RoleCodes 作为时间列展示。
 */
export interface AiAuditRecord {
  occurred_at: string
  user_id?: string | null
  username: string
  role_codes: string
  session_id?: string | null
  task_id?: string | null
  action: string
  task_type: string
  agent_code: string
  tool_code: string
  model_code: string
  prompt_version: string
  input_tokens: number
  output_tokens: number
  duration_ms: number
  estimated_cost: number
  request_summary: string
  result_summary: string
  draft_reference: string
  confirm_result: string
}

export interface AiAuditListParams {
  page: number
  page_size: number
  user_id?: string
  session_id?: string
  action?: string
  task_type?: string
  start_time?: string
  end_time?: string
}

export interface AiAuditVerifyResult {
  checked: number
  mismatches: number
  ok: boolean
}

/** AI 审计（ai.audits.read） */
export const aiAuditsApi = {
  list: async (params: AiAuditListParams) => {
    const data = await request<PageResult<AiAuditRecord>>('/ai/audits', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  verify: (limit?: number) =>
    request<AiAuditVerifyResult>('/ai/audits/verify', { method: 'POST', body: { limit } }),
}

/* ==================== 用量与成本 ==================== */

export interface AiUsageOverview {
  today_input_tokens: number
  today_output_tokens: number
  today_model_calls: number
  today_tool_calls: number
  today_cost: number
}

export interface AiUsageByUser {
  username: string
  input_tokens: number
  output_tokens: number
  model_calls: number
  cost: number
}

/** 用量与成本（ai.usage.read） */
export const aiUsageApi = {
  overview: async () => (await request<{ usage: AiUsageOverview }>('/ai/usage/overview')).usage,
  byUser: async () =>
    (await request<{ items: AiUsageByUser[] }>('/ai/usage/by-user')).items ?? [],
  byAgent: async () =>
    (await request<{ items: Record<string, unknown>[] }>('/ai/usage/by-agent')).items ?? [],
  byTask: async () =>
    (await request<{ items: Record<string, unknown>[] }>('/ai/usage/by-task')).items ?? [],
}

export const aiRecommendationsApi = {
  accept: (id: string) =>
    request<{ message: string }>(`/ai/recommendations/${id}/accept`, { method: 'POST' }),
  reject: (id: string) =>
    request<{ message: string }>(`/ai/recommendations/${id}/reject`, { method: 'POST' }),
}

export const aiStatusApi = {
  get: () =>
    request<{ enabled: boolean; degraded: boolean; message: string }>('/ai/status'),
}

/* ==================== AI 自动降噪 ==================== */

/** 降噪簇（与 server/internal/ainoise.Cluster 对齐） */
export interface AiNoiseCluster {
  id: string
  source: string // WAF / API
  fingerprint_hash: string
  application_id?: string | null
  host: string
  normalized_uri: string
  rule_id?: number | null
  detector_code: string
  client_ip: string
  event_count: number
  first_seen: string
  last_seen: string
  status: string // ACTIVE / SUPPRESSED / RESOLVED
  ai_verdict: string // TRUE_POSITIVE / LIKELY_FALSE_POSITIVE / UNKNOWN
  ai_confidence?: number | null
  ai_summary: string
  created_at: string
  updated_at: string
}

/** 降噪簇代表事件 */
export interface AiNoiseClusterEvent {
  event_id: string
  source: string
  is_representative: boolean
  created_at: string
}

/** 降噪面板统计 */
export interface AiNoiseStats {
  active_clusters: number
  folded_events: number
  likely_false_positive_clusters: number
  suppressed_clusters: number
}

/** 降噪扫描历史记录 */
export interface AiNoiseSweepRun {
  id: string
  started_at: string
  finished_at?: string | null
  scanned_events: number
  new_clusters: number
  updated_clusters: number
  llm_calls: number
  tokens_used: number
  status: string // SUCCESS / FAILED / PARTIAL
  error: string
}

/** 手动触发扫描的同步返回 */
export interface AiNoiseSweepResult {
  started_at: string
  finished_at: string
  scanned_events: number
  new_clusters: number
  updated_clusters: number
  llm_calls: number
  tokens_used: number
  recommendations: number
  status: string
  error?: string
}

/** 降噪设置（生效值，含默认回退） */
export interface AiNoiseSettings {
  enabled: boolean
  interval_seconds: number
  sweep_window_minutes: number
  min_events_threshold: number
  llm_verdict_enabled: boolean
}

export interface AiNoiseClusterListParams {
  page: number
  page_size: number
  source?: string
  status?: string
  verdict?: string
  start_time?: string
  end_time?: string
}

/** AI 自动降噪（ai.noise_reduction.use / ai.noise_reduction.manage） */
export const aiNoiseApi = {
  listClusters: async (params: AiNoiseClusterListParams) => {
    const data = await request<PageResult<AiNoiseCluster>>('/ai/noise/clusters', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  getCluster: async (id: string) =>
    request<{ cluster: AiNoiseCluster; events: AiNoiseClusterEvent[] }>(
      `/ai/noise/clusters/${id}`,
    ),
  stats: () => request<AiNoiseStats>('/ai/noise/stats'),
  suppressCluster: (id: string) =>
    request<AiNoiseCluster>(`/ai/noise/clusters/${id}/suppress`, { method: 'POST' }),
  resolveCluster: (id: string) =>
    request<AiNoiseCluster>(`/ai/noise/clusters/${id}/resolve`, { method: 'POST' }),
  /** 从降噪簇生成自定义规则草稿（DRAFT，需人工审核启用） */
  draftRuleFromCluster: (id: string) =>
    request<{ message: string; rule_id: number; draft: unknown }>(
      `/ai/noise/clusters/${id}/draft-rule`,
      { method: 'POST' },
    ),
  /** 手动触发一次降噪扫描（manage 权限，同步返回统计） */
  triggerSweep: () => request<AiNoiseSweepResult>('/ai/noise/sweeps', { method: 'POST' }),
  listSweeps: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<AiNoiseSweepRun>>('/ai/noise/sweeps', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  getSettings: () => request<AiNoiseSettings>('/ai/noise/settings'),
  putSettings: (body: Partial<AiNoiseSettings>) =>
    request<AiNoiseSettings>('/ai/noise/settings', { method: 'PUT', body }),
}

/* ==================== 质量评估 ==================== */

export interface AiEvalCase {
  question: string
  expected_contains?: string
}

export interface AiEvalSet {
  id: string
  code: string
  name: string
  description: string
  cases?: AiEvalCase[] | null
  created_at: string
}

export interface AiEvalRun {
  id: string
  evaluation_set_id: string
  set_code: string
  status: string
  score?: number | null
  details?: unknown
  started_at: string
  finished_at?: string | null
}

export interface AiEvalRunResult {
  id: string
  evaluation_set_id: string
  status: string
  score: number
  total: number
  passed: number
  truncated: boolean
}

/** 质量评估（ai.evaluations.run / 只读者可见） */
export const aiEvaluationsApi = {
  listSets: async () =>
    (await request<{ items: AiEvalSet[] }>('/ai/evaluation-sets')).items ?? [],
  createSet: (body: { code: string; name: string; description?: string; cases: AiEvalCase[] }) =>
    request<{ message: string }>('/ai/evaluation-sets', { method: 'POST', body }),
  listRuns: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<AiEvalRun>>('/ai/evaluation-runs', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 触发评估运行（服务端逐条串行上限 10 分钟，evalRunTimeout；客户端留 1 分钟余量） */
  run: async (evaluationSetId: string) =>
    (
      await request<{ run: AiEvalRunResult }>('/ai/evaluations/run', {
        method: 'POST',
        body: { evaluation_set_id: evaluationSetId },
        timeoutMs: 660_000,
      })
    ).run,
}

/* ==================== 用户反馈汇总 ==================== */

/** 反馈质量聚合行（GET /ai/feedback/summary；negative_rate 为 0-100 百分制，不返回 comment 明细） */
export interface AiFeedbackSummaryItem {
  task_type: string
  feedback_type: string // GENERAL / WRONG_FACT / MISSING_EVIDENCE / HALLUCINATION / OTHER
  total: number
  negative: number
  negative_rate: number
}

/** 用户反馈汇总（随质量评估页展示；days 支持 7/30） */
export const aiFeedbackApi = {
  summary: async (days: 7 | 30) =>
    (
      await request<{ items: AiFeedbackSummaryItem[] }>('/ai/feedback/summary', {
        query: { days },
      })
    ).items ?? [],
}
