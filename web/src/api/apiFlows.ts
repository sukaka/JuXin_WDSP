import { request } from './client'

/**
 * 业务流程基线（/api-security/flow-baselines，阶段8 §44 发布下发面；
 * 字段与 server/internal/apiflows/types.go 一致，迁移 000155/000158）。
 * 权限点：api_flow.read / api_flow.manage。
 * 注意：步骤绑定端点用 endpoint_id（api_endpoints.id），endpoint_key 仅出参；
 * PUT 为整体替换且 expected_version 必填做乐观锁（冲突 409）。
 */

/** 步骤写入载荷（与 apiflows.StepInput 一致） */
export interface ApiFlowStepInput {
  /** 步骤标识（同一流程内唯一，≤128 字符） */
  step_id: string
  /** 绑定端点（api_endpoints.id） */
  endpoint_id: string
  /** 流程内单调序号（逆序判定基准） */
  sequence: number
  /** 期望前置步骤 step_id 列表（AND 语义；空 = 无前置约束，≤16 个） */
  predecessors: string[]
  /** 是否流程终点（描述性字段） */
  terminal: boolean
  /** 要求的对象前置状态（空 = 不参与状态机判定，≤64 字符） */
  state_from: string
  /** 步骤完成后的对象状态（空 = 不推进状态记录，≤64 字符） */
  state_to: string
  /** 步骤级短窗调用上限（>0 启用 rapid_batch 步骤级判定；省略 = 不判定） */
  max_per_window?: number
  /** 步骤级短窗秒数（>0 覆盖缺省 60s，≤600；省略 = 缺省窗口） */
  rate_window_seconds?: number
  /** 取消语义声明（post_cancel_operation 判定来源；省略/false = 不判定） */
  cancels_flow?: boolean
}

/** 步骤读模型（endpoint_key 由 api_endpoints 关联带出，仅出参；三字段后端恒回传） */
export interface ApiFlowStep extends ApiFlowStepInput {
  id: string
  endpoint_key: string
  max_per_window: number
  rate_window_seconds: number
  cancels_flow: boolean
}

/** 流程基线详情（含步骤明细，步骤按 sequence 稳定排序） */
export interface ApiFlowBaseline {
  id: string
  flow_id: string
  name: string
  description: string
  enabled: boolean
  /** 乐观锁版本戳（编辑 +1） */
  version: number
  /** 流程级短窗调用上限（同主体对本流程任意步骤的合计调用；>0 启用 rapid_batch 流程级判定；0 = 不判定） */
  max_per_window: number
  /** 流程级短窗秒数（>0 覆盖缺省 60s，≤600；0 = 缺省窗口） */
  rate_window_seconds: number
  steps: ApiFlowStep[]
  created_by: string
  created_at: string
  updated_at: string
}

/** 流程基线列表行（不含步骤明细，带步骤数） */
export interface ApiFlowBaselineSummary {
  id: string
  flow_id: string
  name: string
  description: string
  enabled: boolean
  version: number
  step_count: number
  created_by: string
  created_at: string
  updated_at: string
}

/** 创建/整体替换写入载荷（Update 时由 update() 附带 expected_version） */
export interface ApiFlowBaselineUpsertInput {
  flow_id: string
  name: string
  description: string
  enabled: boolean
  /** 流程级短窗调用上限（>0 启用 rapid_batch 流程级判定；省略 = 不判定） */
  max_per_window?: number
  /** 流程级短窗秒数（>0 覆盖缺省 60s，≤600；省略 = 缺省窗口） */
  rate_window_seconds?: number
  steps: ApiFlowStepInput[]
}

export const apiFlowBaselinesApi = {
  /** 流程基线列表（enabled 过滤可选；不分页，返回总数） */
  list: async (params: { enabled?: boolean } = {}) => {
    const data = await request<{ items: ApiFlowBaselineSummary[]; total: number }>(
      '/api-security/flow-baselines',
      { query: { enabled: params.enabled } },
    )
    return { items: data.items ?? [], total: data.total ?? 0 }
  },
  /** 单条详情（含步骤明细，编辑前拉取以取得最新 version） */
  get: (id: string) => request<ApiFlowBaseline>(`/api-security/flow-baselines/${id}`),
  /** 创建（enabled 缺省 true；flow_id 冲突 409） */
  create: (input: ApiFlowBaselineUpsertInput) =>
    request<ApiFlowBaseline>('/api-security/flow-baselines', { method: 'POST', body: input }),
  /** 整体替换（expected_version 乐观锁，冲突 409；成功后 version +1） */
  update: (id: string, input: ApiFlowBaselineUpsertInput, expectedVersion: number) =>
    request<ApiFlowBaseline>(`/api-security/flow-baselines/${id}`, {
      method: 'PUT',
      body: { ...input, expected_version: expectedVersion },
    }),
  /** 删除（步骤级联删除，删除即退出下次发布载荷） */
  remove: (id: string) =>
    request<{ status: string }>(`/api-security/flow-baselines/${id}`, { method: 'DELETE' }),
}

/** 读模型步骤 → 写入载荷（去掉仅出参的 id / endpoint_key；零值字段省略不发送，0/false 语义 = 不判定） */
export function toStepInput(s: ApiFlowStep): ApiFlowStepInput {
  return {
    step_id: s.step_id,
    endpoint_id: s.endpoint_id,
    sequence: s.sequence,
    predecessors: s.predecessors ?? [],
    terminal: s.terminal,
    state_from: s.state_from ?? '',
    state_to: s.state_to ?? '',
    ...(s.max_per_window ? { max_per_window: s.max_per_window } : {}),
    ...(s.rate_window_seconds ? { rate_window_seconds: s.rate_window_seconds } : {}),
    ...(s.cancels_flow ? { cancels_flow: true } : {}),
  }
}

/** 详情 → 整体替换写入载荷（启用/禁用等 PUT 场景复用原步骤） */
export function toUpsertInput(f: ApiFlowBaseline): ApiFlowBaselineUpsertInput {
  return {
    flow_id: f.flow_id,
    name: f.name,
    description: f.description,
    enabled: f.enabled,
    ...(f.max_per_window ? { max_per_window: f.max_per_window } : {}),
    ...(f.rate_window_seconds ? { rate_window_seconds: f.rate_window_seconds } : {}),
    steps: (f.steps ?? []).map(toStepInput),
  }
}
