import { request } from './client'
import type { PageResult } from '../types'

/* ==================== AI 定时运营任务（server/internal/apiops）：任务类型 / 计划 CRUD / 启停 / 立即执行 / 执行记录 ==================== */

/** 内置任务类型（与迁移 000062 chk_api_ai_schedules_task_type 一致） */
export type ApiAITaskType =
  | 'API_ASSET_DIGEST'
  | 'SHADOW_REVIEW'
  | 'WEAKNESS_FOLLOW'
  | 'RISK_DIGEST'
  | 'SENSITIVE_DIGEST'

/** 任务类型展示元数据（GET /task-types） */
export interface ApiAITaskTypeInfo {
  task_type: ApiAITaskType
  name: string
  description: string
}

/** 执行记录状态（与迁移 000062 chk_api_ai_schedule_runs_status 一致） */
export type ApiAIRunStatus = 'RUNNING' | 'SUCCESS' | 'FAILED'

/** 任务入参（config_json 白名单键；零值走后端缺省） */
export interface ApiAITaskConfig {
  /** 统计窗口（小时），缺省 24，上限 720 */
  window_hours?: number
  /** 清单条数上限，缺省 20，上限 100 */
  limit?: number
  /** WEAKNESS_FOLLOW 临近到期窗口（天），缺省 3，上限 30 */
  due_within_days?: number
}

/** AI 运营定时计划（api_ai_schedules） */
export interface ApiAISchedule {
  id: string
  task_type: ApiAITaskType
  name: string
  cron_expr: string
  enabled: boolean
  config: ApiAITaskConfig
  next_run_at?: string | null
  last_run_at?: string | null
  last_status: string
  last_error: string
  created_by?: string | null
  created_at: string
  updated_at: string
}

/** 计划创建提交体（enabled 缺省 false；更新走启停接口忽略该字段） */
export interface ApiAIScheduleBody {
  task_type: ApiAITaskType
  name: string
  cron_expr: string
  enabled?: boolean
  config?: ApiAITaskConfig
}

/** 执行记录（api_ai_schedule_runs；report 为按任务类型结构化的报告对象） */
export interface ApiAIRun {
  id: string
  schedule_id: string
  started_at: string
  finished_at?: string | null
  status: ApiAIRunStatus
  summary: string
  report: Record<string, unknown>
  created_at: string
}

export const apiAIOpsApi = {
  /** 内置任务类型词表与说明 */
  listTaskTypes: async () => {
    const data = await request<{ items: ApiAITaskTypeInfo[] }>(`/api-security/ai-ops/task-types`)
    return data.items ?? []
  },
  /** 计划列表（过滤 task_type/enabled + 分页） */
  listSchedules: async (params: {
    task_type?: string
    enabled?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiAISchedule>>(`/api-security/ai-ops/schedules`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  createSchedule: async (body: ApiAIScheduleBody) => {
    const data = await request<{ schedule: ApiAISchedule }>(`/api-security/ai-ops/schedules`, {
      method: 'POST',
      body,
    })
    return data.schedule
  },
  /** 更新 name/cron_expr/config（task_type 不可变；启停走专用接口） */
  updateSchedule: async (id: string, body: ApiAIScheduleBody) => {
    const data = await request<{ schedule: ApiAISchedule }>(
      `/api-security/ai-ops/schedules/${id}`,
      { method: 'PUT', body },
    )
    return data.schedule
  },
  deleteSchedule: (id: string) =>
    request<{ deleted: boolean }>(`/api-security/ai-ops/schedules/${id}`, { method: 'DELETE' }),
  enableSchedule: async (id: string) => {
    const data = await request<{ schedule: ApiAISchedule }>(
      `/api-security/ai-ops/schedules/${id}/enable`,
      { method: 'POST' },
    )
    return data.schedule
  },
  disableSchedule: async (id: string) => {
    const data = await request<{ schedule: ApiAISchedule }>(
      `/api-security/ai-ops/schedules/${id}/disable`,
      { method: 'POST' },
    )
    return data.schedule
  },
  /** 手动触发一次（同步执行并返回执行记录；不改变排期） */
  runSchedule: async (id: string) => {
    const data = await request<{ run: ApiAIRun }>(`/api-security/ai-ops/schedules/${id}/run`, {
      method: 'POST',
    })
    return data.run
  },
  /** 执行记录列表（按开始时间倒序分页） */
  listRuns: async (scheduleId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAIRun>>(
      `/api-security/ai-ops/schedules/${scheduleId}/runs`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 执行记录详情（摘要 + 结构化报告） */
  getRun: async (id: string) => {
    const data = await request<{ run: ApiAIRun }>(`/api-security/ai-ops/runs/${id}`)
    return data.run
  },
}
