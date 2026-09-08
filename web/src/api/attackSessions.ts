import { request } from './client'
import type { PageResult } from '../types'

/** 攻击阶段（八阶段，与 server 端 attack_session 词表一致，设计文档 #16.2） */
export type AttackStage =
  | 'RECON'
  | 'DISCOVERY'
  | 'AUTH_PROBE'
  | 'AUTHORIZATION_PROBE'
  | 'EXPLOIT'
  | 'DATA_ACCESS'
  | 'PERSISTENCE'
  | 'UNKNOWN'

/** 攻击活动状态（OPEN 进行中 / CLOSED 已关闭） */
export type AttackSessionStatus = 'OPEN' | 'CLOSED'

/** 风险等级（与 server 端 security/identities 词表一致） */
export type AttackRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** 攻击活动列表项（GET /security/attack-sessions 元素） */
export interface AttackSessionItem {
  id: string
  session_key: string
  identity_id: string
  start_time: string
  end_time: string
  request_count: number
  event_count: number
  risk_score: number
  risk_level: AttackRiskLevel
  attack_stage: AttackStage
  status: AttackSessionStatus
  /** 疑似自动化攻击派生标注（server 端规则：有效阶段≥3 且命中无头/枚举/低慢类指示信号，单调 false→true） */
  automation_suspected: boolean
  /** 标注判定依据（stages=命中阶段集;indicator=首个指示信号；未标注时仅阶段集） */
  automation_basis: string
}

/** 攻击活动关联事件（详情接口 events 元素，按时间序；source_table/source_id 指向来源事件记录） */
export interface AttackSessionEventItem {
  source_table: string
  source_id: string
  occurred_at: string
  stage: AttackStage
}

export interface AttackSessionListParams {
  stage?: string
  risk_level?: string
  status?: string
  from?: string
  to?: string
  page: number
  page_size: number
}

export const attackSessionsApi = {
  list: async (params: AttackSessionListParams) => {
    const data = await request<PageResult<AttackSessionItem>>('/security/attack-sessions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => {
    // 后端响应为 { session, events } 包裹结构；无关联事件时 events 为 null（Go nil slice），归一化为空数组
    const data = await request<{
      session: AttackSessionItem
      events: AttackSessionEventItem[] | null
    }>(`/security/attack-sessions/${id}`)
    return { session: data.session, events: data.events ?? [] }
  },
}
