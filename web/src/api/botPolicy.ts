import { request } from './client'

/**
 * 应用级 Bot 挑战策略管理面客户端（WDSP P1-02 B4，契约
 * server/openapi/fragments/17-bot-policy.yaml；服务端 server/internal/botpolicy）。
 * 路由：GET/PUT /applications/{id}/bot-policy、POST .../preflight。
 * 权限：bot_policy.read / bot_policy.edit。保存草稿不等于节点生效，发布走既有发布通道；
 * 草稿版本 / 发布批次 / 节点有效版本分离返回，不混成一个 enabled。
 */

export type BotPolicyMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type BotPolicyState = 'NOT_CONFIGURED' | 'DRAFT_PENDING' | 'PUBLISHED'
export type BotCheckStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP'
export type BotReservationState = 'ENABLED' | 'RESERVED_TOMBSTONE' | 'RELEASED'

/** 与后端一致的产品限制（server/internal/botpolicy/policy.go，B0 冻结） */
export const BOT_POLICY_LIMITS = {
  maxSelectors: 64,
  maxSelectorPathLen: 512,
  maxSignalRules: 32,
  maxRuleIDLen: 64,
  minGroups: 2,
  maxGroups: 3,
  minWindowSeconds: 30,
  maxWindowSeconds: 3600,
  defaultWindowSeconds: 300,
  maxRuleWeight: 10,
  minNonceTTL: 30,
  maxNonceTTL: 300,
  defaultNonceTTL: 90,
  minClearanceTTL: 60,
  maxClearanceTTL: 3600,
  defaultClearanceTTL: 900,
  minDifficulty: 10,
  maxDifficulty: 18,
  defaultDifficulty: 14,
  minMaxAttempts: 1,
  maxMaxAttempts: 5,
  defaultMaxAttempts: 3,
  maxKeyRefLen: 64,
  maxReasonLen: 500,
} as const

/** Bot 保留命名空间（B0 冻结；verify 固定协议端点在其下，永不反向代理） */
export const BOT_RESERVED_NAMESPACE = '/_wdsp/bot/v1/'
export const BOT_RESERVED_VERIFY_PATH = '/_wdsp/bot/v1/verify'

/** 挑战适用范围选择器（path_exact / path_prefix 二选一；仅 GET 浏览器文档导航；OR 关系） */
export interface BotSelector {
  path_exact?: string
  path_prefix?: string
}

/** 单条信号规则（id 稳定且策略内唯一；params 允许键按指标白名单） */
export interface BotSignalRule {
  id: string
  group: string
  metric: string
  params?: Record<string, string>
  window_seconds: number
  weight: number
  threshold: number
}

/** 多信号判定配置（≥min_independent_groups 个独立组满足且至少 1 个行为组才提出挑战） */
export interface BotSignalRules {
  min_independent_groups: number
  require_behavior_group: boolean
  rules: BotSignalRule[]
}

/** 挑战参数（仅 type=JS；key_ref 仅引用名，任何接口均不返回密钥材料） */
export interface BotChallenge {
  type: string
  nonce_ttl_seconds: number
  clearance_ttl_seconds: number
  difficulty: number
  max_attempts: number
  key_ref?: string
}

/** 保留路由状态（版本化配置；namespace 恒为保留命名空间） */
export interface BotRouteReservation {
  state: BotReservationState
  namespace: string
}

/** 应用 Bot 策略（当前草稿；version 乐观锁不可变递增；无记录应用 version=0） */
export interface BotPolicy {
  id: string
  application_id: string
  mode: BotPolicyMode
  version: number
  selectors: BotSelector[]
  signal_rules: BotSignalRules
  challenge: BotChallenge
  route_reservation: BotRouteReservation
  updated_by: string
  created_at: string
  updated_at: string
}

/** 最近成功发布快照中本应用策略的生效状态（found=false = 从未成功发布） */
export interface BotPublishState {
  found: boolean
  version_no: number
  version_id: string
  policy_version: number
}

/** 扇出节点同步状态（effective=true 表示已同步到最新成功发布批次） */
export interface BotNodeSyncState {
  node_name: string
  last_sync_result: string
  last_sync_version_id?: string | null
  effective: boolean
}

/** 状态摘要：草稿版本 vs 发布批次 vs 节点有效版本分离（发布失败不回退草稿） */
export interface BotStatusSummary {
  state: BotPolicyState
  draft_version: number
  published: BotPublishState
  nodes?: BotNodeSyncState[]
}

export interface BotPolicyGetResult {
  policy: BotPolicy
  summary: BotStatusSummary
}

/** PUT 全量草稿请求体（expected_version 乐观锁：无草稿=0，冲突 409；reason 非空进审计） */
export interface BotPolicyUpdateBody {
  mode: BotPolicyMode
  expected_version: number
  selectors: BotSelector[]
  signal_rules?: {
    min_independent_groups?: number
    require_behavior_group?: boolean
    rules?: BotSignalRule[]
  }
  challenge?: {
    type?: string
    nonce_ttl_seconds?: number
    clearance_ttl_seconds?: number
    difficulty?: number
    max_attempts?: number
    key_ref?: string
  }
  route_reservation?: BotRouteReservation
  reason: string
}

/** 预检单项结果（structure / route_conflicts / shared_state / signing_key / node_capability） */
export interface BotPreflightCheck {
  name: string
  status: BotCheckStatus
  message: string
}

/** 保留路由冲突条目（status=FAIL 阻断发布，WARN 仅提示） */
export interface BotRouteConflict {
  type: string
  status: 'FAIL' | 'WARN'
  message: string
  ref: string
}

/** 预检候选策略（全部缺省时后端检查当前草稿；不保存、不发布） */
export interface BotPreflightBody {
  mode?: BotPolicyMode
  selectors?: BotSelector[]
  signal_rules?: BotPolicyUpdateBody['signal_rules']
  challenge?: BotPolicyUpdateBody['challenge']
  route_reservation?: BotRouteReservation
}

export interface BotPreflightResult {
  policy: BotPolicy
  checks: BotPreflightCheck[]
  conflicts: BotRouteConflict[]
  publishable: boolean
}

/** Go nil slice/map 序列化为 null，统一归一化（含未知枚举值的兜底原样保留） */
function normalizePolicy(p: BotPolicy): BotPolicy {
  const rules = p.signal_rules?.rules ?? []
  return {
    ...p,
    selectors: p.selectors ?? [],
    signal_rules: {
      min_independent_groups:
        p.signal_rules?.min_independent_groups ?? BOT_POLICY_LIMITS.minGroups,
      require_behavior_group: p.signal_rules?.require_behavior_group ?? true,
      rules: rules.map((r) => ({ ...r, params: r.params ?? {} })),
    },
    challenge: p.challenge ?? {
      type: 'JS',
      nonce_ttl_seconds: BOT_POLICY_LIMITS.defaultNonceTTL,
      clearance_ttl_seconds: BOT_POLICY_LIMITS.defaultClearanceTTL,
      difficulty: BOT_POLICY_LIMITS.defaultDifficulty,
      max_attempts: BOT_POLICY_LIMITS.defaultMaxAttempts,
    },
    route_reservation: p.route_reservation ?? {
      state: 'RELEASED',
      namespace: BOT_RESERVED_NAMESPACE,
    },
  }
}

export const botPolicyApi = {
  get: async (appId: string): Promise<BotPolicyGetResult> => {
    const data = await request<BotPolicyGetResult>(
      `/applications/${appId}/bot-policy`,
    )
    return { ...data, policy: normalizePolicy(data.policy) }
  },
  update: async (
    appId: string,
    body: BotPolicyUpdateBody,
  ): Promise<BotPolicy> => {
    const data = await request<{ policy: BotPolicy }>(
      `/applications/${appId}/bot-policy`,
      { method: 'PUT', body },
    )
    return normalizePolicy(data.policy)
  },
  preflight: async (
    appId: string,
    body: BotPreflightBody,
  ): Promise<BotPreflightResult> => {
    const data = await request<BotPreflightResult>(
      `/applications/${appId}/bot-policy/preflight`,
      { method: 'POST', body },
    )
    return {
      ...data,
      policy: normalizePolicy(data.policy),
      checks: data.checks ?? [],
      conflicts: data.conflicts ?? [],
    }
  },
}
