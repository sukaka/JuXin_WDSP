/* ==================== NG-AZ-04：授权实断（enforcement）共享纯函数与词表 ====================
 * 契约：docs/nextgen/NG-AZ-04-protect-wizard.md §1.1~§1.5。
 * readiness 判定为服务端唯一事实源，前端只渲染徽章与 reasons，不复制判定逻辑（D2）。
 */

/** 「UNKNOWN 永不阻断」固定注明（契约文案：readiness tooltip 与向导中固定出现） */
export const UNKNOWN_NEVER_BLOCKS_NOTE = 'UNKNOWN 永不阻断'

/** readiness 徽章词表（§1.2 六态 + PROTECT_ACTIVE 展示态） */
export const ENFORCEMENT_READINESS_META: Record<string, { color: string; label: string }> = {
  READY: { color: 'green', label: '可实断' },
  PROTECT_ACTIVE: { color: 'geekblue', label: '实断中（PROTECT）' },
  NOT_PUBLISHABLE: { color: 'default', label: '资格不齐' },
  BLOCKED_BY_NO_RELATION: { color: 'orange', label: '无有效 OWNER 关系' },
  BLOCKED_BY_CONFLICT: { color: 'gold', label: '存在 OPEN 冲突' },
  BLOCKED_BY_STALE: { color: 'volcano', label: '快照/租约过期' },
  BLOCKED_BY_NODE: { color: 'red', label: '节点未就绪' },
}

/** enforcement 当前值词表（api_object_models.enforcement） */
export const ENFORCEMENT_VALUE_META: Record<string, { color: string; label: string }> = {
  OBSERVE: { color: 'default', label: '观测（OBSERVE）' },
  PROTECT: { color: 'red', label: '实断（PROTECT）' },
}

/** 节点 ACK 五态词表（NG-AZ-02 D6，服务端派生） */
export const ACK_STATE_META: Record<string, { color: string; label: string }> = {
  FRESH: { color: 'green', label: 'FRESH' },
  STALE_WITHIN_LEASE: { color: 'gold', label: '租约内陈旧' },
  STALE_EXPIRED: { color: 'red', label: '租约外陈旧' },
  NEVER_ACKED: { color: 'default', label: '从未 ACK' },
  CLOCK_SKEW: { color: 'orange', label: '时钟偏差' },
}

/** 权威来源缺口状态（authorities/{id}/status.gap_status） */
export const GAP_STATUS_META: Record<string, { color: string; label: string }> = {
  OK: { color: 'green', label: '连续' },
  NO_DATA: { color: 'default', label: '暂无数据' },
  AUTHZ_SOURCE_GAP: { color: 'red', label: '存在缺口' },
}

/** 关系来源词表（api_object_relations.source，迁移 000172 扩 AUTHORITY_SYNC） */
export const RELATION_SOURCE_META: Record<string, { color: string; label: string }> = {
  MANUAL: { color: 'blue', label: '手工登记' },
  IMPORT: { color: 'purple', label: '导入' },
  CREATE_BINDING: { color: 'cyan', label: '创建绑定' },
  AUTHORITY_SYNC: { color: 'geekblue', label: '权威同步' },
}

/** 证据来源声明词表（§8.4 四要素之二） */
export const EVIDENCE_SOURCE_META: Record<string, { label: string; hint: string }> = {
  AUTHORITY_SYNC: { label: '权威同步（AUTHORITY_SYNC）', hint: '对象关系来自权威来源签名批次同步' },
  MANUAL_CONFIRMED: { label: '人工确认（MANUAL_CONFIRMED）', hint: '对象关系经管理面人工审核确认' },
}

/**
 * 冻结确认语义文案 v1（§1.4；与 server confirmTextV1 同模板——前端仅用于签署页展示，
 * 落库文本以 server 为准）。
 */
export function buildAuthzConfirmTextV1(params: {
  windowDays: number
  observeViolationCount: number
  distinctPrincipalCount: number
  confirmedByName: string
}): string {
  return `我已知悉：本端点切换 PROTECT 后，经显式资格判定成立的违规请求将被实断（403 AUTHZ_VIOLATION_DENIED）；UNKNOWN 永不阻断。近 ${params.windowDays} 天观测违规 ${params.observeViolationCount} 次、涉及主体 ${params.distinctPrincipalCount} 个；我（${params.confirmedByName}）作为业务负责人确认承担实断影响。（确认文案 v1）`
}

/** PATCH 400 归类（§1.5 失败路径：token 类回影响评估步重新签发；要素类回四要素步） */
export type PatchErrorKind = 'token' | 'elements' | 'other'

export function classifyPatchError(message: string): PatchErrorKind {
  const m = message.toLowerCase()
  if (m.includes('confirm_token') || m.includes('token') || m.includes('签署')) return 'token'
  if (m.includes('enforcement_owner') || m.includes('evidence_source') || m.includes('on_unknown')) return 'elements'
  return 'other'
}

/** 签署令牌是否已过期（15 分钟 TTL；§1.5 token 过期回第 2 步重新评估签发） */
export function isConfirmTokenExpired(expiresAt?: string, now: number = Date.now()): boolean {
  if (!expiresAt) return false
  const t = Date.parse(expiresAt)
  return Number.isFinite(t) && now >= t
}

/** readiness 是否为可实断/展示态之外的阻塞态（向导第 3 步黄条预期管理） */
export function isReadinessBlocking(readiness?: string): boolean {
  return Boolean(readiness) && readiness !== 'READY' && readiness !== 'PROTECT_ACTIVE'
}

/** 「为什么被实断」证据对象（NG-AZ-03 §1.4 逐键冻结；随 decisions.evidence.authz_enforcement 透传） */
export interface AuthzEnforcementEvidence {
  decision?: string
  reason_code?: string
  enforced?: boolean
  endpoint_key?: string
  model_version?: string
  policy_version?: string
  revocation_watermark?: { manual_seq?: number; sources?: Record<string, number> }
  principal_source?: string
  /** BFLA 形态为空（无对象维度）——如实呈现 */
  object_ref?: string
  /** BOLA 为冻结八键；BFLA 为其实际评估键集（如实渲染不补齐） */
  eligibility?: Record<string, boolean>
  lease_seconds?: number
  applied_at_age_seconds?: number
  enforcement_owner?: string
  evidence_source?: string
  recorded_at?: string
  /** OBSERVE 形态降级留痕（拟实断） */
  proposed_decision?: string
}

/** 从决策 evidence（Record<string, unknown>）提取 authz_enforcement 子对象；无则 null */
export function extractAuthzEnforcement(evidence?: Record<string, unknown> | null): AuthzEnforcementEvidence | null {
  const raw = evidence?.authz_enforcement
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  return raw as AuthzEnforcementEvidence
}
