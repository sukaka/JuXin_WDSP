import { request } from './client'

/**
 * 业务 JWT 信任链策略管理面客户端（WDSP P0-03，契约 server/openapi/fragments/16-jwt-trust.yaml）。
 * 路由：GET/PUT /applications/{id}/jwt-trust-policy、POST .../preflight。
 * 权限：jwt_trust.read / jwt_trust.manage。草稿保存不等于线上生效，发布走既有发布通道。
 */

export type JwtTrustMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type JwtTrustKeySourceType = 'STATIC_JWKS' | 'REMOTE_JWKS'
export type JwtTrustState = 'NOT_CONFIGURED' | 'DRAFT_PENDING' | 'PUBLISHED'
export type JwtTrustCheckStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP'

/** 与后端一致的产品限制（server/internal/jwttrust/policy.go） */
export const JWT_TRUST_LIMITS = {
  maxIssuers: 8,
  maxSelectors: 64,
  defaultClockSkew: 30,
  maxClockSkew: 120,
  maxReasonLen: 500,
  maxTenantClaimLen: 64,
  maxRoleClaims: 8,
  maxRoleClaimLen: 64,
  maxJWKSKeys: 32,
  maxJWKSBytes: 256 * 1024,
  minRSAKeyBits: 2048,
} as const

/** 请求范围选择器（path_exact / path_prefix 二选一；不同 selector 之间 OR） */
export interface JwtTrustSelector {
  methods: string[]
  path_exact?: string
  path_prefix?: string
  token_required: boolean
}

/** issuer 密钥来源（二选一：静态公钥 JWKS / 远程 HTTPS JWKS 地址） */
export interface JwtTrustKeySource {
  type: JwtTrustKeySourceType
  jwks?: string
  url?: string
}

/** 受信发行方配置（issuer 为大小写敏感精确值，策略内唯一） */
export interface JwtTrustIssuer {
  issuer: string
  audiences: string[]
  algorithms: string[]
  key_source: JwtTrustKeySource
  clock_skew_seconds: number
  tenant_claim?: string
  role_claims?: string[]
}

/** 应用 JWT 信任策略（当前草稿；version 乐观锁不可变递增；无记录应用 version=0） */
export interface JwtTrustPolicy {
  id: string
  application_id: string
  mode: JwtTrustMode
  version: number
  selectors: JwtTrustSelector[]
  issuers: JwtTrustIssuer[]
  updated_by: string
  created_at: string
  updated_at: string
}

/** 状态摘要：草稿版本 vs 最近成功发布快照中的生效版本 */
export interface JwtTrustStatusSummary {
  state: JwtTrustState
  draft_version: number
  published_version: number
}

export interface JwtTrustPolicyGetResult {
  policy: JwtTrustPolicy
  summary: JwtTrustStatusSummary
}

/** PUT 全量草稿请求体（expected_version 乐观锁：无草稿=0，冲突 409；reason 非空进审计） */
export interface JwtTrustPolicyUpdateBody {
  mode: JwtTrustMode
  expected_version: number
  selectors: JwtTrustSelector[]
  issuers: JwtTrustIssuer[]
  reason: string
}

/** 预检单项结果（structure / remote_url_ssrf / remote_connectivity / pipeline_gate / node_capability） */
export interface JwtTrustPreflightCheck {
  name: string
  status: JwtTrustCheckStatus
  message: string
}

/** 预检候选策略（全部缺省时后端检查当前草稿；不保存、不发布） */
export interface JwtTrustPreflightBody {
  mode?: JwtTrustMode
  selectors?: JwtTrustSelector[]
  issuers?: JwtTrustIssuer[]
}

export interface JwtTrustPreflightResult {
  policy: JwtTrustPolicy
  checks: JwtTrustPreflightCheck[]
  publishable: boolean
}

/** Go nil slice 序列化为 null，统一归一化为空数组 */
function normalizePolicy(p: JwtTrustPolicy): JwtTrustPolicy {
  return {
    ...p,
    selectors: p.selectors ?? [],
    issuers: (p.issuers ?? []).map((is) => ({
      ...is,
      audiences: is.audiences ?? [],
      algorithms: is.algorithms ?? [],
      role_claims: is.role_claims ?? [],
    })),
  }
}

export const jwtTrustApi = {
  get: async (appId: string): Promise<JwtTrustPolicyGetResult> => {
    const data = await request<JwtTrustPolicyGetResult>(
      `/applications/${appId}/jwt-trust-policy`,
    )
    return { ...data, policy: normalizePolicy(data.policy) }
  },
  update: async (
    appId: string,
    body: JwtTrustPolicyUpdateBody,
  ): Promise<JwtTrustPolicy> => {
    const data = await request<{ policy: JwtTrustPolicy }>(
      `/applications/${appId}/jwt-trust-policy`,
      {
        method: 'PUT',
        body,
      },
    )
    return normalizePolicy(data.policy)
  },
  preflight: async (
    appId: string,
    body: JwtTrustPreflightBody,
  ): Promise<JwtTrustPreflightResult> => {
    const data = await request<JwtTrustPreflightResult>(
      `/applications/${appId}/jwt-trust-policy/preflight`,
      { method: 'POST', body },
    )
    return {
      ...data,
      policy: data.policy ? normalizePolicy(data.policy) : data.policy,
      checks: data.checks ?? [],
    }
  },
}

/** JWK 私钥/对称材料参数名（RFC 7517/7518：RSA 私参 d/p/q/dp/dq/qi/oth，EC 私参 d，oct 为对称密钥） */
const PRIVATE_JWK_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']

/**
 * 快速检测 JWKS 文本是否包含私钥或对称密钥材料（粘贴即时拒绝用）。
 * JSON 解析失败等结构问题返回 false，交由 validateStaticJwks 在保存/预检时给出字段级错误。
 */
export function jwksHasPrivateMaterial(text: string): boolean {
  const trimmed = text.trim()
  if (!trimmed) return false
  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return false
  }
  const keys = (parsed as { keys?: unknown }).keys
  if (!Array.isArray(keys)) return false
  return keys.some((k) => {
    if (!k || typeof k !== 'object') return false
    const jwk = k as Record<string, unknown>
    if (jwk.kty === 'oct') return true
    return PRIVATE_JWK_PARAMS.some((p) => jwk[p] !== undefined)
  })
}

/**
 * 静态 JWKS 客户端基本校验（与后端口径一致的核心规则；完整校验仍以服务端为准）。
 * 返回错误信息，合法返回 null。
 */
export function validateStaticJwks(text: string): string | null {
  const trimmed = text.trim()
  if (!trimmed) return '请粘贴公钥 JWKS JSON'
  if (
    new TextEncoder().encode(trimmed).length > JWT_TRUST_LIMITS.maxJWKSBytes
  ) {
    return `JWKS 大小不能超过 ${JWT_TRUST_LIMITS.maxJWKSBytes / 1024} KiB`
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return 'JWKS 不是合法 JSON'
  }
  const keys = (parsed as { keys?: unknown }).keys
  if (!Array.isArray(keys) || keys.length === 0)
    return 'JWKS 缺少 keys 公钥数组'
  if (keys.length > JWT_TRUST_LIMITS.maxJWKSKeys) {
    return `公钥数量不能超过 ${JWT_TRUST_LIMITS.maxJWKSKeys} 个`
  }
  const kids = new Set<string>()
  for (let i = 0; i < keys.length; i++) {
    const jwk = keys[i] as Record<string, unknown> | null
    if (!jwk || typeof jwk !== 'object') return `keys[${i}] 不是合法的 JWK 对象`
    if (jwk.kty === 'oct')
      return `keys[${i}] 为对称密钥（kty=oct），静态 JWKS 仅允许公钥`
    const priv = PRIVATE_JWK_PARAMS.find((p) => jwk[p] !== undefined)
    if (priv) return `keys[${i}] 含私钥参数 "${priv}"，静态 JWKS 仅允许公钥`
    if (jwk.kty !== 'RSA' && jwk.kty !== 'EC') {
      return `keys[${i}] 密钥类型须为 RSA 或 EC（实际: ${String(jwk.kty ?? '缺失')}）`
    }
    if (
      jwk.kty === 'RSA' &&
      (typeof jwk.n !== 'string' || typeof jwk.e !== 'string')
    ) {
      return `keys[${i}] RSA 公钥缺少 n/e 参数`
    }
    if (jwk.kty === 'EC' && jwk.crv !== 'P-256') {
      return `keys[${i}] EC 公钥仅支持 P-256 曲线`
    }
    if (typeof jwk.kid !== 'string' || jwk.kid.trim() === '') {
      return `keys[${i}] kid 必须为非空字符串`
    }
    if (kids.has(jwk.kid)) return `keys[${i}] kid 重复: ${jwk.kid}`
    kids.add(jwk.kid)
  }
  return null
}
