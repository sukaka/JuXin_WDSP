/**
 * JWT 信任链（WDSP P0-03）状态中文映射（配色对齐 utils/stage3 PROTECTION_MODE_META：
 * OFF 灰 / OBSERVE 蓝 / PROTECT 绿）。
 */

/** 策略模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制验证 */
export const JWT_TRUST_MODE_META: Record<
  string,
  { color: string; label: string }
> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制验证' },
}

/** 状态摘要：草稿 vs 已发布生效版本（server/internal/jwttrust StatusSummary） */
export const JWT_TRUST_STATE_META: Record<
  string,
  { color: string; label: string }
> = {
  NOT_CONFIGURED: { color: 'default', label: '未配置' },
  DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
  PUBLISHED: { color: 'green', label: '已发布' },
}

/** 预检单项状态 */
export const JWT_TRUST_CHECK_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  PASS: { color: 'success', label: '通过' },
  FAIL: { color: 'error', label: '未通过' },
  WARN: { color: 'warning', label: '警告' },
  SKIP: { color: 'default', label: '跳过' },
}

/** 预检检查项名称 */
export const JWT_TRUST_CHECK_NAME_LABELS: Record<string, string> = {
  structure: '结构与公钥',
  remote_url_ssrf: '远程地址 SSRF',
  remote_connectivity: '远程连通性（管理端）',
  pipeline_gate: 'API 管线门禁',
  node_capability: '节点状态与能力',
}

/**
 * JWT 验证状态（server/internal/jwttrust/result.go VerificationStatus）。
 * 注意：UNVERIFIED 表示策略关闭或不在校验范围（不可信也非非法），不得渲染为「非法用户」。
 */
export const JWT_VERIFICATION_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  VERIFIED: { color: 'green', label: '验证通过' },
  INVALID: { color: 'red', label: '验证不通过' },
  UNAVAILABLE: { color: 'orange', label: '验证不可用' },
  NOT_PRESENT: { color: 'default', label: '未携带 Token' },
  UNVERIFIED: { color: 'blue', label: '未验证' },
}

/** 令牌持有证明绑定模式（RFC 9449 DPoP / RFC 8705 mTLS） */
export const JWT_TOKEN_BINDING_MODE_META: Record<
  string,
  { color: string; label: string; description: string }
> = {
  NONE: {
    color: 'default',
    label: '关闭（仅 Bearer JWT）',
    description: '不要求持有证明绑定，保持传统 Bearer 令牌校验行为',
  },
  DPOP_OPTIONAL: {
    color: 'blue',
    label: 'DPoP 可选（兼容模式）',
    description: '携带 DPoP 证明或 cnf.jkt 时执行校验，兼容存量 Bearer 客户端',
  },
  DPOP_REQUIRED: {
    color: 'purple',
    label: '强制 DPoP（RFC 9449）',
    description: '要求携带有效 DPoP 证明且公钥指纹与 Token cnf.jkt 一致',
  },
  MTLS_REQUIRED: {
    color: 'cyan',
    label: '强制 mTLS 证书绑定（RFC 8705）',
    description: '要求经校验的客户端 TLS 证书指纹与 Token cnf.x5t#S256 一致',
  },
  DPOP_OR_MTLS: {
    color: 'geekblue',
    label: '强制 DPoP 或 mTLS 绑定',
    description: '要求满足 DPoP 证明或 mTLS 客户端证书绑定中的至少一种',
  },
}

/** DPoP 证明签名算法选项（RFC 9449，排除 none 与对称 HS*） */
export const JWT_DPOP_ALG_OPTIONS = [
  { value: 'ES256', label: 'ES256' },
  { value: 'RS256', label: 'RS256' },
  { value: 'EdDSA', label: 'EdDSA' },
]

export function isDPoPBindingMode(mode?: string): boolean {
  return (
    mode === 'DPOP_OPTIONAL' ||
    mode === 'DPOP_REQUIRED' ||
    mode === 'DPOP_OR_MTLS'
  )
}

export function isMTLSBindingMode(mode?: string): boolean {
  return mode === 'MTLS_REQUIRED' || mode === 'DPOP_OR_MTLS'
}

/** JWT 验证原因码（result.go ReasonCode + Phase 9A-1 DPoP/mTLS 原因码） */
export const JWT_REASON_CODE_LABELS: Record<string, string> = {
  POLICY_OFF: '策略关闭',
  OUT_OF_SCOPE: '校验范围外',
  MISSING_TOKEN: '缺少必需 Token',
  MALFORMED_TOKEN: 'Token 格式错误',
  ALGORITHM_REJECTED: '算法不被允许',
  UNKNOWN_ISSUER: '未知发行方',
  UNKNOWN_KID: '未知密钥标识',
  SIGNATURE_INVALID: '签名无效',
  ISSUER_MISMATCH: '发行方不匹配',
  AUDIENCE_MISMATCH: '受众不匹配',
  EXPIRED: 'Token 已过期',
  NOT_YET_VALID: 'Token 尚未生效',
  CLAIM_INVALID: '声明不合法',
  KEYSET_UNAVAILABLE: '密钥集不可用',
  VERIFIER_ERROR: '验证器内部错误',
  VALID: '验证通过',
  DPOP_MISSING: '缺少 DPoP 证明头',
  DPOP_MALFORMED: 'DPoP 证明格式错误',
  DPOP_ALGORITHM_REJECTED: 'DPoP 算法不被允许',
  DPOP_SIGNATURE_INVALID: 'DPoP 证明签名无效',
  DPOP_JKT_MISMATCH: 'DPoP 公钥指纹与 Token 不匹配',
  DPOP_HTM_MISMATCH: 'DPoP 请求方法（htm）不匹配',
  DPOP_HTU_MISMATCH: 'DPoP 请求地址（htu）不匹配',
  DPOP_ATH_MISMATCH: 'DPoP 令牌摘要（ath）不匹配',
  DPOP_EXPIRED: 'DPoP 证明已过期',
  DPOP_REPLAY: '检测到 DPoP 证明重放',
  DPOP_NONCE_REQUIRED: '需要 DPoP-Nonce 挑战',
  DPOP_REPLAY_UNAVAILABLE: 'DPoP 防重放存储不可用',
  MTLS_CLIENT_CERT_MISSING: '缺少已验链的客户端 TLS 证书',
  MTLS_CERT_MISMATCH: '客户端证书指纹与 Token 不匹配',
  TOKEN_BINDING_MISSING: '缺少必需的令牌持有证明绑定',
}

/** UNVERIFIED 补充说明（防止误读为「非法用户」） */
export const JWT_UNVERIFIED_HINT =
  '未验证表示策略关闭或请求不在校验范围，不代表用户非法'

/** 后端字段级错误路径 → 表单字段路径（selectors[0].path_exact → ['selectors',0,'path'] 等） */
export function mapJwtTrustFieldErrorPath(
  field: string,
): (string | number)[] | null {
  if (field === 'mode' || field === 'reason') return [field]
  const m = /^(selectors|issuers)\[(\d+)\](?:\.(.+))?$/.exec(field)
  if (!m) return null
  const base = m[1] as 'selectors' | 'issuers'
  const idx = Number(m[2])
  const sub = m[3]
  if (!sub) return [base, idx]
  if (base === 'selectors') {
    if (sub === 'path_exact' || sub === 'path_prefix')
      return [base, idx, 'path']
    if (sub === 'methods' || sub === 'token_required') return [base, idx, sub]
    return null
  }
  // issuers 子字段
  switch (sub) {
    case 'issuer':
    case 'audiences':
    case 'algorithms':
    case 'clock_skew_seconds':
    case 'tenant_claim':
    case 'role_claims':
      return [base, idx, sub]
    case 'key_source.jwks':
      return [base, idx, 'jwks']
    case 'key_source.url':
      return [base, idx, 'url']
    case 'key_source.type':
      return [base, idx, 'key_source_type']
    case 'token_binding':
    case 'token_binding.mode':
      return [base, idx, 'token_binding_mode']
    case 'token_binding.require_nonce':
      return [base, idx, 'dpop_require_nonce']
    case 'token_binding.max_proof_age_seconds':
      return [base, idx, 'dpop_max_proof_age_seconds']
    case 'token_binding.nonce_ttl_seconds':
      return [base, idx, 'dpop_nonce_ttl_seconds']
    case 'token_binding.allowed_dpop_algs':
      return [base, idx, 'dpop_allowed_algs']
    default:
      return null
  }
}
