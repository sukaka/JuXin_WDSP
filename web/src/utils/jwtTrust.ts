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

/** JWT 验证原因码（result.go ReasonCode，16 项固定枚举） */
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
      return [base, idx, sub]
    case 'key_source.jwks':
      return [base, idx, 'jwks']
    case 'key_source.url':
      return [base, idx, 'url']
    case 'key_source.type':
      return [base, idx, 'key_source_type']
    default:
      return null
  }
}
