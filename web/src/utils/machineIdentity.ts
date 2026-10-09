/* ==================== NG-ID G1：机器身份词表与纯函数（docs/nextgen/NG-ID-g1-machine-identity.md） ==================== */

/** 键状态机（§1.2：ACTIVE 可签发可验证 / RETIRED 重叠窗口内仅验证（不得用于新签名）/ REVOKED 立即拒验） */
export const KEY_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: 'ACTIVE（可签发可验证）' },
  RETIRED: { color: 'gold', label: 'RETIRED（窗口内仅验证）' },
  REVOKED: { color: 'red', label: 'REVOKED（立即拒验）' },
}

/** 身份启停（DISABLED 不下发不参与验证） */
export const IDENTITY_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '启用' },
  DISABLED: { color: 'default', label: '停用' },
}

/** 算法词表（§1.2：hmac-sha256 共享密钥形态排除；rsa-v1_5-sha256 RFC 9421 不推荐排除） */
export const KEY_ALG_META: Record<string, { label: string }> = {
  ed25519: { label: 'ed25519' },
  'ecdsa-p256-sha256': { label: 'ecdsa-p256-sha256' },
  'rsa-pss-sha512': { label: 'rsa-pss-sha512' },
}

/** 绑定模式（OBSERVE 只记录 / PROTECT 验签失败与违规模态协议化执行 401） */
export const MACHINE_IDENTITY_MODE_META: Record<string, { color: string; label: string }> = {
  OBSERVE: { color: 'default', label: '观测（OBSERVE）' },
  PROTECT: { color: 'red', label: '实断（PROTECT）' },
}

/** 覆盖范围提示（设计 §3 口径：可选叠加缺省 OFF；RFC 9421 首期；DPoP/stdio 未覆盖——不冒充已保护） */
export const MACHINE_IDENTITY_COVERAGE_NOTE =
  '机器身份为可选叠加能力（缺省 OFF，绑定驱动识别——空绑定=零行为）；首期支持 HTTP Message Signatures（RFC 9421）；DPoP（RFC 9449）与 stdio/本地场景未覆盖。'

/** bot_challenge_exempt 三重豁免语义（§1.7：三重显式，未豁免的 VERIFIED 机器照走挑战） */
export const BOT_EXEMPT_NOTE =
  'Bot 精确豁免成立当且仅当：①身份行 bot_challenge_exempt=true 且 ②当前请求命中该身份的绑定 selector 且 ③签名验证链全步通过——豁免事实进事件（MID-BOT-EXEMPT）；未豁免的 VERIFIED 机器照走 Bot 挑战。'

/** 撤销高危警示（§1.6/D6：水位单调不下降——普通策略回滚不复活已撤销密钥） */
export const REVOKE_WARNING =
  '撤销即拒验且不可经回滚复活：撤销事实与撤销水位 seq+1 同事务原子提交，水位单调不下降——发布快照水位低于网关已应用水位将拒载（fail-closed），普通策略回滚不复活已撤销密钥。'

/** 轮换重叠窗口说明（§1.6：缺省 24h，上限 168h；窗口内新旧两键均可验证，窗口外旧键拒验） */
export const ROTATE_OVERLAP_NOTE =
  '重叠窗口内新旧两键均可验证（旧键事件标注 RETIRED 事实，不得用于新签名），窗口外旧键拒验（MID-KEY-RETIRED-EXPIRED）；窗口时长缺省 24 小时、上限 168 小时。'

/** 接入契约摘要（§1.14 冻结：sig1/必含成分/nonce/窗口 ≤120s/Content-Digest sha-256 优先） */
export const MACHINE_IDENTITY_ONBOARDING_NOTE =
  '客户端签名约定（RFC 9421/9530/8941）：签名标签恒 sig1（恰一个）；必含成分 @method、@authority、@path、created、expires、nonce、keyid（请求有 query 必含 @query，有 body 必含 content-digest）；nonce 取密码学随机 16~32 字节 base64；created/expires 为 Unix 秒且窗口 ≤120 秒；Content-Digest 头按 RFC 9530（sha-256 优先）；验签失败为 401 固定短语。'

/** 指纹短显（sha256 前 16 hex 原文已短——直接展示，长值截断兜底） */
export function shortFingerprint(value?: string | null): string {
  if (!value) return '—'
  return value.length > 18 ? `${value.slice(0, 16)}…` : value
}

/** PEM 文本域形态校验（恰一个 PUBLIC KEY 块；算法-键型一致性核对在服务端（不符 400）） */
export function validatePemText(text: string): string | undefined {
  const raw = (text ?? '').trim()
  if (raw === '') return '公钥 PEM 必填'
  if (raw.length > 8192) return 'PEM 不超过 8192 字符'
  const blocks = raw.match(/-----BEGIN [A-Z ]*PUBLIC KEY-----[\s\S]*?-----END [A-Z ]*PUBLIC KEY-----/g)
  if (!blocks || blocks.length !== 1) return 'PEM 形态非法（须含恰一个 PUBLIC KEY 块：PKIX PUBLIC KEY 或 RSA PUBLIC KEY）'
  return undefined
}

/** 绑定路径二选一校验（path_exact|path_prefix 恰一个；/ 开头 ≤512 不含 query/fragment） */
export function validateBindingPath(kind: string, path: string): string | undefined {
  if (kind !== 'path_exact' && kind !== 'path_prefix') return '请选择路径形态（精确/前缀二选一）'
  const p = (path ?? '').trim()
  if (!p.startsWith('/')) return '路径须为 / 开头'
  if (p.length > 512) return '路径不超过 512 字符'
  if (/[?#]/.test(p)) return '路径不含 query/fragment'
  return undefined
}
