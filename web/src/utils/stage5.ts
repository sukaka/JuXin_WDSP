/* ==================== 阶段5：访问控制 展示元数据与地址格式校验工具 ==================== */

/** 可信代理头类型 */
export const TRUSTED_PROXY_HEADER_TYPE_META: Record<string, { color: string; label: string }> = {
  X_FORWARDED_FOR: { color: 'blue', label: 'X-Forwarded-For 头' },
  X_REAL_IP: { color: 'geekblue', label: 'X-Real-IP 头' },
  FORWARDED: { color: 'purple', label: 'Forwarded 头' },
  CUSTOM: { color: 'orange', label: '自定义头' },
}

/** 可信代理生效范围 */
export const TRUSTED_PROXY_SCOPE_META: Record<string, { color: string; label: string }> = {
  GLOBAL: { color: 'purple', label: '全局' },
  NODE: { color: 'blue', label: '指定节点' },
}

/** 客户端 IP 识别来源（access_logs.client_ip_source，统计分析分布展示用） */
export const CLIENT_IP_SOURCE_META: Record<string, { color: string; label: string }> = {
  CONNECTION: { color: 'blue', label: '直连连接' },
  X_FORWARDED_FOR: { color: 'geekblue', label: 'X-Forwarded-For' },
  X_REAL_IP: { color: 'cyan', label: 'X-Real-IP' },
  FORWARDED: { color: 'purple', label: 'Forwarded' },
  CUSTOM_HEADER: { color: 'orange', label: '自定义头' },
}

/** IP 版本 */
export const IP_VERSION_META: Record<string, { color: string; label: string }> = {
  IPV4: { color: 'blue', label: 'IPv4' },
  IPV6: { color: 'purple', label: 'IPv6' },
}

/** 保护地址类型 */
export const PROTECTED_ADDRESS_TYPE_META: Record<string, { color: string; label: string }> = {
  GATEWAY: { color: 'geekblue', label: '网关地址' },
  MANAGEMENT: { color: 'blue', label: '管理面地址' },
  UPSTREAM: { color: 'cyan', label: '源站地址' },
  DATABASE: { color: 'purple', label: '数据库地址' },
  CACHE: { color: 'purple', label: '缓存地址' },
  TRUSTED_PROXY: { color: 'blue', label: '可信代理' },
  LOOPBACK: { color: 'default', label: '回环地址' },
  LINK_LOCAL: { color: 'default', label: '链路本地' },
  CUSTOM: { color: 'orange', label: '自定义' },
}

/** 保护地址来源 */
export const PROTECTED_ADDRESS_SOURCE_META: Record<string, { color: string; label: string }> = {
  SYSTEM: { color: 'blue', label: '系统登记' },
  MANUAL: { color: 'orange', label: '手工添加' },
}

/** IP 黑白名单规则类型：ALLOW 绿 / DENY 红 */
export const ACCESS_RULE_TYPE_META: Record<string, { color: string; label: string }> = {
  ALLOW: { color: 'green', label: '白名单' },
  DENY: { color: 'red', label: '黑名单' },
}

/** IP 黑白名单生效范围 */
export const ACCESS_RULE_SCOPE_META: Record<string, { color: string; label: string }> = {
  GLOBAL: { color: 'purple', label: '全局' },
  APPLICATION: { color: 'blue', label: '指定应用' },
}

/** IP 黑白名单状态 */
export const ACCESS_RULE_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'default', label: '草稿' },
  ACTIVE: { color: 'green', label: '生效中' },
  DISABLED: { color: 'default', label: '已停用' },
  EXPIRED: { color: 'orange', label: '已过期' },
  DELETED: { color: 'default', label: '已删除' },
}

/** IP 黑白名单有效期类型 */
export const ACCESS_RULE_VALIDITY_META: Record<string, { color: string; label: string }> = {
  PERMANENT: { color: 'blue', label: '永久' },
  TEMPORARY: { color: 'gold', label: '临时' },
}

/** IP 黑白名单来源 */
export const ACCESS_RULE_SOURCE_META: Record<string, { color: string; label: string }> = {
  MANUAL: { color: 'blue', label: '手工创建' },
  SECURITY_EVENT: { color: 'volcano', label: '安全事件' },
  IMPORT: { color: 'cyan', label: '批量导入' },
  AUTO_BLOCK: { color: 'red', label: '自动封禁' },
  SYSTEM: { color: 'default', label: '系统内置' },
}

/** CC 策略作用范围 */
export const RATE_LIMIT_SCOPE_META: Record<string, { color: string; label: string }> = {
  GLOBAL: { color: 'purple', label: '全局' },
  APPLICATION: { color: 'blue', label: '指定应用' },
  URI: { color: 'geekblue', label: '应用+路径' },
}

/** CC 策略统计维度 */
export const RATE_LIMIT_DIMENSION_META: Record<string, { color: string; label: string }> = {
  CLIENT_IP: { color: 'blue', label: '客户端IP' },
  APPLICATION: { color: 'purple', label: '应用（共享计数）' },
  CLIENT_IP_AND_URI: { color: 'geekblue', label: '客户端 IP+路径' },
  CLIENT_IP_AND_APPLICATION: { color: 'cyan', label: '客户端IP+应用' },
}

/** CC 策略限速算法 */
export const RATE_LIMIT_ALGORITHM_META: Record<string, { color: string; label: string }> = {
  TOKEN_BUCKET: { color: 'blue', label: '令牌桶' },
  SLIDING_WINDOW: { color: 'purple', label: '滑动窗口' },
}

/** CC 策略触发动作 */
export const RATE_LIMIT_ACTION_META: Record<string, { color: string; label: string }> = {
  LOG: { color: 'blue', label: '仅记录' },
  OBSERVE: { color: 'orange', label: '观察' },
  REJECT: { color: 'red', label: '拒绝(429)' },
  TEMP_BLOCK: { color: 'magenta', label: '临时封禁' },
}

/** CC 策略 URI 匹配方式 */
export const RATE_LIMIT_URI_MATCH_META: Record<string, { color: string; label: string }> = {
  ALL: { color: 'default', label: '全部路径' },
  EXACT: { color: 'blue', label: '精确匹配' },
  PREFIX: { color: 'geekblue', label: '前缀匹配' },
  REGEX: { color: 'orange', label: '正则匹配' },
}

/** CC 策略状态 */
export const RATE_LIMIT_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '生效中' },
  DISABLED: { color: 'default', label: '已停用' },
}

/** 临时封禁状态 */
export const TEMP_BLOCK_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'red', label: '封禁中' },
  EXPIRED: { color: 'orange', label: '已过期' },
  MANUALLY_RELEASED: { color: 'green', label: '已人工解封' },
  CANCELLED: { color: 'default', label: '已取消' },
}

/** 临时封禁触发类型 */
export const TEMP_BLOCK_TRIGGER_META: Record<string, { color: string; label: string }> = {
  CC_AUTO: { color: 'red', label: '频率防护自动触发' },
  MANUAL: { color: 'blue', label: '人工添加' },
}

/** 临时封禁解除方式 */
export const TEMP_BLOCK_RELEASE_TYPE_META: Record<string, { color: string; label: string }> = {
  AUTO_EXPIRE: { color: 'orange', label: '到期自动解除' },
  MANUAL: { color: 'green', label: '人工解封' },
  CONVERTED: { color: 'purple', label: '已转永久' },
}

/** URL 白名单匹配方式 */
export const URL_WHITELIST_MATCH_META: Record<string, { color: string; label: string }> = {
  EXACT: { color: 'blue', label: '精确匹配' },
  PREFIX: { color: 'geekblue', label: '前缀匹配' },
  REGEX: { color: 'orange', label: '正则匹配' },
}

/** 访问控制事件类型 */
export const AC_EVENT_TYPE_META: Record<string, { color: string; label: string }> = {
  IP_ALLOW_MATCH: { color: 'green', label: '命中 IP 白名单' },
  URL_ALLOW_MATCH: { color: 'green', label: '命中 URL 白名单' },
  IP_DENY_MATCH: { color: 'red', label: '命中 IP 黑名单' },
  CC_THRESHOLD_EXCEEDED: { color: 'orange', label: '频率超阈值' },
  CC_REQUEST_REJECTED: { color: 'red', label: '频率请求被拒绝' },
  CC_TEMP_BLOCK_CREATED: { color: 'magenta', label: '频率临时封禁创建' },
  CC_TEMP_BLOCK_EXPIRED: { color: 'default', label: '频率临时封禁到期' },
  CC_TEMP_BLOCK_RELEASED: { color: 'green', label: '频率临时封禁解除' },
  CC_TEMP_BLOCK_DOWNGRADED: { color: 'gold', label: '频率临时封禁降级' },
  TRUSTED_PROXY_INVALID: { color: 'volcano', label: '可信代理无效' },
  FORWARDED_HEADER_INVALID: { color: 'volcano', label: '转发头无效' },
  FORWARDED_CHAIN_TOO_LONG: { color: 'orange', label: '转发链过长' },
  RATE_LIMIT_ENGINE_ERROR: { color: 'red', label: '限速引擎错误' },
  L7_RULE_ALLOW: { color: 'green', label: 'L7规则放行' },
  L7_RULE_BLOCK: { color: 'red', label: 'L7规则阻断' },
  L7_RULE_REDIRECT: { color: 'blue', label: 'L7规则重定向' },
  L7_RULE_CUSTOM: { color: 'purple', label: 'L7自定义页面' },
  IDENTITY_MANUAL_BLOCK: { color: 'red', label: '身份手工封禁' },
  RISK_POLICY_BLOCK: { color: 'red', label: '风险策略阻断' },
  RISK_POLICY_RATE_LIMIT: { color: 'orange', label: '风险策略限速' },
  RISK_POLICY_CHALLENGE: { color: 'gold', label: '风险策略挑战' },
  JWT_OBSERVED: { color: 'blue', label: 'JWT 校验观察' },
  JWT_AUTH_FAILED: { color: 'red', label: 'JWT 认证失败' },
  JWT_UNAVAILABLE: { color: 'volcano', label: 'JWT 服务不可用' },
  BOT_CHALLENGE_OFFERED: { color: 'gold', label: 'Bot 挑战下发' },
  BOT_VERIFY_SUCCESS: { color: 'green', label: 'Bot 挑战验证通过' },
  BOT_VERIFY_REJECTED: { color: 'red', label: 'Bot 挑战验证拒绝' },
  BOT_CHALLENGE_EXPIRED: { color: 'orange', label: 'Bot 挑战已过期' },
  BOT_STATE_UNAVAILABLE: { color: 'volcano', label: 'Bot 状态存储不可用' },
  BOT_CLEARANCE_ACCEPTED: { color: 'cyan', label: 'Bot 通行凭据有效' },
  MID_VERIFIED: { color: 'green', label: '机器身份验签通过' },
  MID_OBSERVED: { color: 'blue', label: '机器身份观察' },
  MID_AUTH_FAILED: { color: 'red', label: '机器身份认证失败' },
  MID_UNAVAILABLE: { color: 'volcano', label: '机器身份服务不可用' },
  MID_SCOPE_DENIED: { color: 'red', label: '机器身份越权拒绝' },
  MID_BOT_EXEMPT: { color: 'cyan', label: '机器身份豁免 Bot 挑战' },
}

/** 访问控制事件动作 */
export const AC_EVENT_ACTION_META: Record<string, { color: string; label: string }> = {
  ALLOW: { color: 'green', label: '放行' },
  BLOCK: { color: 'red', label: '阻断' },
  LOG: { color: 'blue', label: '仅记录' },
  OBSERVE: { color: 'orange', label: '观察' },
  REDIRECT: { color: 'blue', label: '重定向' },
  CUSTOM_PAGE: { color: 'purple', label: '自定义页面' },
  REJECT: { color: 'red', label: '拒绝' },
  CHALLENGE: { color: 'gold', label: '挑战' },
  TEMP_BLOCK: { color: 'magenta', label: '临时封禁' },
  PASS: { color: 'green', label: '放行' },
  blocked: { color: 'red', label: '已阻断' },
  would_block: { color: 'orange', label: '拟阻断（观察）' },
  challenged: { color: 'gold', label: '已挑战' },
  would_challenge: { color: 'blue', label: '拟挑战（观察）' },
  rate_limited: { color: 'volcano', label: '已限速' },
  would_rate_limit: { color: 'orange', label: '拟限速（观察）' },
}

/** 自定义代理头名规则（与后端 customHeaderRe 一致：字母、数字、点、下划线、连字符） */
export const CUSTOM_HEADER_NAME_PATTERN = /^[A-Za-z0-9._-]+$/

/* ==================== 地址格式校验（镜像后端 netip 严格解析语义） ==================== */

/** 是否含 ASCII 控制字符（与后端校验一致：c < 0x20 或 0x7f） */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 || c === 0x7f) return true
  }
  return false
}

/**
 * 严格 IPv4 字面量校验（镜像 Go netip.ParseAddr）：
 * 四段十进制 0-255，不允许前导零（如 01.2.3.4 视为非法）。
 */
export function isValidIPv4(s: string): boolean {
  const parts = s.split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => {
    if (p === '' || p.length > 3) return false
    if (!/^\d+$/.test(p)) return false
    if (p.length > 1 && p[0] === '0') return false
    return Number(p) <= 255
  })
}

/**
 * 严格 IPv6 字面量校验（镜像 Go netip.ParseAddr 的常用形态）：
 * 支持 "::" 压缩（至多一处）、内嵌 IPv4（仅允许在末尾），拒绝带区域（%zone）地址。
 */
export function isValidIPv6(s: string): boolean {
  if (s === '' || s.includes('%')) return false
  const dbl = s.split('::')
  if (dbl.length > 2) return false
  const head = dbl[0] === '' ? [] : dbl[0].split(':')
  const tail = dbl.length === 2 ? (dbl[1] === '' ? [] : dbl[1].split(':')) : []
  const groups = [...head, ...tail]
  let v4Groups = 0
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i]
    if (g.includes('.')) {
      // 内嵌 IPv4 仅允许作为最后一段，且按 2 个 16 位组计数
      if (i !== groups.length - 1 || !isValidIPv4(g)) return false
      v4Groups += 1
    } else if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
      return false
    }
  }
  const count = groups.length + v4Groups
  // 无 "::" 必须满 8 组；有 "::" 时 "::" 至少压缩一个全零组
  return dbl.length === 2 ? count < 8 : count === 8
}

/** 判断是否为合法 IP 字面量（仅单 IP，不含 CIDR），镜像后端 isValidIPLiteral */
export function isValidIPLiteral(s: string): boolean {
  const v = s.trim()
  return isValidIPv4(v) || isValidIPv6(v)
}

/**
 * 校验「单 IP 或 CIDR」地址（镜像后端 accessrules.NormalizeAddress / trustedproxies.NormalizeCIDR）。
 * 禁止：域名、协议前缀（http://）、端口、通配符、带区域地址与控制字符。
 * 返回 null 表示合法，否则返回错误信息（用于表单校验）。
 */
export function validateIPOrCIDR(raw: string): string | null {
  const s = raw.trim()
  if (s === '') return '地址不能为空'
  if (s.length > 64) return '地址长度不能超过 64 字符'
  if (hasControlChar(s)) return '地址包含非法控制字符'
  if (s.includes('://')) return '不允许包含协议前缀（如 http://）'
  if (s.includes('*')) return '不支持通配符地址'
  if (s.includes('/')) {
    const parts = s.split('/')
    if (parts.length !== 2 || parts[0] === '' || parts[1] === '') return `无效的CIDR地址：${s}`
    const [addr, bits] = parts
    if (!/^\d+$/.test(bits) || (bits.length > 1 && bits[0] === '0')) return `无效的CIDR地址：${s}`
    const n = Number(bits)
    if (isValidIPv4(addr)) return n <= 32 ? null : `无效的CIDR地址：${s}（IPv4 前缀 0-32）`
    if (isValidIPv6(addr)) return n <= 128 ? null : `无效的CIDR地址：${s}（IPv6 前缀 0-128）`
    return `无效的CIDR地址：${s}`
  }
  if (isValidIPLiteral(s)) return null
  return `无效的IP地址：${s}（仅支持单 IP 或 CIDR，禁止域名/端口/协议）`
}

/** 判断地址是否为 CIDR（含 "/" 前缀长度），用于区分单 IP 与网段 */
export function isCIDRAddress(raw: string): boolean {
  return validateIPOrCIDR(raw) === null && raw.trim().includes('/')
}
