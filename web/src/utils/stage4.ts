/* ==================== 阶段4：WAF策略/规则/例外/安全事件 展示元数据与判定工具 ==================== */

/** 攻击类型展示元数据（与后端 normalize / sync 的攻击类型枚举一致） */
export const ATTACK_TYPE_META: Record<string, { color: string; label: string }> = {
  SQL_INJECTION: { color: 'red', label: 'SQL注入' },
  XSS: { color: 'volcano', label: 'XSS跨站脚本' },
  COMMAND_INJECTION: { color: 'magenta', label: '命令注入' },
  LOCAL_FILE_INCLUSION: { color: 'purple', label: '本地文件包含' },
  REMOTE_FILE_INCLUSION: { color: 'purple', label: '远程文件包含' },
  PHP_INJECTION: { color: 'geekblue', label: 'PHP注入' },
  JAVA_INJECTION: { color: 'geekblue', label: 'Java注入' },
  PROTOCOL_VIOLATION: { color: 'orange', label: '协议违规' },
  SESSION_FIXATION: { color: 'gold', label: '会话固定' },
  SCANNER_DETECTION: { color: 'cyan', label: '扫描器探测' },
  INFORMATION_DISCLOSURE: { color: 'blue', label: '信息泄露' },
  REMOTE_CODE_EXECUTION: { color: 'red', label: '远程代码执行' },
  SSRF: { color: 'volcano', label: 'SSRF' },
  XXE_INJECTION: { color: 'purple', label: 'XXE注入' },
  WEBSHELL: { color: 'red', label: 'WebShell' },
  FILE_UPLOAD: { color: 'magenta', label: '文件上传攻击' },
  DESERIALIZATION: { color: 'geekblue', label: '反序列化' },
  SSTI: { color: 'purple', label: '模板注入' },
  DOS: { color: 'orange', label: '拒绝服务' },
  MASS_ASSIGNMENT: { color: 'gold', label: '批量赋值' },
  EXCLUSION: { color: 'green', label: '应用白名单排除' },
  OTHER: { color: 'default', label: '其他' },
}

/** 安全事件严重级别（后端已映射为 HIGH/MEDIUM/LOW/INFO） */
export const EVENT_SEVERITY_META: Record<string, { color: string; label: string }> = {
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
  LOW: { color: 'blue', label: '低' },
  INFO: { color: 'default', label: '信息' },
}

/** CRS / 自定义规则严重级别（CRITICAL/ERROR/WARNING/NOTICE） */
export const RULE_SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: '#7f1d1d', label: '严重' },
  ERROR: { color: 'red', label: '高' },
  WARNING: { color: 'orange', label: '中' },
  NOTICE: { color: 'blue', label: '低' },
}

/** 事件动作：OBSERVE 蓝 / BLOCK 红 */
export const EVENT_ACTION_META: Record<string, { color: string; label: string }> = {
  OBSERVE: { color: 'blue', label: '观察' },
  BLOCK: { color: 'red', label: '阻断' },
}

/** 自定义规则动作：LOG 蓝 / OBSERVE 橙 / BLOCK 红 */
export const CUSTOM_RULE_ACTION_META: Record<string, { color: string; label: string }> = {
  LOG: { color: 'blue', label: '仅记录' },
  OBSERVE: { color: 'orange', label: '观察' },
  BLOCK: { color: 'red', label: '阻断' },
}

/** 事件处置状态 */
export const DISPOSITION_STATUS_META: Record<string, { color: string; label: string }> = {
  UNPROCESSED: { color: 'default', label: '未处置' },
  ANALYZING: { color: 'processing', label: '分析中' },
  CONFIRMED_ATTACK: { color: 'red', label: '确认攻击' },
  CONFIRMED_FALSE_POSITIVE: { color: 'orange', label: '确认误报' },
  IGNORED: { color: 'default', label: '已忽略' },
  RESOLVED: { color: 'green', label: '已处置' },
}

/** 例外策略动作（P0-04：LOG_ONLY/ADJUST_SCORE 为历史动作，不支持新启用；OBSERVE_RULE 仅 API 引擎） */
export const EXCEPTION_ACTION_META: Record<string, { color: string; label: string }> = {
  REMOVE_RULE: { color: 'red', label: '移除指定规则' },
  REMOVE_RULE_TAG: { color: 'volcano', label: '移除规则标签' },
  REMOVE_VAR_DETECTION: { color: 'orange', label: '移除变量检测' },
  ADJUST_SCORE: { color: 'gold', label: '调整异常评分' },
  LOG_ONLY: { color: 'blue', label: '仅记录不阻断' },
  OBSERVE_RULE: { color: 'purple', label: 'API 规则仅观察' },
}

/** 例外策略状态 */
export const EXCEPTION_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'default', label: '草稿' },
  ENABLED: { color: 'green', label: '已启用' },
  DISABLED: { color: 'default', label: '已停用' },
  EXPIRED: { color: 'orange', label: '已过期' },
}

/** 例外范围类型 */
export const EXCEPTION_SCOPE_META: Record<string, { color: string; label: string }> = {
  GLOBAL: { color: 'purple', label: '全局' },
  APPLICATION: { color: 'blue', label: '应用' },
  POLICY: { color: 'geekblue', label: '策略' },
}

/** 通用启停状态（自定义规则等） */
export const ENABLE_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '已启用' },
  DISABLED: { color: 'default', label: '已停用' },
}

/** 规则默认状态 */
export const RULE_DEFAULT_STATE_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '默认启用' },
  DISABLED: { color: 'default', label: '默认停用' },
}

/** 规则来源 */
export const RULE_SOURCE_META: Record<string, { color: string; label: string }> = {
  OWASP_CRS: { color: 'blue', label: 'OWASP 核心规则集' },
  CUSTOM_PACK: { color: 'cyan', label: '扩展规则包' },
  USER_CUSTOM: { color: 'purple', label: '用户自定义' },
  CRS_PLUGIN: { color: 'geekblue', label: 'CRS 插件' },
  THIRD_PARTY: { color: 'orange', label: '第三方规则' },
  JIUZHANG_BUILTIN: { color: 'green', label: '九章内置规则' },
}

/** 攻击类型下拉选项（纯中文标签，提交值仍为后端枚举） */
export const ATTACK_TYPE_OPTIONS = Object.entries(ATTACK_TYPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/**
 * 解析 WAF 规则的 tags 字段。
 * 后端将 jsonb 以 []byte 放入 map 序列化，实际返回 base64 编码的 JSON 字符串
 * （如 "WyJPV0FTUF9DUlMiXQ==" → ["OWASP_CRS"]）；同时兼容已修复后的数组返回。
 */
export function parseWafRuleTags(tags: unknown): string[] {
  if (tags === null || tags === undefined || tags === '') return []
  if (Array.isArray(tags)) return tags.filter((t): t is string => typeof t === 'string')
  if (typeof tags !== 'string') return []
  // 优先按 base64 → JSON 数组解码（后端当前行为）
  try {
    const decoded = atob(tags)
    const parsed: unknown = JSON.parse(decoded)
    if (Array.isArray(parsed)) return parsed.filter((t): t is string => typeof t === 'string')
  } catch {
    // 非 base64 或非 JSON，继续按普通字符串处理
  }
  // 兼容直接返回 JSON 字符串的情况
  try {
    const parsed: unknown = JSON.parse(tags)
    if (Array.isArray(parsed)) return parsed.filter((t): t is string => typeof t === 'string')
  } catch {
    // 非 JSON 字符串
  }
  return [tags]
}

/** 宽泛例外判定输入（与后端 exceptions.IsBroad 逻辑保持一致，用于表单实时风险提示） */
export interface BroadExceptionCheckInput {
  scope_type?: string
  application_id?: string | null
  domain?: string
  uri_exact?: string
  uri_prefix?: string
  source_ips?: string[]
  param_names?: string[]
  cookie_names?: string[]
  header_names?: string[]
  rule_ids?: number[]
  rule_tags?: string[]
  attack_types?: string[]
}

/** 后端判定为宽泛例外（高风险）的攻击类型 */
const BROAD_ATTACK_TYPES = ['SQL_INJECTION', 'XSS', 'COMMAND_INJECTION']

/**
 * 宽泛例外判定（镜像后端 exceptions.IsBroad）：
 * 有具体限定条件（域名/URI/参数/规则ID/来源IP/Cookie/请求头）则不算宽泛；
 * 否则命中以下任一条件即为宽泛：针对 SQLi/XSS/CMDi 攻击类型、全局范围、
 * 或无应用限定且规则标签含 SQLI/XSS。
 */
export function isBroadExceptionDraft(v: BroadExceptionCheckInput): boolean {
  const hasSpecific =
    !!v.domain ||
    !!v.uri_exact ||
    !!v.uri_prefix ||
    (v.param_names?.length ?? 0) > 0 ||
    (v.rule_ids?.length ?? 0) > 0 ||
    (v.source_ips?.length ?? 0) > 0 ||
    (v.cookie_names?.length ?? 0) > 0 ||
    (v.header_names?.length ?? 0) > 0
  if (hasSpecific) return false
  if ((v.attack_types ?? []).some((t) => BROAD_ATTACK_TYPES.includes(t))) return true
  if (v.scope_type === 'GLOBAL') return true
  if ((v.rule_tags?.length ?? 0) > 0 && !v.application_id) {
    return (v.rule_tags ?? []).some((t) => {
      const upper = t.toUpperCase()
      return upper.includes('SQLI') || upper.includes('XSS')
    })
  }
  return false
}
