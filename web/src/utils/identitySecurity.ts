/* ==================== AI 自动化渗透防护 阶段1：风险身份 / 行为策略 展示元数据 ==================== */

/** 身份风险等级（与 server 端 security/identities 词表一致） */
export const RISK_LEVEL_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'green', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: 'magenta', label: '严重' },
}

/** 身份类型 */
export const IDENTITY_TYPE_META: Record<string, { color: string; label: string }> = {
  UNKNOWN: { color: 'default', label: '未知' },
  HUMAN: { color: 'green', label: '真人' },
  BOT: { color: 'volcano', label: '机器人' },
  APPLICATION: { color: 'geekblue', label: '应用程序' },
  SERVICE: { color: 'blue', label: '服务' },
  AGENT: { color: 'purple', label: '智能体' },
}

/** 行为检测信号（十种，与 server 端行为检测器词表一致） */
export const SIGNAL_META: Record<string, { color: string; label: string }> = {
  URI_ENUMERATION: { color: 'volcano', label: 'URI枚举' },
  NOT_FOUND_ENUMERATION: { color: 'orange', label: '404枚举' },
  SENSITIVE_PATH_PROBE: { color: 'magenta', label: '敏感路径探测' },
  METHOD_ENUMERATION: { color: 'gold', label: '方法枚举' },
  PARAMETER_MUTATION: { color: 'red', label: '参数变异' },
  AUTH_FAIL_PROBE: { color: 'purple', label: '认证探测' },
  LOW_SLOW_RECON: { color: 'cyan', label: '低慢侦察' },
  HEADLESS: { color: 'gold', label: '无头访问' },
  ACCOUNT_ENUMERATION: { color: 'orange', label: '账号枚举' },
  OBJECT_ENUMERATION: { color: 'volcano', label: '对象枚举' },
}

/* ==================== AI 自动化渗透防护 阶段4：攻击活动（Attack Session）展示元数据 ==================== */

/** 攻击阶段（八阶段，与 server 端 attack_session 词表一致，设计文档 #16.2；颜色按攻击链递进加深） */
export const ATTACK_STAGE_META: Record<string, { color: string; label: string }> = {
  RECON: { color: 'cyan', label: '侦察' },
  DISCOVERY: { color: 'blue', label: 'API发现' },
  AUTH_PROBE: { color: 'gold', label: '认证探测' },
  AUTHORIZATION_PROBE: { color: 'orange', label: '授权探测' },
  EXPLOIT: { color: 'volcano', label: '漏洞利用' },
  DATA_ACCESS: { color: 'red', label: '数据访问' },
  PERSISTENCE: { color: 'magenta', label: '持久化' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 攻击活动状态（OPEN 进行中 / CLOSED 已关闭） */
export const ATTACK_SESSION_STATUS_META: Record<string, { color: string; label: string }> = {
  OPEN: { color: 'processing', label: '进行中' },
  CLOSED: { color: 'default', label: '已关闭' },
}
