/**
 * AI 爬虫治理与 Web Bot Auth（WDSP Phase 9A-2）中文枚举映射与表单错误路径映射。
 */

/** 策略模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制执行 */
export const AI_CRAWL_MODE_META: Record<
  string,
  { color: string; label: string }
> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制执行' },
}

/** 策略状态摘要：草稿 vs 已发布生效版本 */
export const AI_CRAWL_STATE_META: Record<
  string,
  { color: string; label: string }
> = {
  NOT_CONFIGURED: { color: 'default', label: '未配置' },
  DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
  PUBLISHED: { color: 'green', label: '已发布' },
}

/** 爬虫类别（SEARCH_ENGINE / AI_TRAINING / AI_ASSISTANT / AI_AGENT / UNKNOWN_BOT） */
export const AI_CRAWL_CATEGORY_META: Record<
  string,
  { color: string; label: string }
> = {
  SEARCH_ENGINE: { color: 'blue', label: '搜索引擎爬虫' },
  AI_TRAINING: { color: 'volcano', label: 'AI 训练爬虫' },
  AI_ASSISTANT: { color: 'purple', label: 'AI 助手爬虫' },
  AI_AGENT: { color: 'magenta', label: 'AI 智能体' },
  UNKNOWN_BOT: { color: 'default', label: '未知自动化爬虫' },
}

/** 治理处置动作（ALLOW / RATE_LIMIT / CHALLENGE / TARPIT / HTTP_402 / BLOCK） */
export const AI_CRAWL_ACTION_META: Record<
  string,
  { color: string; label: string }
> = {
  ALLOW: { color: 'green', label: '放行' },
  RATE_LIMIT: { color: 'gold', label: '限速' },
  CHALLENGE: { color: 'blue', label: 'Bot 挑战' },
  TARPIT: { color: 'purple', label: 'AI 迷宫拖延' },
  HTTP_402: { color: 'orange', label: 'HTTP 402 付费告知' },
  BLOCK: { color: 'red', label: '阻断（403）' },
}

/** Web Bot Auth 公钥算法选项（RFC 9421） */
export const AI_CRAWL_KEY_ALG_OPTIONS = [
  { value: 'ed25519', label: 'Ed25519' },
  { value: 'ecdsa-p256-sha256', label: 'ECDSA P-256 (SHA-256)' },
]

/** 常用 Content-Signal 响应头预设 */
export const CONTENT_SIGNAL_PRESETS = [
  {
    label: '允许搜索 / 禁止训练与 AI 输入',
    value: 'ai-train=no, search=yes, ai-input=no',
  },
  {
    label: '允许搜索与 AI 输入 / 禁止训练',
    value: 'ai-train=no, search=yes, ai-input=yes',
  },
  {
    label: '全部禁止（搜索/训练/输入）',
    value: 'ai-train=no, search=no, ai-input=no',
  },
] as const

/** 后端字段级错误路径 → AiCrawlTab 表单字段路径 */
export function mapAiCrawlFieldErrorPath(
  field: string,
): (string | number)[] | null {
  switch (field) {
    case 'mode':
    case 'default_ai_action':
    case 'content_signal':
    case 'verify_web_bot_auth':
    case 'labyrinth_enabled':
    case 'labyrinth_inject_links':
    case 'labyrinth_max_depth':
    case 'labyrinth_max_concurrency':
    case 'labyrinth_delay_ms':
    case 'reason':
      return [field]
    case 'http_402.message':
      return ['http_402_message']
    case 'http_402.price_hint':
      return ['http_402_price_hint']
    case 'http_402.contact_url':
      return ['http_402_contact_url']
    case 'http_402.receipt_header':
      return ['http_402_receipt_header']
    default:
      break
  }
  const m = /^rules\[(\d+)\](?:\.(.+))?$/.exec(field)
  if (!m) return null
  const idx = Number(m[1])
  const sub = m[2]
  if (!sub) return ['rules', idx]
  switch (sub) {
    case 'id':
    case 'name':
    case 'category':
    case 'agent_id':
    case 'ua_patterns':
    case 'require_verified_sig':
    case 'action':
    case 'exempt_bot_challenge':
    case 'rate_limit_rpm':
    case 'priority':
      return ['rules', idx, sub]
    default:
      return null
  }
}
