import { request } from './client'

/**
 * AI 爬虫治理与 Web Bot Auth（RFC 9421）管理面客户端（WDSP Phase 9A-2）。
 * 目录路由：GET/POST /ai-crawl/directories、PUT/DELETE /ai-crawl/directories/{id}、
 * POST /ai-crawl/directories/import、POST /ai-crawl/directories/{id}/sync。
 * 应用策略路由：GET/PUT /applications/{id}/ai-crawl-policy。
 * 权限：ai_crawl.read / ai_crawl.manage。草稿保存不等于线上生效，发布走既有发布通道。
 */

export type AiCrawlMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type AiCrawlCategory =
  | 'SEARCH_ENGINE'
  | 'AI_TRAINING'
  | 'AI_ASSISTANT'
  | 'AI_AGENT'
  | 'UNKNOWN_BOT'
export type AiCrawlAction =
  | 'ALLOW'
  | 'RATE_LIMIT'
  | 'CHALLENGE'
  | 'TARPIT'
  | 'HTTP_402'
  | 'BLOCK'
export type AiCrawlState = 'NOT_CONFIGURED' | 'DRAFT_PENDING' | 'PUBLISHED'
export type AiCrawlKeyAlg = 'ed25519' | 'ecdsa-p256-sha256'

export const AI_CRAWL_LIMITS = {
  maxRules: 64,
  maxRuleNameLen: 128,
  minRulePriority: 0,
  maxRulePriority: 10000,
  maxRateLimitRPM: 1000000,
  maxSignatureAgentLen: 512,
  maxReasonLen: 500,
  defaultLabyrinthMaxDepth: 5,
  minLabyrinthMaxDepth: 1,
  maxLabyrinthMaxDepth: 16,
  defaultLabyrinthMaxConcurrency: 256,
  minLabyrinthMaxConcurrency: 1,
  maxLabyrinthMaxConcurrency: 4096,
  defaultLabyrinthDelayMs: 150,
  minLabyrinthDelayMs: 0,
  maxLabyrinthDelayMs: 5000,
  defaultContentSignal: 'ai-train=no, search=yes, ai-input=no',
  reservedLabyrinthNamespace: '/_wdsp/labyrinth/v1/',
} as const

/** Web Bot Auth 目录中的单条验证公钥 */
export interface AiCrawlerDirectoryKey {
  kid: string
  alg: string
  public_key_pem: string
}

/** Web Bot Auth 爬虫公钥目录记录 */
export interface AiCrawlerDirectory {
  id: string
  slug: string
  name: string
  category: AiCrawlCategory | string
  signature_agent: string
  directory_url: string
  keys: AiCrawlerDirectoryKey[]
  is_builtin: boolean
  enabled: boolean
  last_synced_at?: string | null
  last_sync_error: string
  created_at: string
  updated_at: string
}

/** 目录创建/更新载荷 */
export interface AiCrawlerDirectoryInput {
  slug: string
  name: string
  category: AiCrawlCategory | string
  signature_agent: string
  directory_url?: string
  keys: AiCrawlerDirectoryKey[]
  enabled: boolean
}

export interface AiCrawlerDirectoryListResult {
  items: AiCrawlerDirectory[]
}

export interface AiCrawlerDirectoryImportBody {
  directories: AiCrawlerDirectoryInput[]
}

export interface AiCrawlerDirectoryImportResult {
  imported: number
  items: AiCrawlerDirectory[]
}

export interface AiCrawlerDirectorySyncResult {
  directory: AiCrawlerDirectory
  keys_count: number
}

export interface AiCrawlerDirectoryDeleteResult {
  deleted: boolean
  id: string
}

/** HTTP 402 Payment Required 响应配置 */
export interface AiCrawlHttp402Config {
  message: string
  price_hint: string
  contact_url: string
  receipt_header: string
}

/** 单条 AI 爬虫治理规则（按 priority 升序首中即停） */
export interface AiCrawlRule {
  id: string
  name: string
  category: AiCrawlCategory | string
  agent_id: string
  ua_patterns: string[]
  require_verified_sig: boolean
  action: AiCrawlAction | string
  exempt_bot_challenge: boolean
  rate_limit_rpm: number
  priority: number
}

/** 应用级 AI 爬虫治理与迷宫策略（服务端永不返回 labyrinth_key_hex 密钥材料） */
export interface AiCrawlPolicy {
  id: string
  schema_version: number
  application_id: string
  mode: AiCrawlMode
  version: number
  default_ai_action: AiCrawlAction
  content_signal: string
  verify_web_bot_auth: boolean
  labyrinth_enabled: boolean
  labyrinth_inject_links: boolean
  labyrinth_max_depth: number
  labyrinth_max_concurrency: number
  labyrinth_delay_ms: number
  http_402: AiCrawlHttp402Config
  rules: AiCrawlRule[]
  updated_by: string
  created_at: string
  updated_at: string
}

/** 状态摘要：草稿版本 vs 已发布生效版本 */
export interface AiCrawlStatusSummary {
  state: AiCrawlState
  draft_version: number
  published_version: number
}

export interface AiCrawlPolicyGetResult {
  policy: AiCrawlPolicy
  summary: AiCrawlStatusSummary
}

/** PUT 应用级 AI 爬虫治理策略载荷（expected_version 乐观锁 + reason 审计） */
export interface AiCrawlPolicyUpdateBody {
  mode: AiCrawlMode
  expected_version: number
  default_ai_action: AiCrawlAction
  content_signal: string
  verify_web_bot_auth: boolean
  labyrinth_enabled: boolean
  labyrinth_inject_links: boolean
  labyrinth_max_depth: number
  labyrinth_max_concurrency: number
  labyrinth_delay_ms: number
  http_402: AiCrawlHttp402Config
  rules: AiCrawlRule[]
  reason: string
}

function normalizeDirectory(d: AiCrawlerDirectory): AiCrawlerDirectory {
  return {
    ...d,
    directory_url: d.directory_url ?? '',
    last_sync_error: d.last_sync_error ?? '',
    keys: d.keys ?? [],
  }
}

function normalizePolicy(p: AiCrawlPolicy): AiCrawlPolicy {
  return {
    ...p,
    schema_version: p.schema_version ?? 1,
    content_signal: p.content_signal ?? '',
    http_402: {
      message: p.http_402?.message ?? '',
      price_hint: p.http_402?.price_hint ?? '',
      contact_url: p.http_402?.contact_url ?? '',
      receipt_header: p.http_402?.receipt_header ?? '',
    },
    rules: (p.rules ?? []).map((r) => ({
      ...r,
      agent_id: r.agent_id ?? '',
      ua_patterns: r.ua_patterns ?? [],
      rate_limit_rpm: r.rate_limit_rpm ?? 0,
      priority: r.priority ?? 100,
    })),
  }
}

export const aiCrawlApi = {
  listDirectories: async (): Promise<AiCrawlerDirectoryListResult> => {
    const data = await request<AiCrawlerDirectoryListResult>(
      '/ai-crawl/directories',
    )
    return {
      items: (data?.items ?? []).map(normalizeDirectory),
    }
  },
  createDirectory: async (
    body: AiCrawlerDirectoryInput,
  ): Promise<AiCrawlerDirectory> => {
    const data = await request<{ directory: AiCrawlerDirectory }>(
      '/ai-crawl/directories',
      { method: 'POST', body },
    )
    return normalizeDirectory(data.directory)
  },
  updateDirectory: async (
    id: string,
    body: AiCrawlerDirectoryInput,
  ): Promise<AiCrawlerDirectory> => {
    const data = await request<{ directory: AiCrawlerDirectory }>(
      `/ai-crawl/directories/${id}`,
      { method: 'PUT', body },
    )
    return normalizeDirectory(data.directory)
  },
  deleteDirectory: async (
    id: string,
  ): Promise<AiCrawlerDirectoryDeleteResult> => {
    return request<AiCrawlerDirectoryDeleteResult>(
      `/ai-crawl/directories/${id}`,
      { method: 'DELETE' },
    )
  },
  importDirectories: async (
    body: AiCrawlerDirectoryImportBody,
  ): Promise<AiCrawlerDirectoryImportResult> => {
    const data = await request<AiCrawlerDirectoryImportResult>(
      '/ai-crawl/directories/import',
      { method: 'POST', body },
    )
    return {
      imported: data.imported ?? 0,
      items: (data.items ?? []).map(normalizeDirectory),
    }
  },
  syncDirectory: async (id: string): Promise<AiCrawlerDirectorySyncResult> => {
    const data = await request<AiCrawlerDirectorySyncResult>(
      `/ai-crawl/directories/${id}/sync`,
      { method: 'POST' },
    )
    return {
      directory: normalizeDirectory(data.directory),
      keys_count: data.keys_count ?? 0,
    }
  },
  getPolicy: async (appId: string): Promise<AiCrawlPolicyGetResult> => {
    const data = await request<AiCrawlPolicyGetResult>(
      `/applications/${appId}/ai-crawl-policy`,
    )
    return {
      ...data,
      policy: normalizePolicy(data.policy),
    }
  },
  updatePolicy: async (
    appId: string,
    body: AiCrawlPolicyUpdateBody,
  ): Promise<AiCrawlPolicy> => {
    const data = await request<{ policy: AiCrawlPolicy }>(
      `/applications/${appId}/ai-crawl-policy`,
      { method: 'PUT', body },
    )
    return normalizePolicy(data.policy)
  },
}
