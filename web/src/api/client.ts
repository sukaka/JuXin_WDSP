import type { ApiEnvelope } from '../types'

const BASE = '/api/v1'

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly requestId?: string
  readonly details?: unknown

  constructor(message: string, code: string, status: number, requestId?: string, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.requestId = requestId
    this.details = details
  }
}

// CSRF Token 仅存内存（由 auth store 登录/刷新后写入），不落 LocalStorage
let csrfToken: string | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
}

export function getCsrfToken(): string | null {
  return csrfToken
}

// 会话失效（401）时的全局回调，由 App 注册（清理状态并跳登录页）
let sessionExpiredHandler: (() => void) | null = null

export function setSessionExpiredHandler(handler: (() => void) | null): void {
  sessionExpiredHandler = handler
}

type QueryValue = string | number | boolean | undefined | null

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
  query?: Record<string, QueryValue>
  /** 响应不是统一信封格式时置为 true（如 /health） */
  raw?: boolean
}

export function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const params = new URLSearchParams()
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        params.set(key, String(value))
      }
    }
  }
  const qs = params.toString()
  return `${BASE}${path}${qs ? `?${qs}` : ''}`
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = {}
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  // 所有写操作必须携带 CSRF Token
  if (method !== 'GET' && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  let resp: Response
  try {
    resp = await fetch(buildUrl(path, options.query), {
      method,
      headers,
      credentials: 'include',
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    })
  } catch {
    throw new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0)
  }

  if (resp.status === 401) {
    sessionExpiredHandler?.()
  }

  let payload: unknown = null
  const text = await resp.text()
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (options.raw) {
    if (!resp.ok) {
      throw new ApiError(`请求失败（HTTP ${resp.status}）`, 'HTTP_ERROR', resp.status)
    }
    return payload as T
  }

  const env = payload as ApiEnvelope<T> | null
  if (!resp.ok || !env || typeof env.code !== 'string' || env.code !== 'SUCCESS') {
    const code = env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
    const message = env && typeof env.message === 'string' ? env.message : `请求失败（HTTP ${resp.status}）`
    throw new ApiError(message, code, resp.status, env?.request_id, env?.details)
  }
  return env.data
}
