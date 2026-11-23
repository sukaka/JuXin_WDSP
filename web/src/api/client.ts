import type { ApiEnvelope } from '../types'

const BASE = '/api/v1'

/** 默认请求超时：防 fetch 挂起永不 settle；长耗时端点（AI 分析/评估、大文件上传）经 timeoutMs 显式放宽 */
const DEFAULT_TIMEOUT_MS = 60_000

/** 上传默认超时（升级包等大文件，内网/弱网留足余量） */
const DEFAULT_UPLOAD_TIMEOUT_MS = 600_000

/** 单响应体大小上限（10 MiB）：防异常/恶意响应无界读入撑爆内存；
 * SSE 流式路径（api/ai.ts streamPostSSE）不经 request()/upload()，不受此限 */
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024

/** 仅对未登录态预期可能返回 401 的公开/探测认证端点跳过全局会话失效回调；
 * 已认证端点（如 /auth/password、/auth/totp/* 管理接口）返回 401 时必须触发会话失效处理 */
const PUBLIC_AUTH_401_PATHS = new Set([
  '/auth/login',
  '/auth/me',
  '/auth/logout',
  '/auth/captcha',
  '/auth/totp-verify',
])

function isPublicAuth401Path(path: string): boolean {
  const normalized = path.split('?')[0]
  return PUBLIC_AUTH_401_PATHS.has(normalized)
}

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

// 授权失效（423）时的全局回调，由 App 注册（重载授权状态进入锁定态）
let licenseInvalidHandler: (() => void) | null = null

export function setLicenseInvalidHandler(handler: (() => void) | null): void {
  licenseInvalidHandler = handler
}

/** 独立 fetch 封装（SSE 流式等不走 request() 的路径）命中 401 时调用，与 request() 保持同一全局处置 */
export function notifySessionExpired(): void {
  sessionExpiredHandler?.()
}

/** 独立 fetch 封装命中 423 时调用，与 request() 保持同一全局处置 */
export function notifyLicenseInvalid(): void {
  licenseInvalidHandler?.()
}

type QueryValue = string | number | boolean | undefined | null

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'
  body?: unknown
  query?: Record<string, QueryValue>
  /** 响应不是统一信封格式时置为 true（如 /health） */
  raw?: boolean
  /** 响应为纯文本/HTML（非 JSON 信封，如报告预览）时置为 true，返回原始文本 */
  rawText?: boolean
  /** 业务成功分支码（HTTP 200 但 code 非 SUCCESS，如登录的 TOTP_REQUIRED）。
   * 声明后 SUCCESS 与分支码统一返回 { code, data }，由调用方按 code 判别 */
  branchCodes?: string[]
  /** 请求超时（毫秒），默认 60s；超时/读取超时统一抛 ApiError(code=TIMEOUT) */
  timeoutMs?: number
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

/** 有界读取响应文本：Content-Length 声明超限直接拒收；无声明时流式累积、超过上限即中断。
 * 读取被超时信号中断时抛 ApiError(code=TIMEOUT)；超限抛 ApiError(code=RESPONSE_TOO_LARGE) */
async function readResponseText(resp: Response): Promise<string> {
  const declared = Number(resp.headers.get('Content-Length'))
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new ApiError('响应体超过大小上限，已中断接收', 'RESPONSE_TOO_LARGE', resp.status)
  }
  if (!resp.body) {
    return resp.text()
  }
  const reader = resp.body.getReader()
  const chunks: Uint8Array[] = []
  let received = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      received += value.byteLength
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw new ApiError('响应体超过大小上限，已中断接收', 'RESPONSE_TOO_LARGE', resp.status)
      }
      chunks.push(value)
    }
  } catch (e) {
    if (e instanceof ApiError) throw e
    if (e instanceof DOMException && e.name === 'TimeoutError') {
      throw new ApiError('请求超时，请稍后重试', 'TIMEOUT', resp.status)
    }
    throw e
  } finally {
    reader.releaseLock()
  }
  const merged = new Uint8Array(received)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(merged)
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
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'TimeoutError') {
      throw new ApiError('请求超时，请稍后重试', 'TIMEOUT', 0)
    }
    throw new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0)
  }

  // 仅对公开/探测认证端点忽略 401 全局会话失效回调，已认证接口 401 必须触发会话失效处理
  if (resp.status === 401 && !isPublicAuth401Path(path)) {
    sessionExpiredHandler?.()
  }

  // 授权失效（423 Locked）：触发授权状态重载，由授权守卫锁定到授权管理页；
  // 响应仍按错误抛出给调用方（不静默吞错）
  if (resp.status === 423) {
    licenseInvalidHandler?.()
  }

  let payload: unknown = null
  const text = await readResponseText(resp)
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

  // 纯文本响应（如报告预览 HTML）：成功返回原文；失败按信封提取错误信息
  if (options.rawText) {
    if (!resp.ok) {
      const env = payload as ApiEnvelope<null> | null
      const code = env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
      const message = env && typeof env.message === 'string' ? env.message : `请求失败（HTTP ${resp.status}）`
      throw new ApiError(message, code, resp.status, env?.request_id, env?.details)
    }
    return text as T
  }

  // 空 body 的 2xx（典型为 204 No Content，如 WDSP Agent 管理写操作，契约 WDSP_AGENT_PHASE1_CONTRACT §4）：
  // 无信封可解析，按成功返回 null；失败响应（非 2xx）即使空 body 仍走下方统一错误分支
  if (resp.ok && !text) {
    return null as T
  }

  const env = payload as ApiEnvelope<T> | null
  // 业务分支码（如登录两步验证 TOTP_REQUIRED）：HTTP 200 且命中声明列表时按成功返回完整 { code, data }
  if (
    resp.ok &&
    env &&
    typeof env.code === 'string' &&
    options.branchCodes &&
    (env.code === 'SUCCESS' || options.branchCodes.includes(env.code))
  ) {
    return { code: env.code, data: env.data } as T
  }
  if (!resp.ok || !env || typeof env.code !== 'string' || env.code !== 'SUCCESS') {
    const code = env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
    const message = env && typeof env.message === 'string' ? env.message : `请求失败（HTTP ${resp.status}）`
    throw new ApiError(message, code, resp.status, env?.request_id, env?.details)
  }
  return env.data
}

/**
 * multipart/form-data 上传：request() 固定 JSON Content-Type，无法承载 FormData
 * （浏览器需自动生成带 boundary 的 Content-Type）。按 request() 同一纪律
 * （credentials、CSRF 头、401/423 全局回调、统一信封解析、超时与响应大小上限）封装，新增上传统一复用。
 */
export interface UploadProgress {
  loaded: number
  total: number
  lengthComputable: boolean
}

export interface UploadOptions {
  timeoutMs?: number
  onProgress?: (progress: UploadProgress) => void
}

export async function upload<T>(
  path: string,
  form: FormData,
  options: UploadOptions = {},
): Promise<T> {
  if (options.onProgress) {
    return uploadWithProgress<T>(path, form, options)
  }
  const headers: Record<string, string> = {}
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  let resp: Response
  try {
    resp = await fetch(buildUrl(path), {
      method: 'POST',
      headers,
      credentials: 'include',
      body: form,
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_UPLOAD_TIMEOUT_MS),
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'TimeoutError') {
      throw new ApiError('请求超时，请稍后重试', 'TIMEOUT', 0)
    }
    throw new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0)
  }

  if (resp.status === 401) {
    sessionExpiredHandler?.()
  }
  if (resp.status === 423) {
    licenseInvalidHandler?.()
  }

  let payload: unknown = null
  const text = await readResponseText(resp)
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  const env = payload as ApiEnvelope<T> | null
  if (!resp.ok || !env || typeof env.code !== 'string' || env.code !== 'SUCCESS') {
    const code = env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
    const message = env && typeof env.message === 'string' ? env.message : `请求失败（HTTP ${resp.status}）`
    throw new ApiError(message, code, resp.status, env?.request_id, env?.details)
  }
  return env.data
}

function uploadWithProgress<T>(path: string, form: FormData, options: UploadOptions): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    let settled = false
    let abortedForSize = false

    const rejectOnce = (err: ApiError) => {
      if (settled) return
      settled = true
      reject(err)
    }

    const exceedsLimit = (loaded: number): boolean => {
      const declared = Number(xhr.getResponseHeader('Content-Length'))
      return loaded > MAX_RESPONSE_BYTES || (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES)
    }

    const abortIfOversized = (loaded: number): boolean => {
      if (settled || !exceedsLimit(loaded)) return false
      abortedForSize = true
      const status = xhr.status
      xhr.abort()
      rejectOnce(new ApiError('响应体超过大小上限，已中断接收', 'RESPONSE_TOO_LARGE', status))
      return true
    }

    xhr.open('POST', buildUrl(path))
    xhr.withCredentials = true
    xhr.timeout = options.timeoutMs ?? DEFAULT_UPLOAD_TIMEOUT_MS
    if (csrfToken) xhr.setRequestHeader('X-CSRF-Token', csrfToken)

    xhr.upload.onprogress = (event) => {
      options.onProgress?.({
        loaded: event.loaded,
        total: event.lengthComputable ? event.total : 0,
        lengthComputable: event.lengthComputable,
      })
    }
    xhr.onreadystatechange = () => {
      if (xhr.readyState >= 2) {
        abortIfOversized(0)
      }
    }
    xhr.onprogress = (event) => {
      abortIfOversized(event.loaded)
    }
    xhr.onerror = () => rejectOnce(new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0))
    xhr.ontimeout = () => rejectOnce(new ApiError('请求超时，请稍后重试', 'TIMEOUT', 0))
    xhr.onabort = () => {
      if (abortedForSize) return
      rejectOnce(new ApiError('上传已取消', 'UPLOAD_CANCELLED', 0))
    }
    xhr.onload = () => {
      if (settled || abortedForSize) return
      if (xhr.status === 401) sessionExpiredHandler?.()
      if (xhr.status === 423) licenseInvalidHandler?.()

      if (exceedsLimit(new Blob([xhr.responseText]).size)) {
        rejectOnce(new ApiError('响应体超过大小上限，已中断接收', 'RESPONSE_TOO_LARGE', xhr.status))
        return
      }
      let payload: unknown = null
      if (xhr.responseText) {
        try {
          payload = JSON.parse(xhr.responseText)
        } catch {
          payload = null
        }
      }
      const env = payload as ApiEnvelope<T> | null
      if (xhr.status < 200 || xhr.status >= 300 || !env || typeof env.code !== 'string' || env.code !== 'SUCCESS') {
        const code = env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
        const message = env && typeof env.message === 'string' ? env.message : `请求失败（HTTP ${xhr.status}）`
        rejectOnce(new ApiError(message, code, xhr.status, env?.request_id, env?.details))
        return
      }
      settled = true
      resolve(env.data)
    }
    xhr.send(form)
  })
}
