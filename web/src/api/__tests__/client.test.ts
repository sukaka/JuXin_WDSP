import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  buildUrl,
  request,
  setCsrfToken,
  setSessionExpiredHandler,
} from '../client'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  const fn = vi.fn(handler)
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('api client', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('成功响应解包 data 字段', async () => {
    stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { a: 1 } })),
    )
    await expect(request<{ a: number }>('/test')).resolves.toEqual({ a: 1 })
  })

  it('POST 请求自动携带 X-CSRF-Token', async () => {
    setCsrfToken('csrf-abc')
    const fetchMock = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    await request('/test', { method: 'POST', body: { x: 1 } })
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-abc')
  })

  it('GET 请求不携带 X-CSRF-Token', async () => {
    setCsrfToken('csrf-abc')
    const fetchMock = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    await request('/test')
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined()
  })

  it('401 触发会话失效回调并抛出 UNAUTHENTICATED', async () => {
    const onExpired = vi.fn()
    setSessionExpiredHandler(onExpired)
    stubFetch(() =>
      Promise.resolve(
        jsonResponse(401, { code: 'UNAUTHENTICATED', message: '未登录或会话已过期' }),
      ),
    )
    const err = await request('/test').catch((e: unknown) => e)
    expect(onExpired).toHaveBeenCalledTimes(1)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('UNAUTHENTICATED')
    expect((err as ApiError).status).toBe(401)
  })

  it('403 抛出 PERMISSION_DENIED 并保留后端 message', async () => {
    stubFetch(() =>
      Promise.resolve(
        jsonResponse(403, { code: 'PERMISSION_DENIED', message: '无权限执行该操作' }),
      ),
    )
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('PERMISSION_DENIED')
    expect((err as ApiError).message).toBe('无权限执行该操作')
  })

  it('始终使用 credentials: include', async () => {
    const fetchMock = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    await request('/test')
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.credentials).toBe('include')
  })

  it('buildUrl 拼接查询参数并忽略空值', () => {
    expect(buildUrl('/users', { page: 1, username: 'admin', status: undefined, role_code: '' })).toBe(
      '/api/v1/users?page=1&username=admin',
    )
  })
})
