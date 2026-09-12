import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError,
  buildUrl,
  request,
  upload,
  setCsrfToken,
  setLicenseInvalidHandler,
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
    setLicenseInvalidHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
    setLicenseInvalidHandler(null)
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

  it('423 触发授权失效回调并抛出 LICENSE_INVALID（不触发会话失效回调）', async () => {
    const onLicenseInvalid = vi.fn()
    const onExpired = vi.fn()
    setLicenseInvalidHandler(onLicenseInvalid)
    setSessionExpiredHandler(onExpired)
    stubFetch(() =>
      Promise.resolve(
        jsonResponse(423, { code: 'LICENSE_INVALID', message: '授权无效，系统已锁定' }),
      ),
    )
    const err = await request('/test').catch((e: unknown) => e)
    expect(onLicenseInvalid).toHaveBeenCalledTimes(1)
    expect(onExpired).not.toHaveBeenCalled()
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('LICENSE_INVALID')
    expect((err as ApiError).status).toBe(423)
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

  it('204 No Content（空 body 的 2xx）按成功处理，返回 null', async () => {
    stubFetch(() => Promise.resolve(new Response(null, { status: 204 })))
    await expect(request<null>('/test', { method: 'DELETE' })).resolves.toBeNull()
  })

  it('空 body 的非 2xx 仍按错误抛出（不静默吞错）', async () => {
    stubFetch(() => Promise.resolve(new Response(null, { status: 500 })))
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(500)
  })

  it('/auth/* 端点 401 不触发全局会话失效回调（登录密码错误等未登录态预期 401），仍按错误抛出', async () => {
    const onExpired = vi.fn()
    setSessionExpiredHandler(onExpired)
    stubFetch(() =>
      Promise.resolve(jsonResponse(401, { code: 'UNAUTHENTICATED', message: '用户名或密码错误' })),
    )
    const err = await request('/auth/login', { method: 'POST', body: {} }).catch((e: unknown) => e)
    expect(onExpired).not.toHaveBeenCalled()
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(401)
    expect((err as ApiError).message).toBe('用户名或密码错误')
  })

  it('/auth/me 启动探测 401 不触发全局会话失效回调', async () => {
    const onExpired = vi.fn()
    setSessionExpiredHandler(onExpired)
    stubFetch(() =>
      Promise.resolve(jsonResponse(401, { code: 'UNAUTHENTICATED', message: '未登录或会话已过期' })),
    )
    await expect(request('/auth/me')).rejects.toBeInstanceOf(ApiError)
    expect(onExpired).not.toHaveBeenCalled()
  })

  it('请求携带 AbortSignal（默认超时挂起防护）', async () => {
    const fetchMock = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    await request('/test')
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.signal).toBeInstanceOf(AbortSignal)
  })

  it('fetch 超时拒绝映射为 ApiError(code=TIMEOUT)', async () => {
    stubFetch(() => Promise.reject(new DOMException('The operation timed out', 'TimeoutError')))
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('TIMEOUT')
  })

  it('网络异常仍映射为 ApiError(code=NETWORK_ERROR)', async () => {
    stubFetch(() => Promise.reject(new TypeError('fetch failed')))
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('NETWORK_ERROR')
  })

  it('响应体超过 10MiB 上限（无 Content-Length 声明）中断接收并抛 RESPONSE_TOO_LARGE', async () => {
    const big = 'x'.repeat(10 * 1024 * 1024 + 1)
    stubFetch(() => Promise.resolve(new Response(big, { status: 200 })))
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('RESPONSE_TOO_LARGE')
  })

  it('Content-Length 声明超过 10MiB 上限直接拒收（不读取 body）', async () => {
    stubFetch(() =>
      Promise.resolve(
        new Response('{}', {
          status: 200,
          headers: { 'Content-Length': String(10 * 1024 * 1024 + 1) },
        }),
      ),
    )
    const err = await request('/test').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('RESPONSE_TOO_LARGE')
  })

  it('upload 携带 AbortSignal 与 CSRF 头，解包信封 data', async () => {
    setCsrfToken('csrf-up')
    const fetchMock = stubFetch(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { id: 'p1' } })),
    )
    const form = new FormData()
    form.append('file', new Blob(['x']), 'x.bin')
    await expect(upload<{ id: string }>('/upgrades/packages/upload', form)).resolves.toEqual({
      id: 'p1',
    })
    const init = fetchMock.mock.calls[0][1] as RequestInit
    expect(init.signal).toBeInstanceOf(AbortSignal)
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-up')
  })

  it('upload 超时映射为 ApiError(code=TIMEOUT)', async () => {
    stubFetch(() => Promise.reject(new DOMException('The operation timed out', 'TimeoutError')))
    const err = await upload('/upgrades/packages/upload', new FormData()).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('TIMEOUT')
  })
})
