import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  aiChatApi,
  patchAiAgent,
  patchAiProvider,
  patchAiTool,
  renameAiSession,
  type AiSseEvent,
} from '../ai'
import {
  ApiError,
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

function sseResponse(lines: string[]): Response {
  const text = lines.map((l) => `data: ${l}\n\n`).join('')
  return new Response(text, { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
}

const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>()

describe('ai.ts 自制封装收敛与全局回调纪律', () => {
  beforeEach(() => {
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
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

  it('renameAiSession：PATCH + CSRF 头 + JSON body', async () => {
    setCsrfToken('csrf-ai')
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
    await expect(renameAiSession('s1', '新标题')).resolves.toBeUndefined()
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/ai/sessions/s1')
    expect(init?.method).toBe('PATCH')
    expect((init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-ai')
    expect(JSON.parse(String(init?.body))).toEqual({ title: '新标题' })
  })

  it('renameAiSession：HTTP 200 但信封 code 非 SUCCESS 仍抛错（不得只看 resp.ok）', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { code: 'INVALID_ARGUMENT', message: '标题不能为空' }),
    )
    const err = await renameAiSession('s1', '').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('INVALID_ARGUMENT')
    expect((err as ApiError).message).toBe('标题不能为空')
  })

  it('renameAiSession：401/423 触发全局回调', async () => {
    const onExpired = vi.fn()
    const onLicenseInvalid = vi.fn()
    setSessionExpiredHandler(onExpired)
    setLicenseInvalidHandler(onLicenseInvalid)
    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { code: 'UNAUTHENTICATED', message: '未登录或会话已过期' }),
    )
    await expect(renameAiSession('s1', 't')).rejects.toBeInstanceOf(ApiError)
    expect(onExpired).toHaveBeenCalledTimes(1)
    fetchMock.mockResolvedValueOnce(
      jsonResponse(423, { code: 'LICENSE_INVALID', message: '授权无效，系统已锁定' }),
    )
    await expect(renameAiSession('s1', 't')).rejects.toBeInstanceOf(ApiError)
    expect(onLicenseInvalid).toHaveBeenCalledTimes(1)
  })

  it('patchAiProvider / patchAiAgent / patchAiTool：PATCH 到对应端点', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { provider: { id: 'p1', name: 'n' } } })),
    )
    const provider = await patchAiProvider('p1', { name: 'n' })
    expect(provider).toEqual({ id: 'p1', name: 'n' })
    await patchAiAgent('a1', { enabled: false })
    await patchAiTool('t1', { timeout_seconds: 30 })
    const urls = fetchMock.mock.calls.map((c) => String(c[0]))
    expect(urls).toEqual(['/api/v1/ai/models/providers/p1', '/api/v1/ai/agents/a1', '/api/v1/ai/tools/t1'])
    for (const call of fetchMock.mock.calls) {
      expect(call[1]?.method).toBe('PATCH')
    }
  })

  it('patchAiProvider：HTTP 200 但信封 code 非 SUCCESS 仍抛错', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { code: 'CONFLICT', message: '供应商被占用' }))
    await expect(patchAiProvider('p1', {})).rejects.toThrow('供应商被占用')
  })

  it('streamMessage（SSE）：逐行解析 data: 事件', async () => {
    fetchMock.mockResolvedValueOnce(
      sseResponse([
        JSON.stringify({ type: 'plan', text: '计划' }),
        'not-json',
        JSON.stringify({ type: 'done', payload: { finish_reason: 'stop' } }),
      ]),
    )
    const events: AiSseEvent[] = []
    await aiChatApi.streamMessage('s1', '你好', (e) => events.push(e), new AbortController().signal)
    expect(events).toHaveLength(2)
    expect(events[0].type).toBe('plan')
    expect(events[1].type).toBe('done')
  })

  it('streamMessage（SSE）：401 触发会话失效回调并按信封抛错', async () => {
    const onExpired = vi.fn()
    setSessionExpiredHandler(onExpired)
    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { code: 'UNAUTHENTICATED', message: '未登录或会话已过期' }),
    )
    const err = await aiChatApi
      .streamMessage('s1', 'hi', () => {}, new AbortController().signal)
      .catch((e: unknown) => e)
    expect(onExpired).toHaveBeenCalledTimes(1)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).code).toBe('UNAUTHENTICATED')
  })

  it('streamMessage（SSE）：423 触发授权失效回调', async () => {
    const onLicenseInvalid = vi.fn()
    const onExpired = vi.fn()
    setLicenseInvalidHandler(onLicenseInvalid)
    setSessionExpiredHandler(onExpired)
    fetchMock.mockResolvedValueOnce(
      jsonResponse(423, { code: 'LICENSE_INVALID', message: '授权无效，系统已锁定' }),
    )
    await expect(
      aiChatApi.streamMessage('s1', 'hi', () => {}, new AbortController().signal),
    ).rejects.toBeInstanceOf(ApiError)
    expect(onLicenseInvalid).toHaveBeenCalledTimes(1)
    expect(onExpired).not.toHaveBeenCalled()
  })
})
