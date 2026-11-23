import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  aiAnalyzeApi,
  aiAuditsApi,
  aiChatApi,
  aiPromptsApi,
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

  it('aiPromptsApi.testVersion：使用 21 分钟（1_260_000ms）超时避免回归请求在 60s 中断', async () => {
    const timeoutSpy = vi.spyOn(AbortSignal, 'timeout')
    try {
      fetchMock.mockResolvedValueOnce(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { test_result: 'PASSED', checks: [], test_detail: { static_checks: [] } },
        }),
      )
      const res = await aiPromptsApi.testVersion('v1')
      expect(res.test_result).toBe('PASSED')
      expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/ai/prompts/versions/v1/test')
      expect(fetchMock.mock.calls[0][1]?.method).toBe('POST')
      expect(timeoutSpy).toHaveBeenCalledWith(1_260_000)
    } finally {
      timeoutSpy.mockRestore()
    }
  })

  it('aiAuditsApi.get：解包 data.audit 并保留 id / prompt_version / confirm_result', async () => {
    const audit = {
      id: 'audit-1',
      occurred_at: '2026-11-20T03:00:00Z',
      username: 'secadmin',
      role_codes: 'SECURITY_ADMIN',
      action: 'prompt_test',
      task_type: 'EVENT_ANALYSIS',
      agent_code: '',
      tool_code: '',
      model_code: 'qwen2.5:3b',
      prompt_version: 'v3',
      input_tokens: 10,
      output_tokens: 20,
      duration_ms: 50,
      estimated_cost: 0.001,
      request_summary: 'test',
      result_summary: 'PASSED',
      draft_reference: '',
      confirm_result: 'CONFIRMED',
    }
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { audit } }),
    )
    const got = await aiAuditsApi.get('audit-1')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/ai/audits/audit-1')
    expect(got).toEqual(audit)
  })

  it('aiAnalyzeApi：reportSummary / attackProfile / event 透传 question 字段', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { task_id: 't1', answer: 'ok' } }),
      ),
    )
    await aiAnalyzeApi.reportSummary({ period: '近7天', question: 'ERP 应用重点总结' })
    await aiAnalyzeApi.attackProfile({ ip: '203.0.113.10', question: '关注撞库手法' })
    await aiAnalyzeApi.event({
      event_id: '11111111-2222-3333-4444-555555555555',
      question: '检查是否绕过',
    })
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      period: '近7天',
      question: 'ERP 应用重点总结',
    })
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({
      ip: '203.0.113.10',
      question: '关注撞库手法',
    })
    expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({
      event_id: '11111111-2222-3333-4444-555555555555',
      question: '检查是否绕过',
    })
  })
})
