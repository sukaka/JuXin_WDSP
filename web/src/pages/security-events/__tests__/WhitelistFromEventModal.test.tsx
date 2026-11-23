import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import WhitelistFromEventModal from '../WhitelistFromEventModal'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, WhitelistPrefill } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const BASE_PREFILL: WhitelistPrefill = {
  event_id: 'evt-1',
  address: '45.148.10.75',
  request_path: '/api/v1/health',
  request_method: 'GET',
  domain: 'www.jxdr.cn',
  application_id: 'app-1',
  application_name: '官网',
  attack_type: 'SCANNER',
  severity: 'HIGH',
  related_event_count_24h: 3,
  last_attack_at: '2026-11-19T12:05:29Z',
  hit_rules: [{ rule_id: 1000220, rule_name: '扫描器探测', hits: 2 }],
  event_rule_ids: [1000220, 9000102],
  can_create_waf_exception: true,
  suggested_ip_name: '事件白名单-45.148.10.75',
  suggested_url_name: '事件URL白名单-/api/v1/health',
  suggested_reason: '安全事件误报/可信放行：SCANNER（来源事件 evt-1）',
}

function renderModal(onClose = () => {}, onCreated = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <WhitelistFromEventModal eventId="evt-1" onClose={onClose} onCreated={onCreated} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('WhitelistFromEventModal', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['access_rules.manage', 'access_rules.publish', 'exceptions.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('默认加载 IP 白名单预填并创建 rule_type=ALLOW 规则', async () => {
    const captured: { url: string; method?: string; body?: Record<string, unknown> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
        captured.push({ url, method: init?.method, body })
        if (url.includes('/whitelist-prefill')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { prefill: BASE_PREFILL } }))
        }
        if (url.endsWith('/api/v1/access-rules') && init?.method === 'POST') {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { rule: { id: 'r1' } } }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const onCreated = vi.fn()
    renderModal(() => {}, onCreated)

    expect(await screen.findByDisplayValue('事件白名单-45.148.10.75')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认创建' }))

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1))
    const postReq = captured.find((c) => c.url.endsWith('/api/v1/access-rules') && c.method === 'POST')
    expect(postReq?.body).toMatchObject({
      rule_type: 'ALLOW',
      scope_type: 'APPLICATION',
      application_id: 'app-1',
      address: '45.148.10.75',
      source_type: 'SECURITY_EVENT',
      source_event_id: 'evt-1',
    })
  })

  it('切换为 URL 白名单并勾选同步创建 WAF 精确例外草稿时同时调用两个接口', async () => {
    const captured: { url: string; method?: string; body?: Record<string, unknown> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
        captured.push({ url, method: init?.method, body })
        if (url.includes('/whitelist-prefill')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { prefill: BASE_PREFILL } }))
        }
        if (url.endsWith('/api/v1/url-whitelists') && init?.method === 'POST') {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { rule: { id: 'u1' } } }))
        }
        if (url.includes('/security-events/evt-1/create-exception') && init?.method === 'POST') {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { id: 'exc-1' } }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const onCreated = vi.fn()
    renderModal(() => {}, onCreated)

    await screen.findByDisplayValue('事件白名单-45.148.10.75')
    fireEvent.click(screen.getByRole('radio', { name: 'URL 白名单' }))
    expect(await screen.findByDisplayValue('事件URL白名单-/api/v1/health')).toBeInTheDocument()
    expect(screen.getByDisplayValue('/api/v1/health')).toBeInTheDocument()

    // 勾选同步创建 WAF 精确例外草稿
    const checkbox = screen.getByRole('checkbox', { name: /同步创建 WAF 精确例外草稿/ })
    fireEvent.click(checkbox)
    fireEvent.click(screen.getByRole('button', { name: '确认创建' }))

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1))
    const urlPost = captured.find((c) => c.url.endsWith('/api/v1/url-whitelists') && c.method === 'POST')
    expect(urlPost?.body).toMatchObject({
      scope_type: 'APPLICATION',
      application_id: 'app-1',
      match_type: 'EXACT',
      uri_pattern: '/api/v1/health',
      methods: ['GET'],
      source_type: 'SECURITY_EVENT',
      source_event_id: 'evt-1',
    })
    expect(captured.some((c) => c.url.includes('/security-events/evt-1/create-exception'))).toBe(true)
  })
})
