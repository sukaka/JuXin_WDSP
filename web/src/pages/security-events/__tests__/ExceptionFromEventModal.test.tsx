import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ExceptionFromEventModal from '../ExceptionFromEventModal'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, SecurityEventDetail } from '../../../types'

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

const BLOCKING_MATCH = {
  rule_id: 949110,
  rule_name: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
  rule_source: 'OWASP_CRS',
  severity: 'INFO',
  message: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
  matched_variable: '',
  matched_data: '',
  tags: [],
  phase: 2,
}

const BASE_DETAIL: SecurityEventDetail = {
  event: {
    id: '11111111-2222-3333-4444-555555555555',
    request_id: 'req-1',
    occurred_at: '2026-11-26T19:57:59Z',
    application_id: 'app-1',
    application_name_snapshot: '官网',
    domain: 'www.jxdr.cn',
    gateway_node_id: 'gateway-poc-01',
    client_ip: '123.121.181.151',
    client_port: 5617,
    request_method: 'POST',
    request_uri: '/admin-api/customer/messages/heartbeat?sessionId=masked&role=visitor',
    request_path: '/admin-api/customer/messages/heartbeat',
    query_summary: 'sessionId=masked&role=visitor',
    http_version: 'HTTP/2.0',
    content_type: '',
    user_agent_summary: 'Mozilla/5.0 wxwork/5.0.13',
    referer_summary: '',
    attack_type: 'SESSION_FIXATION',
    severity: 'HIGH',
    action: 'BLOCK',
    anomaly_score: 5,
    rule_match_count: 2,
    disposition_status: 'UNPROCESSED',
    disposition_result: '',
    raw_log_reference: '',
    response_status: 403,
  },
  matches: [
    {
      rule_id: 943120,
      rule_name: 'Possible Session Fixation Attack: SessionID Parameter Name with No Referer',
      rule_source: 'OWASP_CRS',
      severity: 'HIGH',
      message: 'Possible Session Fixation Attack: SessionID Parameter Name with No Referer',
      matched_variable: 'ARGS_NAMES:sessionId',
      matched_data: 'sessionId',
      tags: ['attack-fixation'],
      phase: 2,
    },
    BLOCKING_MATCH,
  ],
  notes: [],
  actions: [],
  related: [],
}

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="modal-location">{location.pathname}</div>
}

function renderModal(
  detail: SecurityEventDetail | null = BASE_DETAIL,
  onClose = () => {},
  onCreated = () => {},
) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={['/security-events']}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <LocationProbe />
          <ExceptionFromEventModal
            detail={detail}
            open={true}
            onClose={onClose}
            onCreated={onCreated}
          />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('ExceptionFromEventModal', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['exceptions.manage', 'gateway_configs.publish']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('自动排除 949110 评分汇总规则，默认一键创建、启用并发布到网关', async () => {
    const captured: { url: string; method?: string; body?: Record<string, unknown> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
        captured.push({ url, method: init?.method, body })
        if (url.includes('/create-exception') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { exception_id: 'exc-99', message: 'ok' },
            }),
          )
        }
        if (url.endsWith('/api/v1/exceptions/exc-99/enable') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception: { id: 'exc-99', status: 'ENABLED' } } }),
          )
        }
        if (url.endsWith('/api/v1/gateway-config/publish') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { id: 'task-1', status: 'SUCCESS', result_summary: 'published' } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const onCreated = vi.fn()
    const onClose = vi.fn()
    renderModal(BASE_DETAIL, onClose, onCreated)

    expect(await screen.findByText('943120')).toBeInTheDocument()
    expect(screen.getByText(/已自动排除异常评分汇总规则（949110）/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '创建并发布' }))

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1))
    expect(onClose).toHaveBeenCalledTimes(1)

    expect(captured.map((c) => c.url)).toEqual([
      '/api/v1/security-events/11111111-2222-3333-4444-555555555555/create-exception',
      '/api/v1/exceptions/exc-99/enable',
      '/api/v1/gateway-config/publish',
    ])
    expect(captured[0].body).toMatchObject({
      restrict_source_ip: false,
      is_temporary: true,
      duration_minutes: 30,
      rule_ids: [943120],
    })
    expect(captured[2].body?.idempotency_key).toBeTruthy()
  })

  it('可切换仅限本次 IP、永久并关闭立即发布，仅保存草稿不触发启用/发布', async () => {
    const captured: { url: string; method?: string; body?: Record<string, unknown> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
        captured.push({ url, method: init?.method, body })
        if (url.includes('/create-exception') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception_id: 'exc-draft', message: 'ok' } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const onCreated = vi.fn()
    renderModal(BASE_DETAIL, () => {}, onCreated)

    fireEvent.click(await screen.findByRole('radio', { name: /仅限本次客户端 IP/ }))
    fireEvent.click(screen.getByRole('radio', { name: /永久/ }))
    fireEvent.click(screen.getByRole('switch'))
    fireEvent.click(screen.getByRole('button', { name: '仅保存草稿' }))

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1))
    expect(captured).toHaveLength(1)
    expect(captured[0].body).toMatchObject({
      restrict_source_ip: true,
      is_temporary: false,
      rule_ids: [943120],
    })
    expect(captured[0].body).not.toHaveProperty('duration_minutes')
  })

  it('无 gateway_configs.publish 权限时仅执行创建与启用，不调用发布接口', async () => {
    useAuthStore.setState({
      user: makeUser(['exceptions.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    const captured: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        captured.push(url)
        if (url.includes('/create-exception')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception_id: 'exc-2', message: 'ok' } }),
          )
        }
        if (url.includes('/enable')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception: { id: 'exc-2', status: 'ENABLED' } } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const onCreated = vi.fn()
    renderModal(BASE_DETAIL, () => {}, onCreated)

    fireEvent.click(await screen.findByRole('button', { name: '创建并启用' }))
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(1))
    expect(captured).toEqual([
      '/api/v1/security-events/11111111-2222-3333-4444-555555555555/create-exception',
      '/api/v1/exceptions/exc-2/enable',
    ])
  })

  it('缺少应用或检测规则证据时禁用立即启用开关，仅允许保存草稿', async () => {
    const incompleteDetail: SecurityEventDetail = {
      ...BASE_DETAIL,
      event: { ...BASE_DETAIL.event, application_id: null, application_name_snapshot: '' },
      matches: [BLOCKING_MATCH], // 仅剩 949110
    }
    renderModal(incompleteDetail)

    expect(
      await screen.findByText('该事件缺少启用所需的精确范围证据，仅可保存为待审查草稿'),
    ).toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.getByRole('button', { name: '仅保存草稿' })).toBeInTheDocument()
  })

  it('发布任务返回 FAILED 时弹出警告并展示真实失败原因，不伪报成功', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/create-exception')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception_id: 'exc-3', message: 'ok' } }),
          )
        }
        if (url.includes('/enable')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception: { id: 'exc-3', status: 'ENABLED' } } }),
          )
        }
        if (url.includes('/gateway-config/publish')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { id: 'task-fail', status: 'FAILED', failure_message: 'Caddy 配置校验失败' },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderModal(BASE_DETAIL)
    fireEvent.click(await screen.findByRole('button', { name: '创建并发布' }))

    expect(await screen.findByText(/Caddy 配置校验失败/)).toBeInTheDocument()
    expect(screen.getAllByText('例外已创建并启用，但发布到网关失败').length).toBeGreaterThan(0)
  })

  it('启用门禁失败时弹出警告，点击跳转链接可导航至例外策略页并关闭警告弹窗', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/create-exception')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { exception_id: 'exc-4', message: 'ok' } }),
          )
        }
        if (url.includes('/enable')) {
          return Promise.resolve(
            jsonResponse(400, { code: 'VALIDATION_ERROR', message: '缺少目标规则 ID，启用门禁未通过' }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderModal(BASE_DETAIL)
    fireEvent.click(await screen.findByRole('button', { name: '创建并发布' }))

    expect(await screen.findByText(/缺少目标规则 ID，启用门禁未通过/)).toBeInTheDocument()
    const link = screen.getByRole('link', { name: '前往例外策略页面完善后启用' })
    fireEvent.click(link)

    await waitFor(() => {
      expect(screen.getByTestId('modal-location')).toHaveTextContent('/exceptions')
    })
    await waitFor(() => {
      expect(screen.queryByRole('link', { name: '前往例外策略页面完善后启用' })).not.toBeInTheDocument()
    })
  })
})
