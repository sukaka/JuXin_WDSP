import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import EventDetailDrawer from '../EventDetailDrawer'
import { useAuthStore } from '../../../stores/auth'
import { useProductStore } from '../../../stores/product'
import type { CurrentUser } from '../../../types'

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

const EVENT_DETAIL = {
  event: {
    id: 'evt-1',
    request_id: 'req-trace-1',
    occurred_at: '2026-08-30T00:30:00Z',
    application_id: 'app-1',
    application_name_snapshot: '商城站点',
    domain: 'shop.example.com',
    gateway_node_id: 'node-1',
    client_ip: '1.2.3.4',
    client_port: 51000,
    request_method: 'GET',
    request_uri: '/api/orders?id=1',
    request_path: '/api/orders',
    query_summary: 'id=1',
    http_version: 'HTTP/1.1',
    content_type: '',
    user_agent_summary: 'curl',
    referer_summary: '',
    attack_type: 'sqli',
    severity: 'HIGH',
    anomaly_score: 10,
    action: 'BLOCK',
    response_status: 403,
    rule_match_count: 1,
    disposition_status: 'PENDING',
    disposition_result: '',
    raw_log_reference: '',
  },
  matches: [],
  notes: [],
  actions: [],
  related: [],
}

function mockFetch(detail: unknown = EVENT_DETAIL) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/remediation')) {
      return Promise.resolve(jsonResponse(404, { code: 'NOT_FOUND', message: '无建议', data: null }))
    }
    if (url.includes('/security-events/')) return ok(detail)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <EventDetailDrawer eventId="evt-1" onClose={() => {}} onSelectEvent={() => {}} />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('EventDetailDrawer 关联 Trace 跳转', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useProductStore.setState({ apmEnabled: true, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('apmEnabled 且持有 apm.traces.read 时展示「关联 Trace」，链接携带 request_id、application_id、±5 分钟时间窗与站内返回地址', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    const button = await screen.findByRole('button', { name: '关联 Trace' })
    const href = button.closest('a')!.getAttribute('href')!
    expect(href.startsWith('/apm-traces?')).toBe(true)
    const qs = new URLSearchParams(href.slice('/apm-traces?'.length))
    expect(qs.get('request_id')).toBe('req-trace-1')
    expect(qs.get('application_id')).toBe('app-1')
    // 事件时间 2026-08-30T00:30:00Z 前后各 5 分钟
    expect(qs.get('start_time')).toBe('2026-08-30T00:25:00.000Z')
    expect(qs.get('end_time')).toBe('2026-08-30T00:35:00.000Z')
    expect(qs.get('from')).toBe('/security-events')
  })

  it('APM 能力关闭时不渲染「关联 Trace」', async () => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.queryByRole('button', { name: '关联 Trace' })).not.toBeInTheDocument()
  })

  it('无 apm.traces.read 权限时不渲染「关联 Trace」', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.queryByRole('button', { name: '关联 Trace' })).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer JWT 验证信息', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('事件携带 jwt_verification 时展示状态/原因/主体指纹/策略版本', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          jwt_verification: {
            status: 'VERIFIED',
            reason_code: 'VALID',
            verified_principal_id: 'hmac-fp-9f8e7d',
            policy_version: 3,
            issuer_config_id: 'iss-01',
            keyset_version: 'ks-2026-09',
            evaluated_at: '2026-08-30T00:30:00Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('JWT 验证信息')).toBeInTheDocument()
    // 状态标签与原因码 VALID 的中文均为「验证通过」，断言至少出现一处
    expect(screen.getAllByText('验证通过').length).toBeGreaterThan(0)
    expect(screen.getByText('hmac-fp-9f8e7d')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('iss-01')).toBeInTheDocument()
    expect(screen.getByText('ks-2026-09')).toBeInTheDocument()
  })

  it('历史事件无 jwt_verification 字段时显示「当时未记录」', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.getByText('JWT 验证信息')).toBeInTheDocument()
    expect(
      screen.getByText('当时未记录 JWT 验证信息（历史事件或未启用 JWT 信任策略）'),
    ).toBeInTheDocument()
  })

  it('UNVERIFIED 显示为「未验证」，不渲染为「非法用户」', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          jwt_verification: {
            status: 'UNVERIFIED',
            reason_code: 'POLICY_OFF',
            policy_version: 0,
            evaluated_at: '2026-08-30T00:30:00Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('未验证')).toBeInTheDocument()
    expect(screen.getByText(/不代表用户非法/)).toBeInTheDocument()
    expect(screen.queryByText(/非法用户/)).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer 最终处置（P0-04）', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('历史事件无 final_decision：显示「该事件无最终处置记录（旧数据）」，不用空图', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.getByText('最终处置')).toBeInTheDocument()
    const empty = screen.getByText('该事件无最终处置记录（旧数据）')
    // 空态为纯文本说明，不用空图（Empty 组件）
    expect(empty.closest('div')?.querySelector('.ant-empty')).toBeNull()
  })

  it('API ALLOW（中间决策）+ WAF BLOCK（最终处置）区分展示：执行模块 WAF，API 决策单独一行', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            request_id: 'req-trace-1',
            application_id: 'app-1',
            gateway_node: 'node-1',
            completion_status: 'COMPLETED',
            security_action: 'BLOCK',
            executor_module: 'WAF',
            response_source: 'GATEWAY',
            http_status: 403,
            response_committed: true,
            reason_codes: ['WAF_RULE_MATCH'],
            rule_refs: [{ module: 'WAF', rule_id: '942100', version: '4.26.0' }],
            effective_config: {
              config_fingerprint: 'fp-shop-01',
              api_policy_version: 'apv-7',
              exception_versions: { 'e4b6f7a8-0000-4000-8000-000000000001': 2 },
            },
            findings: { observed: 1, enforced: 1, excepted: 0, skipped: 2 },
            steps: [
              { module: 'RISK_POLICY', result: 'OBSERVED', detail: 'observe 模式命中' },
              { module: 'API', result: 'EXECUTED', detail: 'final_action=ALLOW' },
              { module: 'WAF', result: 'EXECUTED', detail: 'rule 942100 matched' },
              { module: 'CC', result: 'SKIPPED' },
            ],
            matched_exceptions: [
              {
                exception_id: 'e4b6f7a8-0000-4000-8000-000000000001',
                version: 2,
                target: 'WAF',
                rule_refs: ['949110'],
                scope_summary: 'shop.example.com POST /api/orders',
                effective_from: '2026-08-30T00:00:00Z',
                effective_until: '2026-08-30T00:30:00Z',
              },
            ],
            finalized_at: '2026-08-30T00:30:01Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    // 最终处置：执行模块为 WAF，安全动作行为「阻断」
    expect(screen.getByText('执行模块')).toBeInTheDocument()
    expect(screen.getByText('WAF（Coraza/CRS）')).toBeInTheDocument()
    {
      let row: HTMLElement | null = screen.getByText('安全动作')
      while (row && !row.textContent?.includes('阻断')) row = row.parentElement
      expect(row).toBeTruthy()
    }
    // API 中间决策单独一行，且不等于最终放行
    expect(screen.getByText('API 中间决策')).toBeInTheDocument()
    expect(screen.getByText('API EXECUTED：final_action=ALLOW')).toBeInTheDocument()
    expect(
      screen.getByText(/API 决策为中间结果：API ALLOW 不等于最终放行/),
    ).toBeInTheDocument()
    // 规则引用 / 有效配置 / 命中例外 / Finding 计数 / 步骤语义
    expect(screen.getByText('WAF 942100@4.26.0')).toBeInTheDocument()
    expect(screen.getByText(/fp-shop-01/)).toBeInTheDocument()
    expect(screen.getByText(/shop\.example\.com POST \/api\/orders/)).toBeInTheDocument()
    expect(screen.getByText('仅观察 1')).toBeInTheDocument()
    expect(screen.getByText('例外豁免 0')).toBeInTheDocument()
    expect(screen.getByText('仅观察')).toBeInTheDocument()
    expect(screen.getByText('未运行')).toBeInTheDocument()
    expect(screen.getByText('执行过程（4 步）')).toBeInTheDocument()
  })

  it('步骤超出有界上限：显示「已截断」提示', async () => {
    const steps = Array.from({ length: 33 }, (_, i) => ({
      module: `MOD_${i}`,
      result: 'SKIPPED',
    }))
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'NONE',
            executor_module: 'NONE',
            response_source: 'ORIGIN',
            http_status: 200,
            completion_status: 'COMPLETED',
            steps,
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('执行过程（33 步）')).toBeInTheDocument()
    expect(screen.getByText('已截断：超出 32 步未显示')).toBeInTheDocument()
    // 仅渲染前 32 步
    expect(screen.queryByText('MOD_32')).not.toBeInTheDocument()
    expect(screen.getByText('MOD_31')).toBeInTheDocument()
  })

  it('completion_status=PENDING_CORRELATION：显示「证据待关联」，不伪造规则明细', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'BLOCK',
            executor_module: 'WAF',
            response_source: 'GATEWAY',
            http_status: 403,
            completion_status: 'PENDING_CORRELATION',
            rule_refs: [],
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('证据待关联')).toBeInTheDocument()
    // 安全动作行为「阻断」（事件概览的 action 列也可能出现同文案，按行容器断言）
    let row: HTMLElement | null = screen.getByText('安全动作')
    while (row && !row.textContent?.includes('阻断')) row = row.parentElement
    expect(row).toBeTruthy()
  })

  it('CHALLENGE/BOT（P1-02 Bot 挑战）：映射展示为「Bot 挑战」', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'CHALLENGE',
            executor_module: 'BOT',
            response_source: 'GATEWAY',
            http_status: 403,
            completion_status: 'COMPLETED',
            reason_codes: ['BOT_CHALLENGE_OFFERED'],
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    // 安全动作与执行模块均命中新映射（同文案出现两处：动作行 + 模块行）
    expect(screen.getAllByText('Bot 挑战').length).toBeGreaterThanOrEqual(2)
  })

  it('未知安全动作/执行模块（未来新增值）：原样展示原始值，不渲染为空或误导文案', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'FUTURE_ACTION_X',
            executor_module: 'FUTURE_MODULE_X',
            response_source: 'GATEWAY',
            http_status: 418,
            completion_status: 'COMPLETED',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_ACTION_X')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_MODULE_X')).toBeInTheDocument()
  })
})
