import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApmTraceDrawer from '../ApmTraceDrawer'
import { useAuthStore } from '../../stores/auth'
import type { CurrentUser } from '../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
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

/** 旧数据结构/异常载荷：三个列表字段为 null 或缺失 */
const legacyNullTrace = {
  trace_id: 't-null',
  access_logs: null,
  security_events: null,
  otel_spans: null,
  partial: false,
  note: '',
}

const legacyMixedTrace = {
  trace_id: 't-mixed',
  access_logs: null,
  security_events: [
    {
      id: 'ev1',
      occurred_at: '2026-09-09T01:00:00Z',
      action: 'BLOCK',
      attack_type: 'SQL_INJECTION',
      severity: 'HIGH',
      response_status: 403,
      request_method: 'POST',
      request_uri: '/api/orders',
      rule_match_count: 2,
      disposition_status: 'UNPROCESSED',
      request_id: 'req-1',
    },
  ],
  // otel_spans 缺失
  partial: false,
  note: '',
}

const traceWithLogs = {
  trace_id: 't-logs',
  access_logs: [
    {
      id: 'log-null-ttfb',
      occurred_at: '2026-09-09T01:00:00Z',
      request_id: 'req-null',
      application_id: null,
      domain: 'shop.example.com',
      client_ip: '10.0.0.1',
      request_method: 'GET',
      request_path: '/health',
      response_status: 200,
      duration_ms: 25,
      ttfb_ms: null,
      waf_action: 'ALLOW',
      endpoint_key: null,
    },
    {
      id: 'log-with-ttfb',
      occurred_at: '2026-09-09T01:00:05Z',
      request_id: 'req-ttfb',
      application_id: null,
      domain: 'shop.example.com',
      client_ip: '10.0.0.2',
      request_method: 'POST',
      request_path: '/checkout',
      response_status: 200,
      duration_ms: 48,
      ttfb_ms: 12,
      waf_action: 'ALLOW',
      endpoint_key: 'POST /checkout',
    },
  ],
  security_events: [],
  otel_spans: [],
  partial: false,
  note: '',
}

let traceBody: Record<string, unknown>

function renderDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApmTraceDrawer traceId="t-null" onClose={() => {}} />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApmTraceDrawer · L27 旧数据结构运行时归一化', () => {
  beforeEach(() => {
    traceBody = legacyNullTrace
    useAuthStore.setState({ user: makeUser(['apm.traces.read']), csrfToken: null, initialized: true })
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: traceBody })),
      ),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('access_logs/security_events/otel_spans 全为 null 时不崩溃，降级为未命中提示', async () => {
    renderDrawer()
    expect(await screen.findByText('未命中，可能未采样或已超保留期')).toBeInTheDocument()
  })

  it('access_logs 为 null、otel_spans 缺失但有关联事件时正常渲染事件表且展示攻击类型/级别/命中数/处置状态', async () => {
    traceBody = legacyMixedTrace
    renderDrawer()
    expect(await screen.findByText('关联 WAF 事件（1）')).toBeInTheDocument()
    expect(screen.getByText(/Trace ID：t-mixed/)).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    expect(screen.getByText('SQL注入')).toBeInTheDocument()
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('未处置')).toBeInTheDocument()
    expect(screen.getByText('req-1')).toBeInTheDocument()
    expect(screen.queryByText('命中规则')).not.toBeInTheDocument()
  })

  it('access_logs 中 ttfb_ms 为 null 时展示占位符 "-"，绝不渲染 "null ms"', async () => {
    traceBody = traceWithLogs
    renderDrawer()
    expect(await screen.findByText('访问记录（2）')).toBeInTheDocument()
    expect(screen.getByText('25 ms')).toBeInTheDocument()
    expect(screen.getByText('48 ms')).toBeInTheDocument()
    expect(screen.getByText('12 ms')).toBeInTheDocument()
    expect(screen.queryByText(/null ms/i)).not.toBeInTheDocument()
  })
})
