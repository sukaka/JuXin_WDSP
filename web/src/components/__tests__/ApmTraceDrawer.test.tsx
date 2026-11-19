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
      rule_id: 942100,
      request_id: 'req-1',
    },
  ],
  // otel_spans 缺失
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

  it('access_logs 为 null、otel_spans 缺失但有关联事件时正常渲染事件表且中文化动作与 Trace ID', async () => {
    traceBody = legacyMixedTrace
    renderDrawer()
    expect(await screen.findByText('关联 WAF 事件（1）')).toBeInTheDocument()
    expect(screen.getByText(/Trace ID：t-mixed/)).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    expect(screen.getByText('req-1')).toBeInTheDocument()
  })
})
