import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import HeaderAlertsPopover from '../HeaderAlertsPopover'
import { useAuthStore } from '../../stores/auth'
import type { CurrentUser, SystemAlertItem } from '../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'oper',
    display_name: 'oper',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SAMPLE_ALERT: SystemAlertItem = {
  id: 'alert-1',
  alert_type: 'GATEWAY_DOWN',
  severity: 'HIGH',
  component: 'GATEWAY',
  title: '网关节点 gw-1 健康检查异常',
  message: '连续 3 次探活失败',
  status: 'OPEN',
  first_seen_at: '2026-11-20T12:00:00Z',
  last_seen_at: '2026-11-20T12:05:00Z',
  occurrence_count: 3,
  created_at: '2026-11-20T12:00:00Z',
}

function renderPopover(disabled = false) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <AntdApp>
          <Routes>
            <Route path="/dashboard" element={<HeaderAlertsPopover disabled={disabled} />} />
            <Route path="/system-alerts" element={<div>system-alerts-page</div>} />
          </Routes>
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('HeaderAlertsPopover 站内告警铃铛', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['system_alerts.read_security', 'system_alerts.acknowledge_security']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('拉取活跃告警展示角标，点击铃铛展开告警列表并支持一键确认与跳转全部告警', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/system-alerts/alert-1/acknowledge') && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ ...SAMPLE_ALERT, status: 'ACKNOWLEDGED' }))
      }
      if (url.includes('/system-alerts')) {
        return Promise.resolve(
          jsonResponse({ items: [SAMPLE_ALERT], total: 2, page: 1, page_size: 8 }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPopover()

    const bellBtn = await screen.findByRole('button', { name: '站内告警（2 条活跃）' })
    expect(
      fetchMock.mock.calls.some(
        (c) => String(c[0]).includes('/system-alerts?') && String(c[0]).includes('view=ACTIVE'),
      ),
    ).toBe(true)

    fireEvent.click(bellBtn)
    expect(await screen.findByText('网关节点 gw-1 健康检查异常')).toBeInTheDocument()
    expect(screen.getByText('2 条活跃')).toBeInTheDocument()
    expect(screen.getByText('高危')).toBeInTheDocument()

    // 一键确认仅触发 POST /acknowledge，不跳转到系统告警页
    fireEvent.click(screen.getByRole('button', { name: /确\s*认/ }))
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          (c) => String(c[0]).includes('/system-alerts/alert-1/acknowledge') && c[1]?.method === 'POST',
        ),
      ).toBe(true)
    })
    expect(screen.queryByText('system-alerts-page')).not.toBeInTheDocument()

    // 点击底部入口跳转到系统告警页
    fireEvent.click(screen.getByRole('button', { name: /查看全部系统告警/ }))
    expect(await screen.findByText('system-alerts-page')).toBeInTheDocument()
  })

  it('无确认权限时不显示快捷确认按钮，且无活跃告警时显示空态', async () => {
    useAuthStore.setState({
      user: makeUser(['system_alerts.read_audit']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).includes('/system-alerts')) {
          return Promise.resolve(jsonResponse({ items: [], total: 0, page: 1, page_size: 8 }))
        }
        return Promise.reject(new Error(`unexpected url: ${String(input)}`))
      }),
    )

    renderPopover()
    const bellBtn = await screen.findByRole('button', { name: '站内告警' })
    fireEvent.click(bellBtn)

    expect(await screen.findByText('当前无活跃告警')).toBeInTheDocument()
    expect(screen.getByText('正常')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /确\s*认/ })).not.toBeInTheDocument()
  })
})
