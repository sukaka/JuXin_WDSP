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
    roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
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

  it('拉取未处理告警展示角标，确认后红色角标与红色提示立即消失并支持跳转全部告警', async () => {
    let alerts: SystemAlertItem[] = [SAMPLE_ALERT]
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/system-alerts/alert-1/acknowledge') && init?.method === 'POST') {
        alerts = alerts.map((item) =>
          item.id === 'alert-1' ? { ...item, status: 'ACKNOWLEDGED' } : item,
        )
        return Promise.resolve(jsonResponse({ ...SAMPLE_ALERT, status: 'ACKNOWLEDGED' }))
      }
      if (url.includes('/system-alerts')) {
        const openOnly = url.includes('status=OPEN')
          ? alerts.filter((item) => item.status === 'OPEN')
          : alerts
        return Promise.resolve(
          jsonResponse({ items: openOnly, total: openOnly.length, page: 1, page_size: 8 }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    const { container } = renderPopover()

    const bellBtn = await screen.findByRole('button', { name: '站内告警（1 条未处理）' })
    expect(
      fetchMock.mock.calls.some(
        (c) =>
          String(c[0]).includes('/system-alerts?') &&
          String(c[0]).includes('status=OPEN') &&
          !String(c[0]).includes('view=ACTIVE'),
      ),
    ).toBe(true)
    expect(container.querySelector('.ant-badge-count')).toBeInTheDocument()

    fireEvent.click(bellBtn)
    expect(await screen.findByText('网关节点 gw-1 健康检查异常')).toBeInTheDocument()
    expect(screen.getByText('1 条未处理')).toBeInTheDocument()
    expect(screen.getByText('高危')).toBeInTheDocument()

    // 一键确认仅触发 POST /acknowledge，不跳转到系统告警页，且重拉后红色角标和红色标签消失
    fireEvent.click(screen.getByRole('button', { name: /确\s*认/ }))
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          (c) => String(c[0]).includes('/system-alerts/alert-1/acknowledge') && c[1]?.method === 'POST',
        ),
      ).toBe(true)
    })
    expect(screen.queryByText('system-alerts-page')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: '站内告警' })).toBeInTheDocument()
      expect(container.querySelector('.ant-badge-count')).not.toBeInTheDocument()
      expect(screen.queryByText('1 条未处理')).not.toBeInTheDocument()
      expect(screen.getByText('无未处理')).toBeInTheDocument()
      expect(screen.getByText('当前无未处理告警')).toBeInTheDocument()
    })

    // 点击底部入口跳转到系统告警页
    fireEvent.click(screen.getByRole('button', { name: /查看全部系统告警/ }))
    expect(await screen.findByText('system-alerts-page')).toBeInTheDocument()
  })

  it('无确认权限时不显示快捷确认按钮，且无未处理告警时隐藏角标并显示空态', async () => {
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

    const { container } = renderPopover()
    const bellBtn = await screen.findByRole('button', { name: '站内告警' })
    expect(container.querySelector('.ant-badge-count')).not.toBeInTheDocument()
    fireEvent.click(bellBtn)

    expect(await screen.findByText('当前无未处理告警')).toBeInTheDocument()
    expect(screen.getByText('无未处理')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /确\s*认/ })).not.toBeInTheDocument()
  })

  it('告警已在其他页面被确认返回 409 时，自动刷新并消除过期红色角标', async () => {
    let listCalls = 0
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/system-alerts/alert-1/acknowledge') && init?.method === 'POST') {
        return Promise.resolve(
          new Response(
            JSON.stringify({ code: 'RESOURCE_CONFLICT', message: '当前状态不允许该操作' }),
            { status: 409, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      if (url.includes('/system-alerts')) {
        listCalls += 1
        if (listCalls <= 2) {
          return Promise.resolve(
            jsonResponse({ items: [SAMPLE_ALERT], total: 1, page: 1, page_size: 8 }),
          )
        }
        return Promise.resolve(jsonResponse({ items: [], total: 0, page: 1, page_size: 8 }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    const { container } = renderPopover()
    const bellBtn = await screen.findByRole('button', { name: '站内告警（1 条未处理）' })
    fireEvent.click(bellBtn)
    fireEvent.click(await screen.findByRole('button', { name: /确\s*认/ }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: '站内告警' })).toBeInTheDocument()
      expect(container.querySelector('.ant-badge-count')).not.toBeInTheDocument()
    })
  })
})
