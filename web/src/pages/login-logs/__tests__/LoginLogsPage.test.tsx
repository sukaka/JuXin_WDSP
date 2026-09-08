import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import LoginLogsPage from '../LoginLogsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, LoginLogEntry } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'auditor',
    display_name: '审计员',
    status: 'ACTIVE',
    roles: [{ code: 'AUDITOR', name: '审计员' }],
    permissions,
    must_change_password: false,
  }
}

function makeEntry(partial: Partial<LoginLogEntry>): LoginLogEntry {
  return {
    id: 'log-1',
    occurred_at: '2026-09-04T08:00:00Z',
    username: 'ops',
    source_ip: '10.0.0.8',
    event_type: 'LOGIN_SUCCESS',
    result: 'SUCCESS',
    failure_code: null,
    request_id: null,
    ...partial,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch(entries: LoginLogEntry[]) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/login-logs')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: entries, page: 1, page_size: 20, total: entries.length },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <LoginLogsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('LoginLogsPage 登录日志', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: makeUser(['login_logs.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('事件类型与失败码中文映射：含 TOTP 双因子相关枚举', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch([
        makeEntry({ id: 'l1', event_type: 'LOGIN_TOTP_CHALLENGE' }),
        makeEntry({
          id: 'l2',
          event_type: 'LOGIN_FAILURE',
          result: 'FAILURE',
          failure_code: 'TOTP_CHALLENGE_INVALID',
        }),
        makeEntry({
          id: 'l3',
          event_type: 'LOGIN_FAILURE',
          result: 'FAILURE',
          failure_code: 'TOTP_INVALID',
        }),
      ]),
    )
    renderPage()

    // 事件类型：LOGIN_TOTP_CHALLENGE 不裸码显示
    expect(await screen.findByText('双因子挑战（TOTP）')).toBeInTheDocument()
    // 失败码：TOTP_CHALLENGE_INVALID / TOTP_INVALID 不裸码显示
    expect(screen.getByText('双因子挑战无效或过期')).toBeInTheDocument()
    expect(screen.getByText('动态令牌或恢复码错误')).toBeInTheDocument()
    expect(screen.queryByText('LOGIN_TOTP_CHALLENGE')).not.toBeInTheDocument()
    expect(screen.queryByText('TOTP_INVALID')).not.toBeInTheDocument()
  })

  it('事件类型筛选下拉包含「双因子挑战（TOTP）」选项', async () => {
    vi.stubGlobal('fetch', mockFetch([]))
    renderPage()
    // 空数据时 antd Table 不渲染分页文案（total 为 0 时分页整体不挂载），以空态节点作为列表加载完成信号
    await waitFor(() => expect(document.querySelector('.ant-empty')).toBeTruthy())

    const candidates = screen.getAllByText('事件类型')
    const placeholder = candidates.find((el) => el.closest('.ant-select-placeholder'))
    expect(placeholder).toBeTruthy()
    fireEvent.mouseDown(placeholder as HTMLElement)
    const option = await screen.findAllByText('双因子挑战（TOTP）')
    expect(option.some((el) => el.closest('.ant-select-item-option-content'))).toBe(true)
  })
})
