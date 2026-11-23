import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DeliveryCheckPage from '../DeliveryCheckPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, DeliveryCheckItem, DeliveryCheckResultItem } from '../../../types'
import type { Mock } from 'vitest'

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const CHECK_PASS: DeliveryCheckItem = {
  id: 'chk-11111111-2222-3333-4444-555555555555',
  overall_result: 'PASS',
  total: 2,
  pass_count: 2,
  warning_count: 0,
  fail_count: 0,
  requested_by: 'u1',
  started_at: '2026-11-20T08:00:00Z',
  finished_at: '2026-11-20T08:00:05Z',
}

const CHECK_FAIL: DeliveryCheckItem = {
  id: 'chk-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  overall_result: 'FAIL',
  total: 1,
  pass_count: 0,
  warning_count: 0,
  fail_count: 1,
  requested_by: 'u1',
  started_at: '2026-11-20T07:00:00Z',
  finished_at: '2026-11-20T07:00:03Z',
}

const CHECK_PENDING: DeliveryCheckItem = {
  id: 'chk-99999999-0000-0000-0000-000000000000',
  overall_result: 'PENDING',
  total: 0,
  pass_count: 0,
  warning_count: 0,
  fail_count: 0,
  requested_by: 'u1',
  started_at: '2026-11-20T09:00:00Z',
  finished_at: null,
}

const RESULTS_PASS: DeliveryCheckResultItem[] = [
  {
    item_key: 'components_up',
    item_name: '核心组件运行状态',
    category: '运行状态',
    result: 'PASS',
    critical: true,
    message: '所有组件健康',
  },
  {
    item_key: 'https_config',
    item_name: 'HTTPS 证书配置',
    category: '安全配置',
    result: 'PASS',
    critical: false,
    message: '已启用 TLS',
  },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <DeliveryCheckPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('DeliveryCheckPage (B11-1 / B11-2 / B11-3)', () => {
  beforeEach(() => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'sysadmin',
      display_name: '系统管理员',
      status: 'ACTIVE',
      roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
      permissions: ['delivery_checks.read', 'delivery_checks.run'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示 overall_result（含 PENDING 进行中）与 started_at，点击运行检查消费 { check, results } 并展示 item_name / item_key', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/delivery-checks/run') && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ check: CHECK_PASS, results: RESULTS_PASS }))
      }
      if (url.includes(`/delivery-checks/${CHECK_PASS.id}`)) {
        return Promise.resolve(jsonResponse({ check: CHECK_PASS, results: RESULTS_PASS }))
      }
      if (url.includes(`/delivery-checks/${CHECK_PENDING.id}`)) {
        return Promise.resolve(jsonResponse({ check: CHECK_PENDING, results: [] }))
      }
      if (url.includes('/delivery-checks')) {
        return Promise.resolve(
          jsonResponse({
            items: [CHECK_FAIL, CHECK_PENDING],
            page: 1,
            page_size: 10,
            total: 2,
          }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPage()

    expect(await screen.findByText('进行中')).toBeInTheDocument()
    expect(screen.getAllByText('失败').length).toBeGreaterThanOrEqual(2)

    // 触发运行检查
    fireEvent.click(screen.getByRole('button', { name: /运行检查/ }))
    const dialog = await screen.findByRole('dialog')
    const okBtn = dialog.querySelector('.ant-modal-confirm-btns .ant-btn-primary') as HTMLElement
    expect(okBtn).toBeTruthy()
    fireEvent.click(okBtn)

    await waitFor(() => {
      expect(screen.getByText('核心组件运行状态')).toBeInTheDocument()
      expect(screen.getByText('HTTPS 证书配置')).toBeInTheDocument()
    })

    // 绝不能向 /delivery-checks/undefined 发起请求
    const calledUrls = (fetchMock as Mock).mock.calls.map((c) => String(c[0]))
    expect(calledUrls.some((u) => u.includes('/delivery-checks/undefined'))).toBe(false)

    // rowKey 应为 item_key
    expect(document.querySelector('tr[data-row-key="components_up"]')).toBeInTheDocument()
    expect(document.querySelector('tr[data-row-key="https_config"]')).toBeInTheDocument()

    // 终态 check 不应显示进行中提示
    expect(screen.queryByText('检查执行中，结果将自动刷新…')).not.toBeInTheDocument()
  })

  it('查看 PENDING 与 FAIL 检查详情时分别展示进行中与关键项失败提示', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes(`/delivery-checks/${CHECK_PENDING.id}`)) {
          return Promise.resolve(jsonResponse({ check: CHECK_PENDING, results: [] }))
        }
        if (url.includes(`/delivery-checks/${CHECK_FAIL.id}`)) {
          return Promise.resolve(
            jsonResponse({
              check: CHECK_FAIL,
              results: [
                {
                  item_key: 'waf_detection',
                  item_name: 'WAF 检测能力',
                  category: '防护能力',
                  result: 'FAIL',
                  critical: true,
                  message: '阻断未生效',
                },
              ],
            }),
          )
        }
        return Promise.resolve(
          jsonResponse({ items: [CHECK_PENDING, CHECK_FAIL], page: 1, page_size: 10, total: 2 }),
        )
      }),
    )

    renderPage()

    const viewButtons = await screen.findAllByRole('button', { name: '查看' })
    expect(viewButtons).toHaveLength(2)

    // 第1行是 PENDING
    fireEvent.click(viewButtons[0])
    expect(await screen.findByText('检查执行中，结果将自动刷新…')).toBeInTheDocument()

    // 第2行是 FAIL
    fireEvent.click(viewButtons[1])
    expect(await screen.findByText('存在关键检查项失败，不得标记正式交付')).toBeInTheDocument()
    expect(screen.getByText('WAF 检测能力')).toBeInTheDocument()
    expect(screen.queryByText('检查执行中，结果将自动刷新…')).not.toBeInTheDocument()
  })
})
