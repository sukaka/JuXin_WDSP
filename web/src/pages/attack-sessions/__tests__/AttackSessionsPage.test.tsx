import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import AttackSessionsPage from '../AttackSessionsPage'
import { useAuthStore } from '../../../stores/auth'
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

const SESSION_ROW = {
  id: 'ats-1',
  session_key: 'AS-20260831-0001',
  identity_id: 'idn-87231',
  start_time: '2026-08-31T10:00:00Z',
  end_time: '2026-08-31T10:43:00Z',
  request_count: 286,
  event_count: 12,
  risk_score: 96,
  risk_level: 'CRITICAL',
  attack_stage: 'EXPLOIT',
  status: 'OPEN',
  automation_suspected: true,
  automation_basis: 'stages=AUTH_PROBE,EXPLOIT,RECON;indicator=SENSITIVE_PATH_PROBE',
}

function mockFetchWith(body: unknown, status = 200) {
  const envelope =
    status === 200
      ? { code: 'SUCCESS', message: 'ok', data: body }
      : { code: 'INTERNAL_ERROR', message: '数据库异常', data: null }
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/security/attack-sessions')) {
      return Promise.resolve(jsonResponse(status, envelope))
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <MemoryRouter>
            <AttackSessionsPage />
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

/** 点击占位文本所属 Select 的下拉项（antd 占位符 class 为 .ant-select-placeholder） */
async function selectOption(placeholder: string, optionText: string) {
  const candidates = screen.getAllByText(placeholder)
  const target = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
  fireEvent.mouseDown(target)
  const options = await screen.findAllByText(optionText)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('AttackSessionsPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['attack_sessions.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染攻击活动列表：会话号、阶段、风险等级、计数与状态', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({ items: [SESSION_ROW], page: 1, page_size: 20, total: 1 }),
    )
    renderPage()

    expect(await screen.findByText('AS-20260831-0001')).toBeInTheDocument()
    expect(screen.getByText('idn-87231')).toBeInTheDocument()
    expect(screen.getByText('漏洞利用')).toBeInTheDocument()
    expect(screen.getByText('严重')).toBeInTheDocument()
    expect(screen.getByText('96')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('286')).toBeInTheDocument()
    expect(screen.getByText('43分钟')).toBeInTheDocument()
    expect(screen.getByText('进行中')).toBeInTheDocument()
    expect(screen.getByText('疑似自动化攻击')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
  })

  it('未标注会话不渲染自动化攻击徽标', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({
        items: [{ ...SESSION_ROW, automation_suspected: false, automation_basis: 'stages=EXPLOIT' }],
        page: 1,
        page_size: 20,
        total: 1,
      }),
    )
    renderPage()

    expect(await screen.findByText('AS-20260831-0001')).toBeInTheDocument()
    expect(screen.queryByText('疑似自动化攻击')).not.toBeInTheDocument()
  })

  it('阶段筛选：选择「侦察」后请求携带 stage=RECON', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({ items: [SESSION_ROW], page: 1, page_size: 20, total: 1 }),
    )
    renderPage()
    await screen.findByText('AS-20260831-0001')

    await selectOption('攻击阶段', '侦察')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/security/attack-sessions?') && u.includes('stage=RECON'))).toBe(true)
    })
  })

  it('状态筛选：选择「已关闭」后请求携带 status=CLOSED', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({ items: [SESSION_ROW], page: 1, page_size: 20, total: 1 }),
    )
    renderPage()
    await screen.findByText('AS-20260831-0001')

    await selectOption('状态', '已关闭')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('status=CLOSED'))).toBe(true)
    })
  })

  it('列表为空时展示空态', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ items: [], page: 1, page_size: 20, total: 0 }))
    renderPage()

    // antd Empty 的 SVG title 与描述文本同名，用 findAllByText 断言存在即可
    expect((await screen.findAllByText('暂无数据')).length).toBeGreaterThan(0)
  }, 15000)

  it('接口报错时展示错误提示', async () => {
    vi.stubGlobal('fetch', mockFetchWith(null, 500))
    renderPage()

    expect(await screen.findByText('加载攻击活动失败')).toBeInTheDocument()
    expect(screen.getByText('数据库异常')).toBeInTheDocument()
  })
})
