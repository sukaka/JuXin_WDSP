import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AttackSessionDetailPage from '../AttackSessionDetailPage'
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

const SESSION = {
  id: 'ats-1',
  session_key: 'AS-20260831-0001',
  identity_id: 'idn-87231',
  start_time: '2026-08-31T10:00:00Z',
  end_time: '2026-08-31T10:43:00Z',
  request_count: 286,
  event_count: 3,
  risk_score: 96,
  risk_level: 'CRITICAL',
  attack_stage: 'EXPLOIT',
  status: 'OPEN',
  automation_suspected: true,
  automation_basis: 'stages=AUTH_PROBE,EXPLOIT,RECON;indicator=SENSITIVE_PATH_PROBE',
}

const EVENTS = [
  { source_table: 'identity_behavior_events', source_id: '101', occurred_at: '2026-08-31T10:02:00Z', stage: 'RECON' },
  { source_table: 'behavior_event', source_id: '102', occurred_at: '2026-08-31T10:11:00Z', stage: 'AUTH_PROBE' },
  { source_table: 'security_events', source_id: '207', occurred_at: '2026-08-31T10:40:00Z', stage: 'AUTH_PROBE' },
]

function mockFetchWith(body: unknown, status = 200) {
  const envelope =
    status === 200
      ? { code: 'SUCCESS', message: 'ok', data: body }
      : { code: 'INTERNAL_ERROR', message: '数据库异常', data: null }
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/security/attack-sessions/')) {
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
          <MemoryRouter initialEntries={['/attack-sessions/ats-1']}>
            <Routes>
              <Route path="/attack-sessions/:id" element={<AttackSessionDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

describe('AttackSessionDetailPage', () => {
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

  it('渲染会话卡：会话号、身份链接、阶段、风险分与持续时长', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ session: SESSION, events: EVENTS }))
    renderPage()

    expect(await screen.findByText('AS-20260831-0001')).toBeInTheDocument()
    const identityLink = screen.getByRole('link', { name: 'idn-87231' })
    expect(identityLink).toHaveAttribute('href', '/risk-identities/idn-87231')
    expect(screen.getAllByText('漏洞利用').length).toBeGreaterThan(0)
    expect(screen.getByText('96 / 100')).toBeInTheDocument()
    expect(screen.getAllByText('严重').length).toBeGreaterThan(0)
    expect(screen.getByText('进行中')).toBeInTheDocument()
    expect(screen.getByText('43分钟')).toBeInTheDocument()
    expect(screen.getByText('286')).toBeInTheDocument()
    // 自动化标注：徽标（标题区+描述列表各一）与中文化判定依据
    expect(screen.getAllByText('疑似自动化攻击').length).toBeGreaterThan(0)
    expect(
      screen.getByText('命中阶段：认证探测、漏洞利用、侦察；指示信号：敏感路径探测'),
    ).toBeInTheDocument()
  })

  it('未标注会话展示「未标注」且不渲染徽标', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({
        session: { ...SESSION, automation_suspected: false, automation_basis: 'stages=EXPLOIT' },
        events: EVENTS,
      }),
    )
    renderPage()

    expect(await screen.findByText('未标注')).toBeInTheDocument()
    expect(screen.queryByText('疑似自动化攻击')).not.toBeInTheDocument()
  })

  it('时间线按时间序展示关联事件：阶段标签、时间与来源记录', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ session: SESSION, events: EVENTS }))
    renderPage()

    expect(await screen.findByText('关联事件（3）')).toBeInTheDocument()
    expect(screen.getByText('身份行为事件#101')).toBeInTheDocument()
    expect(screen.getByText('behavior_event#102')).toBeInTheDocument()
    expect(screen.getByText('WAF 安全事件#207')).toBeInTheDocument()
    // 阶段标签：侦察 ×1、认证探测 ×2（时间线标签 + 分布标签合计）
    expect(screen.getAllByText('侦察').length).toBeGreaterThan(0)
    expect(screen.getAllByText('认证探测').length).toBeGreaterThan(0)
  })

  it('风险分组成：按攻击链顺序展示事件阶段分布', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ session: SESSION, events: EVENTS }))
    renderPage()

    expect(await screen.findByText(/风险分组成/)).toBeInTheDocument()
    expect(screen.getByText('侦察 ×1')).toBeInTheDocument()
    expect(screen.getByText('认证探测 ×2')).toBeInTheDocument()
    // 攻击链顺序：侦察 在 认证探测 之前
    const recon = screen.getByText('侦察 ×1')
    const authProbe = screen.getByText('认证探测 ×2')
    expect(recon.compareDocumentPosition(authProbe) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('events 为 null 时归一化为空态', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ session: SESSION, events: null }))
    renderPage()

    expect(await screen.findByText('暂无关联事件')).toBeInTheDocument()
    expect(screen.getByText('关联事件（0）')).toBeInTheDocument()
  })

  it('接口报错时展示错误提示', async () => {
    vi.stubGlobal('fetch', mockFetchWith(null, 500))
    renderPage()

    expect(await screen.findByText('加载攻击活动详情失败')).toBeInTheDocument()
    expect(screen.getByText('数据库异常')).toBeInTheDocument()
  })
})
