import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmSlosPage from '../ApmSlosPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

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

const SERVICES = {
  items: [
    {
      application_id: 'svc-1',
      app: 'shop',
      name: '商城站点',
      observation_mode: 'agent',
      agents_online: 1,
      agents_total: 1,
      requests: 5000,
      error_rate: 0.01,
      blocked: 0,
      p50: 10,
      p95: 120,
      p99: 300,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const SLO_LIST = {
  list: [
    {
      id: 'slo-1',
      name: '商城站点可用性',
      service: 'shop',
      metric_type: 'availability',
      target: 0.999,
      window: '30d',
      current_value: 0.9995,
      compliance_ratio: 1,
      error_budget_remaining: 0.83,
      status: 'OK',
      updated_at: '2026-08-30T01:00:00Z',
    },
    {
      id: 'slo-2',
      name: '支付 P95 时延',
      service: 'pay',
      metric_type: 'latency_p95',
      target: 500,
      window: '7d',
      current_value: 620,
      compliance_ratio: 0.91,
      error_budget_remaining: -0.02,
      status: 'BREACHED',
      updated_at: '2026-08-30T01:00:00Z',
    },
  ],
  total: 2,
}

const SLO_DETAIL = {
  ...SLO_LIST.list[0],
  trend: [
    { bucket_start: '2026-08-29T00:00:00Z', compliance_ratio: 1 },
    { bucket_start: '2026-08-30T00:00:00Z', compliance_ratio: 0.998 },
  ],
}

interface MockOptions {
  listStatus?: number
  writeStatus?: number
  list?: unknown
  detail?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/slos/')) return ok(opts.detail ?? SLO_DETAIL)
    if (url.includes('/apm/slos')) {
      if (method !== 'GET') {
        const status = opts.writeStatus ?? 200
        if (status !== 200) {
          return Promise.resolve(
            jsonResponse(status, { code: 'CONFLICT', message: '同名 SLO 已存在', data: null }),
          )
        }
        return ok({ id: 'slo-new', message: 'ok' })
      }
      const status = opts.listStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.list ?? SLO_LIST)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/apm-slos']}>
          <ApmSlosPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmSlosPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.settings.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染 SLO 列表：目标/当前值按指标类型格式化、达标率进度条、剩余预算与状态 Tag', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('商城站点可用性')).toBeInTheDocument()
    expect(screen.getByText('支付 P95 时延')).toBeInTheDocument()
    // availability 目标/当前值按百分比；latency_p95 按毫秒
    expect(screen.getByText('99.90%')).toBeInTheDocument()
    expect(screen.getByText('99.95%')).toBeInTheDocument()
    expect(screen.getByText('500 ms')).toBeInTheDocument()
    expect(screen.getByText('620 ms')).toBeInTheDocument()
    // 状态 Tag
    expect(screen.getByText('达标')).toBeInTheDocument()
    expect(screen.getByText('已违约')).toBeInTheDocument()
    // 指标类型 Tag
    expect(screen.getByText('可用性')).toBeInTheDocument()
    expect(screen.getByText('P95 时延')).toBeInTheDocument()
    // 进度条（达标率 100% 与 91%）
    expect(document.querySelectorAll('.ant-progress').length).toBeGreaterThanOrEqual(2)
  })

  it('无写权限（仅 apm.overview.read）隐藏新建/编辑/删除按钮，保留详情入口', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    expect(screen.queryByRole('button', { name: '新建 SLO' })).not.toBeInTheDocument()
    expect(screen.queryByText('编辑')).not.toBeInTheDocument()
    expect(screen.queryByText('删除')).not.toBeInTheDocument()
    expect(screen.getAllByText('详情').length).toBeGreaterThanOrEqual(1)
  })

  it('新建 SLO：写权限用户提交表单发起 POST 并刷新列表', { timeout: 20000 }, async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.settings.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    fireEvent.click(screen.getByRole('button', { name: '新建 SLO' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：商城站点可用性 SLO'), {
      target: { value: '订单服务可用性' },
    })
    // 服务为 AutoComplete（antd 6 占位符非 input placeholder），其输入框为表单内第一个 combobox
    fireEvent.change(within(dialog).getAllByRole('combobox')[0], {
      target: { value: 'order' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^创\s*建$/ }))

    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes('/apm/slos') && (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
      expect(JSON.parse(String((post![1] as RequestInit).body))).toEqual({
        name: '订单服务可用性',
        service: 'order',
        metric_type: 'availability',
        target: 0.999,
        window: '30d',
      })
    })
    // 创建成功后 Modal 关闭并提示
    expect(await screen.findByText('SLO 已创建')).toBeInTheDocument()
  })

  it('编辑 SLO：表单回填并发起 PUT', { timeout: 20000 }, async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.settings.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    fireEvent.click(screen.getAllByText('编辑')[0])
    const dialog = await screen.findByRole('dialog')
    const nameInput = within(dialog).getByPlaceholderText('如：商城站点可用性 SLO')
    expect(nameInput).toHaveValue('商城站点可用性')
    fireEvent.change(nameInput, { target: { value: '商城站点可用性（调整）' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() => {
      const put = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]) === '/api/v1/apm/slos/slo-1' && (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(put).toBeTruthy()
      expect(JSON.parse(String((put![1] as RequestInit).body)).name).toBe('商城站点可用性（调整）')
    })
  })

  it('删除 SLO：Popconfirm 确认后发起 DELETE', { timeout: 20000 }, async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.settings.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    fireEvent.click(screen.getAllByText('删除')[0])
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      const del = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]) === '/api/v1/apm/slos/slo-1' && (c[1] as RequestInit | undefined)?.method === 'DELETE',
      )
      expect(del).toBeTruthy()
    })
    expect(await screen.findByText('SLO 已删除')).toBeInTheDocument()
  })

  it('写操作失败（409）展示后端错误消息', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch({ writeStatus: 409 }))
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.settings.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    fireEvent.click(screen.getByRole('button', { name: '新建 SLO' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：商城站点可用性 SLO'), {
      target: { value: '重复名称' },
    })
    // 服务为 AutoComplete（antd 6 占位符非 input placeholder），其输入框为表单内第一个 combobox
    fireEvent.change(within(dialog).getAllByRole('combobox')[0], {
      target: { value: 'shop' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^创\s*建$/ }))

    expect(await screen.findByText('同名 SLO 已存在')).toBeInTheDocument()
  })

  it('详情 Drawer：拉取详情并渲染达标率趋势', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点可用性')

    fireEvent.click(screen.getAllByText('详情')[0])
    expect(await screen.findByText('SLO 详情')).toBeInTheDocument()
    expect(await screen.findByText('达标率趋势')).toBeInTheDocument()
    expect(screen.getByTestId('echart-stub')).toBeInTheDocument()
    // 详情接口被调用
    const detailCalls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/slos/slo-1'))
    expect(detailCalls.length).toBeGreaterThanOrEqual(1)
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    useAuthStore.setState({
      user: makeUser(['apm.overview.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
