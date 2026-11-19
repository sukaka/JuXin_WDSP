import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiAdmissionPage from '../ApiAdmissionPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

function makeApp(id: string, code: string, name: string, mode: string | undefined, version: number) {
  return {
    id,
    code,
    name,
    description: '',
    business_owner: '',
    technical_owner: '',
    status: 'ACTIVE',
    protection_mode: 'PROTECT',
    deployment_status: 'PUBLISHED',
    health_status: 'HEALTHY',
    last_publish_result: 'SUCCESS',
    domain_count: 1,
    upstream_count: 1,
    // app-3 故意缺省该字段：缺省按 OFF 处理
    ...(mode !== undefined ? { api_admission_mode: mode } : {}),
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version,
  }
}

const appsData = {
  items: [
    makeApp('app-1', 'shop', '商城应用', 'OBSERVE', 3),
    makeApp('app-2', 'pay', '支付应用', 'PROTECT', 1),
    makeApp('app-3', 'legacy', '遗留应用', undefined, 5),
  ],
  page: 1,
  page_size: 20,
  total: 3,
}

const coverageApp1 = {
  application_id: 'app-1',
  mode: 'OBSERVE',
  hits_window_hours: 168,
  endpoints: { confirmed: 24, discovered: 5, ignored: 1, deprecated: 0, zombie: 0 },
  confirm_rate: 0.8,
  unconfirmed_hot: [
    {
      endpoint_key: 'GET /v1/coupon',
      http_method: 'GET',
      normalized_path: '/v1/coupon',
      asset_status: 'DISCOVERED',
      hits: 1320,
      last_seen_at: '2026-09-20T08:00:00Z',
    },
    {
      endpoint_key: 'POST /v1/feedback',
      http_method: 'POST',
      normalized_path: '/v1/feedback',
      asset_status: 'DISCOVERED',
      hits: 12,
      last_seen_at: '2026-09-19T08:00:00Z',
    },
  ],
  blocked: 0,
}

const coverageApp2 = {
  application_id: 'app-2',
  mode: 'PROTECT',
  hits_window_hours: 168,
  endpoints: { confirmed: 10, discovered: 0, ignored: 0, deprecated: 0, zombie: 0 },
  confirm_rate: 1,
  unconfirmed_hot: [],
  blocked: 7,
}

const coverageApp3 = {
  application_id: 'app-3',
  mode: 'OFF',
  hits_window_hours: 168,
  endpoints: { confirmed: 0, discovered: 0, ignored: 0, deprecated: 0, zombie: 0 },
  confirm_rate: 0,
  unconfirmed_hot: [],
  blocked: 0,
}

const endpointsApp1 = [
  {
    id: 'e1',
    endpoint_key: 'GET /v1/coupon',
    http_method: 'GET',
    normalized_path: '/v1/coupon',
    application_name: '商城应用',
    directory_path: '',
    asset_status: 'DISCOVERED',
    learning_status: 'LEARNING',
    hit_count: 1320,
    first_seen_at: '2026-08-01T00:00:00Z',
    last_seen_at: '2026-09-20T08:00:00Z',
  },
  {
    id: 'e2',
    endpoint_key: 'POST /v1/feedback',
    http_method: 'POST',
    normalized_path: '/v1/feedback',
    application_name: '商城应用',
    directory_path: '',
    asset_status: 'DISCOVERED',
    learning_status: 'NOT_STARTED',
    hit_count: 12,
    first_seen_at: '2026-08-02T00:00:00Z',
    last_seen_at: '2026-09-19T08:00:00Z',
  },
]

const endpointsApp2 = [
  {
    id: 'e9',
    endpoint_key: 'GET /v1/admin',
    http_method: 'GET',
    normalized_path: '/v1/admin',
    application_name: '支付应用',
    directory_path: '',
    asset_status: 'DISCOVERED',
    learning_status: 'NOT_STARTED',
    hit_count: 3,
    first_seen_at: '2026-09-01T00:00:00Z',
    last_seen_at: '2026-09-20T09:00:00Z',
  },
]

const deniedItemApp2 = {
  endpoint_key: 'GET /v1/admin',
  http_method: 'GET',
  normalized_path: '/v1/admin',
  asset_status: 'DISCOVERED',
  denied_count: 3,
  last_denied_at: '2026-09-20T09:00:00Z',
  sample_client_ips: ['198.51.100.7'],
  first_seen_at: '2026-09-01T00:00:00Z',
}

function urlOf(input: RequestInfo | URL): URL {
  return new URL(String(input), 'http://localhost')
}

/** 默认 mock：按 application_id 分发覆盖率/拦截/资产数据；failApps=true 时应用列表 500 */
function mockFetch({ failApps = false, globalMode = 'OBSERVE' }: { failApps?: boolean; globalMode?: string } = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const u = urlOf(input)
    const method = init?.method ?? 'GET'
    const appId = u.searchParams.get('application_id')
    if (method === 'GET' && url.includes('/api-security/policy')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            edition: 'WDSP',
            api_dynamic_protection: true,
            mode: globalMode,
            mode_source: 'CONFIG',
            limits: { max_body_parse_bytes: 1024, max_body_sample_bytes: 1024, max_json_depth: 32, max_field_count: 512 },
          },
        }),
      )
    }
    if (method === 'PUT' && /\/api\/v1\/applications\/[^/?]+/.test(url)) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { ...appsData.items[0], api_admission_mode: 'PROTECT', version: 4 },
        }),
      )
    }
    if (url.includes('/api-security/admission/coverage')) {
      const data = appId === 'app-2' ? coverageApp2 : appId === 'app-3' ? coverageApp3 : coverageApp1
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    }
    if (url.includes('/api-security/admission/denied')) {
      const page = Number(u.searchParams.get('page') ?? '1')
      const data =
        appId === 'app-2'
          ? { items: [deniedItemApp2], page, page_size: 20, total: 21 }
          : { items: [], page, page_size: 20, total: 0 }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    }
    if (method === 'POST' && url.includes('/api-security/endpoints/confirm')) {
      const body = JSON.parse(String(init?.body)) as { ids: string[] }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { confirmed: body.ids.length, confirmed_ids: body.ids, failed: [] },
        }),
      )
    }
    if (method === 'POST' && /\/api-security\/endpoints\/[^/]+\/ignore/.test(url)) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { endpoint: {}, message: '已忽略' } }),
      )
    }
    if (url.includes('/api-security/endpoints')) {
      const items = appId === 'app-2' ? endpointsApp2 : endpointsApp1
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items, page: 1, page_size: 200, total: items.length },
        }),
      )
    }
    if (url.includes('/applications')) {
      if (failApps) {
        return Promise.resolve(jsonResponse(500, { code: 'INTERNAL', message: '数据库连接失败' }))
      }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: appsData }))
    }
    return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiAdmissionPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function fetchUrls(): string[] {
  return (fetch as Mock).mock.calls.map((c) => String(c[0]))
}

describe('ApiAdmissionPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.confirm', 'api_asset.ignore', 'applications.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('总览渲染：模式徽标（观察/防护/缺省 OFF 关闭）、覆盖率、未确认命中红色警示与拦截数', async () => {
    renderPage()
    await screen.findByText('商城应用')
    expect(screen.getByText('支付应用')).toBeInTheDocument()
    expect(screen.getByText('遗留应用')).toBeInTheDocument()
    // 准入模式徽标：app-3 未携带 api_admission_mode 字段，按 OFF 展示
    expect(screen.getByText('观察')).toBeInTheDocument()
    expect(screen.getByText('防护')).toBeInTheDocument()
    expect(screen.getByText('关闭')).toBeInTheDocument()
    // 确认覆盖率：80% 进度 + confirmed/discovered 计数文本
    expect(await screen.findByText('80%')).toBeInTheDocument()
    expect(screen.getByText('已确认 24 / 未确认 5')).toBeInTheDocument()
    // 窗口内未确认命中：1320 + 12 = 1332（红色警示数字）
    expect(screen.getByText('1332')).toBeInTheDocument()
    // 窗口内准入拦截：app-2 为 7，其余为 0
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('共 3 条')).toBeInTheDocument()
    // 默认窗口 7 天：覆盖率请求携带 hits_window=168
    await waitFor(() => {
      expect(
        fetchUrls().some((u) => u.includes('/api-security/admission/coverage') && u.includes('hits_window=168')),
      ).toBe(true)
    })
  })

  it('命中窗口切换：预设 30 天换算 720 小时；自定义 10 天换算 240 小时', async () => {
    renderPage()
    await screen.findByText('商城应用')
    await waitFor(() => {
      expect(fetchUrls().some((u) => u.includes('hits_window=168'))).toBe(true)
    })
    // 预设：30 天
    fireEvent.click(screen.getByText('30天'))
    await waitFor(() => {
      expect(
        fetchUrls().some((u) => u.includes('/api-security/admission/coverage') && u.includes('hits_window=720')),
      ).toBe(true)
    })
    // 自定义：Popover 内输入 10 天 → 240 小时
    fireEvent.click(screen.getByRole('button', { name: '自定义' }))
    const input = await screen.findByRole('spinbutton')
    fireEvent.change(input, { target: { value: '10' } })
    fireEvent.click(screen.getByRole('button', { name: /^确\s*定$/ }))
    await waitFor(() => {
      expect(
        fetchUrls().some((u) => u.includes('/api-security/admission/coverage') && u.includes('hits_window=240')),
      ).toBe(true)
    })
    expect(screen.getByText('当前：10天')).toBeInTheDocument()
  })

  it('切换 PROTECT 弹窗：未勾选「我已知晓影响面」确定禁用；全部确认按 endpoint_key 解析 id 批量提交；勾选后 PUT 携带 api_admission_mode', async () => {
    renderPage()
    // 等覆盖率就绪（弹窗内覆盖率复用同一 queryKey 缓存）
    await screen.findByText('1332')
    fireEvent.click(screen.getAllByRole('button', { name: '切换模式' })[0])
    const dialog = await screen.findByRole('dialog')
    const okBtn = () => within(dialog).getByRole('button', { name: /^确\s*定$/ })
    // 未变更（仍为 OBSERVE）：确定禁用
    expect(okBtn()).toBeDisabled()
    // 选择 PROTECT：内嵌覆盖率报告
    fireEvent.click(within(dialog).getByText('防护（PROTECT）'))
    expect(await within(dialog).findByText('覆盖率与影响面评估')).toBeInTheDocument()
    expect(within(dialog).getByText('/v1/coupon')).toBeInTheDocument()
    expect(within(dialog).getByText('/v1/feedback')).toBeInTheDocument()
    expect(within(dialog).getByText('切换后以上 2 个未确认接口访问将被拒绝（403）')).toBeInTheDocument()
    // 未勾选影响面：确定仍禁用
    expect(okBtn()).toBeDisabled()
    // 顶部「全部确认」：等资产 id 映射就绪后，hot 行按 endpoint_key 映射资产 id 批量提交
    const confirmAllBtn = within(dialog).getByRole('button', { name: /全部确认/ })
    await waitFor(() => expect(confirmAllBtn).not.toBeDisabled())
    fireEvent.click(confirmAllBtn)
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/api-security/endpoints/confirm'),
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ ids: ['e1', 'e2'] })
    })
    // 勾选「我已知晓影响面」后提交：PUT 应用更新携带 api_admission_mode=PROTECT 与乐观锁 version
    fireEvent.click(within(dialog).getByText('我已知晓影响面'))
    await waitFor(() => expect(okBtn()).not.toBeDisabled())
    fireEvent.click(okBtn())
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) => String(c[1]?.method) === 'PUT' && String(c[0]).includes('/applications/app-1'),
      )
      expect(call).toBeTruthy()
      const body = JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>
      expect(body.api_admission_mode).toBe('PROTECT')
      expect(body.version).toBe(3)
      expect(body.name).toBe('商城应用')
    })
    // 切换成功提示发布（含配置发布入口链接）
    expect((await screen.findAllByText(/确认集变更需发布后生效/)).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('link', { name: '前往配置发布' }).length).toBeGreaterThan(0)
  })

  it('切换模式弹窗：全局 OBSERVE 且准入选择 OBSERVE/PROTECT 时显示实断总阀门联动提示', async () => {
    renderPage()
    await screen.findByText('1332')
    fireEvent.click(screen.getAllByRole('button', { name: '切换模式' })[0])
    const dialog = await screen.findByRole('dialog')
    // 当前模式 OBSERVE（非 OFF）+ 全局 OBSERVE：提示随策略查询就绪直接出现
    expect(await within(dialog).findByText(/全局 API 防护模式当前为「观察」/)).toBeInTheDocument()
    expect(within(dialog).getByText(/准入拦截将只记录、不实际阻断/)).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: '前往 API 防护策略' })).toBeInTheDocument()
    // 选择 PROTECT 后提示仍在
    fireEvent.click(within(dialog).getByText('防护（PROTECT）'))
    await within(dialog).findByText('覆盖率与影响面评估')
    expect(within(dialog).getByText(/全局 API 防护模式当前为「观察」/)).toBeInTheDocument()
  })

  it('切换模式弹窗：全局 PROTECT 时不显示实断总阀门联动提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ globalMode: 'PROTECT' }))
    renderPage()
    await screen.findByText('1332')
    fireEvent.click(screen.getAllByRole('button', { name: '切换模式' })[0])
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByText('防护（PROTECT）'))
    // 等策略查询发出且覆盖率报告渲染完成后再断言缺省（提示只由全局模式控制）
    await waitFor(() => {
      expect(fetchUrls().some((u) => u.includes('/api-security/policy'))).toBe(true)
    })
    await within(dialog).findByText('切换后以上 2 个未确认接口访问将被拒绝（403）')
    expect(within(dialog).queryByText(/全局 API 防护模式当前为/)).not.toBeInTheDocument()
  })

  it('准入详情抽屉：准入拦截 Tab 渲染拦截聚合（样本 IP/次数/总数），确认放行解析 id 提交，翻页携带 page=2', async () => {
    renderPage()
    await screen.findByText('支付应用')
    fireEvent.click(screen.getAllByRole('button', { name: '准入详情' })[1])
    expect(await screen.findByText('准入详情：支付应用（pay）')).toBeInTheDocument()
    // 默认「准入拦截」Tab
    expect(await screen.findByText('/v1/admin')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.7')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('共 21 条')).toBeInTheDocument()
    // 确认放行（Popconfirm）：按 endpoint_key → e9 提交确认
    fireEvent.click(screen.getByRole('button', { name: '确认放行' }))
    fireEvent.click(await screen.findByRole('button', { name: /^确\s*定$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/api-security/endpoints/confirm'),
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ ids: ['e9'] })
    })
    // 翻页：page=2 随请求发出
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => {
      expect(
        fetchUrls().some((u) => u.includes('/api-security/admission/denied') && u.includes('page=2')),
      ).toBe(true)
    })
  })

  it('准入详情抽屉：未确认端点 Tab 按 DISCOVERED 过滤，忽略经 Popconfirm 提交', async () => {
    renderPage()
    await screen.findByText('商城应用')
    fireEvent.click(screen.getAllByRole('button', { name: '准入详情' })[0])
    expect(await screen.findByText('准入详情：商城应用（shop）')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: '未确认端点' }))
    expect(await screen.findByText('/v1/coupon')).toBeInTheDocument()
    expect(screen.getByText('/v1/feedback')).toBeInTheDocument()
    // 忽略第一行（e1）
    fireEvent.click(screen.getAllByRole('button', { name: /^忽\s*略$/ })[0])
    fireEvent.click(await screen.findByRole('button', { name: /^确\s*定$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) => String(c[1]?.method) === 'POST' && String(c[0]).includes('/api-security/endpoints/e1/ignore'),
      )
      expect(call).toBeTruthy()
    })
  })

  it('无 applications.update 权限：操作列不显示「切换模式」，仍显示「准入详情」', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('商城应用')
    expect(screen.queryByRole('button', { name: '切换模式' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '准入详情' }).length).toBeGreaterThan(0)
  })

  it('应用列表加载失败：展示 Alert 与后端错误消息', async () => {
    vi.stubGlobal('fetch', mockFetch({ failApps: true }))
    renderPage()
    expect(await screen.findByText('加载数据失败')).toBeInTheDocument()
    expect(screen.getByText('数据库连接失败')).toBeInTheDocument()
  })
})
