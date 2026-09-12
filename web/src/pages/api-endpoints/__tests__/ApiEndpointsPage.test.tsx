import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiEndpointsPage from '../ApiEndpointsPage'
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

const listData = {
  items: [
    {
      id: 'e1',
      http_method: 'GET',
      normalized_path: '/v1/users/{id}',
      endpoint_key: 'GET /v1/users/{id}',
      application_name: '',
      directory_path: '/test/php',
      api_confidence: 0.6,
      asset_status: 'DISCOVERED',
      learning_status: 'LEARNING',
      is_api: true,
      hit_count: 3,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T08:30:00Z',
    },
    {
      id: 'e2',
      http_method: 'POST',
      normalized_path: '/v1/orders',
      endpoint_key: 'POST /v1/orders',
      application_name: '站点A',
      directory_path: '',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
      is_api: true,
      hit_count: 12,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
      confirmed_at: '2026-07-02T01:00:00Z',
      asset_value: 'HIGH',
      asset_value_explain: {
        level: 'HIGH',
        total: 14,
        max_total: 26,
        computed_at: '2026-07-22T00:00:00Z',
        dimensions: [
          { name: 'business_sensitivity', score: 2, max: 3, input: 'ADMIN', reason: '管理类接口' },
          { name: 'traffic_scale', score: 2, max: 3, input: '1200', reason: '日均流量过千' },
        ],
      },
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

const siteSummaryData = {
  items: [
    { application_id: 'app-1', application_name: '站点A', endpoint_count: 5 },
    { application_id: 'app-2', application_name: '站点B', endpoint_count: 3 },
  ],
  unassigned: 2,
}

const directoryTreeData = {
  items: [
    { directory_path: '/test', endpoint_count: 4 },
    { directory_path: '/test/php', endpoint_count: 2 },
  ],
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiEndpointsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 左侧站点列表项（全部 / 未归属 / 各站点均为 role=button 的 div） */
function siteItem(name: string, index = 0): HTMLElement {
  const el = screen.getAllByText(name).map((n) => n.closest('[role="button"]')).filter(Boolean)[index]
  expect(el).toBeTruthy()
  return el as HTMLElement
}

describe('ApiEndpointsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/endpoints/site-summary')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: siteSummaryData }))
        }
        if (url.includes('/api-security/endpoints/directory-tree')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: directoryTreeData }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：路径模板、中文状态与学习状态 Tag、分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('/v1/users/{id}')).toBeInTheDocument()
    expect(screen.getByText('/v1/orders')).toBeInTheDocument()
    expect(screen.getByText('已发现')).toBeInTheDocument()
    expect(screen.getByText('已确认')).toBeInTheDocument()
    expect(screen.getByText('学习中')).toBeInTheDocument()
    expect(screen.getByText('已完成')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('站点列表：全部（合计）、未归属与各站点名称与接口计数角标', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    // 「站点A」同时出现在站点列表与表格站点列，须用 findAllByText
    await screen.findAllByText('站点A')
    // 角标计数：antd Badge 多位数会拆分为逐位动画节点，统一用 sup 的 title 断言
    // 全部 = 5 + 3 + 2 = 10
    expect(within(siteItem('全部')).getByTitle('10')).toBeInTheDocument()
    expect(within(siteItem('未归属')).getByTitle('2')).toBeInTheDocument()
    expect(within(siteItem('站点A')).getByTitle('5')).toBeInTheDocument()
    expect(within(siteItem('站点B')).getByTitle('3')).toBeInTheDocument()
    // 目录树按段组装层级：test (4) → php (2)
    expect(screen.getByText('test (4)')).toBeInTheDocument()
    expect(screen.getByText('php (2)')).toBeInTheDocument()
  })

  it('点击站点：列表与目录树请求携带 application_id，并出现可关闭过滤 Tag', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findByText('站点B'))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/api-security/endpoints?') && u.includes('application_id=app-2'))).toBe(true)
      expect(
        urls.some((u) => u.includes('/api-security/endpoints/directory-tree') && u.includes('application_id=app-2')),
      ).toBe(true)
    })
    expect(screen.getByText('站点：站点B')).toBeInTheDocument()
  })

  it('表格新增目录与站点列：目录 code 展示，站点空值显示未归属', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    const table = await screen.findByRole('table')
    // 表头（横向滚动下 antd 可能有辅助节点，统一按 columnheader 断言；SmartTable 表头附带列宽拖拽手柄文本，按包含匹配）
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.textContent)
    expect(headers.some((h) => h?.includes('目录'))).toBe(true)
    expect(headers.some((h) => h?.includes('站点'))).toBe(true)
    // 等数据行渲染后再断言单元格内容
    expect(await within(table).findByText('/test/php')).toBeInTheDocument()
    expect(within(table).getByText('未归属')).toBeInTheDocument()
    expect(within(table).getByText('站点A')).toBeInTheDocument()
  })

  it('无 confirm/ignore 权限：不显示行内「确认」与「忽略」', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^忽\s*略$/ })).not.toBeInTheDocument()
  })

  it('无 merge/split 权限：不显示行内「合并」与「拆分」', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.queryByRole('button', { name: /^合\s*并$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^拆\s*分$/ })).not.toBeInTheDocument()
  })

  it('合并弹窗：选择待并入接口后发起 POST /merge（other_id 为目标接口）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.merge']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    fireEvent.click(screen.getAllByRole('button', { name: /^合\s*并$/ })[0])
    const dialog = await screen.findByRole('dialog')
    // 保留方为当前行接口，目标选择器排除自身
    expect(within(dialog).getByText('GET /v1/users/{id}')).toBeInTheDocument()
    fireEvent.mouseDown(within(dialog).getByRole('combobox'))
    fireEvent.click(await screen.findByText('POST /v1/orders'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^合\s*并$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) => String(c[0]).includes('/api-security/endpoints/e1/merge'))
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ other_id: 'e2' })
    })
  })

  it('拆分弹窗：按行输入路径后发起 POST /split（paths 为拆分路径数组）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.split']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    fireEvent.click(screen.getAllByRole('button', { name: /^拆\s*分$/ })[0])
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), {
      target: { value: '/v1/users/{id}/orders\n\n/v1/users/{id}/profile' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^拆\s*分$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) => String(c[0]).includes('/api-security/endpoints/e1/split'))
      expect(call).toBeTruthy()
      // 空行被过滤
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({
        paths: ['/v1/users/{id}/orders', '/v1/users/{id}/profile'],
      })
    })
  })

  it('有 confirm/ignore 权限：未确认行显示「确认」，未忽略行显示「忽略」；「登记发现」已移除', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.confirm', 'api_asset.ignore']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.getAllByRole('button', { name: /^确\s*认$/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^忽\s*略$/ })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /登\s*记\s*发\s*现/ })).not.toBeInTheDocument()
  })

  it('价值列：已评分接口展示等级 Tag，未评分显示 -；表头包含「价值」', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    const table = await screen.findByRole('table')
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.textContent)
    expect(headers.some((h) => h?.includes('价值'))).toBe(true)
    // e2 asset_value=HIGH → 「高」Tag；e1 未评分 → 「-」（目录等空值列同样渲染 -，取全部断言非空）
    expect(await within(table).findByText('高')).toBeInTheDocument()
    expect(within(table).getAllByText('-').length).toBeGreaterThan(0)
  })

  it('生命周期操作：DISCOVERED 行可下线、DEPRECATED 行可恢复；下线二次确认后发起 POST deprecate', async () => {
    const lifecycleList = {
      items: [
        { ...listData.items[0] },
        {
          ...listData.items[1],
          id: 'e3',
          endpoint_key: 'GET /v1/legacy',
          normalized_path: '/v1/legacy',
          asset_status: 'DEPRECATED',
        },
      ],
      page: 1,
      page_size: 20,
      total: 2,
    }
    const deprecateCalls: string[] = []
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.includes('/api-security/endpoints/site-summary')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: siteSummaryData }))
      }
      if (url.includes('/api-security/endpoints/directory-tree')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: directoryTreeData }))
      }
      if (method === 'POST' && url.includes('/api-security/endpoints/e1/deprecate')) {
        deprecateCalls.push(url)
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { endpoint: { ...listData.items[0], asset_status: 'DEPRECATED' }, message: '接口已标记下线' },
          }),
        )
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: lifecycleList }))
      }
      return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
    })
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/legacy')
    expect(screen.getByRole('button', { name: /^下\s*线$/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^恢\s*复$/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^下\s*线$/ }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(deprecateCalls).toHaveLength(1))
  })

  it('详情抽屉：展示接口信息与参数约束（类型/必填/长度）', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/endpoints/site-summary')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: siteSummaryData }))
      }
      if (url.includes('/api-security/endpoints/directory-tree')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: directoryTreeData }))
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [
                {
                  id: 'mv1',
                  api_endpoint_id: 'e1',
                  endpoint_key: 'GET /v1/users/{id}',
                  status: 'FORMAL',
                  schema: {},
                  content_hash: 'h1',
                  version_number: 2,
                  change_summary: '',
                  created_reason: '',
                  created_at: '2026-07-10T00:00:00Z',
                },
              ],
              page: 1,
              page_size: 100,
              total: 1,
            },
          }),
        )
      }
      if (url.includes('/api-security/models/mv1/parameters')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [
                {
                  id: 'p1',
                  model_version_id: 'mv1',
                  direction: 'REQUEST',
                  location: 'PATH',
                  structured_path: '/v1/users/{id}',
                  parameter_name: 'id',
                  base_type: 'integer',
                  semantic_type: 'user_id',
                  required: true,
                  nullable: false,
                  empty_allowed: false,
                  observed_constraints: {},
                  recommended_constraints: { min_length: 1, max_length: 19 },
                  confirmed_constraints: {},
                  sensitivity_level: 'LOW',
                  confidence: 0.9,
                  created_at: '2026-07-10T00:00:00Z',
                },
              ],
              page: 1,
              page_size: 100,
              total: 1,
            },
          }),
        )
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    fireEvent.click(screen.getAllByRole('button', { name: /^详\s*情$/ })[0])
    // 抽屉标题与基础信息
    expect(await screen.findByText('接口详情：GET /v1/users/{id}')).toBeInTheDocument()
    // 参数行：参数名、类型（base_type 经 API_BASE_TYPE_META 映射为中文标签）、必填、长度约束（推荐约束 min/max）
    expect(await screen.findByText('user_id')).toBeInTheDocument()
    expect(screen.getByText('整数')).toBeInTheDocument()
    expect(screen.getByText('1 ~ 19')).toBeInTheDocument()
    // 原始数据区块：默认展示接口记录 JSON
    expect(screen.getByText('原始数据')).toBeInTheDocument()
    expect(screen.getByText(/"normalized_path": "\/v1\/users\/\{id\}"/)).toBeInTheDocument()
  })
})
