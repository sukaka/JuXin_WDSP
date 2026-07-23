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

  it('站点列表：全部（合计）、未归属与各站点名称与端点计数角标', async () => {
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
    // 表头（横向滚动下 antd 可能有辅助节点，统一按 columnheader 断言）
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.textContent)
    expect(headers).toContain('目录')
    expect(headers).toContain('站点')
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
})
