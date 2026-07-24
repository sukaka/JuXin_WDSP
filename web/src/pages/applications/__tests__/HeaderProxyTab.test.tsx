import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import HeaderProxyTab from '../detail/HeaderProxyTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-1'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: 'OPS_ADMIN', name: '运维管理员' }],
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

const headerConfigData = {
  configured: true,
  version: 3,
  config: {
    server_action: 'keep',
    server_value: '',
    x_author_action: 'keep',
    x_author_value: '',
    x_powered_by_action: 'keep',
    x_powered_by_value: '',
    x_frame_options: 'default',
    x_frame_options_url: '',
    x_xss_protection: false,
    vary_user_agent: false,
    hsts_enabled: false,
    hsts_max_age: 31536000,
    csp_mode: 'off',
    csp_value: '',
    response_buffering: false,
    xff_overwrite: false,
    host_strip_port: false,
    accept_encoding_off: false,
    redirect_port_rewrite: false,
    custom_request_rules: [],
    custom_response_rules: [],
  },
}

const pathRoutesData = {
  items: [
    {
      id: 'r1',
      application_id: APP_ID,
      path_prefix: '/api/v1',
      upstream_scheme: 'http',
      upstream_host: '10.0.0.11',
      upstream_port: 8080,
      strip_prefix: true,
      priority: 50,
      status: 'ENABLED',
      description: 'API 转发',
      created_at: '2026-07-01T10:00:00Z',
      updated_at: '2026-07-20T08:30:00Z',
      version: 1,
    },
    {
      id: 'r2',
      application_id: APP_ID,
      path_prefix: '/static',
      upstream_scheme: 'https',
      upstream_host: 'static.internal',
      upstream_port: 443,
      strip_prefix: false,
      priority: 100,
      status: 'DISABLED',
      description: '',
      created_at: '2026-07-02T10:00:00Z',
      updated_at: '2026-07-21T09:00:00Z',
      version: 2,
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

const emptyRoutesData = { items: [], page: 1, page_size: 20, total: 0 }

function mockFetch(routesData: unknown = pathRoutesData, configData: unknown = headerConfigData) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/header-config`)) {
      if (method === 'PUT') {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { ...headerConfigData, version: 4 } }),
        )
      }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: configData }))
    }
    if (url.includes(`/applications/${APP_ID}/path-routes`)) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: routesData }))
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <HeaderProxyTab appId={APP_ID} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('HeaderProxyTab', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染三张卡片与表单默认值', async () => {
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    // 三张卡片标题
    expect(await screen.findByText('HTTP头合规')).toBeInTheDocument()
    expect(screen.getByText('HTTP代理配置')).toBeInTheDocument()
    expect(screen.getByText('路径转发配置')).toBeInTheDocument()
    // 默认值：Server / X-Author / X-Powered-By 保持原样、X-Frame-Options 默认 DENY、CSP 关闭（按选中项文本断言，不依赖 antd 类名）
    await waitFor(() => expect(screen.getAllByText('保持原样')).toHaveLength(3))
    expect(screen.getByText('默认（DENY）')).toBeInTheDocument()
    expect(screen.getByText('关闭')).toBeInTheDocument()
    // 开关默认关闭；下划线头为内核强制说明项
    expect(screen.getByText('X-Xss-Protection')).toBeInTheDocument()
    expect(screen.getByText('下划线请求头')).toBeInTheDocument()
    expect(screen.getByText('始终拦截')).toBeInTheDocument()
    expect(screen.getByText('响应缓冲')).toBeInTheDocument()
    expect(screen.getByText('302重定向端口改写')).toBeInTheDocument()
    // 自定义头修改两个 Form.List
    expect(screen.getByText('自定义请求头修改')).toBeInTheDocument()
    expect(screen.getByText('自定义返回头修改')).toBeInTheDocument()
  })

  it('保存触发 PUT /header-config 并携带 version', async () => {
    // 使用与表单默认值可区分的配置，确保等待的是「数据回显完成」而非初始渲染
    const loadedConfig = {
      ...headerConfigData,
      config: { ...headerConfigData.config, x_frame_options: 'sameorigin' },
    }
    vi.stubGlobal('fetch', mockFetch(pathRoutesData, loadedConfig))
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    const saveBtn = await screen.findByRole('button', { name: /保\s*存\s*配\s*置/ })
    // 等待配置回显（SAMEORIGIN 仅在数据加载后出现）后再提交
    await screen.findByText('SAMEORIGIN')
    fireEvent.click(saveBtn)
    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes(`/applications/${APP_ID}/header-config`) && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect(body.version).toBe(3)
      expect(body.server_action).toBe('keep')
      expect(body.x_frame_options).toBe('sameorigin')
      expect(body.custom_request_rules).toEqual([])
    })
  })

  it('路径转发列表渲染：前缀、源站、剥离/状态 Tag、总数', async () => {
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    expect(await screen.findByText('/api/v1')).toBeInTheDocument()
    expect(screen.getByText('/static')).toBeInTheDocument()
    expect(screen.getByText('http://10.0.0.11:8080')).toBeInTheDocument()
    expect(screen.getByText('https://static.internal:443')).toBeInTheDocument()
    const table = screen.getByRole('table')
    // 「启用」「停用」各出现两次：状态 Tag + 对方行的行内启停按钮
    expect(within(table).getAllByText('启用')).toHaveLength(2)
    expect(within(table).getAllByText('停用')).toHaveLength(2)
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
    // 行内操作按钮
    expect(within(table).getAllByRole('button', { name: /^编\s*辑$/ })).toHaveLength(2)
    expect(within(table).getAllByRole('button', { name: /^删\s*除$/ })).toHaveLength(2)
  })

  it('无 applications.update 权限：隐藏保存/新增/编辑/删除', async () => {
    useAuthStore.setState({ user: makeUser(['applications.read']), csrfToken: null, initialized: true })
    renderTab()
    expect(await screen.findByText('/api/v1')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保\s*存\s*配\s*置/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /新\s*增\s*转\s*发\s*规\s*则/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^编\s*辑$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^删\s*除$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^启\s*用$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^停\s*用$/ })).not.toBeInTheDocument()
  })

  it('路径转发为空时表格正常渲染空态', async () => {
    vi.stubGlobal('fetch', mockFetch(emptyRoutesData))
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    // 空列表：表格渲染但无数据行；新增按钮仍可见（测试未包 zh_CN ConfigProvider，Empty 为英文）
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    expect(screen.queryByText('/api/v1')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新\s*增\s*转\s*发\s*规\s*则/ })).toBeInTheDocument()
  })
})
