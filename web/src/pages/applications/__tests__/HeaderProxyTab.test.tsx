import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
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
    response_compression_enabled: false,
    response_compression_encodings: 'zstd,gzip',
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

// 未配置（configured:false）时服务端返回的默认对象（与 server DefaultHeaderConfig 对齐）
const unconfiguredData = {
  configured: false,
  version: 0,
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
    xff_overwrite: true,
    host_strip_port: false,
    accept_encoding_off: false,
    response_compression_enabled: false,
    response_compression_encodings: 'zstd,gzip',
    redirect_port_rewrite: false,
    custom_request_rules: [],
    custom_response_rules: [],
  },
}

function xffSwitch() {
  const item = screen.getByText('X-Forwarded-For 上一跳覆盖').closest('.ant-form-item') as HTMLElement
  return within(item).getByRole('switch')
}

function lastConfigPut(): Record<string, unknown> | null {
  const putCall = (fetch as Mock).mock.calls.find(
    (c) => String(c[0]).includes(`/applications/${APP_ID}/header-config`) && c[1]?.method === 'PUT',
  )
  return putCall ? (JSON.parse(String(putCall[1]?.body)) as Record<string, unknown>) : null
}

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
      if (method === 'PATCH' || method === 'POST') {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { route: pathRoutesData.items[0], message: '保存成功' },
          }),
        )
      }
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
    // Server / Via / X-Powered-By / 数据库版本头固定隐藏，X-Author 仍可配置
    await waitFor(() => expect(screen.getAllByText('保持原样')).toHaveLength(1))
    expect(screen.getAllByText('始终隐藏')).toHaveLength(2)
    expect(screen.getByText('中间件和数据库版本信息始终隐藏')).toBeInTheDocument()
    expect(screen.getByText('默认（DENY）')).toBeInTheDocument()
    expect(screen.getByText('关闭')).toBeInTheDocument()
    // 开关默认关闭；下划线头为内核强制说明项
    expect(screen.getByText('X-Xss-Protection')).toBeInTheDocument()
    expect(screen.getByText('下划线请求头')).toBeInTheDocument()
    expect(screen.getByText('始终拦截')).toBeInTheDocument()
    expect(screen.getByText('响应缓冲')).toBeInTheDocument()
    expect(screen.getByText('禁止回源压缩（Accept-Encoding）')).toBeInTheDocument()
    expect(screen.getByText('网关响应压缩（gzip / zstd）')).toBeInTheDocument()
    expect(screen.getByText('302重定向端口改写')).toBeInTheDocument()
    // 自定义头修改两个 Form.List
    expect(screen.getByText('自定义请求头修改')).toBeInTheDocument()
    expect(screen.getByText('自定义返回头修改')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: /添加规则/ })[0])
    expect(screen.getByRole('button', { name: '删除此头修改规则' })).toBeInTheDocument()
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
    // 刷新 effect 链（TanStack v5 useMutation 在 useEffect 中 setOptions），
    // 确保保存闭包取到 setConfigVersion 后的最新 version
    await act(async () => {})
    fireEvent.click(saveBtn)
    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes(`/applications/${APP_ID}/header-config`) && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect(body.version).toBe(3)
      expect(body.server_action).toBe('hide')
      expect(body.x_powered_by_action).toBe('hide')
      expect(body.x_frame_options).toBe('sameorigin')
      expect(body.hsts_max_age).toBe(31536000)
      expect(body.response_compression_enabled).toBe(false)
      expect(body.response_compression_encodings).toBe('zstd,gzip')
      expect(body.custom_request_rules).toEqual([])
    })
  })

  it('开启响应压缩开关可展开算法配置并在提交时携带开关与算法', async () => {
    const loadedConfig = {
      ...headerConfigData,
      config: {
        ...headerConfigData.config,
        x_frame_options: 'sameorigin',
        response_compression_enabled: false,
        response_compression_encodings: 'gzip',
      },
    }
    vi.stubGlobal('fetch', mockFetch(pathRoutesData, loadedConfig))
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    const saveBtn = await screen.findByRole('button', { name: /保\s*存\s*配\s*置/ })
    await screen.findByText('SAMEORIGIN')
    await act(async () => {})

    const compItem = screen.getByText('网关响应压缩（gzip / zstd）').closest('.ant-form-item') as HTMLElement
    const compSwitch = within(compItem).getByRole('switch')
    expect(compSwitch).toHaveAttribute('aria-checked', 'false')
    expect(screen.queryByText('压缩算法')).not.toBeInTheDocument()

    fireEvent.click(compSwitch)
    expect(await screen.findByText('压缩算法')).toBeInTheDocument()
    expect(screen.getByText('仅 Gzip（最大兼容性）')).toBeInTheDocument()

    fireEvent.click(saveBtn)
    await waitFor(() => {
      const body = lastConfigPut()
      expect(body).toBeTruthy()
      expect(body!.response_compression_enabled).toBe(true)
      expect(body!.response_compression_encodings).toBe('gzip')
    })
  })

  it('B9-2: HSTS 开启修改 max-age 后再关闭仍保留正整数 hsts_max_age 且 InputNumber min=1', async () => {
    const loadedConfig = {
      ...headerConfigData,
      config: { ...headerConfigData.config, x_frame_options: 'sameorigin', hsts_enabled: false, hsts_max_age: 31536000 },
    }
    vi.stubGlobal('fetch', mockFetch(pathRoutesData, loadedConfig))
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    const saveBtn = await screen.findByRole('button', { name: /保\s*存\s*配\s*置/ })
    await screen.findByText('SAMEORIGIN')
    await act(async () => {})

    const hstsItem = screen.getByText('HSTS').closest('.ant-form-item') as HTMLElement
    const hstsSwitch = within(hstsItem).getByRole('switch')
    fireEvent.click(hstsSwitch)

    const maxAgeInput = await screen.findByRole('spinbutton')
    expect(maxAgeInput).toHaveAttribute('aria-valuemin', '1')
    fireEvent.change(maxAgeInput, { target: { value: '86400' } })
    fireEvent.click(hstsSwitch)

    fireEvent.click(saveBtn)
    await waitFor(() => {
      const body = lastConfigPut()
      expect(body).toBeTruthy()
      expect(body!.hsts_enabled).toBe(false)
      expect(body!.hsts_max_age).toBe(86400)
    })
  })

  it('B9-1: 编辑路径转发携带完整字段与 version，行内停用携带完整替换体与 version', async () => {
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    await screen.findByText('/api/v1')

    const table = screen.getByRole('table')
    const editButtons = within(table).getAllByRole('button', { name: /^编\s*辑$/ })
    fireEvent.click(editButtons[0])

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('编辑路径转发：/api/v1')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() => {
      const patchCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes(`/applications/${APP_ID}/path-routes/r1`) && c[1]?.method === 'PATCH',
      )
      expect(patchCall).toBeTruthy()
      const body = JSON.parse(String(patchCall![1]?.body)) as Record<string, unknown>
      expect(body).toEqual({
        path_prefix: '/api/v1',
        upstream_scheme: 'http',
        upstream_host: '10.0.0.11',
        upstream_port: 8080,
        strip_prefix: true,
        priority: 50,
        status: 'ENABLED',
        description: 'API 转发',
        version: 1,
      })
    })

    // 清除历史调用记录后测试行内停用
    ;(fetch as Mock).mockClear()
    const disableBtn = within(table).getByRole('button', { name: /^停\s*用$/ })
    fireEvent.click(disableBtn)

    await waitFor(() => {
      const patchCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes(`/applications/${APP_ID}/path-routes/r1`) && c[1]?.method === 'PATCH',
      )
      expect(patchCall).toBeTruthy()
      const body = JSON.parse(String(patchCall![1]?.body)) as Record<string, unknown>
      expect(body).toEqual({
        path_prefix: '/api/v1',
        upstream_scheme: 'http',
        upstream_host: '10.0.0.11',
        upstream_port: 8080,
        strip_prefix: true,
        priority: 50,
        status: 'DISABLED',
        description: 'API 转发',
        version: 1,
      })
    })
  })

  it('未配置应用：XFF 上一跳覆盖默认开启，保存显式写入 true', async () => {
    // x_frame_options 仅作「数据回显完成」的等待标记（表单初始渲染开关即为开，需区分）
    const loadedUnconfigured = {
      ...unconfiguredData,
      config: { ...unconfiguredData.config, x_frame_options: 'sameorigin' },
    }
    vi.stubGlobal('fetch', mockFetch(pathRoutesData, loadedUnconfigured))
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    const saveBtn = await screen.findByRole('button', { name: /保\s*存\s*配\s*置/ })
    await screen.findByText('SAMEORIGIN')
    // 刷新 effect 链：setConfigVersion(0) → useMutation options 被动 effect（TanStack v5 在
    // useEffect 中 setOptions），确保保存闭包取到最新 version
    await act(async () => {})
    expect(xffSwitch()).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(saveBtn)
    await waitFor(() => {
      const body = lastConfigPut()
      expect(body).toBeTruthy()
      expect(body!.xff_overwrite).toBe(true)
      expect(body!.version).toBe(0)
    })
  })

  it('显式保存过 xff_overwrite=false 的配置保持关闭', async () => {
    // headerConfigData：configured=true 且 xff_overwrite=false（显式关闭）
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderTab()
    const saveBtn = await screen.findByRole('button', { name: /保\s*存\s*配\s*置/ })
    // 表单初始默认 true，等待数据回显后翻转为 false
    await waitFor(() => expect(xffSwitch()).toHaveAttribute('aria-checked', 'false'))
    fireEvent.click(saveBtn)
    await waitFor(() => {
      const body = lastConfigPut()
      expect(body).toBeTruthy()
      expect(body!.xff_overwrite).toBe(false)
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
