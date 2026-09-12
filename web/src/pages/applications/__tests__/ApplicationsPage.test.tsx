import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApplicationsPage from '../ApplicationsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

function makeApp(overrides: Record<string, unknown> = {}) {
  return {
    id: 'app-1',
    code: 'portal-web',
    name: '门户应用',
    description: '',
    business_owner: '',
    technical_owner: '',
    status: 'ACTIVE',
    protection_mode: 'PROTECT',
    deployment_status: 'PUBLISHED',
    health_status: 'HEALTHY',
    last_publish_at: null,
    last_publish_result: '',
    domain_count: 1,
    upstream_count: 1,
    created_at: '2026-07-01T10:00:00Z',
    updated_at: '2026-07-20T08:30:00Z',
    version: 3,
    ...overrides,
  }
}

// app-1 为路由牵引模式；app-2 不返回 deployment_mode（按默认 REVERSE_PROXY 展示）
const routedApp = makeApp({ deployment_mode: 'ROUTED' })
const plainApp = makeApp({ id: 'app-2', code: 'order-api', name: '订单接口', version: 1 })

function mockFetch(items: unknown[] = [routedApp, plainApp]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (method === 'POST' && url.endsWith('/api/v1/applications')) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: makeApp({ id: 'app-new', code: body.code, name: body.name }),
        }),
      )
    }
    if (method === 'PUT' && url.includes('/api/v1/applications/')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: routedApp }))
    }
    if (method === 'GET' && url.includes('/api/v1/applications')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items, page: 1, page_size: 20, total: items.length },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${method} ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <ApplicationsPage />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

/** 打开新建弹窗并填写必填项（编码/名称），返回弹窗元素 */
async function openCreateDialog() {
  fireEvent.click(screen.getByRole('button', { name: /新\s*建\s*应\s*用/ }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('应用编码'), { target: { value: 'app-new-1' } })
  fireEvent.change(within(dialog).getByLabelText('应用名称'), { target: { value: '新应用' } })
  return dialog
}

function lastCreateCall() {
  return (fetch as Mock).mock.calls.find(
    (c) => String(c[0]).endsWith('/api/v1/applications') && c[1]?.method === 'POST',
  )
}

describe('ApplicationsPage 部署模式', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示部署模式列：ROUTED 显示「路由牵引」，缺省字段按「反向代理」显示', async () => {
    useAuthStore.setState({ user: makeUser(['applications.read']), csrfToken: null, initialized: true })
    renderPage()
    // 「部署模式」同时出现在列头与 SmartTable 列设置中，按多匹配断言
    expect((await screen.findAllByText('部署模式')).length).toBeGreaterThan(0)
    expect(await screen.findByText('路由牵引')).toBeInTheDocument()
    expect(screen.getByText('反向代理')).toBeInTheDocument()
  })

  it('新建默认反向代理：提交体含 deployment_mode=REVERSE_PROXY', async () => {
    useAuthStore.setState({ user: makeUser(['applications.create']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('门户应用')
    const dialog = await openCreateDialog()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(lastCreateCall()).toBeTruthy())
    const body = JSON.parse(String(lastCreateCall()![1]?.body)) as Record<string, unknown>
    expect(body.code).toBe('app-new-1')
    expect(body.deployment_mode).toBe('REVERSE_PROXY')
  })

  it('新建选择路由牵引：出现模式说明且提交体含 deployment_mode=ROUTED', async () => {
    // 列表不含 ROUTED 应用，避免下拉选项文本与表格 Tag 冲突
    vi.stubGlobal('fetch', mockFetch([plainApp]))
    useAuthStore.setState({ user: makeUser(['applications.create']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('订单接口')
    const dialog = await openCreateDialog()
    // 弹窗内两个 Select：防护模式、部署模式；操作第二个
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[1])
    fireEvent.click(await screen.findByText('路由牵引'))
    // 选中 ROUTED 后展示部署说明
    expect(
      await within(dialog).findByText(/流量经三层路由送达本网关节点后转发源站/),
    ).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(lastCreateCall()).toBeTruthy())
    const body = JSON.parse(String(lastCreateCall()![1]?.body)) as Record<string, unknown>
    expect(body.deployment_mode).toBe('ROUTED')
  })

  it('编辑回显部署模式并随 PUT 提交（含 version）', async () => {
    useAuthStore.setState({ user: makeUser(['applications.update']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('门户应用')
    // 第一行（ROUTED 应用）的「编辑」按钮
    fireEvent.click(screen.getAllByRole('button', { name: /^编\s*辑$/ })[0])
    const dialog = await screen.findByRole('dialog')
    // 回显为路由牵引：说明文案随之出现
    expect(
      await within(dialog).findByText(/流量经三层路由送达本网关节点后转发源站/),
    ).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes('/api/v1/applications/app-1') && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect(body.deployment_mode).toBe('ROUTED')
      expect(body.version).toBe(3)
    })
  })

  it('列表展示镜像/透明串接部署模式 Tag', async () => {
    const mirrorApp = makeApp({ id: 'app-3', code: 'mirror-app', name: '镜像应用', deployment_mode: 'MIRROR' })
    const transparentApp = makeApp({
      id: 'app-4',
      code: 'tproxy-app',
      name: '串接应用',
      deployment_mode: 'TRANSPARENT',
    })
    vi.stubGlobal('fetch', mockFetch([mirrorApp, transparentApp]))
    useAuthStore.setState({ user: makeUser(['applications.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('镜像')).toBeInTheDocument()
    expect(await screen.findByText('透明串接')).toBeInTheDocument()
  })

  it('部署模式下拉渲染四个选项', async () => {
    // 空列表避免下拉选项文本与表格 Tag 冲突
    vi.stubGlobal('fetch', mockFetch([]))
    useAuthStore.setState({ user: makeUser(['applications.create']), csrfToken: null, initialized: true })
    renderPage()
    const dialog = await openCreateDialog()
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[1])
    // 「反向代理」同时出现在 Select 当前值与下拉选项中，按多匹配断言
    expect((await screen.findAllByText('反向代理')).length).toBeGreaterThan(0)
    expect(screen.getByText('路由牵引')).toBeInTheDocument()
    expect(screen.getByText('镜像')).toBeInTheDocument()
    expect(screen.getByText('透明串接')).toBeInTheDocument()
  })

  it('新建选择镜像：出现模式说明且提交体含 deployment_mode=MIRROR', async () => {
    vi.stubGlobal('fetch', mockFetch([plainApp]))
    useAuthStore.setState({ user: makeUser(['applications.create']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('订单接口')
    const dialog = await openCreateDialog()
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[1])
    fireEvent.click(await screen.findByText('镜像'))
    // 选中 MIRROR 后展示部署说明
    expect(await within(dialog).findByText(/流量副本经镜像口到达节点/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(lastCreateCall()).toBeTruthy())
    const body = JSON.parse(String(lastCreateCall()![1]?.body)) as Record<string, unknown>
    expect(body.deployment_mode).toBe('MIRROR')
  })

  it('新建选择透明串接：出现模式说明且提交体含 deployment_mode=TRANSPARENT', async () => {
    vi.stubGlobal('fetch', mockFetch([plainApp]))
    useAuthStore.setState({ user: makeUser(['applications.create']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('订单接口')
    const dialog = await openCreateDialog()
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[1])
    fireEvent.click(await screen.findByText('透明串接'))
    // 选中 TRANSPARENT 后展示部署说明
    expect(await within(dialog).findByText(/二层桥接串接/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(lastCreateCall()).toBeTruthy())
    const body = JSON.parse(String(lastCreateCall()![1]?.body)) as Record<string, unknown>
    expect(body.deployment_mode).toBe('TRANSPARENT')
  })
})


describe('ApplicationsPage 筛选分页上下文（BOT-023）', () => {
  function renderAt(url: string) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return render(
      <MemoryRouter initialEntries={[url]}>
        <QueryClientProvider client={qc}>
          <AntdApp>
            <ApplicationsPage />
          </AntdApp>
        </QueryClientProvider>
      </MemoryRouter>,
    )
  }

  function lastListCall() {
    const urls = (fetch as Mock).mock.calls
      .map((c) => String(c[0]))
      .filter((u) => u.includes('/api/v1/applications?'))
    return urls.length > 0 ? urls[urls.length - 1] : undefined
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('URL 查询串驱动筛选与分页：进入页即按 keyword/status/page/page_size 请求', async () => {
    useAuthStore.setState({
      user: makeUser(['applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderAt('/applications?keyword=portal&status=ACTIVE&page=2&page_size=50')
    await screen.findByText('门户应用')
    const url = lastListCall()
    expect(url).toBeTruthy()
    expect(url).toContain('keyword=portal')
    expect(url).toContain('status=ACTIVE')
    expect(url).toContain('page=2')
    expect(url).toContain('page_size=50')
    // 筛选控件回显上下文（返回列表后状态可见）
    expect(screen.getByDisplayValue('portal')).toBeInTheDocument()
  })

  it('变更筛选写回 URL 并重置到第一页（返回列表可恢复上下文）', async () => {
    useAuthStore.setState({
      user: makeUser(['applications.read']),
      csrfToken: null,
      initialized: true,
    })
    const first = renderAt('/applications')
    await screen.findByText('门户应用')
    const search = screen.getByPlaceholderText('搜索编码或名称')
    fireEvent.change(search, { target: { value: 'order' } })
    fireEvent.keyDown(search, { key: 'Enter', code: 'Enter' })
    await waitFor(() => expect(lastListCall()).toContain('keyword=order'))
    // 历史记录中存在带 keyword 的条目：模拟返回 = 重新以该 URL 挂载即恢复
    first.unmount()
    vi.stubGlobal('fetch', mockFetch())
    renderAt('/applications?keyword=order')
    expect(await screen.findByDisplayValue('order')).toBeInTheDocument()
  })
})
