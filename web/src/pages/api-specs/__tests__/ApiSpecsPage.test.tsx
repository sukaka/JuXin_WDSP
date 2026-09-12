import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiSpecsPage from '../ApiSpecsPage'
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

/** spec1：payment-api v2（ACTIVE）；spec2：同名 v1（HISTORICAL），用于激活与版本对比用例 */
const spec1 = {
  id: 'spec1',
  name: 'payment-api',
  version_no: 2,
  status: 'ACTIVE',
  format: 'openapi3',
  file_name: 'openapi-payment.json',
  content_hash: 'abcdef1234567890',
  endpoint_count: 12,
  imported_by: null,
  created_at: '2026-07-21T03:00:00Z',
}

const spec2 = {
  id: 'spec2',
  name: 'payment-api',
  version_no: 1,
  status: 'HISTORICAL',
  format: 'openapi3',
  file_name: 'openapi-payment-v1.json',
  content_hash: 'ffffee1234567890',
  endpoint_count: 10,
  imported_by: null,
  created_at: '2026-07-01T03:00:00Z',
}

const diffData = {
  items: [
    {
      id: 'd1',
      spec_id: 'spec1',
      diff_type: 'MISSING_IN_RUNTIME',
      endpoint_key: 'GET /v1/health',
      detail: { reason: 'not seen in runtime' },
      created_at: '2026-07-21T03:00:01Z',
    },
    {
      id: 'd2',
      spec_id: 'spec1',
      diff_type: 'CHANGED',
      endpoint_key: 'POST /v1/orders',
      detail: { field: 'id' },
      created_at: '2026-07-21T03:00:02Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

const versionDiffData = {
  base: { id: 'spec1', name: 'payment-api', version_no: 2 },
  target: { id: 'spec2', name: 'payment-api', version_no: 1 },
  changes: [
    { endpoint_key: 'POST /v1/orders', change_type: 'PARAM_ADDED', param_in: 'body', param_name: 'trace_id' },
    { endpoint_key: 'GET /v1/health', change_type: 'ENDPOINT_REMOVED' },
  ],
}

/** 各用例可覆盖的列表内容 */
let listItems: Record<string, unknown>[]
let activateCalls: string[]
let importUrlBodies: unknown[]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiSpecsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiSpecsPage', () => {
  beforeEach(() => {
    listItems = [spec1]
    activateCalls = []
    importUrlBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/api-security/specs/spec1/version-diff')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: versionDiffData }))
        }
        if (url.includes('/api-security/specs/spec1/diff')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: diffData }))
        }
        if (method === 'POST' && url.includes('/api-security/specs/spec2/activate')) {
          activateCalls.push(url)
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { spec: { ...spec2, status: 'ACTIVE' } },
            }),
          )
        }
        if (method === 'POST' && url.includes('/api-security/specs/import-url')) {
          importUrlBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                spec: { ...spec1, id: 'spec3', version_no: 3, endpoint_count: 5 },
                missing_in_runtime: 1,
                missing_in_spec: 0,
                changed: 2,
                registered_endpoints: 1,
              },
            }),
          )
        }
        if (url.includes('/api-security/specs')) {
          // 版本链查询（name=payment-api）返回同名全部版本；列表查询返回各用例配置的内容
          const items = url.includes('name=') ? [spec1, spec2] : listItems
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items, page: 1, page_size: 20, total: items.length },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染规范列表：文件名、格式、哈希截断与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('openapi-payment.json')).toBeInTheDocument()
    expect(screen.getByText('openapi3')).toBeInTheDocument()
    expect(screen.getByText('abcdef1234…')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
  })

  it('版本列：规范名 + v 版本号 + 状态 Tag；ACTIVE 行无「激活」按钮', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read', 'api_spec.manage']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('payment-api')).toBeInTheDocument()
    expect(screen.getByText('v2')).toBeInTheDocument()
    expect(screen.getByText('激活')).toBeInTheDocument()
    // ACTIVE 版本不可再激活（按钮为「激 活」两字符自动加空格，与状态 Tag 区分）
    expect(screen.queryByRole('button', { name: /激\s*活/ })).not.toBeInTheDocument()
  })

  it('无 import 权限：不显示「导入规范」', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('openapi-payment.json')
    expect(screen.queryByRole('button', { name: /导入规范/ })).not.toBeInTheDocument()
  })

  it('有 import 权限：显示「导入规范」，非法 JSON 给出提示且不发起导入', async () => {
    useAuthStore.setState({
      user: makeUser(['api_spec.read', 'api_spec.import']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    const importBtn = await screen.findByRole('button', { name: /导入规范/ })
    fireEvent.click(importBtn)
    const textarea = await screen.findByPlaceholderText('{"openapi":"3.0.0",...}')
    fireEvent.change(textarea, { target: { value: 'not-json' } })
    fireEvent.click(screen.getByRole('button', { name: '导 入' }))
    expect(await screen.findByText('规范内容须为合法 JSON')).toBeInTheDocument()
    // 仅列表与初始请求，未触发 /specs/import
    const calls = vi.mocked(fetch).mock.calls.map((c) => String(c[0]))
    expect(calls.some((u) => u.includes('/api-security/specs/import'))).toBe(false)
  })

  it('「查看差异」打开抽屉并渲染差异类型与接口键', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    const viewBtn = await screen.findByRole('button', { name: /查看差异/ })
    fireEvent.click(viewBtn)
    expect(await screen.findByText('运行时缺失')).toBeInTheDocument()
    expect(screen.getByText('定义变更')).toBeInTheDocument()
    expect(screen.getByText('GET /v1/health')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('HISTORICAL 行显示「激活」，二次确认后发起 POST activate', async () => {
    listItems = [spec1, spec2]
    useAuthStore.setState({ user: makeUser(['api_spec.read', 'api_spec.manage']), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /激\s*活/ }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(activateCalls).toHaveLength(1))
    expect(activateCalls[0]).toContain('/api-security/specs/spec2/activate')
  })

  it('「版本对比」抽屉：选择同链另一版本后渲染 CHANGED 级条目', async () => {
    listItems = [spec1, spec2]
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    // 两行同链规范同名，用 findAllByText 兜底
    await screen.findAllByText('payment-api')
    fireEvent.click(screen.getAllByRole('button', { name: /版本对比/ })[0])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('基准 v2')).toBeInTheDocument()
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    fireEvent.click(await screen.findByText('v1（历史）'))
    expect(await within(drawer).findByText('新增参数')).toBeInTheDocument()
    expect(within(drawer).getByText('移除 API')).toBeInTheDocument()
    expect(within(drawer).getByText('body.trace_id')).toBeInTheDocument()
    expect(within(drawer).getByText(/共 2 处定义变更/)).toBeInTheDocument()
  })

  it('「URL 导入」弹窗：提交 url 并展示导入摘要', async () => {
    useAuthStore.setState({
      user: makeUser(['api_spec.read', 'api_spec.import']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('payment-api')
    fireEvent.click(screen.getByRole('button', { name: /URL 导入/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('规范文档 URL'), {
      target: { value: 'https://example.com/openapi.json' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: '导 入' }))
    await waitFor(() => expect(importUrlBodies).toHaveLength(1))
    expect(importUrlBodies[0]).toEqual({ url: 'https://example.com/openapi.json' })
    expect(await screen.findByText(/导入成功：payment-api v3/)).toBeInTheDocument()
  })

  it('「URL 导入」认证头值为密码输入框，填写后组装 headers 提交', async () => {
    useAuthStore.setState({
      user: makeUser(['api_spec.read', 'api_spec.import']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('payment-api')
    fireEvent.click(screen.getByRole('button', { name: /URL 导入/ }))
    const dialog = await screen.findByRole('dialog')

    // 认证头值按凭据处理：password 类型 + new-password 自动完成
    const headerValueInput = within(dialog).getByLabelText('认证头值')
    expect(headerValueInput).toHaveAttribute('type', 'password')
    expect(headerValueInput).toHaveAttribute('autocomplete', 'new-password')

    fireEvent.change(within(dialog).getByLabelText('规范文档 URL'), {
      target: { value: 'https://example.com/openapi.json' },
    })
    fireEvent.change(within(dialog).getByLabelText('认证头名称（可选）'), {
      target: { value: 'Authorization' },
    })
    fireEvent.change(headerValueInput, { target: { value: 'Bearer token-abc' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '导 入' }))

    await waitFor(() => expect(importUrlBodies).toHaveLength(1))
    expect(importUrlBodies[0]).toEqual({
      url: 'https://example.com/openapi.json',
      headers: { Authorization: 'Bearer token-abc' },
    })
  })
})
