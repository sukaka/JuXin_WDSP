import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiRuntimePoliciesPage from '../ApiRuntimePoliciesPage'
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

const endpointsData = {
  items: [
    {
      id: 'e1',
      http_method: 'POST',
      normalized_path: '/v1/orders/{id}',
      endpoint_key: 'POST /v1/orders/{id}',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
      is_api: true,
      hit_count: 12,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const policiesData = {
  items: [
    {
      id: 'p1',
      endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      source_model_version_id: 'm2',
      runtime_version: 'v2',
      compiler_version: 'v1',
      content_hash: 'aaaaaaaaaaaaaaaaaaaa',
      status: 'ACTIVE',
      created_at: '2026-07-20T02:00:00Z',
      published_at: '2026-07-20T03:00:00Z',
      activated_at: '2026-07-20T03:00:00Z',
    },
    {
      id: 'p2',
      endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      source_model_version_id: 'm1',
      runtime_version: 'v1',
      compiler_version: 'v1',
      content_hash: 'bbbbbbbbbbbbbbbbbbbb',
      status: 'FAILED',
      error: 'gateway reload timeout',
      created_at: '2026-07-19T02:00:00Z',
    },
    {
      id: 'p3',
      endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      source_model_version_id: 'm3',
      runtime_version: 'v3',
      compiler_version: 'v1',
      content_hash: 'cccccccccccccccccccc',
      status: 'DRAFT',
      created_at: '2026-07-21T02:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 3,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiRuntimePoliciesPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiRuntimePoliciesPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/runtime-policies')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: policiesData }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：接口键、运行时版本、中文状态 Tag、哈希截断与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('生效中')).toBeInTheDocument()
    expect(screen.getByText('发布失败')).toBeInTheDocument()
    expect(screen.getByText('草稿')).toBeInTheDocument()
    expect(screen.getByText('v2')).toBeInTheDocument()
    expect(screen.getByText('aaaaaaaaaa…')).toBeInTheDocument()
    expect(screen.getByText('共 3 条')).toBeInTheDocument()
  })

  it('无 api_model.activate 权限：不显示「回滚」', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('生效中')
    expect(screen.queryByRole('button', { name: /^回\s*滚$/ })).not.toBeInTheDocument()
  })

  it('有权限：仅 ACTIVE/FAILED 行显示「回滚」，确认后 POST rollback', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.activate']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('生效中')
    // DRAFT 行不显示回滚
    expect(screen.getAllByRole('button', { name: /^回\s*滚$/ })).toHaveLength(2)
    fireEvent.click(screen.getAllByRole('button', { name: /^回\s*滚$/ })[1])
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*认\s*回\s*滚/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/api-security/runtime-policies/p2/rollback'),
      )
      expect(call).toBeTruthy()
      expect(call?.[1]?.method).toBe('POST')
    })
  })

  it('溯源抽屉：展示来源模型版本编译产生的全部策略（含当前标记）', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/models/m2/runtime')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [
                { ...policiesData.items[0] },
                { ...policiesData.items[0], id: 'p0', runtime_version: 'v1', status: 'ROLLED_BACK' },
              ],
            },
          }),
        )
      }
      if (url.includes('/api-security/runtime-policies')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: policiesData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()
    await screen.findByText('生效中')
    fireEvent.click(screen.getAllByRole('button', { name: /^溯\s*源$/ })[0])
    expect(await screen.findByText(/模型 → 策略溯源/)).toBeInTheDocument()
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) => String(c[0]).includes('/api-security/models/m2/runtime')),
      ).toBe(true)
    })
    expect(await screen.findByText('（当前）')).toBeInTheDocument()
    expect(screen.getByText('已退出')).toBeInTheDocument()
  })

  it('状态过滤：选择状态后列表请求携带 status 参数', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('生效中')
    // 按占位文本定位状态选择器并展开下拉
    fireEvent.mouseDown(screen.getByText('按状态过滤'))
    // 「发布失败」同时出现在表格状态 Tag 与下拉项，须取下拉项（.ant-select-item-option-content）
    const candidates = await screen.findAllByText('发布失败')
    const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/api-security/runtime-policies') && u.includes('status=FAILED'))).toBe(true)
    })
  })
})
