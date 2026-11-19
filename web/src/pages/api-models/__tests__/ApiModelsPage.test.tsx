import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiModelsPage from '../ApiModelsPage'
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
      learning_status: 'LEARNING',
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

const listData = {
  items: [
    {
      id: 'm1',
      api_endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      status: 'CANDIDATE',
      schema: { id: 'number' },
      content_hash: 'abcdef1234567890',
      version_number: 3,
      change_summary: '',
      created_reason: 'MANUAL',
      created_at: '2026-07-20T02:00:00Z',
    },
    {
      id: 'm2',
      api_endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      status: 'FORMAL',
      schema: { id: 'number', name: 'string' },
      content_hash: '0011223344556677',
      version_number: 2,
      change_summary: '',
      created_reason: 'MANUAL',
      created_at: '2026-07-19T02:00:00Z',
      confirmed_at: '2026-07-19T03:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiModelsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiModelsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
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

  it('渲染列表：中文状态 Tag、哈希截断与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('候选')).toBeInTheDocument()
    expect(screen.getByText('正式')).toBeInTheDocument()
    expect(screen.getByText('abcdef1234…')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无 edit 权限：不显示「创建候选」与行内「确认冻结」', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('候选')
    expect(screen.queryByRole('button', { name: /创\s*建\s*候\s*选/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /确\s*认\s*冻\s*结/ })).not.toBeInTheDocument()
  })

  it('有 edit 权限：显示「创建候选」，候选行显示「确认冻结」', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('候选')
    expect(screen.getByRole('button', { name: /创\s*建\s*候\s*选/ })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /确\s*认\s*冻\s*结/ })).toHaveLength(1)
  })

  it('生命周期按钮按权限与状态显隐：候选行可评审/拒绝，正式行可激活/归档', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.review', 'api_model.activate', 'api_model.archive']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('候选')
    // m1 为 CANDIDATE：提交评审/拒绝各 1；m2 为 FORMAL：激活/归档各 1
    expect(screen.getAllByRole('button', { name: /提\s*交\s*评\s*审/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^拒\s*绝$/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^激\s*活$/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^归\s*档$/ })).toHaveLength(1)
    // 无 api_learning.start 权限：不显示「重新学习」
    expect(screen.queryByRole('button', { name: /重\s*新\s*学\s*习/ })).not.toBeInTheDocument()
  })

  it('提交评审：弹窗填写意见后 POST submit-review（携带 comment）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.review']),
      csrfToken: null,
      initialized: true,
    })
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/models/m1/submit-review')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { version: {}, message: '已提交评审' } }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()
    await screen.findByText('候选')
    fireEvent.click(screen.getByRole('button', { name: /提\s*交\s*评\s*审/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: '请复核字段' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /提\s*交\s*评\s*审/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) => String(c[0]).includes('/api-security/models/m1/submit-review'))
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ comment: '请复核字段' })
    })
  })

  it('激活：二次确认后 POST activate', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.activate']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('正式')
    fireEvent.click(screen.getByRole('button', { name: /^激\s*活$/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /^O\s*K$|^确\s*定$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) => String(c[0]).includes('/api-security/models/m2/activate'))
      expect(call).toBeTruthy()
    })
  })

  it('对比抽屉：选择对比版本后展示字段级差异', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/models/m1/diff/m2')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              id: 'd1',
              model_version_id: 'm1',
              other_version_id: 'm2',
              diff: { added: ['name'], removed: [], type_changed: [{ field: 'id', from: 'number', to: 'string' }] },
              created_at: '2026-07-21T02:00:00Z',
            },
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()
    await screen.findByText('候选')
    fireEvent.click(screen.getAllByRole('button', { name: /^对\s*比$/ })[0])
    const drawer = await screen.findByText('版本对比：v3（POST /v1/orders/{id}）')
    expect(drawer).toBeInTheDocument()
    const drawerEl = document.querySelector('.ant-drawer') as HTMLElement
    fireEvent.mouseDown(within(drawerEl).getByRole('combobox'))
    fireEvent.click(await screen.findByText('v2 · 正式 · 00112233'))
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) => String(c[0]).includes('/api-security/models/m1/diff/m2')),
      ).toBe(true)
    })
    expect(await within(drawerEl).findByText('新增字段')).toBeInTheDocument()
    expect(within(drawerEl).getByText('name')).toBeInTheDocument()
    expect(within(drawerEl).getByText('类型变化')).toBeInTheDocument()
    expect(within(drawerEl).getByText(/数字 → 字符串/)).toBeInTheDocument()
  })

  it('策略溯源抽屉：展示该模型版本编译产生的运行时策略', async () => {
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
                {
                  id: 'rp1',
                  endpoint_id: 'e1',
                  endpoint_key: 'POST /v1/orders/{id}',
                  source_model_version_id: 'm2',
                  runtime_version: 'v1',
                  compiler_version: 'v1',
                  content_hash: '9988776655443322',
                  status: 'ACTIVE',
                  created_at: '2026-07-19T03:00:00Z',
                },
              ],
            },
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()
    await screen.findByText('正式')
    fireEvent.click(screen.getAllByRole('button', { name: /策\s*略\s*溯\s*源/ })[1])
    expect(await screen.findByText('策略溯源：v2（POST /v1/orders/{id}）')).toBeInTheDocument()
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) => String(c[0]).includes('/api-security/models/m2/runtime')),
      ).toBe(true)
    })
    expect(await screen.findByText('v1')).toBeInTheDocument()
    expect(screen.getByText('生效中')).toBeInTheDocument()
  })

  it('重新学习：有 api_learning.start 权限时显示，确认后 POST learning/start', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_learning.start']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('候选')
    fireEvent.click(screen.getByRole('button', { name: /重\s*新\s*学\s*习/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /^O\s*K$|^确\s*定$/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/api-security/endpoints/e1/learning/start'),
      )
      expect(call).toBeTruthy()
      expect(call?.[1]?.method).toBe('POST')
    })
  })
})
