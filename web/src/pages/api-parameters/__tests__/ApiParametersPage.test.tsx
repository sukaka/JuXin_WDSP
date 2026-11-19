import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiParametersPage from '../ApiParametersPage'
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
      normalized_path: '/v1/orders',
      endpoint_key: 'POST /v1/orders',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
      is_api: true,
      hit_count: 8,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const versionsData = {
  items: [
    {
      id: 'm1',
      api_endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders',
      status: 'FORMAL',
      schema: { note: 'string' },
      content_hash: 'abcdef1234567890',
      version_number: 1,
      change_summary: '',
      created_reason: 'MANUAL',
      created_at: '2026-07-19T02:00:00Z',
      confirmed_at: '2026-07-19T03:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const parameter = {
  id: 'p1',
  model_version_id: 'm1',
  direction: 'REQUEST',
  location: 'BODY',
  structured_path: 'note',
  parameter_name: 'note',
  base_type: 'string',
  semantic_type: '',
  required: true,
  nullable: true,
  empty_allowed: true,
  observed_constraints: {},
  recommended_constraints: {},
  confirmed_constraints: { max_length: 32, enum: ['A', 'B'] },
  sensitivity_level: 'LOW',
  confidence: 1,
  created_at: '2026-07-20T02:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiParametersPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiParametersPage', () => {
  let patchBodies: unknown[]

  beforeEach(() => {
    patchBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/api-security/parameters/p1') && init?.method === 'PATCH') {
          patchBodies.push(JSON.parse(String(init.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: '已保存', data: { parameter } }))
        }
        if (url.includes('/api-security/models/m1/parameters')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [parameter], page: 1, page_size: 20, total: 1 } }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: versionsData }))
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

  it('编辑抽屉：预填确认约束，PATCH 提交体含 confirmed_constraints（钉死词汇）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_parameter.read', 'api_parameter.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    // 打开编辑抽屉
    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    const drawer = await screen.findByRole('dialog')

    // 预填：max_length=32、enum 标签 A/B
    await waitFor(() => {
      expect(screen.getByLabelText('最大长度（字符数）')).toHaveValue('32')
    })
    expect(drawer.textContent).toContain('A')
    expect(drawer.textContent).toContain('B')

    // 修改：填入数值下界 minimum=5，清空 max_length
    fireEvent.change(screen.getByLabelText('数值下界'), { target: { value: '5' } })
    fireEvent.change(screen.getByLabelText('最大长度（字符数）'), { target: { value: '' } })

    fireEvent.click(screen.getByRole('button', { name: '保 存' }))

    await waitFor(() => expect(patchBodies).toHaveLength(1))
    const body = patchBodies[0] as Record<string, unknown>
    expect(body.required).toBe(true)
    expect(body.nullable).toBe(true)
    expect(body.empty_allowed).toBe(true)
    expect(body.sensitivity_level).toBe('LOW')
    expect(body.confirmed_constraints).toEqual({ minimum: 5, enum: ['A', 'B'] })
  })

  it('语义类型：预填、修改后随 PATCH 透传', async () => {
    useAuthStore.setState({
      user: makeUser(['api_parameter.read', 'api_parameter.edit']),
      csrfToken: null,
      initialized: true,
    })
    const semParameter = { ...parameter, semantic_type: 'email' }
    ;(fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/api-security/parameters/p1') && init?.method === 'PATCH') {
        patchBodies.push(JSON.parse(String(init.body)))
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: '已保存', data: { parameter: semParameter } }))
      }
      if (url.includes('/api-security/models/m1/parameters')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [semParameter], page: 1, page_size: 20, total: 1 } }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: versionsData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    await screen.findByRole('dialog')
    // 预填 email；改为 phone 后提交
    await waitFor(() => {
      expect(screen.getByLabelText('语义类型')).toHaveValue('email')
    })
    fireEvent.change(screen.getByLabelText('语义类型'), { target: { value: 'phone' } })
    fireEvent.click(screen.getByRole('button', { name: '保 存' }))

    await waitFor(() => expect(patchBodies).toHaveLength(1))
    expect((patchBodies[0] as Record<string, unknown>).semantic_type).toBe('phone')
  })

  it('全部约束留空时 confirmed_constraints 提交为 {}（清空语义）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_parameter.read', 'api_parameter.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    await screen.findByRole('dialog')
    await waitFor(() => {
      expect(screen.getByLabelText('最大长度（字符数）')).toHaveValue('32')
    })

    // 清空 max_length 与 enum 后提交
    fireEvent.change(screen.getByLabelText('最大长度（字符数）'), { target: { value: '' } })
    for (const close of document.querySelectorAll('.ant-select-selection-item-remove')) {
      fireEvent.click(close)
    }
    fireEvent.click(screen.getByRole('button', { name: '保 存' }))

    await waitFor(() => expect(patchBodies).toHaveLength(1))
    expect((patchBodies[0] as Record<string, unknown>).confirmed_constraints).toEqual({})
  })

  it('无 edit 权限：不显示行内编辑入口', async () => {
    useAuthStore.setState({ user: makeUser(['api_parameter.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('note')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
  })

  it('四层视图：观测/推荐/确认/运行时生效约束四列同屏展示中文约束键与布尔值', async () => {
    useAuthStore.setState({ user: makeUser(['api_parameter.read']), csrfToken: null, initialized: true })
    const richParameter = {
      ...parameter,
      observed_constraints: { max_length: 64, enum_suspected: true },
      recommended_constraints: { max_length: 48, nullable: false },
      confirmed_constraints: { max_length: 32 },
    }
    ;(fetch as unknown as ReturnType<typeof vi.fn>).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/models/m1/parameters')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [richParameter], page: 1, page_size: 20, total: 1 } }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: versionsData }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    renderPage()

    const table = (await screen.findAllByRole('table'))[0]
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.textContent ?? '')
    expect(headers.some((h) => h.includes('观测约束'))).toBe(true)
    expect(headers.some((h) => h.includes('推荐约束'))).toBe(true)
    expect(headers.some((h) => h.includes('确认约束'))).toBe(true)
    expect(headers.some((h) => h.includes('运行时生效约束'))).toBe(true)

    // 行内容：中文约束键 + 布尔转「是/否」；运行时生效约束 = 确认约束（最大长度：32 出现两次）
    await waitFor(() => expect(table.textContent).toContain('最大长度：64'))
    expect(table.textContent).toContain('疑似枚举：是')
    expect(table.textContent).toContain('最大长度：48')
    expect(table.textContent).toContain('允许为空：否')
    expect(table.textContent?.match(/最大长度：32/g)).toHaveLength(2)
    expect(table.textContent).not.toContain('max_length')
  })
})
