import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiSensitiveTypesPage from '../ApiSensitiveTypesPage'
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

const builtinType = {
  id: 't1',
  name: '手机号',
  description: '中国大陆手机号',
  category: '个人信息',
  level: 'SENSITIVE',
  data_type: 'phone',
  locations: ['query', 'json'],
  keywords: ['phone', 'mobile'],
  regex: '^1[3-9]\\d{9}$',
  validator: '',
  exclude_fields: [],
  status: 'ENABLED',
  version: 3,
  is_builtin: true,
  created_at: '2026-08-01T02:00:00Z',
  updated_at: '2026-08-10T02:00:00Z',
}

const customType = {
  id: 't2',
  name: '员工编号',
  description: '',
  category: '',
  level: 'GENERAL',
  data_type: 'emp_no',
  locations: [],
  keywords: ['emp_no'],
  regex: '',
  validator: '',
  exclude_fields: [],
  status: 'ENABLED',
  version: 1,
  is_builtin: false,
  created_at: '2026-08-02T02:00:00Z',
  updated_at: '2026-08-02T02:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiSensitiveTypesPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiSensitiveTypesPage', () => {
  let createBodies: unknown[]
  let patchCalls: { url: string; body: unknown }[]
  let importBodies: unknown[]
  let exportCalled: boolean

  beforeEach(() => {
    createBodies = []
    patchCalls = []
    importBodies = []
    exportCalled = false
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/api-security/sensitive-types/export')) {
          exportCalled = true
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                format: 'jiuzhang-api-sensitive-data-types',
                version: 1,
                exported_at: '2026-08-16T02:00:00Z',
                types: [builtinType, customType],
              },
            }),
          )
        }
        if (method === 'POST' && url.includes('/api-security/sensitive-types/import')) {
          importBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { created: 1, updated: 0 } }),
          )
        }
        if (method === 'POST' && url.includes('/api-security/sensitive-types')) {
          createBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: customType }))
        }
        if (method === 'PATCH' && url.includes('/api-security/sensitive-types/')) {
          patchCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: customType }))
        }
        if (method === 'GET' && url.includes('/api-security/sensitive-types')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [builtinType, customType], page: 1, page_size: 20, total: 2 },
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

  it('列表渲染：内置标识展示，内置类型删除禁用、自定义可删', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const builtinCell = await screen.findByText('手机号')
    const builtinRow = builtinCell.closest('tr') as HTMLElement
    expect(within(builtinRow).getByText('内置')).toBeInTheDocument()
    expect(within(builtinRow).getByRole('button', { name: /删\s*除/ })).toBeDisabled()

    const customRow = (await screen.findByText('员工编号')).closest('tr') as HTMLElement
    expect(within(customRow).queryByText('内置')).not.toBeInTheDocument()
    expect(within(customRow).getByRole('button', { name: /删\s*除/ })).toBeEnabled()
  })

  it('新建类型：提交体带默认 level=GENERAL 与 status=ENABLED', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建类型/ }))
    await screen.findByText('新建敏感数据类型')
    fireEvent.change(screen.getByLabelText('类型名称'), { target: { value: '工号' } })
    fireEvent.change(screen.getByLabelText('数据类型标签'), { target: { value: 'emp_no' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(createBodies).toHaveLength(1))
    expect(createBodies[0]).toEqual({
      name: '工号',
      data_type: 'emp_no',
      level: 'GENERAL',
      category: '',
      description: '',
      locations: [],
      keywords: [],
      regex: '',
      validator: '',
      exclude_fields: [],
      status: 'ENABLED',
    })
  })

  it('行内禁用：二次确认后 PATCH status=DISABLED', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const customRow = (await screen.findByText('员工编号')).closest('tr') as HTMLElement
    fireEvent.click(within(customRow).getByRole('button', { name: /禁\s*用/ }))
    // modal.confirm 二次确认
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toContain('/api-security/sensitive-types/t2')
    expect(patchCalls[0].body).toEqual({ status: 'DISABLED' })
  })

  it('导出：拉取导出文档并提示条数', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /导\s*出/ }))
    await waitFor(() => expect(exportCalled).toBe(true))
    expect(await screen.findByText('已导出 2 条类型定义')).toBeInTheDocument()
  })

  it('导入：选择 JSON 文件，二次确认后按 {types} 提交', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('手机号')

    const file = new File(
      [JSON.stringify({ types: [{ name: '工号', data_type: 'emp_no' }] })],
      'types.json',
      { type: 'application/json' },
    )
    fireEvent.change(screen.getByLabelText('选择导入文件'), { target: { files: [file] } })

    // 解析成功后的二次确认弹窗
    await screen.findByText(/包含 1 条类型定义/)
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(importBodies).toHaveLength(1))
    expect(importBodies[0]).toEqual({ types: [{ name: '工号', data_type: 'emp_no' }] })
  })

  it('无 api_data.manage 权限：不显示新建/编辑/删除入口', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('手机号')
    expect(screen.queryByRole('button', { name: /新建类型/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /导\s*入/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编\s*辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
    // 导出仅需读权限
    expect(screen.getByRole('button', { name: /导\s*出/ })).toBeInTheDocument()
  })
})
