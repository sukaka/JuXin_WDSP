import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiMaskingRulesPage from '../ApiMaskingRulesPage'
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

const globalRule = {
  id: 'r1',
  name: '全局手机号掩码',
  enabled: true,
  scope: 'GLOBAL',
  application_id: null,
  endpoint_key: null,
  field_path: 'users[].phone',
  data_type: null,
  algorithm: 'MASK',
  params_json: { keep_head: 2, keep_tail: 4 },
  exclusions_json: {},
  created_by: 'admin',
  created_at: '2026-08-01T02:00:00Z',
  updated_at: '2026-08-10T02:00:00Z',
}

const endpointRule = {
  id: 'r2',
  name: '订单接口身份证号移除',
  enabled: false,
  scope: 'ENDPOINT',
  application_id: null,
  endpoint_key: 'GET /v1/orders/{id}',
  field_path: 'order.id_card',
  data_type: null,
  algorithm: 'REMOVE',
  params_json: {},
  exclusions_json: { identity: ['u123'], ip: ['10.0.0.0/24'] },
  created_by: 'admin',
  created_at: '2026-08-02T02:00:00Z',
  updated_at: '2026-08-11T02:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiMaskingRulesPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiMaskingRulesPage', () => {
  let createBodies: unknown[]
  let patchCalls: { url: string; body: unknown }[]

  beforeEach(() => {
    createBodies = []
    patchCalls = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.includes('/api-security/masking-rules')) {
          createBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: globalRule }))
        }
        if (method === 'PATCH' && url.includes('/api-security/masking-rules/')) {
          patchCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointRule }))
        }
        if (method === 'GET' && url.includes('/api-security/masking-rules')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [globalRule, endpointRule], page: 1, page_size: 20, total: 2 },
            }),
          )
        }
        if (method === 'GET' && url.includes('/api-security/sensitive-types')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [
                  { id: 't1', name: '手机号', data_type: 'phone' },
                  { id: 't2', name: '身份证号', data_type: 'id_card' },
                ],
                page: 1,
                page_size: 100,
                total: 2,
              },
            }),
          )
        }
        if (method === 'GET' && url.includes('/applications')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [{ id: 'app1', code: 'mall', name: '商城' }],
                page: 1,
                page_size: 100,
                total: 1,
              },
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

  it('列表渲染：作用域/算法/状态标签', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row = (await screen.findByText('全局手机号掩码')).closest('tr') as HTMLElement
    expect(within(row).getByText('全局')).toBeInTheDocument()
    expect(within(row).getByText('掩码')).toBeInTheDocument()
    expect(within(row).getByText('启用')).toBeInTheDocument()
    expect(within(row).getByText('users[].phone')).toBeInTheDocument()
  })

  it('新建 GLOBAL 规则：提交体不含应用/接口字段（显式空串），MASK 参数默认空对象', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建脱敏规则')
    // GLOBAL 作用域下不出现应用/接口字段
    expect(screen.queryByLabelText('目标应用')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('目标接口')).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('规则名称'), { target: { value: '测试规则' } })
    fireEvent.change(screen.getByLabelText('目标字段路径'), { target: { value: 'a.b' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(createBodies).toHaveLength(1))
    expect(createBodies[0]).toEqual({
      name: '测试规则',
      enabled: true,
      scope: 'GLOBAL',
      application_id: '',
      endpoint_key: '',
      field_path: 'a.b',
      data_type: '',
      algorithm: 'MASK',
      params_json: {},
      exclusions_json: {},
    })
  })

  it('scope 切换联动：APPLICATION 出现应用选择，ENDPOINT 出现接口输入', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建脱敏规则')

    // 初始 GLOBAL：无联动字段
    expect(screen.queryByLabelText('目标应用')).not.toBeInTheDocument()

    // 通过 Form.Item 标签定位作用域下拉并展开（antd v6 Select 根节点为 .ant-select，
    // 选项按 .ant-select-item-option-content 消歧，避免与触发器内已选文案混淆）
    const openScopeSelect = () => {
      const item = screen.getByText('作用域', { selector: 'label' }).closest('.ant-form-item')
      fireEvent.mouseDown(item?.querySelector('.ant-select') as HTMLElement)
    }
    const clickOption = async (text: string) => {
      const candidates = await screen.findAllByText(text)
      const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
      expect(option).toBeTruthy()
      fireEvent.click(option as HTMLElement)
    }

    // 切换到应用级
    openScopeSelect()
    await clickOption('应用级（APPLICATION）')
    expect(await screen.findByLabelText('目标应用')).toBeInTheDocument()
    expect(screen.queryByLabelText('目标接口')).not.toBeInTheDocument()

    // 切换到接口级
    openScopeSelect()
    await clickOption('接口级（ENDPOINT）')
    expect(await screen.findByLabelText('目标接口')).toBeInTheDocument()
    expect(screen.queryByLabelText('目标应用')).not.toBeInTheDocument()
  })

  it('编辑：预填接口与排除对象，PATCH 提交全量字段（含 exclusions_json）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row = (await screen.findByText('订单接口身份证号移除')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /编\s*辑/ }))

    await screen.findByText('编辑规则：订单接口身份证号移除')
    // 预填：ENDPOINT 作用域的接口标识与排除对象标签
    await waitFor(() => {
      expect(screen.getByLabelText('目标接口')).toHaveValue('GET /v1/orders/{id}')
    })
    expect(screen.getByText('u123')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument()
    // REMOVE 算法不渲染 MASK 参数
    expect(screen.queryByLabelText(/keep_head/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toContain('/api-security/masking-rules/r2')
    expect(patchCalls[0].body).toEqual({
      name: '订单接口身份证号移除',
      enabled: false,
      scope: 'ENDPOINT',
      application_id: '',
      endpoint_key: 'GET /v1/orders/{id}',
      field_path: 'order.id_card',
      data_type: '',
      algorithm: 'REMOVE',
      params_json: {},
      exclusions_json: { identity: ['u123'], ip: ['10.0.0.0/24'] },
    })
  })

  it('无 api_data.manage 权限：不显示新建与行内操作', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('全局手机号掩码')
    expect(screen.queryByRole('button', { name: /新建规则/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编\s*辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
  })
})
