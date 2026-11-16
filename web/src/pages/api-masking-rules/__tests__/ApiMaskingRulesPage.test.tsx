import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
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

const encryptRule = {
  id: 'r3',
  name: '用户手机号加密',
  enabled: true,
  scope: 'GLOBAL',
  application_id: null,
  endpoint_key: null,
  field_path: 'user.phone',
  data_type: null,
  algorithm: 'ENCRYPT',
  params_json: { key_id: 'key-prod_01' },
  exclusions_json: {},
  created_by: 'admin',
  created_at: '2026-08-03T02:00:00Z',
  updated_at: '2026-08-12T02:00:00Z',
}

const mapRule = {
  id: 'r4',
  name: '用户身份证映射',
  enabled: true,
  scope: 'GLOBAL',
  application_id: null,
  endpoint_key: null,
  field_path: 'user.id_card',
  data_type: null,
  algorithm: 'MAP',
  params_json: { map_id: 'map-prod_01' },
  exclusions_json: {},
  created_by: 'admin',
  created_at: '2026-08-04T02:00:00Z',
  updated_at: '2026-08-13T02:00:00Z',
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
  let decryptCalls: { url: string; body: unknown }[]
  let decryptError: string | null

  beforeEach(() => {
    createBodies = []
    patchCalls = []
    decryptCalls = []
    decryptError = null
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (
          method === 'POST' &&
          url.endsWith('/api-security/masking-rules/decrypt')
        ) {
          decryptCalls.push({ url, body: JSON.parse(String(init?.body)) })
          if (decryptError) {
            return Promise.resolve(
              jsonResponse(400, {
                code: 'DECRYPT_FAILED',
                message: decryptError,
                data: null,
              }),
            )
          }
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { plaintext: '服务端恢复明文' },
            }),
          )
        }
        if (method === 'POST' && url.includes('/api-security/masking-rules')) {
          createBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: globalRule,
            }),
          )
        }
        if (
          method === 'PATCH' &&
          url.includes('/api-security/masking-rules/')
        ) {
          patchCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: endpointRule,
            }),
          )
        }
        if (method === 'GET' && url.includes('/api-security/masking-rules')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [globalRule, endpointRule, encryptRule, mapRule],
                page: 1,
                page_size: 20,
                total: 4,
              },
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

    const row = (await screen.findByText('全局手机号掩码')).closest(
      'tr',
    ) as HTMLElement
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

    fireEvent.change(screen.getByLabelText('规则名称'), {
      target: { value: '测试规则' },
    })
    fireEvent.change(screen.getByLabelText('目标字段路径'), {
      target: { value: 'a.b' },
    })
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
      const item = screen
        .getByText('作用域', { selector: 'label' })
        .closest('.ant-form-item')
      fireEvent.mouseDown(item?.querySelector('.ant-select') as HTMLElement)
    }
    const clickOption = async (text: string) => {
      const candidates = await screen.findAllByText(text)
      const option = candidates.find((el) =>
        el.closest('.ant-select-item-option-content'),
      )
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

    const row = (await screen.findByText('订单接口身份证号移除')).closest(
      'tr',
    ) as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /编\s*辑/ }))

    await screen.findByText('编辑规则：订单接口身份证号移除')
    // 预填：ENDPOINT 作用域的接口标识与排除对象标签
    await waitFor(() => {
      expect(screen.getByLabelText('目标接口')).toHaveValue(
        'GET /v1/orders/{id}',
      )
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

  it('ENCRYPT/MAP：展示标签、校验标识并保存真实 params_json', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const encryptRow = (await screen.findByText('用户手机号加密')).closest(
      'tr',
    ) as HTMLElement
    expect(within(encryptRow).getByText('加密')).toBeInTheDocument()
    const mapRow = (await screen.findByText('用户身份证映射')).closest(
      'tr',
    ) as HTMLElement
    expect(within(mapRow).getByText('映射')).toBeInTheDocument()

    const selectAlgorithm = async (label: string) => {
      const item = screen
        .getByText('脱敏算法', { selector: 'label' })
        .closest('.ant-form-item')
      fireEvent.mouseDown(item?.querySelector('.ant-select') as HTMLElement)
      const candidates = await screen.findAllByText(label)
      const option = candidates.find((el) =>
        el.closest('.ant-select-item-option-content'),
      )
      expect(option).toBeTruthy()
      fireEvent.click(option as HTMLElement)
    }

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建脱敏规则')
    fireEvent.change(screen.getByLabelText('规则名称'), {
      target: { value: '加密规则' },
    })
    fireEvent.change(screen.getByLabelText('目标字段路径'), {
      target: { value: 'user.phone' },
    })
    await selectAlgorithm('加密（ENCRYPT）')

    expect(
      await screen.findByLabelText('密钥标识（key_id）'),
    ).toBeInTheDocument()
    expect(
      screen.queryByLabelText('映射表标识（map_id）'),
    ).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    expect(await screen.findByText('请填写密钥标识')).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)

    fireEvent.change(screen.getByLabelText('密钥标识（key_id）'), {
      target: { value: 'bad key!' },
    })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    expect(
      await screen.findByText('密钥标识须为 1–64 位字母、数字、下划线或连字符'),
    ).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)

    fireEvent.change(screen.getByLabelText('密钥标识（key_id）'), {
      target: { value: 'key_prod-01_ABC' },
    })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(createBodies).toHaveLength(1))
    expect(createBodies[0]).toMatchObject({ algorithm: 'ENCRYPT' })
    expect((createBodies[0] as { params_json: unknown }).params_json).toEqual({
      key_id: 'key_prod-01_ABC',
    })

    fireEvent.click(await screen.findByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建脱敏规则')
    fireEvent.change(screen.getByLabelText('规则名称'), {
      target: { value: '映射规则' },
    })
    fireEvent.change(screen.getByLabelText('目标字段路径'), {
      target: { value: 'user.id_card' },
    })
    await selectAlgorithm('映射（MAP）')

    expect(
      await screen.findByLabelText('映射表标识（map_id）'),
    ).toBeInTheDocument()
    expect(
      screen.queryByLabelText('密钥标识（key_id）'),
    ).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('映射表标识（map_id）'), {
      target: { value: 'bad/map' },
    })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    expect(
      await screen.findByText(
        '映射表标识须为 1–64 位字母、数字、下划线或连字符',
      ),
    ).toBeInTheDocument()
    expect(createBodies).toHaveLength(1)

    fireEvent.change(screen.getByLabelText('映射表标识（map_id）'), {
      target: { value: 'map_prod-02' },
    })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(createBodies).toHaveLength(2))
    expect(createBodies[1]).toMatchObject({ algorithm: 'MAP' })
    expect((createBodies[1] as { params_json: unknown }).params_json).toEqual({
      map_id: 'map_prod-02',
    })
  })

  it('编辑 ENCRYPT 规则：预填并保留 key_id', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row = (await screen.findByText('用户手机号加密')).closest(
      'tr',
    ) as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /编\s*辑/ }))
    await screen.findByText('编辑规则：用户手机号加密')
    await waitFor(() => {
      expect(screen.getByLabelText('密钥标识（key_id）')).toHaveValue(
        'key-prod_01',
      )
    })
    expect(
      screen.queryByLabelText('映射表标识（map_id）'),
    ).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toContain('/api-security/masking-rules/r3')
    expect(patchCalls[0].body).toMatchObject({
      algorithm: 'ENCRYPT',
      params_json: { key_id: 'key-prod_01' },
    })
  })

  it('恢复验证：提交 ciphertext 并显示服务端 plaintext', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: '恢复验证' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('密文（ciphertext）'), {
      target: { value: 'ciphertext_123==' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /验\s*证/ }))

    await waitFor(() => expect(decryptCalls).toHaveLength(1))
    expect(decryptCalls[0].url).toBe(
      '/api/v1/api-security/masking-rules/decrypt',
    )
    expect(decryptCalls[0].body).toEqual({ ciphertext: 'ciphertext_123==' })
    expect(
      await within(dialog).findByLabelText('明文（plaintext）'),
    ).toHaveValue('服务端恢复明文')
  })

  it('恢复验证：真实展示服务端错误且不伪造明文', async () => {
    decryptError = '密文无效或密钥不可用'
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: '恢复验证' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('密文（ciphertext）'), {
      target: { value: 'invalid-ciphertext' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /验\s*证/ }))

    expect(
      await within(dialog).findByText('密文无效或密钥不可用'),
    ).toBeInTheDocument()
    expect(
      within(dialog).queryByLabelText('明文（plaintext）'),
    ).not.toBeInTheDocument()
  })

  it('无 api_data.manage 权限：不显示新建、恢复验证与行内操作', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('全局手机号掩码')
    expect(
      screen.queryByRole('button', { name: /新建规则/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '恢复验证' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /编\s*辑/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /删\s*除/ }),
    ).not.toBeInTheDocument()
  })
})
