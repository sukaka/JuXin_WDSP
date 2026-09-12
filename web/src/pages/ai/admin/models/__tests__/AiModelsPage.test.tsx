import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AiModelsPage from '../AiModelsPage'
import { useAuthStore } from '../../../../../stores/auth'
import type { CurrentUser } from '../../../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'admin',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
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

const provider = {
  id: 'p1',
  name: '自建推理集群',
  provider_type: 'openai_compatible',
  base_url: 'https://llm.internal.example.com',
  canonical_origin: 'https://llm.internal.example.com:443',
  allowed_targets: ['https://backup-llm.internal.example.com'],
  api_key_reference: 'keyref-01abcdef',
  status: 'ENABLED',
}

/** PATCH/POST 请求体捕获 */
let patchCalls: { url: string; body: Record<string, unknown> }[]
let createCalls: { url: string; body: Record<string, unknown> }[]
/** PATCH 响应中的 provider（用于模拟 origin 变化后密钥被清除） */
let patchResponseProvider: Record<string, unknown>

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <AiModelsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 在 tags Select 中输入一个目标并回车 */
function addTag(scope: HTMLElement, label: RegExp, value: string) {
  const input = within(scope).getByLabelText(label) as HTMLInputElement
  fireEvent.change(input, { target: { value } })
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
}

/** 点击当前供应商弹窗的确定按钮（antd 默认 okText 随语言环境变化） */
function clickModalOk(dialog: HTMLElement) {
  fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
}

/** 定位密钥失效确认弹窗（modal.confirm，含「确认保存」按钮） */
async function findKeyLossConfirmDialog(): Promise<HTMLElement> {
  await screen.findAllByText('确认修改服务地址？')
  const dialog = screen
    .getAllByRole('dialog')
    .find((d) => within(d).queryByRole('button', { name: '确认保存' }))
  if (!dialog) throw new Error('未找到密钥失效确认弹窗')
  return dialog
}

describe('AiModelsPage · R22 出站目标绑定', () => {
  beforeEach(() => {
    patchCalls = []
    createCalls = []
    patchResponseProvider = { ...provider, name: '自建推理集群（改）' }
    useAuthStore.setState({
      user: makeUser(['ai.models.read', 'ai.models.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'PATCH' && url.includes('/ai/models/providers/p1')) {
          patchCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { provider: patchResponseProvider } }),
          )
        }
        if (method === 'POST' && url.endsWith('/ai/models/providers')) {
          createCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { provider: { id: 'p2' } } }),
          )
        }
        if (url.includes('/ai/models/providers')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [provider] } }),
          )
        }
        if (url.includes('/ai/models/routes')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { routes: { simple: '', standard: '', high: '' }, loaded_models: 0 },
            }),
          )
        }
        if (url.endsWith('/ai/models')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [] } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('供应商列表：展示规范 origin、目标白名单与密钥「已配置」状态', async () => {
    renderPage()
    expect(await screen.findByText('https://llm.internal.example.com:443')).toBeInTheDocument()
    expect(screen.getByText('https://backup-llm.internal.example.com')).toBeInTheDocument()
    expect(screen.getByText('已配置')).toBeInTheDocument()
    // 密钥引用内部值不作为主要状态展示
    expect(screen.queryByText('keyref-01abcdef')).not.toBeInTheDocument()
  })

  it('新建供应商：allowlist 提交前 trim、去空、去重', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建供应商/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: '新供应商' } })
    fireEvent.change(within(dialog).getByLabelText('服务地址'), {
      target: { value: 'https://api.vendor.example.com' },
    })
    addTag(dialog, /^附加出站目标白名单/, ' https://a.example.com ')
    addTag(dialog, /^附加出站目标白名单/, 'https://b.example.com')
    // 重复项与空白项应被去除
    addTag(dialog, /^附加出站目标白名单/, 'https://a.example.com')
    clickModalOk(dialog)
    await waitFor(() => expect(createCalls).toHaveLength(1))
    expect(createCalls[0].url).toBe('/api/v1/ai/models/providers')
    expect(createCalls[0].body).toEqual({
      name: '新供应商',
      provider_type: 'openai_compatible',
      base_url: 'https://api.vendor.example.com',
      allowed_targets: ['https://a.example.com', 'https://b.example.com'],
      status: 'ENABLED',
    })
    expect(await screen.findByText('供应商已创建')).toBeInTheDocument()
  })

  it('编辑供应商：BaseURL 变更且原记录已配置密钥时，确认后才发送 PATCH', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('服务地址'), {
      target: { value: 'https://llm2.internal.example.com' },
    })
    clickModalOk(dialog)
    // 先弹确认，确认前不得发送 PATCH
    const confirmDialog = await findKeyLossConfirmDialog()
    expect(patchCalls).toHaveLength(0)
    fireEvent.click(within(confirmDialog).getByRole('button', { name: '确认保存' }))
    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toBe('/api/v1/ai/models/providers/p1')
    expect(patchCalls[0].body).toEqual({
      name: '自建推理集群',
      provider_type: 'openai_compatible',
      base_url: 'https://llm2.internal.example.com',
      allowed_targets: ['https://backup-llm.internal.example.com'],
      status: 'ENABLED',
    })
    expect(await screen.findByText('供应商已更新')).toBeInTheDocument()
  })

  it('编辑供应商：BaseURL 变更确认框中取消，不发送任何请求', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('服务地址'), {
      target: { value: 'https://llm2.internal.example.com' },
    })
    clickModalOk(dialog)
    const confirmDialog = await findKeyLossConfirmDialog()
    fireEvent.click(within(confirmDialog).getByRole('button', { name: /取\s*消/ }))
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: '确认保存' })).not.toBeInTheDocument(),
    )
    expect(patchCalls).toHaveLength(0)
  })

  it('编辑供应商：PATCH 响应密钥引用为空时提示「密钥已失效，请立即重新录入」并保留轮换入口', async () => {
    patchResponseProvider = {
      ...provider,
      base_url: 'https://llm2.internal.example.com',
      canonical_origin: 'https://llm2.internal.example.com:443',
      api_key_reference: '',
    }
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('服务地址'), {
      target: { value: 'https://llm2.internal.example.com' },
    })
    clickModalOk(dialog)
    const confirmDialog = await findKeyLossConfirmDialog()
    fireEvent.click(within(confirmDialog).getByRole('button', { name: '确认保存' }))
    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(await screen.findByText(/原密钥已失效，请立即通过「轮换密钥」重新录入/)).toBeInTheDocument()
    // 轮换密钥入口保留
    expect(screen.getByRole('button', { name: /轮换密钥/ })).toBeInTheDocument()
  })

  it('编辑供应商：未改 BaseURL 的普通更新直接 PATCH，不弹密钥失效确认', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: '自建推理集群（改）' } })
    clickModalOk(dialog)
    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(screen.queryByText('确认修改服务地址？')).not.toBeInTheDocument()
    expect(patchCalls[0].body).toEqual({
      name: '自建推理集群（改）',
      provider_type: 'openai_compatible',
      base_url: 'https://llm.internal.example.com',
      allowed_targets: ['https://backup-llm.internal.example.com'],
      status: 'ENABLED',
    })
    expect(await screen.findByText('供应商已更新')).toBeInTheDocument()
  })
})
