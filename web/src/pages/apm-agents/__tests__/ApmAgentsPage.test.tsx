import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApmAgentsPage from '../ApmAgentsPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const APP_ID = '11111111-1111-1111-1111-111111111111'

const AGENTS = {
  items: [
    {
      id: 'ag-1',
      service_name: 'shop-order',
      instance_id: 'i-abcdef01',
      language: 'Java',
      agent_version: '1.2.0',
      status: 'CONNECTED_BASELINE',
      last_heartbeat_at: new Date(Date.now() - 65_000).toISOString(),
      cert_not_after: '2026-12-31T00:00:00Z',
      application_id: APP_ID,
      environment: 'prod',
    },
    {
      id: 'ag-2',
      service_name: 'shop-web',
      instance_id: 'i-abcdef02',
      language: 'Go',
      agent_version: '0.9.1',
      status: 'REVOKED',
      last_heartbeat_at: '2026-08-29T00:00:00Z',
      cert_not_after: '2026-01-01T00:00:00Z',
      application_id: APP_ID,
      environment: 'test',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

const APPS = {
  items: [{ id: APP_ID, code: 'shop', name: '商城站点' }],
  page: 1,
  page_size: 100,
  total: 1,
}

const POLICY = {
  scope: `application:${APP_ID}`,
  version: 3,
  issued_at: '2026-08-01T00:00:00Z',
  expires_at: '2026-09-01T00:00:00Z',
  policy: { sampling_rate: 0.5, signals: ['traces'] },
  signature: 'sig-abc',
}

interface MockOptions {
  listStatus?: number
  agents?: unknown
  getPolicyStatus?: number
  putStatus?: number
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/agents/enrollment-tokens') && method === 'POST') {
      return ok({
        token_id: 'tok-1',
        token: 'tok-secret-abc',
        application_id: APP_ID,
        environment: 'prod',
        allowed_languages: ['java'],
        expires_at: '2026-08-30T02:00:00Z',
      })
    }
    if (url.includes('/apm/agents/') && url.endsWith('/revoke') && method === 'POST') {
      return ok({ ...AGENTS.items[0], status: 'REVOKED' })
    }
    if (url.includes('/apm/policies/')) {
      if (method === 'PUT') {
        if (opts.putStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, { code: 'CONFLICT', message: '策略版本冲突', data: null }),
          )
        }
        const body = JSON.parse(String(init?.body)) as { policy: Record<string, unknown> }
        return ok({ ...POLICY, version: POLICY.version + 1, policy: body.policy })
      }
      if (opts.getPolicyStatus === 404) {
        return Promise.resolve(
          jsonResponse(404, { code: 'NOT_FOUND', message: '该作用域暂无策略版本', data: null }),
        )
      }
      return ok(POLICY)
    }
    if (url.includes('/apm/agents')) {
      const status = opts.listStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.agents ?? AGENTS)
    }
    if (url.includes('/applications')) return ok(APPS)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ApmAgentsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 点击 antd 下拉选项（portal 渲染，按 title 属性定位以避开表格同文本） */
async function clickSelectOption(title: string) {
  await waitFor(() => {
    expect(document.querySelector(`.ant-select-item-option[title="${title}"]`)).toBeTruthy()
  })
  fireEvent.click(document.querySelector(`.ant-select-item-option[title="${title}"]`)!)
}

function policyPutCalls() {
  return (fetch as Mock).mock.calls.filter(
    (c) => String(c[0]).includes('/apm/policies/') && (c[1] as RequestInit | undefined)?.method === 'PUT',
  )
}

describe('ApmAgentsPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染：五态 Tag、服务/实例、相对心跳、证书到期标识；已撤销行无撤销操作', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    const row = (await screen.findByText('shop-order')).closest('tr')!
    expect(row.textContent).toContain('i-abcdef01')
    expect(row.textContent).toContain('Java')
    expect(row.textContent).toContain('1.2.0')
    expect(row.textContent).toContain('生产')
    const row2 = screen.getByText('shop-web').closest('tr')!
    expect(row2.textContent).toContain('测试')
    expect(screen.getByText('已连接·基线')).toBeInTheDocument()
    expect(screen.getByText('已撤销')).toBeInTheDocument()
    // 最后心跳相对时间（65 秒前 → 1 分钟前）
    expect(screen.getByText('1 分钟前')).toBeInTheDocument()
    // 过期证书标识
    expect(screen.getByText(/已过期/)).toBeInTheDocument()
    // 仅未撤销行提供撤销操作
    expect(screen.getAllByRole('button', { name: /撤\s*销/ })).toHaveLength(1)
    // 安装指引折叠面板（静态文案）
    expect(screen.getByText(/安装指引/)).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('空列表展示空态', async () => {
    vi.stubGlobal('fetch', mockFetch({ agents: { items: [], page: 1, page_size: 20, total: 0 } }))
    renderPage()
    expect(await screen.findByText('暂无数据')).toBeInTheDocument()
  })

  it('创建注册令牌：表单提交后令牌原文仅展示一次', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '创建注册令牌' }))
    const dialog = await screen.findByRole('dialog')

    // 应用下拉（combobox[0]）、环境 AutoComplete（combobox[1]）、语言多选（combobox[2]）
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    await clickSelectOption('商城站点（shop）')
    fireEvent.change(within(dialog).getAllByRole('combobox')[1], {
      target: { value: 'prod' },
    })
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[2])
    await clickSelectOption('Java')
    fireEvent.keyDown(within(dialog).getAllByRole('combobox')[2], { key: 'Escape' })

    fireEvent.click(within(dialog).getByRole('button', { name: /^创\s*建$/ }))

    // 令牌一次性展示视图
    expect(await screen.findByText('令牌原文仅显示一次')).toBeInTheDocument()
    expect(screen.getByText('tok-secret-abc')).toBeInTheDocument()

    // 提交体校验（使用后端 allowed_languages 小写枚举与 expires_in_minutes）
    const createCall = (fetch as Mock).mock.calls.find(
      (c) => String(c[0]).includes('/apm/agents/enrollment-tokens'),
    )
    expect(createCall).toBeTruthy()
    expect(JSON.parse(String(createCall![1]?.body))).toEqual({
      application_id: APP_ID,
      environment: 'prod',
      allowed_languages: ['java'],
      expires_in_minutes: 60,
    })

    // 关闭后令牌不再可见
    fireEvent.click(screen.getByRole('button', { name: /完\s*成/ }))
    await waitFor(() => expect(screen.queryByText('tok-secret-abc')).not.toBeInTheDocument())
  })

  it('撤销 Agent：Popconfirm 二次确认后调用 revoke 接口', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: /撤\s*销/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认撤销' }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/apm/agents/ag-1/revoke'),
      )
      expect(call).toBeTruthy()
      expect((call![1] as RequestInit).method).toBe('POST')
    })
    expect(await screen.findByText('Agent 已撤销')).toBeInTheDocument()
  })

  it('基线策略 Drawer：使用 global / application:<uuid> 作用域加载并带 expected_version 保存', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')
    // 未选 scope 前的提示
    expect(within(drawer).getByText('请选择策略作用域（全局或应用）以查看其基线策略')).toBeInTheDocument()

    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('商城站点（shop）')

    // 确认请求携带编码后的 application:<uuid> 作用域
    await waitFor(() => {
      const getCall = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes(`/apm/policies/${encodeURIComponent(`application:${APP_ID}`)}`),
      )
      expect(getCall).toBeTruthy()
    })

    // 策略加载：版本/签发/过期信息与 JSON 草稿
    expect(await within(drawer).findByText('v3')).toBeInTheDocument()
    const textarea = drawer.querySelector('textarea')!
    expect(textarea.value).toContain('"sampling_rate": 0.5')

    fireEvent.change(textarea, { target: { value: '{"sampling_rate": 0.8}' } })
    fireEvent.click(within(drawer).getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => expect(policyPutCalls()).toHaveLength(1))
    expect(String(policyPutCalls()[0][0])).toContain(
      `/apm/policies/${encodeURIComponent(`application:${APP_ID}`)}`,
    )
    expect(JSON.parse(String(policyPutCalls()[0][1]?.body))).toEqual({
      policy: { sampling_rate: 0.8 },
      expected_version: 3,
    })
    expect(await screen.findByText('策略已保存')).toBeInTheDocument()
  })

  it('基线策略 Drawer：作用域尚无策略（404）时可编辑模板并以 expected_version=0 创建 v1', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch({ getPolicyStatus: 404 }))
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('全局默认（global）')

    expect(await within(drawer).findByText('该作用域暂无策略版本')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => expect(policyPutCalls()).toHaveLength(1))
    expect(String(policyPutCalls()[0][0])).toContain('/apm/policies/global')
    expect(JSON.parse(String(policyPutCalls()[0][1]?.body))).toMatchObject({
      expected_version: 0,
    })
  })

  it('策略保存 409 版本冲突：提示刷新重试', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch({ putStatus: 409 }))
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('商城站点（shop）')
    await within(drawer).findByText('v3')

    fireEvent.click(within(drawer).getByRole('button', { name: /保\s*存/ }))

    expect(await screen.findByText(/策略版本冲突.*刷新/)).toBeInTheDocument()
  })

  it('基线策略作用域远程搜索：输入防抖后带 keyword 查询应用列表', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByRole('combobox'), { target: { value: 'shop' } })

    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/applications') && u.includes('keyword=shop'))).toBe(true)
    })
  })

  it('策略 JSON 非法时不发起保存请求', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('商城站点（shop）')
    await within(drawer).findByText('v3')

    fireEvent.change(drawer.querySelector('textarea')!, { target: { value: '{bad json' } })
    fireEvent.click(within(drawer).getByRole('button', { name: /保\s*存/ }))

    expect(await screen.findByText('策略 JSON 格式不正确，请检查后重试')).toBeInTheDocument()
    expect(policyPutCalls()).toHaveLength(0)
  })

  it('基线策略 Drawer：在多个 404 作用域间来回切换（命中缓存 404）仍填充默认模板且不覆盖用户编辑', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch({ getPolicyStatus: 404 }))
    renderPage()
    await screen.findByText('shop-order')

    fireEvent.click(screen.getByRole('button', { name: '基线策略' }))
    const drawer = await screen.findByRole('dialog')

    // 1) global (404) -> 默认基线模板落位
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('全局默认（global）')
    expect(await within(drawer).findByText('该作用域暂无策略版本')).toBeInTheDocument()
    const getTextarea = () => drawer.querySelector('textarea')!
    await waitFor(() => {
      expect(JSON.parse(getTextarea().value)).toEqual({
        signals: ['traces', 'metrics', 'runtime', 'exceptions'],
        sampling_rate: 1,
      })
    })

    // 编辑 global 草稿，确认切换作用域后会重置为新作用域模板
    fireEvent.change(getTextarea(), {
      target: { value: '{"signals":["traces"],"sampling_rate":0.25}' },
    })

    // 2) 切换到 application:<uuid> (404)
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('商城站点（shop）')
    await waitFor(() => {
      const appGet = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes(`/apm/policies/${encodeURIComponent(`application:${APP_ID}`)}`),
      )
      expect(appGet).toBeTruthy()
    })
    await waitFor(() => {
      expect(JSON.parse(getTextarea().value)).toEqual({
        signals: ['traces', 'metrics', 'runtime', 'exceptions'],
        sampling_rate: 1,
      })
    })

    // 3) 切回已缓存 404 的 global：isPolicyNotFound 保持 true->true，仍必须填充默认模板而非清空
    const globalGetsBefore = (fetch as Mock).mock.calls.filter((c) =>
      String(c[0]).endsWith('/apm/policies/global'),
    ).length
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('全局默认（global）')
    await waitFor(() => {
      expect(getTextarea().value).not.toBe('')
      expect(JSON.parse(getTextarea().value)).toEqual({
        signals: ['traces', 'metrics', 'runtime', 'exceptions'],
        sampling_rate: 1,
      })
    })

    // 4) 编辑后即使触发后台重拉 404 也不覆盖用户编辑，重复选择当前作用域也不清空草稿，最终以 expected_version=0 保存
    fireEvent.change(getTextarea(), {
      target: { value: '{"signals":["traces"],"sampling_rate":0.6}' },
    })
    await waitFor(() => {
      const globalGetsAfter = (fetch as Mock).mock.calls.filter((c) =>
        String(c[0]).endsWith('/apm/policies/global'),
      ).length
      expect(globalGetsAfter).toBeGreaterThan(globalGetsBefore)
    })
    expect(JSON.parse(getTextarea().value)).toEqual({
      signals: ['traces'],
      sampling_rate: 0.6,
    })

    // 重复点击当前已选中的作用域，不得清空用户编辑
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('全局默认（global）')
    expect(JSON.parse(getTextarea().value)).toEqual({
      signals: ['traces'],
      sampling_rate: 0.6,
    })

    fireEvent.click(within(drawer).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(policyPutCalls()).toHaveLength(1))
    expect(String(policyPutCalls()[0][0])).toContain('/apm/policies/global')
    expect(JSON.parse(String(policyPutCalls()[0][1]?.body))).toEqual({
      policy: { signals: ['traces'], sampling_rate: 0.6 },
      expected_version: 0,
    })
  })
})
