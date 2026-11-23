import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiFlowBaselinesPage from '../ApiFlowBaselinesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
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

const SUMMARY = {
  id: 'f-1',
  flow_id: 'order-checkout',
  name: '下单结账',
  description: '',
  enabled: true,
  version: 3,
  step_count: 2,
  created_by: 'admin',
  created_at: '2026-09-10T00:00:00Z',
  updated_at: '2026-09-10T01:00:00Z',
}

const DETAIL = {
  ...SUMMARY,
  max_per_window: 25,
  rate_window_seconds: 300,
  steps: [
    {
      id: 's-1',
      step_id: 'create-order',
      endpoint_id: 'e-1',
      endpoint_key: 'POST /api/orders',
      sequence: 1,
      predecessors: [],
      terminal: false,
      state_from: '',
      state_to: 'CREATED',
      max_per_window: 10,
      rate_window_seconds: 120,
      cancels_flow: false,
    },
    {
      id: 's-2',
      step_id: 'pay-order',
      endpoint_id: 'e-2',
      endpoint_key: 'POST /api/orders/{id}/pay',
      sequence: 2,
      predecessors: ['create-order'],
      terminal: true,
      state_from: 'CREATED',
      state_to: 'PAID',
      max_per_window: 0,
      rate_window_seconds: 0,
      cancels_flow: true,
    },
  ],
}

const ENDPOINTS = {
  items: [
    { id: 'e-1', endpoint_key: 'POST /api/orders' },
    { id: 'e-2', endpoint_key: 'POST /api/orders/{id}/pay' },
  ],
  page: 1,
  page_size: 100,
  total: 2,
}

interface MockOptions {
  items?: unknown[]
  detail?: unknown
  putStatus?: number
  postStatus?: number
  deleteStatus?: number
}

function mockFetch(
  opts: MockOptions = {},
  calls: { method: string; url: string; body?: unknown }[] = [],
) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ method, url, body })
    const ok = (status: number, data: unknown) =>
      Promise.resolve(
        jsonResponse(status, { code: 'SUCCESS', message: 'ok', data }),
      )
    if (url.includes('/api-security/endpoints')) return ok(200, ENDPOINTS)
    if (url.includes('/api-security/flow-baselines/')) {
      if (method === 'PUT') {
        if (opts.putStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, {
              code: 'RESOURCE_CONFLICT',
              message: '版本冲突：基线已被他人修改，请刷新后重试',
              data: null,
            }),
          )
        }
        return ok(200, {
          ...DETAIL,
          ...(body as object),
          version: DETAIL.version + 1,
        })
      }
      if (method === 'DELETE') return ok(200, { status: 'deleted' })
      return ok(200, opts.detail ?? DETAIL)
    }
    if (url.includes('/api-security/flow-baselines')) {
      if (method === 'POST')
        return ok(opts.postStatus ?? 201, {
          ...DETAIL,
          ...(body as object),
          id: 'f-new',
        })
      const enabled = new URL(url, 'http://localhost').searchParams.get(
        'enabled',
      )
      return ok(200, {
        items: opts.items ?? [SUMMARY],
        total: (opts.items ?? [SUMMARY]).length,
        enabled,
      })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <ApiFlowBaselinesPage />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function grant(permissions: string[]) {
  useAuthStore.setState({
    user: makeUser(permissions),
    csrfToken: null,
    initialized: true,
  })
}

const READ = ['api_flow.read']
const FULL = ['api_flow.read', 'api_flow.manage']

describe('ApiFlowBaselinesPage', () => {
  beforeEach(() => {
    grant(FULL)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示 flow_id/状态/步骤数/版本/更新时间；enabled 过滤入请求', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    expect(await screen.findByText('order-checkout')).toBeTruthy()
    expect(screen.getByText('下单结账')).toBeTruthy()
    expect(screen.getByText('已启用')).toBeTruthy()
    expect(screen.getByText('2')).toBeTruthy()

    fireEvent.mouseDown(screen.getByText('按状态过滤'))
    const option = (await screen.findAllByText('已禁用')).find((el) =>
      el.closest('.ant-select-item-option-content'),
    )
    fireEvent.click(option as HTMLElement)
    await waitFor(() => {
      expect(
        calls.some((c) => c.url.includes('flow-baselines?enabled=false')),
      ).toBe(true)
    })
  })

  it('权限门控：无 api_flow.manage 时隐藏新建/编辑/启停/删除，仅保留详情', async () => {
    grant(READ)
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    expect(await screen.findByText('order-checkout')).toBeTruthy()
    expect(screen.queryByText('新建流程基线')).toBeNull()
    expect(screen.queryByText('编辑')).toBeNull()
    expect(screen.queryByText('禁用')).toBeNull()
    expect(screen.queryByText('删除')).toBeNull()
    expect(screen.getByText('详情')).toBeTruthy()
  })

  it('新建表单必填校验：空表单提交给出流程标识/步骤标识/绑定端点错误', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('新建流程基线'))
    fireEvent.click(await screen.findByText('保 存'))
    expect(await screen.findByText('流程标识必填')).toBeTruthy()
    expect(screen.getByText('步骤标识必填')).toBeTruthy()
    expect(screen.getByText('请选择绑定端点')).toBeTruthy()
  })

  it('步骤校验：step_id 流程内重复被列表级校验拦截', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('新建流程基线'))
    fireEvent.change(await screen.findByPlaceholderText('如：order-checkout'), {
      target: { value: 'dup-flow' },
    })
    fireEvent.click(screen.getByText('添加步骤'))
    const stepInputs = await screen.findAllByPlaceholderText('如：create-order')
    expect(stepInputs).toHaveLength(2)
    for (const input of stepInputs) {
      fireEvent.change(input, { target: { value: 'dup' } })
    }
    fireEvent.click(screen.getByText('保 存'))
    expect(await screen.findByText('步骤标识重复：dup')).toBeTruthy()
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
  })

  it('前置步骤校验：指向未声明步骤被拦截', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('新建流程基线'))
    fireEvent.change(await screen.findByPlaceholderText('如：order-checkout'), {
      target: { value: 'flow-pred' },
    })
    fireEvent.click(screen.getByText('添加步骤'))
    const stepInputs = await screen.findAllByPlaceholderText('如：create-order')
    fireEvent.change(stepInputs[0], { target: { value: 'step-a' } })
    fireEvent.change(stepInputs[1], { target: { value: 'step-b' } })
    // step-b 选择 step-a 为前置，随后把 step-a 改名为 step-x，前置即悬空
    const predSelects = screen.getAllByText('无前置约束')
    fireEvent.mouseDown(predSelects[predSelects.length - 1])
    fireEvent.click(await screen.findByTitle('step-a'))
    fireEvent.change(stepInputs[0], { target: { value: 'step-x' } })
    fireEvent.click(screen.getByText('保 存'))
    expect(await screen.findByText('前置步骤未声明：step-a')).toBeTruthy()
  })

  it('新建成功：POST 载荷含步骤（endpoint_id 绑定），不含仅出参字段', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('新建流程基线'))
    fireEvent.change(await screen.findByPlaceholderText('如：order-checkout'), {
      target: { value: 'new-flow' },
    })
    fireEvent.change(screen.getByPlaceholderText('如：create-order'), {
      target: { value: 'create-order' },
    })
    fireEvent.mouseDown(screen.getByText('选择 API 端点'))
    fireEvent.click(await screen.findByTitle('POST /api/orders'))
    fireEvent.click(screen.getByText('保 存'))
    await waitFor(() => {
      const post = calls.find((c) => c.method === 'POST')
      expect(post).toBeTruthy()
      const body = post?.body as {
        flow_id: string
        steps: Record<string, unknown>[]
        expected_version?: number
      }
      expect(body.flow_id).toBe('new-flow')
      expect(body.steps).toHaveLength(1)
      expect(body.steps[0].step_id).toBe('create-order')
      expect(body.steps[0].endpoint_id).toBe('e-1')
      expect(body.steps[0]).not.toHaveProperty('endpoint_key')
      // 表单留空的限速/取消字段省略不发送
      expect(body.steps[0]).not.toHaveProperty('max_per_window')
      expect(body.steps[0]).not.toHaveProperty('rate_window_seconds')
      expect(body.steps[0]).not.toHaveProperty('cancels_flow')
      expect(body.expected_version).toBeUndefined()
    })
    expect(await screen.findByText('流程基线已创建')).toBeTruthy()
  })

  it('编辑保存：PUT 携带 expected_version 乐观锁（整体替换）', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('编辑'))
    expect(await screen.findByDisplayValue('order-checkout')).toBeTruthy()
    expect(screen.getByDisplayValue('create-order')).toBeTruthy()
    // 流程级 + 步骤级短窗限速/取消语义字段从详情回填（零值回填为空，开关按布尔回填）
    expect(screen.getByDisplayValue('25')).toBeTruthy()
    expect(screen.getByDisplayValue('300')).toBeTruthy()
    expect(screen.getByDisplayValue('10')).toBeTruthy()
    expect(screen.getByDisplayValue('120')).toBeTruthy()
    fireEvent.click(screen.getByText('保 存'))
    await waitFor(() => {
      const put = calls.find((c) => c.method === 'PUT')
      expect(put).toBeTruthy()
      expect(put?.url).toContain('/api-security/flow-baselines/f-1')
      const body = put?.body as {
        expected_version: number
        max_per_window?: number
        rate_window_seconds?: number
        steps: Record<string, unknown>[]
      }
      expect(body.expected_version).toBe(3)
      expect(body.max_per_window).toBe(25)
      expect(body.rate_window_seconds).toBe(300)
      expect(body.steps).toHaveLength(2)
      // 非零字段随载荷提交；零值/未填写字段省略不发送
      expect(body.steps[0].max_per_window).toBe(10)
      expect(body.steps[0].rate_window_seconds).toBe(120)
      expect(body.steps[0]).not.toHaveProperty('cancels_flow')
      expect(body.steps[1].cancels_flow).toBe(true)
      expect(body.steps[1]).not.toHaveProperty('max_per_window')
      expect(body.steps[1]).not.toHaveProperty('rate_window_seconds')
    })
    expect(await screen.findByText('已保存（版本 4）')).toBeTruthy()
  })

  it('409 乐观锁冲突：抽屉内提示版本冲突并提供「加载最新版本」恢复入口', async () => {
    vi.stubGlobal('fetch', mockFetch({ putStatus: 409 }))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('编辑'))
    expect(await screen.findByDisplayValue('order-checkout')).toBeTruthy()
    fireEvent.click(screen.getByText('保 存'))
    expect(await screen.findByText('版本冲突')).toBeTruthy()
    expect(
      screen.getByText(/版本冲突：基线已被他人修改，请刷新后重试/),
    ).toBeTruthy()
    expect(screen.getByText('加载最新版本')).toBeTruthy()
  })

  it('禁用：确认后先拉详情再 PUT 翻转 enabled（整体替换 + 乐观锁）', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('禁用'))
    fireEvent.click(await screen.findByText('确认禁用'))
    await waitFor(() => {
      const put = calls.find((c) => c.method === 'PUT')
      expect(put).toBeTruthy()
      const body = put?.body as {
        enabled: boolean
        expected_version: number
        max_per_window?: number
        rate_window_seconds?: number
        steps: unknown[]
      }
      expect(body.enabled).toBe(false)
      expect(body.expected_version).toBe(3)
      expect(body.max_per_window).toBe(25)
      expect(body.rate_window_seconds).toBe(300)
      expect(body.steps).toHaveLength(2)
    })
    expect(await screen.findByText('已禁用')).toBeTruthy()
  })

  it('删除：Popconfirm 确认后 DELETE 并提示', async () => {
    const calls: { method: string; url: string; body?: unknown }[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('删除'))
    fireEvent.click(await screen.findByText('确认删除'))
    await waitFor(() => {
      const del = calls.find((c) => c.method === 'DELETE')
      expect(del).toBeTruthy()
      expect(del?.url).toContain('/api-security/flow-baselines/f-1')
    })
    expect(await screen.findByText('已删除')).toBeTruthy()
  })

  it('详情抽屉：展示步骤明细（endpoint_key 关联带出、前置步骤、状态转换）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('order-checkout')
    fireEvent.click(screen.getByText('详情'))
    expect(await screen.findByText('pay-order')).toBeTruthy()
    expect(screen.getByText('POST /api/orders/{id}/pay')).toBeTruthy()
    // 「create-order」同时出现在步骤标识列与 pay-order 的前置步骤列
    expect(screen.getAllByText('create-order').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/CREATED → PAID/)).toBeTruthy()
    // 短窗限速与取消语义读模型展示
    expect(screen.getByText('10 次 / 120s')).toBeTruthy()
    expect(screen.getByText('取消')).toBeTruthy()
  })
})
