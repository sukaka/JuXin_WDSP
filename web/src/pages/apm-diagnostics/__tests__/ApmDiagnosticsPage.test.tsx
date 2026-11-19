import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmDiagnosticsPage from '../ApmDiagnosticsPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const APPLICATIONS = {
  items: [
    {
      id: 'app-1',
      code: 'shop',
      name: '商城站点',
      description: '',
      business_owner: '',
      technical_owner: '',
      status: 'ENABLED',
      protection_mode: 'BLOCK',
      deployment_status: 'DEPLOYED',
      health_status: 'HEALTHY',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const SERVICES = {
  items: [
    {
      application_id: 'app-1',
      app: 'shop',
      name: '商城站点',
      observation_mode: 'agent',
      agents_online: 1,
      agents_total: 1,
      requests: 5000,
      error_rate: 0.01,
      blocked: 0,
      p50: 10,
      p95: 120,
      p99: 300,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const RUNTIME = {
  data_source: 'otel',
  note: '',
  instances: [
    { instance_id: 'inst-001', service_name: 'shop', metrics: [] },
    { instance_id: 'inst-002', service_name: 'shop', metrics: [] },
  ],
}

function makeSession(over: Record<string, unknown>) {
  return {
    id: 'diag-x',
    scope: {
      application_id: 'app-1',
      service: 'shop',
      environment: 'production',
      instance_ids: ['inst-001', 'inst-002'],
    },
    capabilities: ['sql_detail'],
    sampling_rate: 0.5,
    duration_minutes: 30,
    status: 'EXPIRED',
    created_by: 'secops',
    created_at: '2026-08-30T01:00:00Z',
    expires_at: '2026-08-30T01:30:00Z',
    stopped_at: null,
    stopped_by: null,
    stop_reason: null,
    ...over,
  }
}

const SESSIONS_PAGE = {
  list: [
    makeSession({
      id: 'diag-1',
      status: 'ACTIVE',
      capabilities: ['sql_detail', 'function_probe'],
      sampling_rate: 0.5,
      // 未来 30 分钟到期 → 列表/详情显示倒计时
      expires_at: new Date(Date.now() + 30 * 60000).toISOString(),
    }),
    makeSession({
      id: 'diag-2',
      status: 'EXPIRED',
      scope: {
        application_id: 'app-1',
        service: 'pay',
        environment: 'staging',
        instance_ids: ['inst-101'],
      },
      capabilities: ['gc_detail'],
      sampling_rate: 1,
    }),
    makeSession({
      id: 'diag-3',
      status: 'STOPPED',
      capabilities: ['thread_block'],
      stopped_at: '2026-08-30T01:20:00Z',
      stopped_by: 'secops',
      stop_reason: '人工提前停止',
    }),
    makeSession({
      id: 'diag-4',
      status: 'KILLED',
      capabilities: ['mq_wait'],
      stopped_at: '2026-08-30T01:25:00Z',
      stopped_by: 'system',
      stop_reason: 'kill_switch',
    }),
  ],
  total: 4,
  page: 1,
  page_size: 20,
  kill_switch_enabled: false,
}

const SESSION_DETAIL = {
  ...SESSIONS_PAGE.list[0],
  audits: [
    {
      id: 'audit-1',
      action: 'CREATE',
      actor: 'secops',
      detail: '创建诊断会话（dry_run 预估已确认）',
      created_at: '2026-08-30T01:00:00Z',
    },
    {
      id: 'audit-2',
      action: 'POLICY_PUSH',
      actor: 'system',
      detail: '策略已下发至 2 个实例',
      created_at: '2026-08-30T01:00:05Z',
    },
  ],
}

const DRY_RUN_RESULT = {
  estimated_overhead: {
    cpu_hint: '约 +8% CPU（每实例）',
    spans_per_s_hint: '约 1200 spans/s',
    data_volume_hint: '约 300 MB/小时',
    risk_notes: ['SQL 明细可能包含敏感数据片段', '函数探针开销随调用量上升'],
  },
}

const CREATED_SESSION = makeSession({ id: 'diag-new', status: 'ACTIVE' })

interface MockOptions {
  listStatus?: number
  list?: unknown
  detail?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/diagnostics/kill-switch')) return ok({ kill_switch_enabled: true })
    if (url.includes('/apm/diagnostic-sessions/') && url.endsWith('/stop')) {
      return ok({ ...CREATED_SESSION, id: 'diag-1', status: 'STOPPED' })
    }
    if (url.includes('/apm/diagnostic-sessions/')) return ok(opts.detail ?? SESSION_DETAIL)
    if (url.includes('/apm/diagnostic-sessions')) {
      if (method === 'POST') {
        const body = JSON.parse(String(init?.body)) as { dry_run?: boolean }
        if (body.dry_run) return ok(DRY_RUN_RESULT)
        return ok(CREATED_SESSION)
      }
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
      return ok(opts.list ?? SESSIONS_PAGE)
    }
    if (url.includes('/applications')) return ok(APPLICATIONS)
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/runtime')) return ok(RUNTIME)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/apm-diagnostics']}>
          <ApmDiagnosticsPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 等待向导 Steps 指示器进入目标步骤（步骤正文各段常驻挂载仅 display 切换，文本断言不可靠，以指示器为准） */
async function waitWizardStep(dialog: HTMLElement, title: string) {
  await waitFor(() => {
    const current = dialog.querySelector('.ant-steps-item-process .ant-steps-item-title')
    expect(current?.textContent).toBe(title)
  })
}

/** 打开创建向导并完成第 1、2 步（范围 + 能力），停留在第 3 步（采样与时长） */
async function openWizardToStep3() {
  fireEvent.click(screen.getByRole('button', { name: '新建诊断会话' }))
  const dialog = await screen.findByRole('dialog')

  // 第 1 步：范围（应用 Select + 服务/环境 AutoComplete + 实例多选）
  const appPlaceholder = within(dialog).getByText('选择应用')
  fireEvent.mouseDown(appPlaceholder.closest('.ant-select-placeholder') ?? appPlaceholder)
  const appOptions = await screen.findAllByText('商城站点（shop）')
  fireEvent.click(
    appOptions.find((el) => el.closest('.ant-select-item-option-content')) ?? appOptions[0],
  )
  // 服务/环境为 AutoComplete（antd 6 占位符非 input placeholder），按 combobox 顺序定位
  const comboboxes = within(dialog).getAllByRole('combobox')
  fireEvent.change(comboboxes[1], { target: { value: 'shop' } })
  fireEvent.change(comboboxes[2], { target: { value: 'production' } })
  const instPlaceholder = within(dialog).getByText(/选择实例/)
  fireEvent.mouseDown(instPlaceholder.closest('.ant-select-placeholder') ?? instPlaceholder)
  // 每次重试都重新查询当前可见下拉中的选项节点，避免拿到重新渲染前的过期句柄
  await waitFor(() => {
    const option = [...document.querySelectorAll('.ant-select-item-option')].find((o) =>
      o.textContent?.includes('inst-001（shop）'),
    )
    expect(option).toBeTruthy()
    fireEvent.click(option as Element)
  })
  await waitFor(() => {
    const selected = [...dialog.querySelectorAll('.ant-select-selection-item')].some((el) =>
      el.textContent?.includes('inst-001'),
    )
    expect(selected).toBe(true)
  })
  fireEvent.click(within(dialog).getByRole('button', { name: '下一步' }))
  // handleNext 是异步的（validateFields 可能经 outOfDate 重试），必须等步进真正完成再操作
  await waitWizardStep(dialog, '诊断能力')

  // 第 2 步：能力（勾选 SQL 明细 + 函数探针，触发精确范围提示）
  fireEvent.click(await within(dialog).findByText('SQL 明细'))
  fireEvent.click(within(dialog).getByText('函数探针'))
  expect(await within(dialog).findByText('函数探针需精确的实例/服务范围')).toBeInTheDocument()
  fireEvent.click(within(dialog).getByRole('button', { name: '下一步' }))
  await waitWizardStep(dialog, '采样与时长')

  return dialog
}

describe('ApmDiagnosticsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('正常渲染会话列表：状态 Tag 四态、范围摘要、能力标签、采样率、发起人与 ACTIVE 行倒计时', async () => {
    renderPage()

    expect(await screen.findAllByText('进行中')).not.toHaveLength(0)
    // 状态 Tag 四态
    expect(screen.getByText('已到期')).toBeInTheDocument()
    expect(screen.getByText('已停止')).toBeInTheDocument()
    expect(screen.getByText('已熔断')).toBeInTheDocument()
    // 范围摘要：服务名与环境 · 实例数（多条会话同为 production/app-1，按多元素断言）
    expect(screen.getAllByText('shop').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/生产 · 2 实例 · 应用 app-1/).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/预发布 · 1 实例 · 应用 app-1/)).toBeInTheDocument()
    expect(screen.queryByText(/production · 2 实例/)).not.toBeInTheDocument()
    // 能力标签
    expect(screen.getAllByText('SQL 明细').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('函数探针')).toBeInTheDocument()
    expect(screen.getByText('GC 明细')).toBeInTheDocument()
    expect(screen.getByText('消息等待')).toBeInTheDocument()
    // 采样率按百分比展示（多条会话同为 50.00%，按多元素断言）
    expect(screen.getAllByText('50.00%').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('100.00%')).toBeInTheDocument()
    // 发起人
    expect(screen.getAllByText('secops').length).toBeGreaterThanOrEqual(1)
    // ACTIVE 行剩余时间倒计时（30 分钟 → 「N 分 N 秒」），非 ACTIVE 行显示占位符
    expect(screen.getByText(/^\d+ 分 \d+ 秒$/)).toBeInTheDocument()
    // ACTIVE 行有「提前停止」，其余行无
    expect(screen.getAllByText('提前停止')).toHaveLength(1)
  })

  it('空列表展示空态文案', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ list: { list: [], total: 0, page: 1, page_size: 20, kill_switch_enabled: false } }),
    )
    renderPage()
    expect(
      await screen.findByText('暂无诊断会话，点击右上角「新建诊断会话」创建'),
    ).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('kill_switch_enabled=true 时整页红色 Alert 且新建按钮禁用', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ list: { ...SESSIONS_PAGE, kill_switch_enabled: true } }),
    )
    renderPage()
    expect(
      await screen.findByText('全局熔断开关已开启，新建会话被拒绝'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建诊断会话' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '解除全局熔断开关' })).toBeInTheDocument()
  })

  it('创建向导四步流转：dry_run 预估展示，未勾选确认时不能提交', { timeout: 60000 }, async () => {
    renderPage()
    await screen.findAllByText('进行中')
    const dialog = await openWizardToStep3()

    // 第 3 步：采样率/时长 Slider（默认值 50% / 15 分钟）
    expect(dialog.querySelectorAll('.ant-slider')).toHaveLength(2)
    expect(within(dialog).getByText(/采样率（当前 50.00%）/)).toBeInTheDocument()
    expect(within(dialog).getByText(/诊断时长（当前 15 分钟/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '下一步' }))

    // 第 4 步：dry_run 预估结果展示（机器高负载下 antd 步进与 mutation 渲染较慢，给足等待预算）
    expect(
      await within(dialog).findByText('约 +8% CPU（每实例）', undefined, { timeout: 30000 }),
    ).toBeInTheDocument()
    expect(within(dialog).getByText('约 1200 spans/s')).toBeInTheDocument()
    expect(within(dialog).getByText('约 300 MB/小时')).toBeInTheDocument()
    expect(within(dialog).getByText('SQL 明细可能包含敏感数据片段')).toBeInTheDocument()
    expect(within(dialog).getByText('函数探针开销随调用量上升')).toBeInTheDocument()

    // dry_run 请求体验证
    await waitFor(() => {
      const dryRun = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/apm/diagnostic-sessions') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(dryRun).toBeTruthy()
      expect(JSON.parse(String((dryRun![1] as RequestInit).body))).toEqual({
        scope: {
          application_id: 'app-1',
          service: 'shop',
          environment: 'production',
          instance_ids: ['inst-001'],
        },
        capabilities: ['sql_detail', 'function_probe'],
        sampling_rate: 0.5,
        duration_minutes: 15,
        dry_run: true,
      })
    })

    // 未勾选「我已了解开销与风险」时确认创建按钮禁用
    expect(within(dialog).getByRole('button', { name: '确认创建' })).toBeDisabled()
    // 未提交正式创建请求（仅有 dry_run 一次 POST）
    expect(
      (fetch as Mock).mock.calls.filter(
        (c) =>
          String(c[0]).includes('/apm/diagnostic-sessions') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toHaveLength(1)
  })

  it('勾选「我已了解开销与风险」后以 confirm=true 正式创建', { timeout: 60000 }, async () => {
    renderPage()
    await screen.findAllByText('进行中')
    const dialog = await openWizardToStep3()
    fireEvent.click(within(dialog).getByRole('button', { name: '下一步' }))
    await within(dialog).findByText('约 +8% CPU（每实例）', undefined, { timeout: 30000 })

    fireEvent.click(within(dialog).getByText('我已了解开销与风险'))
    const submit = within(dialog).getByRole('button', { name: '确认创建' })
    expect(submit).toBeEnabled()
    fireEvent.click(submit)

    await waitFor(() => {
      const create = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/apm/diagnostic-sessions') &&
          (c[1] as RequestInit | undefined)?.method === 'POST' &&
          JSON.parse(String((c[1] as RequestInit).body)).confirm === true,
      )
      expect(create).toBeTruthy()
      expect(JSON.parse(String((create![1] as RequestInit).body))).toEqual({
        scope: {
          application_id: 'app-1',
          service: 'shop',
          environment: 'production',
          instance_ids: ['inst-001'],
        },
        capabilities: ['sql_detail', 'function_probe'],
        sampling_rate: 0.5,
        duration_minutes: 15,
        confirm: true,
      })
    })
    expect(await screen.findByText('诊断会话已创建')).toBeInTheDocument()
  })

  it('提前停止：Popconfirm 二次确认后调用 stop 接口', { timeout: 60000 }, async () => {
    renderPage()
    await screen.findAllByText('进行中')

    fireEvent.click(screen.getAllByText('提前停止')[0])
    fireEvent.click(await screen.findByRole('button', { name: '确认停止' }))

    await waitFor(() => {
      const stop = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]) === '/api/v1/apm/diagnostic-sessions/diag-1/stop' &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(stop).toBeTruthy()
    })
    expect(await screen.findByText('诊断会话已停止')).toBeInTheDocument()
  })

  it('全局熔断开关：Popconfirm 说明影响，确认后 POST enable=true', { timeout: 60000 }, async () => {
    renderPage()
    await screen.findAllByText('进行中')

    fireEvent.click(screen.getByRole('button', { name: '开启全局熔断开关' }))
    expect(
      await screen.findByText(/开启后将立即终止全部进行中的诊断会话，并拒绝新建任何诊断会话/),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认开启' }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes('/apm/diagnostics/kill-switch'),
      )
      expect(call).toBeTruthy()
      expect((call![1] as RequestInit | undefined)?.method).toBe('POST')
      expect(JSON.parse(String((call![1] as RequestInit).body))).toEqual({ enable: true })
    })
    expect(await screen.findByText('全局熔断开关已开启')).toBeInTheDocument()
  })

  it('详情 Drawer：会话全字段、倒计时、停止原因与关联审计中文映射', { timeout: 60000 }, async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        detail: {
          ...SESSION_DETAIL,
          stop_reason: 'kill_switch',
        },
      }),
    )
    renderPage()
    await screen.findAllByText('进行中')

    fireEvent.click(screen.getAllByText('详情')[0])
    expect(await screen.findByText('诊断会话详情')).toBeInTheDocument()
    // 详情为异步查询，等待数据落位后再断言字段
    expect(await screen.findByText('diag-1')).toBeInTheDocument()
    expect(screen.getByText('inst-001、inst-002')).toBeInTheDocument()
    expect(screen.getByText('全局熔断终止')).toBeInTheDocument()
    // ACTIVE 详情显示倒计时与停止入口
    expect(screen.getAllByText(/^\d+ 分 \d+ 秒$/).length).toBeGreaterThanOrEqual(1)
    // 关联审计：CREATE 映射为「创建诊断会话」，未知动作 POLICY_PUSH 原样兜底
    expect(await screen.findByText('关联审计')).toBeInTheDocument()
    expect(screen.getByText('创建诊断会话')).toBeInTheDocument()
    expect(screen.getByText('POLICY_PUSH')).toBeInTheDocument()
    expect(screen.getByText('策略已下发至 2 个实例')).toBeInTheDocument()
    // 详情接口被调用
    const detailCalls = (fetch as Mock).mock.calls.filter((c) =>
      String(c[0]).includes('/apm/diagnostic-sessions/diag-1'),
    )
    expect(detailCalls.length).toBeGreaterThanOrEqual(1)
  })
})
