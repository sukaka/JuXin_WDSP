import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiAIOpsPage from '../ApiAIOpsPage'
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

const taskTypesData = {
  items: [
    { task_type: 'API_ASSET_DIGEST', name: '资产变化摘要', description: '新增/确认端点与 Shadow/Zombie 计数' },
    { task_type: 'RISK_DIGEST', name: '高风险发现摘要', description: 'HIGH/CRITICAL 未闭环发现' },
  ],
}

/** 启用中的计划（含上次执行结果） */
const schedule1 = {
  id: 'sch-1',
  task_type: 'API_ASSET_DIGEST',
  name: '每日资产摘要',
  cron_expr: '0 7 * * *',
  enabled: true,
  config: {},
  next_run_at: '2026-08-20T07:00:00Z',
  last_run_at: '2026-08-19T07:00:05Z',
  last_status: 'SUCCESS',
  last_error: '',
  consecutive_failures: 0,
  circuit_opened_at: null,
  circuit_reason: '',
  created_by: null,
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-19T07:00:07Z',
}

/** 停用中的计划（无排期游标与执行历史） */
const schedule2 = {
  id: 'sch-2',
  task_type: 'RISK_DIGEST',
  name: '高危摘要',
  cron_expr: '@daily',
  enabled: false,
  config: {},
  next_run_at: null,
  last_run_at: null,
  last_status: '',
  last_error: '',
  consecutive_failures: 0,
  circuit_opened_at: null,
  circuit_reason: '',
  created_by: null,
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-01T00:00:00Z',
}

/** 熔断中的计划（连续失败 3 次被自动熔断停用） */
const schedule3 = {
  id: 'sch-3',
  task_type: 'RISK_DIGEST',
  name: '熔断计划',
  cron_expr: '@hourly',
  enabled: false,
  config: {},
  next_run_at: null,
  last_run_at: '2026-08-19T07:00:05Z',
  last_status: 'FAILED',
  last_error: 'LLM 调用超时',
  consecutive_failures: 3,
  circuit_opened_at: '2026-08-19T07:00:07Z',
  circuit_reason: '连续失败 3 次，自动熔断',
  created_by: null,
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-19T07:00:07Z',
}

const schedulesData = { items: [schedule1, schedule2, schedule3], page: 1, page_size: 20, total: 3 }

/** 成功执行记录（报告含标量指标与对象清单，验证表格化渲染） */
const run1 = {
  id: 'run-1',
  schedule_id: 'sch-1',
  started_at: '2026-08-19T07:00:05Z',
  finished_at: '2026-08-19T07:00:07Z',
  status: 'SUCCESS',
  summary: '截至 2026-08-19 15:00，API 资产共 42 个。',
  report: {
    total_endpoints: 42,
    new_in_window: 3,
    new_endpoints: [
      {
        id: 'ep-1',
        endpoint_key: 'GET /v1/assets/new',
        method: 'GET',
        path: '/v1/assets/new',
        asset_status: 'DISCOVERED',
        first_seen_at: '2026-08-19T06:00:00Z',
      },
    ],
  },
  created_at: '2026-08-19T07:00:07Z',
}

const runsData = { items: [run1], page: 1, page_size: 20, total: 1 }

/** 写操作捕获 */
let createBodies: unknown[] = []
let putCalls: { path: string; body: unknown }[] = []
let postPaths: string[] = []

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiAIOpsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 在弹窗中展开「任务类型」下拉并选择指定选项（与表格列头按 label 选择器消歧） */
async function selectTaskType(optionText: string) {
  const item = screen.getByText('任务类型', { selector: 'label' }).closest('.ant-form-item')
  fireEvent.mouseDown(item?.querySelector('.ant-select') as HTMLElement)
  const candidates = await screen.findAllByText(optionText)
  const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('ApiAIOpsPage', () => {
  beforeEach(() => {
    createBodies = []
    putCalls = []
    postPaths = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const path = new URL(url, 'http://localhost').pathname
        const method = init?.method ?? 'GET'
        const ok = (data: unknown, status = 200) =>
          Promise.resolve(jsonResponse(status, { code: 'SUCCESS', message: 'ok', data }))
        if (path.endsWith('/api-security/ai-ops/task-types')) return ok(taskTypesData)
        if (path.includes('/schedules/sch-1/runs')) return ok(runsData)
        if (path.includes('/schedules/sch-3/runs')) {
          return ok({ items: [], page: 1, page_size: 20, total: 0 })
        }
        if (path.endsWith('/schedules/sch-1/run') && method === 'POST') {
          postPaths.push(path)
          return ok({ run: run1 })
        }
        if (path.endsWith('/schedules/sch-2/enable') && method === 'POST') {
          postPaths.push(path)
          return ok({ schedule: { ...schedule2, enabled: true } })
        }
        if (path.endsWith('/schedules/sch-3/enable') && method === 'POST') {
          postPaths.push(path)
          return ok({
            schedule: {
              ...schedule3,
              enabled: true,
              consecutive_failures: 0,
              circuit_opened_at: null,
              circuit_reason: '',
            },
          })
        }
        if (path.endsWith('/schedules/sch-1') && method === 'PUT') {
          putCalls.push({ path, body: JSON.parse(String(init?.body)) })
          return ok({ schedule: schedule1 })
        }
        if (path.endsWith('/api-security/ai-ops/schedules')) {
          if (method === 'POST') {
            createBodies.push(JSON.parse(String(init?.body)))
            return ok({ schedule: schedule1 }, 201)
          }
          return ok(schedulesData)
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({
      user: makeUser(['api_ai.read', 'api_ai.execute']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('计划列表：任务类型中文名/cron 表达式/启用开关/下次运行/上次状态', async () => {
    renderPage()
    const row1 = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    expect(within(row1).getByText('资产变化摘要')).toBeInTheDocument()
    expect(within(row1).getByText('0 7 * * *')).toBeInTheDocument()
    expect(within(row1).getByRole('switch')).toBeChecked()
    expect(within(row1).getByText('成功')).toBeInTheDocument()
    // 停用计划：无上次状态显示占位符，开关未勾选
    const row2 = (await screen.findByText('高危摘要')).closest('tr') as HTMLElement
    expect(within(row2).getByText('高风险发现摘要')).toBeInTheDocument()
    expect(within(row2).getByRole('switch')).not.toBeChecked()
    expect(row2.textContent).toContain('-')
  })

  it('新建计划：cron 非法时前端拦截提示且不提交；修正后提交创建体', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建计划/ }))
    await screen.findByText('新建运营计划')

    await selectTaskType('资产变化摘要（API_ASSET_DIGEST）')
    fireEvent.change(screen.getByLabelText('计划名称'), { target: { value: '测试计划' } })
    fireEvent.change(screen.getByLabelText('cron 表达式'), { target: { value: 'bad cron' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    // cron 前端预检拦截：提示五段/宏，未发起创建请求
    expect(await screen.findByText(/须为五段/)).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)

    fireEvent.change(screen.getByLabelText('cron 表达式'), { target: { value: '0 8 * * *' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(createBodies).toHaveLength(1))
    expect(createBodies[0]).toEqual({
      task_type: 'API_ASSET_DIGEST',
      name: '测试计划',
      cron_expr: '0 8 * * *',
      enabled: false,
    })
  })

  it('编辑计划：task_type 不可变更，PUT 提交 name/cron（不含 enabled）', async () => {
    renderPage()
    const row = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /编\s*辑/ }))
    await screen.findByText('编辑计划：每日资产摘要')

    // 类型下拉在编辑态禁用
    const item = screen.getByText('任务类型', { selector: 'label' }).closest('.ant-form-item')
    expect(item?.querySelector('.ant-select')?.className).toContain('ant-select-disabled')

    fireEvent.change(screen.getByLabelText('cron 表达式'), { target: { value: '0 9 * * *' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(putCalls).toHaveLength(1))
    expect(putCalls[0].path).toContain('/api-security/ai-ops/schedules/sch-1')
    expect(putCalls[0].body).toEqual({
      task_type: 'API_ASSET_DIGEST',
      name: '每日资产摘要',
      cron_expr: '0 9 * * *',
    })
  })

  it('启停：点击停用计划的开关触发 enable 接口并反馈', async () => {
    renderPage()
    const row = (await screen.findByText('高危摘要')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('switch'))
    await waitFor(() => {
      expect(postPaths.some((p) => p.endsWith('/schedules/sch-2/enable'))).toBe(true)
    })
    expect(await screen.findByText('计划「高危摘要」已启用')).toBeInTheDocument()
  })

  it('熔断计划：列表展示连续失败次数与已熔断标记', async () => {
    renderPage()
    const row = (await screen.findByText('熔断计划')).closest('tr') as HTMLElement
    // 连续失败列：计数 3 + 已熔断标记
    expect(within(row).getByText('3')).toBeInTheDocument()
    expect(within(row).getByText('已熔断')).toBeInTheDocument()
    // 非熔断计划不展示熔断标记
    const row1 = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    expect(within(row1).queryByText('已熔断')).not.toBeInTheDocument()
  })

  it('熔断计划点击启用：先弹「重新启用（重置熔断计数）」确认，确认后才调 enable', async () => {
    renderPage()
    const row = (await screen.findByText('熔断计划')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('switch'))
    // 确认弹窗展示熔断上下文（antd modal 标题渲染多处，按集合断言）；确认前不发起 enable 请求
    expect((await screen.findAllByText('重新启用（重置熔断计数）')).length).toBeGreaterThan(0)
    const dialog = screen
      .getAllByRole('dialog')
      .find((d) => within(d).queryAllByText('重新启用（重置熔断计数）').length > 0)
    if (!dialog) throw new Error('未找到重新启用确认弹窗')
    expect(within(dialog).getByText(/已连续失败 3 次并熔断/)).toBeInTheDocument()
    expect(within(dialog).getByText(/熔断原因：连续失败 3 次，自动熔断/)).toBeInTheDocument()
    expect(postPaths.some((p) => p.endsWith('/schedules/sch-3/enable'))).toBe(false)
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      expect(postPaths.some((p) => p.endsWith('/schedules/sch-3/enable'))).toBe(true)
    })
    expect(await screen.findByText('计划「熔断计划」已启用')).toBeInTheDocument()
  })

  it('熔断计划的运行记录抽屉：顶部展示熔断告警（连续失败/熔断时间/原因）', async () => {
    renderPage()
    const row = (await screen.findByText('熔断计划')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /^运\s*行\s*记\s*录$/ }))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('运行记录：熔断计划')).toBeInTheDocument()
    expect(within(drawer).getByText('计划已熔断')).toBeInTheDocument()
    expect(within(drawer).getByText(/连续失败 3 次/)).toBeInTheDocument()
    expect(within(drawer).getByText(/熔断原因：连续失败 3 次，自动熔断/)).toBeInTheDocument()
  })

  it('立即执行：POST run 并反馈执行结果，随后可刷新执行记录', async () => {
    renderPage()
    const row = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /立即执行/ }))
    await waitFor(() => {
      expect(postPaths.some((p) => p.endsWith('/schedules/sch-1/run'))).toBe(true)
    })
    expect(await screen.findByText('立即执行完成，报告已生成（展开运行记录查看）')).toBeInTheDocument()
  })

  it('运行记录抽屉：状态/耗时/摘要，行展开后 report_json 关键字段表格化', async () => {
    renderPage()
    const row = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /^运\s*行\s*记\s*录$/ }))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('运行记录：每日资产摘要')).toBeInTheDocument()
    expect(await within(drawer).findByText('成功')).toBeInTheDocument()
    expect(within(drawer).getByText('2.0 s')).toBeInTheDocument()
    expect(within(drawer).getByText(/API 资产共 42 个/)).toBeInTheDocument()

    // 展开行：标量指标入关键指标区，对象清单入小表
    const expandIcon = drawer.querySelector('.ant-table-row-expand-icon')
    expect(expandIcon).toBeTruthy()
    fireEvent.click(expandIcon as HTMLElement)
    expect(await within(drawer).findByText('total_endpoints')).toBeInTheDocument()
    expect(within(drawer).getByText('new_endpoints（1 条）')).toBeInTheDocument()
    expect(within(drawer).getByText('GET /v1/assets/new')).toBeInTheDocument()
    expect(within(drawer).getByText('DISCOVERED')).toBeInTheDocument()
  })

  it('运行记录 Tab：选择计划后展示其执行记录', async () => {
    renderPage()
    await screen.findByText('每日资产摘要')
    fireEvent.click(screen.getByRole('tab', { name: '运行记录' }))
    // 未选计划时的提示
    expect(await screen.findByText('请先选择计划')).toBeInTheDocument()

    const ph = screen.getByText('选择计划查看执行记录')
    fireEvent.mouseDown(ph.closest('.ant-select') as HTMLElement)
    const candidates = await screen.findAllByText('每日资产摘要（资产变化摘要）')
    const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)

    expect(await screen.findByText(/API 资产共 42 个/)).toBeInTheDocument()
  })

  it('运行记录 Tab：计划选项加载失败时展示错误告警（不静默吞错）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const path = new URL(String(input), 'http://localhost').pathname
        if (path.endsWith('/api-security/ai-ops/task-types')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: taskTypesData }))
        }
        if (path.endsWith('/api-security/ai-ops/schedules')) {
          return Promise.resolve(
            jsonResponse(500, { code: 'INTERNAL', message: 'db down', data: null }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${path}`))
      }),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('tab', { name: '运行记录' }))
    // 失败时如实展示后端错误消息（RunsTab 与计划列表共用接口，可能多处告警）
    expect((await screen.findAllByText('加载数据失败')).length).toBeGreaterThan(0)
    expect((await screen.findAllByText('db down')).length).toBeGreaterThan(0)
  })

  it('无 api_ai.execute 权限：隐藏新建与行内写操作，开关禁用，运行记录仍可查看', async () => {
    useAuthStore.setState({
      user: makeUser(['api_ai.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    const row = (await screen.findByText('每日资产摘要')).closest('tr') as HTMLElement
    expect(screen.queryByRole('button', { name: /新建计划/ })).not.toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: /编\s*辑/ })).not.toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: /立即执行/ })).not.toBeInTheDocument()
    expect(within(row).getByRole('switch')).toBeDisabled()
    expect(within(row).getByRole('button', { name: /^运\s*行\s*记\s*录$/ })).toBeInTheDocument()
  })
})
