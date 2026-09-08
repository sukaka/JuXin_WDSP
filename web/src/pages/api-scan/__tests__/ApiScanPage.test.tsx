import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiScanPage from '../ApiScanPage'
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

function envelope(data: unknown) {
  return { code: 'SUCCESS', message: 'ok', data }
}

function page<T>(items: T[]) {
  return { items, page: 1, page_size: 20, total: items.length }
}

const app1 = {
  id: 'app1',
  code: 'order',
  name: '订单中心',
  description: '',
  business_owner: '',
  technical_owner: '',
  status: 'ACTIVE',
  protection_mode: 'BLOCK',
  deployment_status: 'DEPLOYED',
  health_status: 'HEALTHY',
}

const target1 = {
  id: 't1',
  application_id: 'app1',
  name: '订单 API',
  base_url: 'https://api.example.com',
  allowed_paths: ['/v1/orders'],
  status: 'ENABLED',
  created_by: 'u2',
  created_at: '2026-08-01T02:00:00Z',
  updated_at: '2026-08-01T02:00:00Z',
}

const authz1 = {
  id: 'a1',
  target_id: 't1',
  authorized_by: 'u9',
  allowlist: ['api.example.com'],
  time_window: { start: null, end: null },
  max_qps: 5,
  max_concurrency: 1,
  test_profile: 'AUTH_REQUIRED,SENSITIVE_EXPOSURE',
  expires_at: '2027-01-01T00:00:00Z',
  revoked_at: null,
  created_at: '2026-08-02T02:00:00Z',
}

const job1 = {
  id: 'j1',
  target_id: 't1',
  authorization_id: 'a1',
  probe_set: 'AUTH_REQUIRED',
  status: 'PENDING',
  progress: { total: 0, done: 0, requests: 0, findings: 0, errors: 0 },
  started_at: null,
  finished_at: null,
  created_by: 'u1',
  created_at: '2026-08-10T02:00:00Z',
}

const job2 = {
  ...job1,
  id: 'j2',
  status: 'RUNNING',
  progress: { total: 10, done: 4, requests: 12, findings: 1, errors: 0 },
  started_at: '2026-08-10T03:00:00Z',
}

const finding1 = {
  id: 'f1',
  job_id: 'j1',
  engine: 'apiscan',
  template: 'AUTH_REQUIRED',
  endpoint_key: 'GET /v1/orders',
  category: 'AUTHN',
  severity: 'HIGH',
  confidence: 0.9,
  evidence: { status: 200 },
  request_sample: 'GET /v1/orders HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: [redacted]\r\n',
  response_sample: 'HTTP 200\r\n\r\n{}',
  status: 'NEW',
  weakness_id: null,
  created_at: '2026-08-10T03:01:00Z',
}

const finding2 = {
  ...finding1,
  id: 'f2',
  endpoint_key: 'POST /v1/cards',
  template: 'SENSITIVE_EXPOSURE',
  category: 'SENSITIVE',
  status: 'CONFIRMED',
  weakness_id: '11111111-2222-3333-4444-555555555555',
  request_sample: 'POST /v1/cards HTTP/1.1\r\nHost: api.example.com\r\n',
  response_sample: '',
}

const ALL_PERMS = ['api_scan.read', 'api_scan.execute', 'api_scan.manage']

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiScanPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 点击占位文本所属 Select 并选中下拉项（对齐现有页面测试的 antd 6 Select 操作方式） */
async function selectOption(placeholder: string, optionText: string) {
  const candidates = screen.getAllByText(placeholder)
  const target = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
  fireEvent.mouseDown(target)
  const options = await screen.findAllByText(optionText)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

/** 最后打开的弹窗（Modal/确认框）的 OK 按钮（测试环境默认 en locale，文案为 OK）。
 * 抽屉上再开弹窗时存在多个 dialog，antd 后开的排在 DOM 末尾，取最后一个。 */
async function clickDialogOk() {
  const dialogs = await screen.findAllByRole('dialog')
  const dialog = dialogs[dialogs.length - 1]
  fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
}

describe('ApiScanPage', () => {
  let createTargetBodies: unknown[]
  let updateTargetBodies: unknown[]
  let authorizeBodies: unknown[]
  let createJobBodies: unknown[]
  let confirmBodies: unknown[]
  let revokedIds: string[]
  let startedIds: string[]
  let emergencyIds: string[]
  let falsePositiveIds: string[]
  let retestBodies: unknown[]

  beforeEach(() => {
    createTargetBodies = []
    updateTargetBodies = []
    authorizeBodies = []
    createJobBodies = []
    confirmBodies = []
    revokedIds = []
    startedIds = []
    emergencyIds = []
    falsePositiveIds = []
    retestBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        const body = init?.body ? JSON.parse(String(init.body)) : undefined
        // ---- 授权（先于 /targets 通用匹配，避免被列表分支截获）----
        if (method === 'POST' && url.includes('/revoke')) {
          revokedIds.push(url)
          return Promise.resolve(
            jsonResponse(200, envelope({ authorization: { ...authz1, revoked_at: '2026-08-18T01:00:00Z' }, stopped_jobs: 2 })),
          )
        }
        if (method === 'POST' && url.includes('/authorize')) {
          authorizeBodies.push(body)
          return Promise.resolve(jsonResponse(200, envelope({ authorization: authz1 })))
        }
        if (method === 'GET' && url.includes('/authorizations')) {
          return Promise.resolve(jsonResponse(200, envelope(page([authz1]))))
        }
        // ---- 目标 ----
        if (method === 'POST' && url.includes('/scans/targets')) {
          createTargetBodies.push(body)
          return Promise.resolve(jsonResponse(200, envelope({ target: target1 })))
        }
        if (method === 'PUT' && url.includes('/scans/targets/')) {
          updateTargetBodies.push(body)
          return Promise.resolve(jsonResponse(200, envelope({ target: { ...target1, status: 'DISABLED' } })))
        }
        if (method === 'GET' && url.includes('/scans/targets')) {
          return Promise.resolve(jsonResponse(200, envelope(page([target1]))))
        }
        // ---- 任务 ----
        if (method === 'POST' && url.includes('/start')) {
          startedIds.push(url)
          return Promise.resolve(jsonResponse(200, envelope({ job: { ...job1, status: 'RUNNING' } })))
        }
        if (method === 'POST' && url.includes('/emergency-stop')) {
          emergencyIds.push(url)
          return Promise.resolve(jsonResponse(200, envelope({ authorization: authz1, stopped_jobs: 3 })))
        }
        if (method === 'POST' && url.includes('/scans/jobs')) {
          createJobBodies.push(body)
          return Promise.resolve(jsonResponse(200, envelope({ job: job1 })))
        }
        if (method === 'GET' && url.includes('/scans/jobs')) {
          return Promise.resolve(jsonResponse(200, envelope(page([job1, job2]))))
        }
        // ---- 发现 ----
        if (method === 'POST' && url.includes('/confirm')) {
          confirmBodies.push(body)
          return Promise.resolve(
            jsonResponse(200, envelope({ finding: { ...finding1, status: 'CONFIRMED' } })),
          )
        }
        if (method === 'POST' && url.includes('/false-positive')) {
          falsePositiveIds.push(url)
          return Promise.resolve(
            jsonResponse(200, envelope({ finding: { ...finding1, status: 'FALSE_POSITIVE' } })),
          )
        }
        if (method === 'POST' && url.includes('/retest')) {
          retestBodies.push(body ?? {})
          return Promise.resolve(
            jsonResponse(200, envelope({ result: 'PASS', reproduced: false, weakness_id: finding2.weakness_id })),
          )
        }
        if (method === 'GET' && url.includes('/scans/findings')) {
          return Promise.resolve(jsonResponse(200, envelope(page([finding1, finding2]))))
        }
        // ---- 应用（目标表单选项）----
        if (method === 'GET' && url.includes('/applications')) {
          return Promise.resolve(jsonResponse(200, envelope(page([app1]))))
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('目标 Tab：渲染目标列表与操作按钮（完整权限）', async () => {
    renderPage()
    expect(await screen.findByText('订单 API')).toBeInTheDocument()
    expect(screen.getByText('https://api.example.com')).toBeInTheDocument()
    expect(screen.getByText('订单中心')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '新建目标' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /编\s*辑/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '签发授权' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /停\s*用/ })).toBeInTheDocument()
  })

  it('权限门控：仅 api_scan.read 时不显示管理/执行按钮', async () => {
    useAuthStore.setState({ user: makeUser(['api_scan.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('订单 API')
    expect(screen.queryByRole('button', { name: '新建目标' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编\s*辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '签发授权' })).not.toBeInTheDocument()
  })

  it('新建目标：提交 application_id/name/base_url/allowed_paths', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('button', { name: '新建目标' }))
    await screen.findByText('新建扫描目标')

    await selectOption('选择应用', '订单中心（order）')
    fireEvent.change(screen.getByLabelText('目标名称'), { target: { value: '支付 API' } })
    fireEvent.change(screen.getByLabelText('基准地址（base_url）'), {
      target: { value: 'https://pay.example.com' },
    })
    await clickDialogOk()

    await waitFor(() => expect(createTargetBodies).toHaveLength(1))
    expect(createTargetBodies[0]).toEqual({
      application_id: 'app1',
      name: '支付 API',
      base_url: 'https://pay.example.com',
      allowed_paths: [],
    })
  })

  it('停用目标：二次确认后 PUT 全量保留并翻转状态', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('button', { name: /停\s*用/ }))
    // antd 6 确认框同时渲染 a11y 标题与可视标题，用 findAll 容忍双节点
    expect((await screen.findAllByText('停用目标')).length).toBeGreaterThanOrEqual(1)
    await clickDialogOk()

    await waitFor(() => expect(updateTargetBodies).toHaveLength(1))
    expect(updateTargetBodies[0]).toEqual({
      name: '订单 API',
      base_url: 'https://api.example.com',
      allowed_paths: ['/v1/orders'],
      status: 'DISABLED',
    })
  })

  it('签发授权：展示双人分离提示，提交默认限流参数与截止时间', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('button', { name: '签发授权' }))
    // 双人分离提示（建标人不可自签）
    expect(
      await screen.findByText('双人分离：目标创建人与授权人不得为同一人'),
    ).toBeInTheDocument()

    // 授权截止时间：打开 DatePicker 点「此刻」（Now 直接提交并关闭面板，见 @rc-component/picker onNow）
    const pickerInput = screen.getByPlaceholderText('须为未来时间')
    const picker = pickerInput.closest('.ant-picker') as HTMLElement
    fireEvent.focus(pickerInput)
    fireEvent.mouseDown(picker)
    fireEvent.click(pickerInput)
    const nowBtn = await waitFor(() => {
      const el = document.querySelector('.ant-picker-now-btn')
      expect(el).toBeTruthy()
      return el as HTMLElement
    })
    fireEvent.click(nowBtn)

    await clickDialogOk()
    await waitFor(() => expect(authorizeBodies).toHaveLength(1))
    const body = authorizeBodies[0] as Record<string, unknown>
    expect(body.max_qps).toBe(5)
    expect(body.max_concurrency).toBe(1)
    expect(body.test_profile).toBe('')
    expect(body.allowlist).toEqual([])
    expect(typeof body.expires_at).toBe('string')
  })

  it('授权 Tab：选择目标渲染授权列表，吊销二次确认并联动停任务提示', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描授权' }))
    await selectOption('选择扫描目标查看授权', '订单 API（https://api.example.com）')

    expect(await screen.findByText('有效')).toBeInTheDocument()
    expect(screen.getByText('#a1')).toBeInTheDocument()
    // 探针集画像按中文标签展示
    expect(screen.getByText('未认证访问检测、敏感字段暴露检测')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /吊\s*销/ }))
    // 吊销二次确认：说明吊销即停全部关联任务
    expect(await screen.findByText(/吊销立即生效/)).toBeInTheDocument()
    await clickDialogOk()

    await waitFor(() => expect(revokedIds).toHaveLength(1))
    expect(revokedIds[0]).toContain('/api-security/scans/authorizations/a1/revoke')
    expect(await screen.findByText('授权已吊销，已联动停止 2 个在跑任务')).toBeInTheDocument()
  })

  it('任务 Tab：渲染状态与进度，启动前二次确认（目标/授权单/探针集/限流）后启动', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描任务' }))

    expect(await screen.findByText('待启动')).toBeInTheDocument()
    expect(screen.getByText('执行中')).toBeInTheDocument()
    // 进度：4/10 · 发现 1 · 错误 0
    expect(screen.getByText(/4\/10 · 发现 1 · 错误 0/)).toBeInTheDocument()

    // 两行均有「启动」按钮，点待启动的 j1 行
    const row = screen.getByText('待启动').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /启\s*动/ }))

    // 二次确认：展示目标名、授权单、探针集与限流参数；确认前不得发起 start
    expect(await screen.findByText(/目标：订单 API/)).toBeInTheDocument()
    expect(screen.getByText(/授权单：#a1/)).toBeInTheDocument()
    expect(screen.getByText(/探针集：未认证访问检测/)).toBeInTheDocument()
    expect(screen.getByText(/限流：QPS ≤ 5，并发 ≤ 1/)).toBeInTheDocument()
    expect(startedIds).toHaveLength(0)

    fireEvent.click(screen.getByRole('button', { name: /确\s*认\s*启\s*动/ }))
    await waitFor(() => expect(startedIds).toHaveLength(1))
    expect(startedIds[0]).toContain('/api-security/scans/jobs/j1/start')
    expect(await screen.findByText('任务已启动')).toBeInTheDocument()
  })

  it('任务 Tab：紧急停止 danger 确认后 POST emergency-stop', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描任务' }))
    await screen.findByText('执行中')

    // j1（PENDING）与 j2（RUNNING）均可紧急停止，点执行中的 j2 行
    const row = screen.getByText('执行中').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: '紧急停止' }))
    // danger 确认文案：撤销授权 + 联动停止
    expect(await screen.findByText(/吊销关联授权/)).toBeInTheDocument()
    await clickDialogOk()

    await waitFor(() => expect(emergencyIds).toHaveLength(1))
    expect(emergencyIds[0]).toContain('/api-security/scans/jobs/j2/emergency-stop')
    expect(await screen.findByText('紧急停止完成：授权已吊销，联动停止 3 个任务')).toBeInTheDocument()
  })

  it('发现 Tab：详情抽屉展示脱敏证据与样本，确认可关联弱点', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描发现' }))
    expect(await screen.findByText('GET /v1/orders')).toBeInTheDocument()

    const row = screen.getByText('GET /v1/orders').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    // 脱敏证据与样本展示
    await within(drawer).findByText('证据（已脱敏）')
    expect(within(drawer).getByText(/Authorization: \[redacted\]/)).toBeInTheDocument()
    expect(within(drawer).getByText('请求样本（凭据头已脱敏）')).toBeInTheDocument()

    // 确认：携带 weakness_id 关联弱点
    fireEvent.click(within(drawer).getByRole('button', { name: /确\s*认/ }))
    await screen.findByText('确认发现')
    fireEvent.change(screen.getByLabelText('关联弱点 ID（可选）'), {
      target: { value: '11111111-2222-3333-4444-555555555555' },
    })
    await clickDialogOk()

    await waitFor(() => expect(confirmBodies).toHaveLength(1))
    expect(confirmBodies[0]).toEqual({ weakness_id: '11111111-2222-3333-4444-555555555555' })
  })

  it('发现 Tab：误报二次确认后 POST false-positive', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描发现' }))
    await screen.findByText('GET /v1/orders')

    const row = screen.getByText('GET /v1/orders').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(within(drawer).getByRole('button', { name: /误\s*报/ }))
    expect(await screen.findByText(/判定为误报吗/)).toBeInTheDocument()
    await clickDialogOk()

    await waitFor(() => expect(falsePositiveIds).toHaveLength(1))
    expect(falsePositiveIds[0]).toContain('/api-security/scans/findings/f1/false-positive')
    expect(await screen.findByText('已判定为误报')).toBeInTheDocument()
  })

  it('发现 Tab：已关联弱点的发现可复测，并反馈复测结果', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描发现' }))
    await screen.findByText('POST /v1/cards')

    const row = screen.getByText('POST /v1/cards').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    // f2 已关联弱点：复测可点
    fireEvent.click(within(drawer).getByRole('button', { name: /复\s*测/ }))
    await screen.findByText('定向复测')
    await clickDialogOk()

    await waitFor(() => expect(retestBodies).toHaveLength(1))
    expect(await screen.findByText('复测通过：未复现，弱点已回写复测结论')).toBeInTheDocument()
  })

  it('发现 Tab：未关联弱点的发现复测按钮禁用', async () => {
    renderPage()
    await screen.findByText('订单 API')
    fireEvent.click(screen.getByRole('tab', { name: '扫描发现' }))
    await screen.findByText('GET /v1/orders')

    const row = screen.getByText('GET /v1/orders').closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('证据（已脱敏）')
    // f1 未关联弱点：复测禁用
    expect(within(drawer).getByRole('button', { name: /复\s*测/ })).toBeDisabled()
  })
})
