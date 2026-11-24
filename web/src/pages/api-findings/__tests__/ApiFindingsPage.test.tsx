import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiFindingsPage from '../ApiFindingsPage'
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

/** 七态状态机（迁移 000042 词表）：NEW 待确认 / CONFIRMED 已确认 / RESOLVED 已解决 */
const findingNew = {
  id: 'f1',
  endpoint_id: 'e1',
  endpoint_key: 'POST /v1/orders',
  request_id: 'req-1',
  finding_type: 'SHADOW',
  severity: 'HIGH',
  status: 'NEW',
  title: '发现未登记的影子接口',
  detail: { evidence: 'hit 12 times' },
  first_seen_at: '2026-07-01T10:00:00Z',
  last_seen_at: '2026-07-22T09:00:00Z',
}

const findingConfirmed = {
  ...findingNew,
  id: 'f2',
  finding_type: 'BOLA',
  severity: 'CRITICAL',
  status: 'CONFIRMED',
  title: '对象级越权风险',
}

const findingResolved = {
  ...findingNew,
  id: 'f3',
  finding_type: 'SENSITIVE_LEAK',
  severity: 'MEDIUM',
  status: 'RESOLVED',
  title: '敏感数据泄露风险',
}

const listData = { items: [findingNew, findingConfirmed, findingResolved], page: 1, page_size: 20, total: 3 }

/** 与后端 RiskSummary 一致：三视图一次返回，无 group_by 参数 */
const summaryData = {
  by_subject: [
    { subject_type: 'IDENTITY', subject_id: 'fp-abc123', count: 1, hits: 5, max_severity: 'HIGH', last_seen_at: '2026-07-22T09:00:00Z' },
  ],
  by_endpoint: [
    { endpoint_id: 'e1', endpoint_key: 'POST /v1/orders', count: 2, hits: 7, max_severity: 'CRITICAL', last_seen_at: '2026-07-22T09:00:00Z' },
  ],
  by_finding_type: [
    { finding_type: 'SHADOW', count: 2, hits: 7, max_severity: 'HIGH', last_seen_at: '2026-07-22T09:00:00Z' },
  ],
}

/** 与后端 RiskFindingDetail 一致：finding + 近似关联 request_id 列表 */
const detailData = {
  finding: {
    ...findingNew,
    subject_type: 'IDENTITY',
    subject_id: 'fp-user-1',
    risk_score: 80,
    risk_level: 'HIGH',
    count: 12,
    evidence: { field: 'order_id' },
    model_version: 'mv-1',
    policy_version: 'pv-1',
  },
  related_request_ids: ['req-a', 'req-b'],
  related_request_note: '同 API（同身份）近期运行时事件的 request_id，近似关联',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiFindingsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const ALL_PERMS = ['api_runtime.read', 'api_risk.read', 'api_risk.handle']

describe('ApiFindingsPage', () => {
  let postCalls: { url: string; body: unknown }[]

  beforeEach(() => {
    localStorage.clear()
    postCalls = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (init?.method === 'POST') {
          postCalls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { finding: findingNew } }))
        }
        if (url.includes('/api-security/findings/summary')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: summaryData }))
        }
        // 风险详情 GET /findings/{id}（路径段为 id，非 summary 且不带查询串）
        if (/\/api-security\/findings\/[\w-]+(\?|$)/.test(url)) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: detailData }))
        }
        if (url.includes('/api-security/findings')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：七态中文标签；NEW 行有「确认」、CONFIRMED 行有「开始处置」、RESOLVED 行无行内快捷动作', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('发现未登记的影子接口')).toBeInTheDocument()
    // 「影子 API」同时出现在汇总表与列表行（用户有 api_risk.read）
    expect(screen.getAllByText('影子 API').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('对象级越权')).toBeInTheDocument()
    expect(screen.getByText('待确认')).toBeInTheDocument()
    expect(screen.getByText('已确认')).toBeInTheDocument()
    expect(screen.getByText('已解决')).toBeInTheDocument()
    // 过滤器占位文本（antd 6 占位符 class 为 .ant-select-placeholder，与表头同文案故按 class 断言）
    const placeholders = Array.from(document.querySelectorAll('.ant-select-placeholder')).map((el) => el.textContent)
    expect(placeholders).toContain('风险类型')
    expect(placeholders).toContain('严重级别')
    expect(placeholders).toContain('处置状态')
    // NEW 行「确认」、CONFIRMED 行「开始处置」各一个；RESOLVED 行无快捷动作
    expect(screen.getAllByRole('button', { name: /^确\s*认$/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '开始处置' })).toHaveLength(1)
  })

  it('汇总卡片：一次请求无 group_by 参数，默认按类型，切换「按主体」为前端本地切换', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_risk.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('风险汇总')).toBeInTheDocument()
    // 默认按类型视图：分组键渲染为类型中文标签
    const summaryTable = (await screen.findAllByRole('table'))[0]
    expect(await within(summaryTable).findByText('影子 API')).toBeInTheDocument()
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      const summaryUrls = urls.filter((u) => u.includes('/api-security/findings/summary'))
      expect(summaryUrls).toHaveLength(1)
      expect(summaryUrls[0]).not.toContain('group_by')
    })
    // 切换「按主体」：展示 subject 桶且不追加请求（三视图已一次返回）
    fireEvent.click(screen.getByText('按主体'))
    expect(await screen.findByText('fp-abc123')).toBeInTheDocument()
    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.filter((u) => u.includes('/api-security/findings/summary'))).toHaveLength(1)
  })

  it('风险汇总表格支持拖拽调整列宽并持久化到 localStorage', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_risk.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('风险汇总')).toBeInTheDocument()
    const summaryTable = (await screen.findAllByRole('table'))[0]
    expect(await within(summaryTable).findByText('影子 API')).toBeInTheDocument()
    const handles = within(summaryTable).getAllByRole('separator', { name: '拖拽调整列宽' })
    expect(handles).toHaveLength(5)
    // 拖拽「风险条目」列（初始宽 100）+50 → 150
    fireEvent.mouseDown(handles[1], { clientX: 100 })
    fireEvent.mouseMove(document, { clientX: 150 })
    fireEvent.mouseUp(document)
    const saved = JSON.parse(localStorage.getItem('smart-table:api-findings-summary')!)
    expect(saved.w.count).toBe(150)
  })

  it('无 api_risk.read/handle：不渲染汇总卡片与任何处置按钮，也不发汇总请求', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('发现未登记的影子接口')).toBeInTheDocument()
    expect(screen.queryByText('风险汇总')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '开始处置' })).not.toBeInTheDocument()
    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes('/api-security/findings/summary'))).toBe(false)
  })

  it('行内「确认」：二次确认后 POST /findings/{id}/confirm（空备注 body {}）', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^确\s*认$/ }))
    // modal.confirm 的确认按钮文案随 locale（OK/确 定），正则兼容
    fireEvent.click(await screen.findByRole('button', { name: /^(OK|确\s*定)$/ }))
    await waitFor(() => expect(postCalls).toHaveLength(1))
    expect(postCalls[0].url).toContain('/api-security/findings/f1/confirm')
    expect(postCalls[0].body).toEqual({})
  })

  it('详情抽屉按状态机显隐动作：NEW 无「标记解决/开始处置」，CONFIRMED 有「标记解决/开始处置」', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    // NEW 行抽屉：确认/标记误报/忽略（两字按钮 antd 自动插空格，用正则匹配）
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    let drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByRole('button', { name: /^确\s*认$/ })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '标记误报' })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: /^忽\s*略$/ })).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '标记解决' })).not.toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: '开始处置' })).not.toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: /^归\s*档$/ })).not.toBeInTheDocument()

    // CONFIRMED 行抽屉（直接点第二行「详情」切换选中记录）：开始处置/标记解决/标记误报/忽略
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[1]))
    drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByRole('button', { name: '开始处置' })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '标记解决' })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '标记误报' })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: /^忽\s*略$/ })).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
  })

  it('「标记解决」弹窗：处置说明必填校验，通过后 POST {resolution}', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    // 打开 CONFIRMED 行的详情抽屉（第二个「详情」按钮）
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[1]))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(within(drawer).getByRole('button', { name: '标记解决' }))

    // 不填直接确定 → 必填校验提示且不发请求
    fireEvent.click(await screen.findByRole('button', { name: /^确\s*定$/ }))
    expect(await screen.findByText('请输入处置说明')).toBeInTheDocument()
    expect(postCalls).toHaveLength(0)

    // 填写后提交 → POST /resolve，body 为 {resolution}
    fireEvent.change(screen.getByPlaceholderText(/说明根因与修复方式/), { target: { value: '已下线该接口' } })
    fireEvent.click(screen.getByRole('button', { name: /^确\s*定$/ }))
    await waitFor(() => expect(postCalls).toHaveLength(1))
    expect(postCalls[0].url).toContain('/api-security/findings/f2/resolve')
    expect(postCalls[0].body).toEqual({ resolution: '已下线该接口' })
  })

  it('「标记误报」弹窗：误报原因必填校验，通过后 POST {reason}（后端契约字段为 reason）', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(within(drawer).getByRole('button', { name: '标记误报' }))

    fireEvent.click(await screen.findByRole('button', { name: /^确\s*定$/ }))
    expect(await screen.findByText('请输入误报原因')).toBeInTheDocument()
    expect(postCalls).toHaveLength(0)

    fireEvent.change(screen.getByPlaceholderText(/说明判定为误报的依据/), { target: { value: '测试环境造数' } })
    fireEvent.click(screen.getByRole('button', { name: /^确\s*定$/ }))
    await waitFor(() => expect(postCalls).toHaveLength(1))
    expect(postCalls[0].url).toContain('/api-security/findings/f1/false-positive')
    expect(postCalls[0].body).toEqual({ reason: '测试环境造数' })
  })

  it('详情抽屉（有 api_risk.read）：拉取 GET /findings/{id} 并展示主体/累计命中/关联请求', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => /\/api-security\/findings\/f1(\?|$)/.test(u))).toBe(true)
    })
    expect(await within(drawer).findByText('fp-user-1')).toBeInTheDocument()
    expect(within(drawer).getByText('12')).toBeInTheDocument()
    expect(within(drawer).getByText('req-a')).toBeInTheDocument()
    expect(within(drawer).getByText('req-b')).toBeInTheDocument()
  })

  it('详情抽屉（仅 api_runtime.read）：不拉取风险详情，仅展示列表行数据', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('发现未登记的影子接口')).toBeInTheDocument()
    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => /\/api-security\/findings\/f1(\?|$)/.test(u))).toBe(false)
    expect(within(drawer).queryByText('关联请求')).not.toBeInTheDocument()
  })

  it('状态过滤：选择「待确认」后列表请求携带 status=NEW', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('发现未登记的影子接口')
    fireEvent.mouseDown(screen.getByText('处置状态'))
    const candidates = await screen.findAllByText('待确认')
    const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/api-security/findings?') && u.includes('status=NEW'))).toBe(true)
    })
  })

  it('严重级别过滤下拉排除 NONE（仅包含 INFO/LOW/MEDIUM/HIGH/CRITICAL）', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('发现未登记的影子接口')
    const severityPlaceholder = screen
      .getAllByText('严重级别')
      .find((el) => el.classList.contains('ant-select-placeholder'))
    expect(severityPlaceholder).toBeTruthy()
    fireEvent.mouseDown(severityPlaceholder as HTMLElement)
    await waitFor(() => {
      const labels = Array.from(document.querySelectorAll('.ant-select-item-option-content')).map((el) =>
        el.textContent?.trim(),
      )
      expect(labels).toContain('严重')
      expect(labels).toContain('信息')
      expect(labels).not.toContain('无')
    })
  })

  it('后端返回英文检测标题时自动展示中文（不泄露原始英文短语）', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    const englishFinding = {
      ...findingNew,
      id: 'f-en',
      title: 'endpoint not in known baseline (shadow candidate)',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/findings/summary')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: summaryData }))
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [englishFinding], page: 1, page_size: 20, total: 1 },
          }),
        )
      }),
    )
    renderPage()
    expect(await screen.findByText('接口不在已知基线中（影子 API 候选）')).toBeInTheDocument()
    expect(screen.queryByText('endpoint not in known baseline (shadow candidate)')).not.toBeInTheDocument()
  })

  it('WAF/敏感数据/授权/服务端泄露英文类型与标题全部中文化，汇总中的动态 WAF 类型可入筛选下拉', async () => {
    useAuthStore.setState({ user: makeUser(ALL_PERMS), csrfToken: null, initialized: true })
    const mixedItems = [
      {
        ...findingNew,
        id: 'f-waf',
        finding_type: 'WAF_942100',
        title: 'SQL Injection Attack Detected via libinjection',
        detail: { detector: 'waf', rule_id: '942100' },
      },
      {
        ...findingNew,
        id: 'f-sens',
        finding_type: 'SENSITIVE_IN_QUERY',
        title: 'sensitive field in url query',
      },
      {
        ...findingNew,
        id: 'f-authz',
        finding_type: 'AUTHZ_BOLA_001',
        title: 'AUTHZ_BOLA_001',
      },
      {
        ...findingNew,
        id: 'f-srv',
        finding_type: 'SERVER_VERSION_DISCLOSURE',
        title: 'server implementation header observed',
      },
    ]
    const mixedSummary = {
      ...summaryData,
      by_finding_type: [
        { finding_type: 'WAF_942100', count: 1, hits: 3, max_severity: 'HIGH', last_seen_at: '2026-07-22T09:00:00Z' },
        { finding_type: 'SENSITIVE_IN_QUERY', count: 1, hits: 2, max_severity: 'HIGH', last_seen_at: '2026-07-22T09:00:00Z' },
      ],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/findings/summary')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: mixedSummary }))
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: mixedItems, page: 1, page_size: 20, total: mixedItems.length },
          }),
        )
      }),
    )
    renderPage()
    expect(await screen.findByText('通过 libinjection 检测到 SQL 注入攻击')).toBeInTheDocument()
    expect(screen.getAllByText('WAF SQL 注入（942100）').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('URL 查询含敏感字段').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('URL 查询参数包含敏感字段')).toBeInTheDocument()
    expect(screen.getAllByText('对象级越权（BOLA）').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('服务端版本信息泄露')).toBeInTheDocument()
    expect(screen.getByText('响应头暴露服务端实现信息')).toBeInTheDocument()
    expect(screen.queryByText('WAF_942100')).not.toBeInTheDocument()
    expect(screen.queryByText('SENSITIVE_IN_QUERY')).not.toBeInTheDocument()
    expect(screen.queryByText('AUTHZ_BOLA_001')).not.toBeInTheDocument()
    expect(screen.queryByText('SERVER_VERSION_DISCLOSURE')).not.toBeInTheDocument()
  })
})
