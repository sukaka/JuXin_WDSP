import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiRuntimeEventsPage from '../ApiRuntimeEventsPage'
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

/** 迁移 000030/000035 后字段齐全的新事件 */
const eventFull = {
  id: 'ev1',
  request_id: 'req-100',
  endpoint_key: 'GET /v1/users/{id}',
  risk_score: 85,
  risk_level: 'HIGH',
  final_action: 'BLOCK',
  details: [
    {
      detector: 'api_schema',
      rule_id: 'R-1',
      category: 'BLOCK',
      severity: 'HIGH',
      message: '未知字段 debug',
      evidence: { field: 'debug' },
      score_delta: 40,
    },
  ],
  occurred_at: '2026-08-01T10:00:00Z',
  identity_fingerprint: 'fp-user-1',
  auth_type: 'api_key',
  response_status: 200,
  client_ip: '10.0.0.1',
  method: 'GET',
  raw_path: '/v1/users/1?debug=true',
  latency_ms: 123,
  model_version: 'mv-3',
  policy_version: 'pv-2',
  /** 迁移 000127：jwt_trust 范围评估过的事件携带 JWT 验证摘要（VERIFIED 全字段形态） */
  jwt_verification: {
    status: 'VERIFIED',
    reason_code: 'VALID',
    policy_version: 'jwt-pv-7',
    issuer_config_id: 'iss-1',
    keyset_version: 'ks-3',
    verified_principal_id: 'prin-hmac-abc123',
    verified_tenant_id: 'tenant-hmac-def456',
    evaluated_at: '2026-08-01T09:59:58Z',
  },
  /** NG-AZ-03：VERIFIED_VIOLATION 实断事件 final_decision 内嵌 authz_enforcement 证据 */
  final_decision: {
    schema_version: 1,
    completion_status: 'COMPLETED',
    security_action: 'BLOCK',
    authz_enforcement: {
      decision: 'VERIFIED_VIOLATION',
      reason_code: 'AUTHZ-BOLA-001',
      enforced: true,
      endpoint_key: 'GET /v1/users/{id}',
      model_version: 'mv-3',
      policy_version: 'pv-2',
      principal_source: 'JWT_VERIFIED',
      object_ref: 'objref:74a55c5af21c3efa',
      eligibility: {
        trusted_identity: true,
        model_applicable: true,
        relation_valid: true,
        no_conflict: true,
        tenant_consistent: true,
        evidence_fresh: true,
        other_owner: true,
        owner_exclusive: true,
      },
      lease_seconds: 60,
      applied_at_age_seconds: 12,
      enforcement_owner: 'zhang.lei@example.com',
      evidence_source: 'MANUAL_CONFIRMED',
      recorded_at: '2026-08-01T10:00:00Z',
    },
  },
}

/** 旧版网关事件：审计维度列为 NULL（读取侧按可空处理） */
const eventLegacy = {
  id: 'ev2',
  request_id: 'req-101',
  endpoint_key: 'POST /v1/login',
  risk_score: 0,
  risk_level: 'NONE',
  final_action: 'ALLOW',
  details: null,
  occurred_at: '2026-08-01T09:00:00Z',
  identity_fingerprint: '',
  auth_type: '',
  response_status: null,
  client_ip: null,
  method: null,
  raw_path: null,
  latency_ms: null,
  model_version: null,
  policy_version: null,
  // 迁移 000127 前的历史事件：jwt_verification 为 NULL（不回填，详情不渲染 JWT 区块）
  jwt_verification: null,
}

const eventsData = { items: [eventFull, eventLegacy], page: 1, page_size: 20, total: 2 }

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiRuntimeEventsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 在指定 placeholder 的 Input.Search 上输入并触发搜索（antd 6 搜索按钮 class 为 .ant-input-search-btn） */
function triggerSearch(placeholder: string, value: string) {
  const input = screen.getByPlaceholderText(placeholder)
  fireEvent.change(input, { target: { value } })
  const wrapper = input.closest('.ant-input-search')
  const btn = wrapper?.querySelector('.ant-input-search-btn')
  expect(btn).toBeTruthy()
  fireEvent.click(btn as HTMLElement)
}

describe('ApiRuntimeEventsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/runtime/events')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: eventsData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染事件列表：接口键/方法/客户端 IP/风险分/动作标签/耗时；NULL 字段显示占位符', async () => {
    renderPage()
    expect(await screen.findByText('GET /v1/users/{id}')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('85')).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    expect(screen.getByText('123 ms')).toBeInTheDocument()
    expect(screen.getByText('放行')).toBeInTheDocument()
    // 旧事件 method/client_ip/latency_ms 为 NULL，渲染占位符
    const row = screen.getByText('POST /v1/login').closest('tr')
    expect(row).toBeTruthy()
    expect((row as HTMLElement).textContent).toContain('-')
  })

  it('过滤：接口键搜索 / 最终动作选择 / 身份指纹搜索分别携带对应查询参数', async () => {
    renderPage()
    await screen.findByText('GET /v1/users/{id}')

    triggerSearch('接口键（精确匹配，如 GET /v1/users/{id}）', 'GET /v1/users/{id}')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('endpoint_key='))).toBe(true)
    })

    // 最终动作下拉：antd 6 占位符 class 为 .ant-select-placeholder，据此与表头消歧
    const candidates = screen.getAllByText('最终动作')
    const ph = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
    fireEvent.mouseDown(ph)
    const options = await screen.findAllByText('阻断')
    const option = options.find((el) => el.closest('.ant-select-item-option-content'))
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('final_action=BLOCK'))).toBe(true)
    })

    triggerSearch('身份指纹（精确匹配）', 'fp-user-1')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('identity_fingerprint=fp-user-1'))).toBe(true)
    })
  })

  it('详情抽屉：审计维度新字段（原始路径/响应状态码/模型版本/策略版本）+ 检测明细表格化', async () => {
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('req-100')).toBeInTheDocument()
    expect(within(drawer).getByText('/v1/users/1?debug=true')).toBeInTheDocument()
    expect(within(drawer).getByText('10.0.0.1')).toBeInTheDocument()
    expect(within(drawer).getByText('200')).toBeInTheDocument()
    expect(within(drawer).getAllByText('mv-3').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getAllByText('pv-2').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getByText('fp-user-1')).toBeInTheDocument()
    expect(within(drawer).getByText('API Key')).toBeInTheDocument()
    // details_json 明细表格化：检测器/规则/类别/信息/证据中文键
    expect(within(drawer).getByText('模型校验')).toBeInTheDocument()
    expect(within(drawer).getByText('R-1')).toBeInTheDocument()
    expect(within(drawer).getAllByText('阻断').length).toBeGreaterThanOrEqual(2)
    expect(within(drawer).getByText('未知字段 debug')).toBeInTheDocument()
    expect(within(drawer).getByText('字段：')).toBeInTheDocument()
    expect(within(drawer).getByText('检测明细')).toBeInTheDocument()
    expect(within(drawer).queryByText('检测明细（details）')).not.toBeInTheDocument()
  })

  it('详情抽屉：旧版事件（details 为 NULL）显示匿名身份与「无检测明细」', async () => {
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[1]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('req-101')).toBeInTheDocument()
    // 身份指纹与认证方式均显示「匿名」
    expect(within(drawer).getAllByText('匿名')).toHaveLength(2)
    expect(within(drawer).getByText('无检测明细')).toBeInTheDocument()
  })

  it('详情抽屉：携带 jwt_verification 的事件渲染「JWT 验证信息」区块（状态/原因/版本/主体/租户/时间）', async () => {
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('JWT 验证信息')).toBeInTheDocument()
    // VERIFIED 状态标签与 VALID 原因文案均为「验证通过」，原始原因码收进 Tooltip
    expect(within(drawer).getAllByText('验证通过').length).toBeGreaterThanOrEqual(2)
    expect(within(drawer).queryByText('VALID')).not.toBeInTheDocument()
    expect(within(drawer).getByText('jwt-pv-7')).toBeInTheDocument()
    expect(within(drawer).getByText('ks-3')).toBeInTheDocument()
    expect(within(drawer).getByText('prin-hmac-abc123')).toBeInTheDocument()
    expect(within(drawer).getByText('tenant-hmac-def456')).toBeInTheDocument()
    expect(within(drawer).getByText('验证时间')).toBeInTheDocument()
  })

  it('详情抽屉：历史事件 jwt_verification 为 NULL 时不渲染「JWT 验证信息」区块（空态不显示）', async () => {
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[1]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('req-101')).toBeInTheDocument()
    expect(within(drawer).queryByText('JWT 验证信息')).toBeNull()
  })

  it('详情抽屉：final_decision.authz_enforcement 渲染「授权实断证据」区块（D7：八因子逐项/已实断/四要素回执）；历史事件无此键不渲染', async () => {
    renderPage()
    // 含证据事件（btns[0]）
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[0]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('授权实断证据')).toBeInTheDocument()
    expect(within(drawer).getByText('实断证据')).toBeInTheDocument()
    expect(within(drawer).getByText('已实断')).toBeInTheDocument()
    expect(within(drawer).getByText('实断违规')).toBeInTheDocument()
    expect(within(drawer).getByText('对象级越权（他人属主）')).toBeInTheDocument()
    // 八因子逐项对错图标（中文名渲染；全真即全 success）
    for (const label of ['可信身份', '模型适用', '关系有效', '无冲突', '租户一致', '证据新鲜', '他人属主', '排他所有权']) {
      expect(within(drawer).getByText(label)).toBeInTheDocument()
    }
    // 版本/租约/四要素回执
    expect(within(drawer).getByText('zhang.lei@example.com')).toBeInTheDocument()
    expect(within(drawer).getByText('人工确认')).toBeInTheDocument()
    expect(within(drawer).getByText('JWT 可信验证')).toBeInTheDocument()
    expect(within(drawer).getByText('objref:74a55c5af21c3efa')).toBeInTheDocument()
  })

  it('详情抽屉：历史事件 final_decision 为 NULL 时不渲染「授权实断证据」区块（空态不显示）', async () => {
    renderPage()
    fireEvent.click(await screen.findAllByRole('button', { name: /^详\s*情$/ }).then((btns) => btns[1]))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('req-101')).toBeInTheDocument()
    expect(within(drawer).queryByText('授权实断证据')).toBeNull()
  })
})
