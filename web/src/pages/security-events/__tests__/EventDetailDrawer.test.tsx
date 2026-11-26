import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import EventDetailDrawer from '../EventDetailDrawer'
import { useAuthStore } from '../../../stores/auth'
import { useProductStore } from '../../../stores/product'
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

const EVENT_DETAIL = {
  event: {
    id: 'evt-1',
    request_id: 'req-trace-1',
    occurred_at: '2026-08-30T00:30:00Z',
    application_id: 'app-1',
    application_name_snapshot: '商城站点',
    domain: 'shop.example.com',
    gateway_node_id: 'node-1',
    client_ip: '1.2.3.4',
    client_port: 51000,
    request_method: 'GET',
    request_uri: '/api/orders?id=1',
    request_path: '/api/orders',
    query_summary: 'id=1',
    http_version: 'HTTP/1.1',
    content_type: '',
    user_agent_summary: 'curl',
    referer_summary: '',
    attack_type: 'sqli',
    severity: 'HIGH',
    anomaly_score: 10,
    action: 'BLOCK',
    response_status: 403,
    rule_match_count: 1,
    disposition_status: 'PENDING',
    disposition_result: '',
    raw_log_reference: '',
  },
  matches: [],
  notes: [],
  actions: [],
  related: [],
}

function mockFetch(detail: unknown = EVENT_DETAIL) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/remediation')) {
      return Promise.resolve(jsonResponse(404, { code: 'NOT_FOUND', message: '无建议', data: null }))
    }
    if (url.includes('/security-events/')) return ok(detail)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderDrawer() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <EventDetailDrawer eventId="evt-1" onClose={() => {}} onSelectEvent={() => {}} />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('EventDetailDrawer 关联 Trace 跳转', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useProductStore.setState({ apmEnabled: true, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('apmEnabled 且持有 apm.traces.read 时展示「关联 Trace」，链接携带 request_id、application_id、±5 分钟时间窗与站内返回地址', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    const button = await screen.findByRole('button', { name: '关联 Trace' })
    const href = button.closest('a')!.getAttribute('href')!
    expect(href.startsWith('/apm-traces?')).toBe(true)
    const qs = new URLSearchParams(href.slice('/apm-traces?'.length))
    expect(qs.get('request_id')).toBe('req-trace-1')
    expect(qs.get('application_id')).toBe('app-1')
    // 事件时间 2026-08-30T00:30:00Z 前后各 5 分钟
    expect(qs.get('start_time')).toBe('2026-08-30T00:25:00.000Z')
    expect(qs.get('end_time')).toBe('2026-08-30T00:35:00.000Z')
    expect(qs.get('from')).toBe('/security-events')
  })

  it('APM 能力关闭时不渲染「关联 Trace」', async () => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.queryByRole('button', { name: '关联 Trace' })).not.toBeInTheDocument()
  })

  it('无 apm.traces.read 权限时不渲染「关联 Trace」', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.queryByRole('button', { name: '关联 Trace' })).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer JWT 验证信息', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('事件携带 jwt_verification 时展示状态/原因/主体指纹/策略版本', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          jwt_verification: {
            status: 'VERIFIED',
            reason_code: 'VALID',
            verified_principal_id: 'hmac-fp-9f8e7d',
            policy_version: 3,
            issuer_config_id: 'iss-01',
            keyset_version: 'ks-2026-09',
            evaluated_at: '2026-08-30T00:30:00Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('JWT 验证信息')).toBeInTheDocument()
    // 状态标签与原因码 VALID 的中文均为「验证通过」，断言至少出现一处
    expect(screen.getAllByText('验证通过').length).toBeGreaterThan(0)
    expect(screen.getByText('hmac-fp-9f8e7d')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('签发方配置')).toBeInTheDocument()
    expect(screen.getByText('iss-01')).toBeInTheDocument()
    expect(screen.getByText('ks-2026-09')).toBeInTheDocument()
    expect(screen.queryByText('VALID')).not.toBeInTheDocument()
  })

  it('历史事件无 jwt_verification 字段时显示「当时未记录」', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.getByText('JWT 验证信息')).toBeInTheDocument()
    expect(
      screen.getByText('当时未记录 JWT 验证信息（历史事件或未启用 JWT 信任策略）'),
    ).toBeInTheDocument()
  })

  it('UNVERIFIED 显示为「未验证」，不渲染为「非法用户」', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          jwt_verification: {
            status: 'UNVERIFIED',
            reason_code: 'POLICY_OFF',
            policy_version: 0,
            evaluated_at: '2026-08-30T00:30:00Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('未验证')).toBeInTheDocument()
    expect(screen.getByText(/不代表用户非法/)).toBeInTheDocument()
    expect(screen.queryByText(/非法用户/)).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer 最终处置（P0-04）', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  it('历史事件无 final_decision：显示「该事件无最终处置记录（旧数据）」，不用空图', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderDrawer()

    await screen.findByText('商城站点')
    expect(screen.getByText('最终处置')).toBeInTheDocument()
    const empty = screen.getByText('该事件无最终处置记录（旧数据）')
    // 空态为纯文本说明，不用空图（Empty 组件）
    expect(empty.closest('div')?.querySelector('.ant-empty')).toBeNull()
  })

  it('API ALLOW（中间决策）+ WAF BLOCK（最终处置）区分展示：执行模块 WAF，API 决策单独一行', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            request_id: 'req-trace-1',
            application_id: 'app-1',
            gateway_node: 'node-1',
            completion_status: 'COMPLETED',
            security_action: 'BLOCK',
            executor_module: 'WAF',
            response_source: 'GATEWAY',
            http_status: 403,
            response_committed: true,
            reason_codes: ['WAF_INTERCEPT'],
            rule_refs: [{ module: 'WAF', rule_id: '942100', version: '4.26.0' }],
            effective_config: {
              config_fingerprint: 'fp-shop-01',
              api_policy_version: 'apv-7',
              exception_versions: { 'e4b6f7a8-0000-4000-8000-000000000001': 2 },
            },
            findings: { observed: 1, enforced: 1, excepted: 0, skipped: 2 },
            steps: [
              { module: 'RISK_POLICY', result: 'OBSERVED', detail: 'observe 模式命中' },
              { module: 'API', result: 'EXECUTED', detail: 'final_action=ALLOW' },
              { module: 'WAF', result: 'EXECUTED', detail: 'rule 942100 matched' },
              { module: 'CC', result: 'SKIPPED' },
            ],
            matched_exceptions: [
              {
                exception_id: 'e4b6f7a8-0000-4000-8000-000000000001',
                version: 2,
                target: 'WAF',
                rule_refs: ['949110'],
                scope_summary: 'shop.example.com POST /api/orders',
                effective_from: '2026-08-30T00:00:00Z',
                effective_until: '2026-08-30T00:30:00Z',
              },
            ],
            finalized_at: '2026-08-30T00:30:01Z',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    // 最终处置：执行模块为 WAF，安全动作行为「阻断」
    expect(screen.getByText('执行模块')).toBeInTheDocument()
    expect(screen.getAllByText('WAF（Coraza/CRS）').length).toBeGreaterThanOrEqual(2)
    {
      let row: HTMLElement | null = screen.getByText('安全动作')
      while (row && !row.textContent?.includes('阻断')) row = row.parentElement
      expect(row).toBeTruthy()
    }
    // API 中间决策单独一行，且不等于最终放行
    expect(screen.getByText('API 中间决策')).toBeInTheDocument()
    expect(screen.getByText('API 已执行：final_action=ALLOW')).toBeInTheDocument()
    expect(
      screen.getByText(/API 决策为中间结果：API 放行不等于最终放行/),
    ).toBeInTheDocument()
    // 原因码 / 规则引用 / 有效配置 / 命中例外 / 检测发现计数 / 步骤语义均中文化
    expect(screen.getByText('WAF 规则拦截')).toBeInTheDocument()
    expect(screen.getByText('WAF（Coraza/CRS） 942100@4.26.0')).toBeInTheDocument()
    expect(screen.getByText('检测发现计数')).toBeInTheDocument()
    expect(screen.getByText('身份风险策略')).toBeInTheDocument()
    expect(screen.getByText('CC 频率限制')).toBeInTheDocument()
    expect(screen.getByText(/fp-shop-01/)).toBeInTheDocument()
    expect(screen.getByText(/shop\.example\.com POST \/api\/orders/)).toBeInTheDocument()
    expect(screen.getByText('仅观察 1')).toBeInTheDocument()
    expect(screen.getByText('例外豁免 0')).toBeInTheDocument()
    expect(screen.getByText('仅观察')).toBeInTheDocument()
    expect(screen.getByText('未运行')).toBeInTheDocument()
    expect(screen.getByText('执行过程（4 步）')).toBeInTheDocument()
  })

  it('步骤超出有界上限：显示「已截断」提示', async () => {
    const steps = Array.from({ length: 33 }, (_, i) => ({
      module: `MOD_${i}`,
      result: 'SKIPPED',
    }))
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'NONE',
            executor_module: 'NONE',
            response_source: 'ORIGIN',
            http_status: 200,
            completion_status: 'COMPLETED',
            steps,
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('执行过程（33 步）')).toBeInTheDocument()
    expect(screen.getByText('已截断：超出 32 步未显示')).toBeInTheDocument()
    // 仅渲染前 32 步
    expect(screen.queryByText('MOD_32')).not.toBeInTheDocument()
    expect(screen.getByText('MOD_31')).toBeInTheDocument()
  })

  it('completion_status=PENDING_CORRELATION：显示「证据待关联」，不伪造规则明细', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'BLOCK',
            executor_module: 'WAF',
            response_source: 'GATEWAY',
            http_status: 403,
            completion_status: 'PENDING_CORRELATION',
            rule_refs: [],
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('证据待关联')).toBeInTheDocument()
    // 安全动作行为「阻断」（事件概览的 action 列也可能出现同文案，按行容器断言）
    let row: HTMLElement | null = screen.getByText('安全动作')
    while (row && !row.textContent?.includes('阻断')) row = row.parentElement
    expect(row).toBeTruthy()
  })

  it('CHALLENGE/BOT（P1-02 Bot 挑战）：映射展示为「Bot 挑战」', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'CHALLENGE',
            executor_module: 'BOT',
            response_source: 'GATEWAY',
            http_status: 403,
            completion_status: 'COMPLETED',
            reason_codes: ['BOT_CHALLENGE_OFFERED'],
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    // 安全动作与执行模块均命中新映射（同文案出现两处：动作行 + 模块行）
    expect(screen.getAllByText('Bot 挑战').length).toBeGreaterThanOrEqual(2)
  })

  it('未知安全动作/执行模块（未来新增值）：原样展示原始值，不渲染为空或误导文案', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        event: {
          ...EVENT_DETAIL.event,
          final_decision: {
            schema_version: 1,
            security_action: 'FUTURE_ACTION_X',
            executor_module: 'FUTURE_MODULE_X',
            response_source: 'GATEWAY',
            http_status: 418,
            completion_status: 'COMPLETED',
          },
        },
      }),
    )
    renderDrawer()

    expect(await screen.findByText('最终处置')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_ACTION_X')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_MODULE_X')).toBeInTheDocument()
  })
})

describe('EventDetailDrawer 相关事件关联口径', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ apmEnabled: false, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  const RELATED_ITEM = {
    id: 'evt-2',
    request_id: 'req-2',
    occurred_at: '2026-08-30T00:10:00Z',
    application_id: 'app-1',
    application_name_snapshot: '商城站点',
    domain: 'shop.example.com',
    gateway_node_id: 'node-1',
    client_ip: '1.2.3.4',
    client_port: 51001,
    request_method: 'GET',
    request_uri: '/v1/users/1?id=1',
    request_path: '/v1/users/1',
    query_summary: 'id=1',
    http_version: 'HTTP/1.1',
    content_type: '',
    user_agent_summary: 'curl',
    referer_summary: '',
    attack_type: 'sqli',
    severity: 'HIGH',
    anomaly_score: 9,
    action: 'BLOCK',
    response_status: 403,
    rule_match_count: 1,
    disposition_status: 'PENDING',
    disposition_result: '',
    raw_log_reference: '',
  }

  it('attack_session 口径：展示「同一攻击会话」说明与攻击活动跳转链接', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        related: [RELATED_ITEM],
        related_mode: 'attack_session',
        related_session_id: 'sess-9',
      }),
    )
    renderDrawer()

    expect(await screen.findByText(/同一攻击会话 · 按攻击时间线排列/)).toBeInTheDocument()
    const link = screen.getByRole('link', { name: '查看攻击活动' })
    expect(link.getAttribute('href')).toBe('/attack-sessions/sess-9')
  })

  it('same_source_ip 口径：展示「同一来源 IP」说明，无会话链接', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        related: [RELATED_ITEM],
        related_mode: 'same_source_ip',
        related_session_id: null,
      }),
    )
    renderDrawer()

    expect(await screen.findByText('同一来源 IP · 前后 24 小时')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '查看攻击活动' })).not.toBeInTheDocument()
  })

  it('无关联口径（none/缺省）：不展示口径说明', async () => {
    vi.stubGlobal('fetch', mockFetch({ ...EVENT_DETAIL, related: [] }))
    renderDrawer()

    expect(await screen.findByText('暂无相关事件')).toBeInTheDocument()
    expect(screen.queryByText(/同一攻击会话/)).not.toBeInTheDocument()
    expect(screen.queryByText(/同一来源 IP/)).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer 命中规则 CNNVD/CVE 编号（CNNVD 兼容性 P1）', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
  })

  const MATCH = {
    rule_id: 7100001,
    rule_name: 'Struts2 RCE 虚拟补丁',
    rule_source: 'CUSTOM',
    severity: 'HIGH',
    message: '命中虚拟补丁',
    matched_variable: 'ARGS',
    matched_data: 'ognl payload',
    tags: [],
    phase: 2,
  }

  it('match 携带编号：CNNVD 红 Tag / CVE 蓝 Tag，CNNVD 标签链接跳漏洞档案 ?focus=', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        matches: [{ ...MATCH, cnnvd_ids: ['CNNVD-202401-2345'], cve_ids: ['CVE-2024-0001'] }],
      }),
    )
    renderDrawer()

    expect(await screen.findByText('漏洞编号：')).toBeInTheDocument()
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument()
    const cnnvdLink = screen.getByRole('link', { name: 'CNNVD-202401-2345' })
    expect(cnnvdLink.getAttribute('href')).toBe('/waf/vuln-refs?focus=CNNVD-202401-2345')
  })

  it('match 编号缺省/为空：不渲染编号区（静默不显示）', async () => {
    vi.stubGlobal('fetch', mockFetch({ ...EVENT_DETAIL, matches: [MATCH] }))
    renderDrawer()

    expect(await screen.findByText('命中虚拟补丁')).toBeInTheDocument()
    expect(screen.queryByText('漏洞编号：')).not.toBeInTheDocument()
  })

  it('历史英文 CRS 命中记录自动转为中文（含异常总分）', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        ...EVENT_DETAIL,
        matches: [
          {
            rule_id: 943120,
            rule_name: 'Possible Session Fixation Attack: SessionID Parameter Name with No Referer',
            rule_source: 'OWASP_CRS',
            severity: 'HIGH',
            message: 'Possible Session Fixation Attack: SessionID Parameter Name with No Referer',
            matched_variable: 'ARGS_NAMES:sessionId',
            matched_data: '0',
            tags: ['attack-fixation'],
            phase: 2,
          },
          {
            rule_id: 949110,
            rule_name: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
            rule_source: 'OWASP_CRS',
            severity: 'INFO',
            message: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
            matched_variable: '',
            matched_data: '',
            tags: [],
            phase: 2,
          },
        ],
      }),
    )
    renderDrawer()

    expect(await screen.findByText('疑似会话固定攻击：SessionID 参数无 Referer')).toBeInTheDocument()
    expect(screen.getByText('入站异常评分超限（总分：5）')).toBeInTheDocument()
    expect(
      screen.queryByText('Possible Session Fixation Attack: SessionID Parameter Name with No Referer'),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('Inbound Anomaly Score Exceeded (Total Score: 5)')).not.toBeInTheDocument()
  })
})

describe('EventDetailDrawer 处置操作收敛与加入白名单入口', () => {
  beforeEach(() => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    useAuthStore.setState({
      user: makeUser([
        'security_events.read',
        'security_events.disposition',
        'access_rules.manage',
        'exceptions.manage',
      ]),
      csrfToken: 'csrf-1',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useProductStore.getState().reset()
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('底部处置操作收敛为研判下拉 + 执行处置/仅添备注，并提供加入黑名单/加入白名单/创建例外', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderDrawer()

    expect(await screen.findByRole('button', { name: '执行处置' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '仅添备注' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '加入黑名单' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '加入白名单' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '创建例外' })).toBeInTheDocument()
    // 原平铺的多余状态按钮已收进下拉，不再平铺占满三行
    expect(screen.queryByRole('button', { name: '标记分析中' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '忽略' })).not.toBeInTheDocument()

    // 点击「创建例外」打开弹窗，而非旧的盲目草稿确认框
    fireEvent.click(screen.getByRole('button', { name: '创建例外' }))
    expect(await screen.findByText('从安全事件创建例外')).toBeInTheDocument()
  })
})
