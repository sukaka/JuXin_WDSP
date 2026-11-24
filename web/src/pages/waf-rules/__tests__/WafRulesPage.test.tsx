import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import WafRulesPage from '../WafRulesPage'
import { useAuthStore } from '../../../stores/auth'

const RULE = {
  id: 'rule-942100',
  rule_id: 942100,
  rule_source: 'CRS',
  file_name: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
  name: 'SQL Injection Attack Detected via libinjection',
  message: 'SQL Injection Attack Detected via libinjection',
  severity: 'CRITICAL',
  phase: 2,
  tags: ['attack-sqli'],
  attack_type: 'SQLI',
  default_state: 'ENABLED',
  crs_version: '4.0.0',
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <WafRulesPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('WafRulesPage 规则效果', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'secops',
        display_name: '安全管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
        permissions: ['waf_rules.read'],
        must_change_password: false,
      },
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/waf-rules/effect-statistics')) {
          return Promise.resolve(
            jsonResponse({
              items: [
                {
                  date: '2026-09-01',
                  rule_id: 942100,
                  rule_key: '942100',
                  rule_name: RULE.name,
                  rule_source: 'CRS',
                  rule_version: '4.0.0',
                  hits: 12,
                  blocks: 5,
                  unresolved: 4,
                  confirmed_attacks: 3,
                  false_positives: 2,
                  reviewed: 5,
                  confirmation_rate: 0.6,
                  fp_rate: 0.4,
                  protect_recommendation: false,
                },
                {
                  date: '2026-08-31',
                  rule_id: 942100,
                  rule_key: '942100',
                  rule_name: RULE.name,
                  rule_source: 'CRS',
                  rule_version: '4.0.0',
                  hits: 0,
                  blocks: 0,
                  unresolved: 0,
                  confirmed_attacks: 0,
                  false_positives: 0,
                  reviewed: 0,
                  confirmation_rate: null,
                  fp_rate: null,
                  protect_recommendation: false,
                },
              ],
              page: 1,
              page_size: 30,
              total: 1,
            }),
          )
        }
        if (url.includes('/waf-rules/categories')) {
          return Promise.resolve(jsonResponse({ items: [{ attack_type: 'SQLI', count: 1 }] }))
        }
        if (url.includes('/waf-rules/versions')) {
          return Promise.resolve(jsonResponse({ versions: ['4.0.0'] }))
        }
        if (url.includes('/waf-rules/942100')) {
          return Promise.resolve(jsonResponse(RULE))
        }
        if (url.includes('/waf-rules')) {
          return Promise.resolve(jsonResponse({ items: [RULE], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('详情中的规则效果展示完整研判指标和费率', async () => {
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('规则详情：942100')).toBeInTheDocument()

    expect(await screen.findByText('命中 12')).toBeInTheDocument()
    expect(screen.getByText('阻断 5')).toBeInTheDocument()
    expect(screen.getByText('确认攻击 3')).toBeInTheDocument()
    expect(screen.getByText('确认误报 2')).toBeInTheDocument()
    expect(screen.getByText('已研判 5')).toBeInTheDocument()
    expect(screen.getByText('未确认 4')).toBeInTheDocument()
    expect(screen.getByText('确认率 60.0% · 误报率 40.0%')).toBeInTheDocument()
    expect(screen.getByText('确认率 — · 误报率 —')).toBeInTheDocument()
  })

  it('规则ID筛选：输入不触发查询，回车提交一次', async () => {
    renderPage()
    // 等初始列表加载完成
    await screen.findByText('942100')
    const listCallsWithRuleId = () =>
      (fetch as Mock).mock.calls.filter(
        (c) => String(c[0]).includes('/waf-rules?') && String(c[0]).includes('rule_id='),
      )

    const input = screen.getByPlaceholderText('规则ID（回车生效）')
    // 逐字符输入不触发带 rule_id 的列表查询
    fireEvent.change(input, { target: { value: '9' } })
    fireEvent.change(input, { target: { value: '94' } })
    fireEvent.change(input, { target: { value: '942100' } })
    expect(listCallsWithRuleId()).toHaveLength(0)

    // 回车提交：按输入值查询一次
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
    await waitFor(() => expect(listCallsWithRuleId()).toHaveLength(1))
    expect(String(listCallsWithRuleId()[0][0])).toContain('rule_id=942100')
  })

  it('规则ID筛选：失焦提交，清空后失焦清除筛选', async () => {
    renderPage()
    await screen.findByText('942100')
    const listCallsWithRuleId = () =>
      (fetch as Mock).mock.calls.filter(
        (c) => String(c[0]).includes('/waf-rules?') && String(c[0]).includes('rule_id='),
      )
    const allListCalls = () =>
      (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/waf-rules?'))

    const input = screen.getByPlaceholderText('规则ID（回车生效）')
    fireEvent.change(input, { target: { value: '942100' } })
    fireEvent.blur(input)
    await waitFor(() => expect(listCallsWithRuleId()).toHaveLength(1))

    // 清空后失焦：再次查询且不带 rule_id
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.blur(input)
    await waitFor(() => expect(allListCalls().length).toBeGreaterThanOrEqual(3))
    const calls = allListCalls()
    const last = String(calls[calls.length - 1]![0])
    expect(last).not.toContain('rule_id=')
  })

  it('规则详情中文化：建议切换防护模式标签与规则覆盖动作/范围中文展示', async () => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'secops',
        display_name: '安全管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
        permissions: ['waf_rules.read', 'rule_overrides.manage'],
        must_change_password: false,
      },
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/waf-rules/effect-statistics')) {
          return Promise.resolve(
            jsonResponse({
              items: [
                {
                  date: '2026-09-02',
                  rule_id: 942100,
                  rule_key: '942100',
                  rule_name: RULE.name,
                  rule_source: 'OWASP_CRS',
                  rule_version: '4.0.0',
                  hits: 20,
                  blocks: 18,
                  unresolved: 0,
                  confirmed_attacks: 20,
                  false_positives: 0,
                  reviewed: 20,
                  confirmation_rate: 1.0,
                  fp_rate: 0.0,
                  protect_recommendation: true,
                  protect_recommendation_reason: '连续高置信命中',
                },
              ],
              page: 1,
              page_size: 30,
              total: 1,
            }),
          )
        }
        if (url.includes('/rule-overrides')) {
          return Promise.resolve(
            jsonResponse({
              items: [
                {
                  id: 'ov-1',
                  rule_id: 942100,
                  action: 'DISABLE',
                  scope_type: 'POLICY',
                  scope_id: 'pol-12345678',
                  reason: '临时误报处理',
                },
                {
                  id: 'ov-2',
                  rule_id: 942100,
                  action: 'ENABLE',
                  scope_type: 'APPLICATION',
                  scope_id: 'app-87654321',
                  reason: '关键业务强制启用',
                },
              ],
              page: 1,
              page_size: 50,
              total: 2,
            }),
          )
        }
        if (url.includes('/applications')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }))
        }
        if (url.includes('/protection-policies')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }))
        }
        if (url.includes('/waf-rules/categories')) {
          return Promise.resolve(jsonResponse({ items: [{ attack_type: 'SQL_INJECTION', count: 1 }] }))
        }
        if (url.includes('/waf-rules/versions')) {
          return Promise.resolve(jsonResponse({ versions: ['4.0.0'] }))
        }
        if (url.includes('/waf-rules/942100')) {
          return Promise.resolve(jsonResponse(RULE))
        }
        if (url.includes('/waf-rules')) {
          return Promise.resolve(jsonResponse({ items: [RULE], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('建议人工评估切换防护模式')).toBeInTheDocument()
    expect(screen.queryByText('建议人工评估 PROTECT')).not.toBeInTheDocument()
    // 规则详情中规则名称与消息均展示中文，不暴露英文原名
    expect(screen.getAllByText('通过 libinjection 检测到 SQL 注入攻击').length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText('SQL Injection Attack Detected via libinjection')).not.toBeInTheDocument()

    expect(await screen.findByText('启用规则')).toBeInTheDocument()
    expect(screen.getAllByText('停用规则').length).toBeGreaterThan(0)
    expect(screen.getAllByText('防护策略').length).toBeGreaterThan(0)
    expect(screen.getAllByText('应用').length).toBeGreaterThan(0)
    expect(screen.queryByText('DISABLE')).not.toBeInTheDocument()
    expect(screen.queryByText('ENABLE')).not.toBeInTheDocument()
    expect(screen.queryByText('POLICY')).not.toBeInTheDocument()
    expect(screen.queryByText('APPLICATION')).not.toBeInTheDocument()
  })

  it('B8-04：来源筛选下拉不含无效的 CUSTOM，包含 USER_CUSTOM 等后端合法来源', async () => {
    renderPage()
    await screen.findByText('942100')

    const sourceCombo = screen.getAllByRole('combobox').find((el) =>
      el.closest('.ant-select')?.textContent?.includes('来源'),
    )
    expect(sourceCombo).toBeTruthy()
    fireEvent.mouseDown(sourceCombo as HTMLElement)

    expect(await screen.findByTitle('用户自定义')).toBeInTheDocument()
    expect(screen.getByTitle('OWASP 核心规则集')).toBeInTheDocument()
    expect(screen.queryByTitle('自定义')).not.toBeInTheDocument()

    fireEvent.click(screen.getByTitle('用户自定义'))
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) => String(c[0]).includes('rule_source=USER_CUSTOM')),
      ).toBe(true)
    })
  })

  it('规则详情抽屉完整展示后端返回的中文详细说明、检测原理、风险影响与调优建议', async () => {
    const detailedRule = {
      ...RULE,
      rule_id: 911100,
      rule_source: 'OWASP_CRS',
      file_name: 'REQUEST-911-METHOD-ENFORCEMENT.conf',
      name: '请求方法不被策略允许',
      message: '请求方法不被策略允许',
      description: '校验客户端使用的 HTTP 请求方法是否在当前策略允许的方法白名单之内。',
      phase: 1,
      attack_type: 'OTHER',
      tags: ['paranoia-level/1', 'OWASP_CRS', 'capec/1000/210/272/220/274'],
      crs_version: '4.28.0',
      detail: {
        rule_type: 'DETECTION',
        rule_type_label: '安全检测规则',
        summary: '校验客户端使用的 HTTP 请求方法是否在当前策略允许的方法白名单之内。',
        detection_logic: '在阶段 1（请求头阶段）检查 HTTP 请求方法（REQUEST_METHOD）；校验取值是否超出白名单集合。',
        risk_impact: '限制非必要或高危 HTTP 方法可有效防范跨站追踪与未授权写入风险。',
        tuning_advice: 'RESTful API 若需 PUT/DELETE 方法，请在对应防护策略或应用例外中按需放行。',
        phase_description: '阶段 1（请求头检查）：在接收完整 HTTP 请求头后执行',
        paranoia_level: 'PL1（默认启用，低误报基线防护）',
        action_behavior: '异常评分（入站，严重级别 +5 分；达到策略阈值后阻断）',
        targets: ['HTTP 请求方法（REQUEST_METHOD）'],
        references: ['CAPEC-274：HTTP 方法篡改', 'OWASP 核心规则集 4.28.0 · HTTP 方法强制规则族'],
      },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/waf-rules/effect-statistics')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 30, total: 0 }))
        }
        if (url.includes('/waf-rules/categories')) {
          return Promise.resolve(jsonResponse({ items: [{ attack_type: 'OTHER', count: 1 }] }))
        }
        if (url.includes('/waf-rules/versions')) {
          return Promise.resolve(jsonResponse({ versions: ['4.28.0'] }))
        }
        if (url.includes('/waf-rules/911100')) {
          return Promise.resolve(jsonResponse(detailedRule))
        }
        if (url.includes('/waf-rules')) {
          return Promise.resolve(jsonResponse({ items: [detailedRule], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('规则详情：911100')).toBeInTheDocument()
    expect(await screen.findByText('规则详细说明')).toBeInTheDocument()
    expect(screen.getByText('安全检测规则')).toBeInTheDocument()
    expect(screen.getByText('PL1（默认启用，低误报基线防护）')).toBeInTheDocument()
    expect(screen.getByText('阶段 1（请求头检查）')).toBeInTheDocument()
    expect(
      screen.getByText('校验客户端使用的 HTTP 请求方法是否在当前策略允许的方法白名单之内。'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('限制非必要或高危 HTTP 方法可有效防范跨站追踪与未授权写入风险。'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('RESTful API 若需 PUT/DELETE 方法，请在对应防护策略或应用例外中按需放行。'),
    ).toBeInTheDocument()
    expect(screen.getByText('HTTP 请求方法（REQUEST_METHOD）')).toBeInTheDocument()
    expect(screen.getByText('CAPEC-274：HTTP 方法篡改')).toBeInTheDocument()
  })

  it('内部规则（如 913011）在详情抽屉清晰展示引擎内部控制说明', async () => {
    const internalRule = {
      ...RULE,
      id: 'rule-913011',
      rule_id: 913011,
      rule_source: 'OWASP_CRS',
      file_name: 'REQUEST-913-SCANNER-DETECTION.conf',
      name: '扫描器检测内部规则',
      message: '扫描器检测内部规则',
      severity: 'NOTICE',
      phase: 1,
      attack_type: 'OTHER',
      tags: ['OWASP_CRS'],
      crs_version: '4.28.0',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/waf-rules/effect-statistics')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 30, total: 0 }))
        }
        if (url.includes('/waf-rules/categories')) {
          return Promise.resolve(jsonResponse({ items: [{ attack_type: 'OTHER', count: 1 }] }))
        }
        if (url.includes('/waf-rules/versions')) {
          return Promise.resolve(jsonResponse({ versions: ['4.28.0'] }))
        }
        if (url.includes('/waf-rules/913011')) {
          return Promise.resolve(jsonResponse(internalRule))
        }
        if (url.includes('/waf-rules')) {
          return Promise.resolve(jsonResponse({ items: [internalRule], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('规则详细说明')).toBeInTheDocument()
    expect(screen.getByText('引擎内部控制规则')).toBeInTheDocument()
    expect(screen.getByText('无条件执行（引擎内部流程控制）')).toBeInTheDocument()
    expect(screen.getByText(/通常不应手动停用/)).toBeInTheDocument()
    // 仅只读权限时不展示「编辑说明」按钮
    expect(screen.queryByRole('button', { name: /编辑说明/ })).not.toBeInTheDocument()
  })

  it('方案 A+B：展示规则文件自动解析来源，并支持安全管理员在线编辑与恢复默认说明', async () => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'sec_admin',
        display_name: '安全管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
        permissions: ['waf_rules.read', 'rule_overrides.manage'],
        must_change_password: false,
      },
      csrfToken: 'csrf-token-1',
      initialized: true,
    })

    const baseRule = {
      ...RULE,
      id: 'rule-1099001',
      rule_id: 1099001,
      rule_source: 'CUSTOM_PACK',
      file_name: 'hot-cve-2026.conf',
      name: '新型接口头命令注入（CVE-2026-99999）',
      message: '新型接口头命令注入（CVE-2026-99999）',
      description: '自动解析自规则文件中文注释。',
      phase: 2,
      attack_type: 'COMMAND_INJECTION',
      tags: ['attack-rce', 'cve/CVE-2026-99999'],
      crs_version: '4.28.0',
      detail: {
        rule_type: 'DETECTION',
        rule_type_label: '安全检测规则',
        source: 'PARSED',
        source_label: '规则文件自动解析',
        customized: false,
        summary: '自动解析自规则文件中文注释。',
        detection_logic: '在阶段 2 检查 X-Api-Version 请求头。',
        risk_impact: '防止远程代码执行。',
        tuning_advice: '默认调优建议。',
        phase_description: '阶段 2（请求体与参数检查）',
        paranoia_level: '全偏执级别生效',
        action_behavior: '异常评分（入站，严重级别 +5 分）',
        targets: ['X-Api-Version 请求头（REQUEST_HEADERS:X-Api-Version）'],
        references: ['漏洞编号：CVE-2026-99999'],
      },
    }
    const customizedRule = {
      ...baseRule,
      detail: {
        ...baseRule.detail,
        source: 'CUSTOM',
        source_label: '人工维护说明',
        customized: true,
        tuning_advice: '本司网关灰度接口需放行特定版本头。',
        custom_fields: {
          summary: '',
          detection_logic: '',
          risk_impact: '',
          tuning_advice: '本司网关灰度接口需放行特定版本头。',
          updated_by_name: 'sec_admin',
          updated_at: '2026-11-23T15:30:00Z',
        },
      },
    }

    let currentRule = baseRule
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/waf-rules/1099001/description') && method === 'PUT') {
          currentRule = customizedRule
          return Promise.resolve(jsonResponse(customizedRule))
        }
        if (url.includes('/waf-rules/1099001/description') && method === 'DELETE') {
          currentRule = baseRule
          return Promise.resolve(jsonResponse(baseRule))
        }
        if (url.includes('/waf-rules/effect-statistics')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 30, total: 0 }))
        }
        if (url.includes('/rule-overrides')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 50, total: 0 }))
        }
        if (url.includes('/applications') || url.includes('/protection-policies')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }))
        }
        if (url.includes('/waf-rules/categories')) {
          return Promise.resolve(jsonResponse({ items: [{ attack_type: 'COMMAND_INJECTION', count: 1 }] }))
        }
        if (url.includes('/waf-rules/versions')) {
          return Promise.resolve(jsonResponse({ versions: ['4.28.0'] }))
        }
        if (url.includes('/waf-rules/1099001')) {
          return Promise.resolve(jsonResponse(currentRule))
        }
        if (url.includes('/waf-rules')) {
          return Promise.resolve(jsonResponse({ items: [currentRule], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('规则文件自动解析')).toBeInTheDocument()
    expect(screen.getByText('自动解析自规则文件中文注释。')).toBeInTheDocument()

    // 进入编辑并保存局部覆盖
    fireEvent.click(screen.getByRole('button', { name: /编辑说明/ }))
    const tuningInput = await screen.findByPlaceholderText(/可补充结合本司业务的排障与例外经验/)
    fireEvent.change(tuningInput, { target: { value: '本司网关灰度接口需放行特定版本头。' } })
    fireEvent.click(screen.getByRole('button', { name: /保存说明/ }))

    expect(await screen.findByText('人工维护说明')).toBeInTheDocument()
    expect(screen.getByText('本司网关灰度接口需放行特定版本头。')).toBeInTheDocument()
    expect(screen.getByText(/最近维护人：sec_admin/)).toBeInTheDocument()

    // 确认发出 PUT 请求
    const putCall = (fetch as Mock).mock.calls.find(
      (c) => String(c[0]).includes('/waf-rules/1099001/description') && c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    expect(String(putCall?.[1]?.body)).toContain('本司网关灰度接口需放行特定版本头。')

    // 点击「恢复默认」并确认
    fireEvent.click(screen.getByRole('button', { name: /恢复默认/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认恢复' }))
    expect(await screen.findByText('规则文件自动解析')).toBeInTheDocument()
    expect(screen.getByText('默认调优建议。')).toBeInTheDocument()
  })
})
