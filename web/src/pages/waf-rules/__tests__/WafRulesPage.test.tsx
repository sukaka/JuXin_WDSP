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
})
