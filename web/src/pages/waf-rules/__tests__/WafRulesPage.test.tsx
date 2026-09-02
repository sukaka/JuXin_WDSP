import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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
})
