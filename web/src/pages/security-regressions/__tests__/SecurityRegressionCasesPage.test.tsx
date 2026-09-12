import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityRegressionCasesPage from '../SecurityRegressionCasesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const RUN_ID = 'run-uuid-1'

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

const RUN_DETAIL = {
  run: {
    id: RUN_ID,
    run_id: 'ci-run-20260908-01',
    manifest_sha256: 'a'.repeat(64),
    level: 'FULL',
    declared_status: 'PASS',
    verification_status: 'PASSED',
    verification_reasons: [],
    signature_algorithm: 'ed25519',
    signature_key_id: 'verifier-2026-09',
    config_fingerprint: 'cfgfpv1:' + 'b'.repeat(32),
    build_digest: 'sha256:' + 'c'.repeat(64),
    compiler: 'regc-1.2.3',
    corpus_id: 'corpus-2026q3',
    corpus_version: 7,
    corpus_sha256: 'd'.repeat(64),
    plan_sha256: 'e'.repeat(64),
    counts: {
      planned: 3,
      executed: 3,
      skipped: 0,
      blocked: 0,
      not_run: 0,
      passed: 1,
      failed: 2,
      mandatory_total: 2,
      mandatory_failed: 1,
    },
    run_started_at: null,
    run_finished_at: null,
    policy_version: 3,
    imported_by: 'ci-bot',
    created_at: '2026-09-08T01:05:00Z',
  },
  gate_assessment: {
    usable_for_publish: false,
    reasons: ['强制用例未全部通过（mandatory_failed=1）'],
    policy_mode: 'ENFORCE',
    required_level: 'FULL',
    evidence_max_age_seconds: 604800,
    age_seconds: 3600,
    expired: false,
  },
}

const XSS_PAYLOAD = '<img src=x onerror=alert(1)><script>alert(2)</script>'

const CASES = [
  {
    id: 'c1',
    case_id: 'sqli-001',
    case_version: 3,
    family: 'sqli',
    truth: 'ATTACK',
    criticality: 'MANDATORY',
    status: 'FAIL',
    diff_summary: {
      expected_action: 'BLOCK',
      observed_action: 'PASS',
      note: '候选版本丢失检测',
    },
  },
  {
    id: 'c2',
    case_id: 'benign-017',
    case_version: 1,
    family: 'benign',
    truth: 'BENIGN',
    criticality: 'OPTIONAL',
    status: 'FAIL',
    diff_summary: { expected_action: 'PASS', observed_action: 'BLOCK' },
  },
  {
    id: 'c3',
    case_id: 'xss-009',
    case_version: 2,
    family: 'xss',
    truth: 'ATTACK',
    criticality: 'MANDATORY',
    status: 'PASS',
    diff_summary: { evidence: XSS_PAYLOAD },
  },
]

function mockFetch(calls: string[] = []) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.includes(`/security/regressions/${RUN_ID}/cases`)) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: CASES, page: 1, page_size: 20, total: 3 },
        }),
      )
    }
    if (url.includes(`/security/regressions/${RUN_ID}`)) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: RUN_DETAIL }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(initialEntry = `/security-regressions/${RUN_ID}/cases`) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <Routes>
            <Route
              path="/security-regressions/:id/cases"
              element={<SecurityRegressionCasesPage />}
            />
          </Routes>
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('SecurityRegressionCasesPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['security_regression.read']),
      csrfToken: null,
      initialized: true,
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('差异类型分类：丢失检测/新增误报/前后动作逐项展示', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    expect(await screen.findByText('sqli-001')).toBeTruthy()
    expect(screen.getByText('丢失检测')).toBeTruthy()
    expect(screen.getByText('新增误报')).toBeTruthy()
    // 展开第一行看差异摘要（前后预期/实际）
    const expandButtons = document.querySelectorAll('button.ant-table-row-expand-icon')
    fireEvent.click(expandButtons[0])
    expect(await screen.findByText('expected_action')).toBeTruthy()
    expect(screen.getByText('BLOCK')).toBeTruthy()
  })

  it('长 Payload/恶意 HTML 一律纯文本渲染，不产生可执行标记（REG-023）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    const { container } = renderPage()
    expect(await screen.findByText('xss-009')).toBeTruthy()
    const expandButtons = container.querySelectorAll('button.ant-table-row-expand-icon')
    fireEvent.click(expandButtons[2])
    // 文本可见（被转义为纯文本；payload 可能在行内与展开摘要中各出现一次）
    const matches = await screen.findAllByText((_, el) => el?.textContent === XSS_PAYLOAD)
    expect(matches.length).toBeGreaterThanOrEqual(1)
    for (const el of matches) {
      expect(el.querySelector('img,script,iframe,svg')).toBeNull()
    }
    // 无真实 img/script 元素注入
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
  })

  it('URL 上下文：状态筛选与页码来自查询串并随请求下发', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', mockFetch(calls))
    renderPage(`/security-regressions/${RUN_ID}/cases?status=FAIL&page=2&page_size=50`)
    await screen.findByText('sqli-001')
    await waitFor(() => {
      const casesCall = calls.find((c) => c.includes('/cases?'))
      expect(casesCall).toBeTruthy()
      expect(casesCall).toContain('status=FAIL')
      expect(casesCall).toContain('page=2')
      expect(casesCall).toContain('page_size=50')
    })
  })

  it('类别本页筛选如实标注作用范围', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage(`/security-regressions/${RUN_ID}/cases?family=sqli`)
    expect(await screen.findByText('sqli-001')).toBeTruthy()
    // 本页筛选只留 sqli 行
    expect(screen.queryByText('benign-017')).toBeNull()
    expect(screen.getByText(/类别\/差异类型筛选仅作用于当前页/)).toBeTruthy()
  })

  it('未知用例状态/真值原样回退', async () => {
    vi.stubGlobal('fetch', mockFetch())
    const weird = {
      ...CASES[0],
      id: 'c9',
      case_id: 'weird-001',
      truth: 'HONEY',
      status: 'FLAKY',
    }
    const base = mockFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/cases')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [weird], page: 1, page_size: 20, total: 1 },
            }),
          )
        }
        return base(input, init)
      }),
    )
    renderPage()
    expect(await screen.findByText('HONEY')).toBeTruthy()
    expect(screen.getByText('FLAKY')).toBeTruthy()
  })
})
