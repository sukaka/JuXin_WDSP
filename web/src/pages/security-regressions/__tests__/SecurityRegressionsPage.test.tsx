import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityRegressionsPage from '../SecurityRegressionsPage'
import { useAuthStore } from '../../../stores/auth'
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

const POLICY_OFF = {
  mode: 'OFF',
  required_level: 'FULL',
  required_corpus_id: '',
  evidence_max_age_seconds: 604800,
  version: 3,
  updated_by: 'secops',
  updated_at: '2026-09-07T00:00:00Z',
}

function makeRun(over: Record<string, unknown> = {}) {
  return {
    id: 'run-uuid-1',
    run_id: 'ci-run-20260908-01',
    manifest_sha256: 'a'.repeat(64),
    level: 'FULL',
    declared_status: 'PASS',
    verification_status: 'PASSED',
    verification_reasons: null,
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
      planned: 12,
      executed: 12,
      skipped: 0,
      blocked: 0,
      not_run: 0,
      passed: 11,
      failed: 1,
      mandatory_total: 4,
      mandatory_failed: 0,
    },
    run_started_at: '2026-09-08T01:00:00Z',
    run_finished_at: '2026-09-08T01:03:00Z',
    policy_version: 3,
    imported_by: 'ci-bot',
    created_at: new Date(Date.now() - 3600_000).toISOString(),
    ...over,
  }
}

interface MockOptions {
  policy?: unknown
  policyPutStatus?: number
  runs?: unknown[]
  total?: number
}

function mockFetch(opts: MockOptions = {}, calls: string[] = []) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.includes('/security/regression-policy')) {
      if (init?.method === 'PUT') {
        if (opts.policyPutStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, {
              code: 'RESOURCE_CONFLICT',
              message: '策略已被其他人修改，请刷新后重试',
              data: null,
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { policy: { ...POLICY_OFF, version: 4, mode: 'ENFORCE' } },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { policy: opts.policy ?? POLICY_OFF },
        }),
      )
    }
    if (url.includes('/security/regressions')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            items: opts.runs ?? [makeRun()],
            page: 1,
            page_size: 20,
            total: opts.total ?? 1,
          },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="location-search">{loc.search}</div>
}

function renderPage(initialEntry = '/security-regressions') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <Routes>
            <Route
              path="/security-regressions"
              element={
                <>
                  <SecurityRegressionsPage />
                  <LocationProbe />
                </>
              }
            />
          </Routes>
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function grant(permissions: string[]) {
  useAuthStore.setState({
    user: makeUser(permissions),
    csrfToken: null,
    initialized: true,
  })
}

const READ = ['security_regression.read']
const FULL = ['security_regression.read', 'security_regression.policy']

describe('SecurityRegressionsPage', () => {
  beforeEach(() => {
    grant(FULL)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示级别/核验/声明/计划实际缺失/新鲜度，OFF 门禁明示未强制', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    expect(await screen.findByText('ci-run-20260908-01')).toBeTruthy()
    // 「全量」同时出现在策略卡要求级别与列表行级别，两处都应渲染
    expect(screen.getAllByText('全量').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('核验通过')).toBeTruthy()
    expect(screen.getByText('声明通过')).toBeTruthy()
    // 计划/实际/缺失 12/12/0
    expect(screen.getByText('12 / 12 / 0')).toBeTruthy()
    expect(
      screen.getByText(/回归门禁未强制（OFF）/),
    ).toBeTruthy()
  })

  it('未知枚举原样回退（不吞掉、不伪造语义）', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ runs: [makeRun({ level: 'NIGHTLY_X', verification_status: 'QUEUED_X' })] }),
    )
    renderPage()
    expect(await screen.findByText('NIGHTLY_X')).toBeTruthy()
    expect(screen.getByText('QUEUED_X')).toBeTruthy()
  })

  it('证据不可用时列出文字原因而非绿色百分比', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        runs: [
          makeRun({
            verification_status: 'FAILED',
            counts: { ...makeRun().counts, mandatory_failed: 2 },
          }),
        ],
      }),
    )
    renderPage()
    const cell = await screen.findByText(/不可用（2 项原因）/)
    expect(cell).toBeTruthy()
  })

  it('URL 筛选与分页上下文：进入列表即按查询串请求（返回不丢状态）', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', mockFetch({}, calls))
    renderPage('/security-regressions?level=FULL&status=PASSED&page=2&page_size=50')
    await screen.findByText('ci-run-20260908-01')
    await waitFor(() => {
      const listCall = calls.find(
        (c) => c.startsWith('GET') && c.includes('/security/regressions?'),
      )
      expect(listCall).toBeTruthy()
      expect(listCall).toContain('level=FULL')
      expect(listCall).toContain('status=PASSED')
      expect(listCall).toContain('page=2')
      expect(listCall).toContain('page_size=50')
    })
  })

  it('权限门控：无 security_regression.policy 不显示修改入口', async () => {
    grant(READ)
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    expect(await screen.findByText('ci-run-20260908-01')).toBeTruthy()
    expect(screen.queryByText('修改门禁策略')).toBeNull()
  })

  it('修改门禁策略：expected_version 乐观锁 + 审计理由必填 + 409 冲突提示', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', mockFetch({ policyPutStatus: 409 }, calls))
    renderPage()
    // 策略未加载完时按钮 disabled，点击不生效；等策略卡渲染后再点击
    await screen.findByText('关闭（不检查）')
    fireEvent.click(screen.getByText('修改门禁策略'))
    const reason = await screen.findByPlaceholderText('如：开启发布级强制门禁（P1-04 上线）')
    fireEvent.change(reason, { target: { value: 'E2E 前开启强制门禁' } })
    fireEvent.click(screen.getByText('保 存'))
    expect(
      await screen.findByText('策略已被他人修改，请刷新后重试'),
    ).toBeTruthy()
    // PUT 携带 expected_version=当前 version 与 reason（进审计）
    const put = calls.find((c) => c.startsWith('PUT'))
    expect(put).toBeTruthy()
  })
})
