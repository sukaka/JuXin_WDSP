import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityRegressionDetailPage from '../SecurityRegressionDetailPage'
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

function makeRun(over: Record<string, unknown> = {}) {
  return {
    id: RUN_ID,
    run_id: 'ci-run-20260909-01',
    manifest_sha256: 'a'.repeat(64),
    level: 'FULL',
    declared_status: 'PASS',
    verification_status: 'PASSED',
    verification_reasons: null,
    signature_algorithm: 'ed25519',
    signature_key_id: 'verifier-2026-09',
    config_fingerprint: 'cfgfpv1:' + 'b'.repeat(64),
    build_digest: 'sha256:' + 'c'.repeat(64),
    compiler: 'regc-1.2.3',
    corpus_id: 'corpus-2026q3',
    corpus_version: 7,
    corpus_sha256: 'd'.repeat(64),
    plan_sha256: 'e'.repeat(64),
    counts: {
      planned: 4,
      executed: 4,
      skipped: 0,
      blocked: 0,
      not_run: 0,
      passed: 4,
      failed: 0,
      mandatory_total: 3,
      mandatory_failed: 0,
    },
    run_started_at: '2026-09-09T01:00:00Z',
    run_finished_at: '2026-09-09T01:03:00Z',
    policy_version: 3,
    imported_by: 'ci-bot',
    created_at: new Date(Date.now() - 3600_000).toISOString(),
    ...over,
  }
}

function makeGate(over: Record<string, unknown> = {}) {
  return {
    usable_for_publish: true,
    // Go nil slice 序列化为 null：可用证据无理由时服务端返回 reasons=null
    reasons: null,
    policy_mode: 'OFF',
    required_level: 'FULL',
    evidence_max_age_seconds: 604800,
    age_seconds: 3600,
    expired: false,
    ...over,
  }
}

function mockFetch(detail: unknown) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes(`/security/regressions/${RUN_ID}`)) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: detail }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={[`/security-regressions/${RUN_ID}`]}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <Routes>
            <Route path="/security-regressions/:id" element={<SecurityRegressionDetailPage />} />
          </Routes>
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('SecurityRegressionDetailPage', () => {
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

  it('gate_assessment.reasons=null（Go nil slice）时可用详情正常渲染不崩溃', async () => {
    vi.stubGlobal('fetch', mockFetch({ run: makeRun(), gate_assessment: makeGate() }))
    renderPage()
    expect(await screen.findByText('回归运行 ci-run-20260909-01')).toBeTruthy()
    expect(await screen.findByText('本证据当前可用于支撑发布')).toBeTruthy()
    expect(screen.getByText('4 / 4 / 0')).toBeTruthy()
    expect(screen.getByText('未超期')).toBeTruthy()
  })

  it('不可用详情：逐项理由与恢复动作如实列出', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        run: makeRun({
          declared_status: 'FAIL',
          counts: { ...makeRun().counts, failed: 1, mandatory_failed: 1 },
        }),
        gate_assessment: makeGate({
          usable_for_publish: false,
          reasons: ['回归声明状态非 PASS', '强制用例未全部通过（1）'],
        }),
      }),
    )
    renderPage()
    expect(await screen.findByText('本证据当前不可用于支撑发布')).toBeTruthy()
    expect(screen.getByText('逐项理由与恢复动作')).toBeTruthy()
    expect(screen.getByText('回归声明状态非 PASS')).toBeTruthy()
    expect(screen.getByText(/强制用例未全部通过（1）/)).toBeTruthy()
  })
})
