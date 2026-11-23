import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ReportTemplatesPage from '../ReportTemplatesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { Mock } from 'vitest'

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ReportTemplatesPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ReportTemplatesPage (B7-1 / B7-5)', () => {
  beforeEach(() => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'sec',
      display_name: '安全管理员',
      status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      permissions: ['reports.read', 'report_templates.manage'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('新建模板提交后端规范章节键（events_overview/conclusions 等），且校验 report_no_format ≤ 50 与 {YYYYMM}/{SEQ} 提示', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/report-templates') && init?.method === 'POST') {
        return Promise.resolve(
          jsonResponse({
            template: {
              id: 'tpl-1',
              ...JSON.parse(String(init.body)),
              is_builtin: false,
              created_at: '2026-11-20T00:00:00Z',
              updated_at: '2026-11-20T00:00:00Z',
              version: 1,
            },
          }),
        )
      }
      if (url.includes('/report-templates')) {
        return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建模板/ }))

    // B7-5: 编号格式帮助与 placeholder 仅含 {YYYYMM} 与 {SEQ}，不含 {TYPE}/{DATE}
    expect(screen.getByText(/\{YYYYMM\}.*\{SEQ\}/)).toBeInTheDocument()
    expect(screen.queryByText(/\{TYPE\}/)).not.toBeInTheDocument()
    expect(screen.queryByText(/\{DATE\}/)).not.toBeInTheDocument()

    fireEvent.change(await screen.findByLabelText('模板名称'), { target: { value: '季度合规模板' } })
    fireEvent.change(screen.getByLabelText('企业名称'), { target: { value: '聚信得仁' } })
    fireEvent.change(screen.getByLabelText('产品名称'), { target: { value: '九章WAF' } })

    // B7-5: 超过 50 字符应被前端表单规则拦截（不得发 POST）
    const fmtInput = screen.getByLabelText('报告编号格式')
    fireEvent.change(fmtInput, { target: { value: 'X'.repeat(51) } })
    fireEvent.click(screen.getByRole('button', { name: '创 建' }))
    expect(await screen.findByText('报告编号格式不能超过 50 个字符')).toBeInTheDocument()
    expect(
      (fetchMock as Mock).mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST'),
    ).toHaveLength(0)

    // 改为合法 <= 50 字符并提交
    fireEvent.change(fmtInput, { target: { value: 'SEC-{YYYYMM}-{SEQ}' } })
    fireEvent.click(screen.getByRole('button', { name: '创 建' }))

    await waitFor(() => {
      const postCall = (fetchMock as Mock).mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
      const payload = JSON.parse(String((postCall![1] as RequestInit).body)) as {
        report_no_format: string
        sections: Record<string, boolean>
      }
      expect(payload.report_no_format).toBe('SEC-{YYYYMM}-{SEQ}')
      // B7-1: 必须使用后端 SectionTitles 规范键，不得包含旧错误键
      for (const validKey of [
        'events_overview',
        'risk_level',
        'rule_hits',
        'cc_protection',
        'ip_lists',
        'upstream_health',
        'system_health',
        'conclusions',
      ]) {
        expect(payload.sections[validKey]).toBe(true)
      }
      for (const legacyKey of [
        'security_events',
        'risk_levels',
        'rules',
        'cc',
        'access_control',
        'upstreams',
        'runtime',
        'conclusion',
      ]) {
        expect(payload.sections[legacyKey]).toBeUndefined()
      }
    })
  })
})
