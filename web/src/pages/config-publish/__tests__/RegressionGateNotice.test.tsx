import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RegressionGateNotice, { RegressionGateFailureDetail } from '../RegressionGateNotice'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, PublishTaskItem } from '../../../types'

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

function makePolicy(mode: string) {
  return {
    mode,
    required_level: 'FULL',
    required_corpus_id: '',
    evidence_max_age_seconds: 604800,
    version: 3,
    updated_by: 'secops',
    updated_at: '2026-09-07T00:00:00Z',
  }
}

function mockPolicyFetch(policy: unknown) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/security/regression-policy')) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { policy } }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderWithProviders(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>{node}</AntdApp>
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

function makeTask(over: Partial<PublishTaskItem> = {}): PublishTaskItem {
  return {
    id: 'task-1',
    task_type: 'PUBLISH',
    status: 'FAILED',
    requested_at: '2026-09-08T02:00:00Z',
    current_step: 'REGRESSION_GATE',
    progress: 40,
    result_summary: '',
    failure_code: 'REGRESSION_GATE_REJECTED',
    failure_message:
      '缺少绑定候选指纹 cfgfpv1:abcdef1234567890 且核验通过的 FULL 级回归证据',
    request_id: 'req-1',
    ...over,
  }
}

describe('RegressionGateNotice', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('无 security_regression.read 权限时不渲染也不发起请求', () => {
    grant(['config_publish.read'])
    const fetchMock = mockPolicyFetch(makePolicy('ENFORCE'))
    vi.stubGlobal('fetch', fetchMock)
    const { container } = renderWithProviders(<RegressionGateNotice />)
    expect(container.querySelector('.ant-alert')).toBeNull()
    expect(container.textContent).toBe('')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('OFF 默认关闭态不渲染提示条', async () => {
    grant(['security_regression.read'])
    const fetchMock = mockPolicyFetch(makePolicy('OFF'))
    vi.stubGlobal('fetch', fetchMock)
    const { container } = renderWithProviders(<RegressionGateNotice style={{ marginBottom: 12 }} />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(container.querySelector('.ant-alert')).toBeNull()
    expect(container.textContent).toBe('')
  })

  it('OBSERVE/ENFORCE 启用态如实展示并给出安全回归入口', async () => {
    grant(['security_regression.read'])
    const cases: Array<[string, RegExp]> = [
      ['OBSERVE', /回归门禁观察中：发布时计算并记录门禁结论，但不阻断不合规发布/],
      ['ENFORCE', /回归门禁强制中：缺少绑定当前候选指纹且核验通过的回归证据时，发布将被拒绝/],
    ]
    for (const [mode, pattern] of cases) {
      vi.stubGlobal('fetch', mockPolicyFetch(makePolicy(mode)))
      const { unmount } = renderWithProviders(<RegressionGateNotice />)
      expect(await screen.findByText(pattern)).toBeTruthy()
      expect(screen.getByText('查看安全回归').closest('a')).toHaveAttribute(
        'href',
        '/security-regressions',
      )
      unmount()
      vi.unstubAllGlobals()
    }
  })

  it('策略加载失败如实提示，不静默吞错', async () => {
    grant(['security_regression.read'])
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(500, { code: 'INTERNAL_ERROR', message: 'db down', data: null }),
        ),
      ),
    )
    renderWithProviders(<RegressionGateNotice />)
    expect(await screen.findByText('回归门禁策略状态加载失败')).toBeTruthy()
  })
})

describe('RegressionGateFailureDetail', () => {
  it('REGRESSION_GATE_REJECTED：列出确切缺失项并提供按候选指纹过滤的深链', () => {
    grant(['security_regression.read'])
    renderWithProviders(<RegressionGateFailureDetail task={makeTask()} />)
    expect(screen.getByText(/确切缺失项：缺少绑定候选指纹/)).toBeTruthy()
    const link = screen.getByText(/前往安全回归（按候选指纹过滤）/).closest('a')
    expect(link).toHaveAttribute(
      'href',
      '/security-regressions?fingerprint=cfgfpv1%3Aabcdef1234567890',
    )
  })

  it('REGRESSION_GATE_UNAVAILABLE：附加依赖不可用说明，未静默放行', () => {
    grant(['security_regression.read'])
    renderWithProviders(
      <RegressionGateFailureDetail
        task={makeTask({
          failure_code: 'REGRESSION_GATE_UNAVAILABLE',
          failure_message: '回归证据存储不可用',
        })}
      />,
    )
    expect(screen.getByText(/确切缺失项：回归证据存储不可用/)).toBeTruthy()
    expect(screen.getByText(/门禁依赖不可用：请先恢复依赖/)).toBeTruthy()
  })

  it('非门禁失败码不渲染；无 read 权限不渲染跳转链接', () => {
    grant(['security_regression.read'])
    const { container, unmount } = renderWithProviders(
      <RegressionGateFailureDetail
        task={makeTask({ failure_code: 'BACKEND_UNREACHABLE', failure_message: 'x' })}
      />,
    )
    expect(container.textContent).toBe('')
    unmount()

    grant(['config_publish.read'])
    renderWithProviders(<RegressionGateFailureDetail task={makeTask()} />)
    // 缺失项明细仍展示（发布结果本身可见），但跳转回归证据域需 read 权限
    expect(screen.getByText(/确切缺失项/)).toBeTruthy()
    expect(screen.queryByText(/前往安全回归/)).toBeNull()
  })
})
