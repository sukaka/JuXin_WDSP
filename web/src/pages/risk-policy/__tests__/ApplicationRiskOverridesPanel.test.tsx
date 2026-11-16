import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApplicationRiskOverridesPanel from '../ApplicationRiskOverridesPanel'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { RiskPolicy } from '../../../api/riskPolicy'

const globalPolicy: RiskPolicy = {
  id: 'global-1',
  scope: 'GLOBAL',
  enabled: true,
  mode: 'OBSERVE',
  version: 3,
  block_threshold: 80,
  rate_limit_threshold: 60,
  rate_limit_rps: 5,
  signal_window_seconds: 86400,
  scores: { RECON: 15 },
  risk_levels: { medium: 20, high: 40, critical: 70 },
  updated_by: 'admin',
  updated_at: '2026-11-01T00:00:00Z',
}

function setPermissions(permissions: string[]) {
  const user: CurrentUser = {
    id: 'u1',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
  useAuthStore.setState({ user, csrfToken: null, initialized: true })
}

function response(data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

describe('ApplicationRiskOverridesPanel', () => {
  let current: RiskPolicy | null

  beforeEach(() => {
    current = null
    setPermissions(['risk_policy.read', 'risk_policy.edit'])
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/api/v1/applications')) {
          return Promise.resolve(
            response({
              items: [{ id: 'app-1', name: '订单系统', code: 'order' }],
              page: 1,
              page_size: 100,
              total: 1,
            }),
          )
        }
        if (url.includes('/security/risk-policy/applications/app-1')) {
          if (init?.method === 'PUT') {
            const body = JSON.parse(String(init.body))
            current = {
              ...globalPolicy,
              ...body,
              id: 'override-1',
              application_id: 'app-1',
              version: body.version + 1,
              updated_at: '2026-11-15T04:00:00Z',
            }
            return Promise.resolve(response({ policy: current }))
          }
          if (init?.method === 'DELETE') {
            current = null
            return Promise.resolve(response({ message: 'deleted' }))
          }
          return Promise.resolve(response({ policy: current }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function renderPanel() {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <ApplicationRiskOverridesPanel globalPolicy={globalPolicy} />
        </AntdApp>
      </QueryClientProvider>,
    )
  }

  async function selectApplication() {
    const select = screen.getByRole('combobox', {
      name: '选择需要配置风险覆盖的应用',
    })
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByText('订单系统（order）'))
    await screen.findByText('当前应用未配置覆盖，将继承全局策略')
  }

  it('创建应用覆盖：从全局值初始化并携带 version=0', async () => {
    renderPanel()
    await selectApplication()
    fireEvent.click(screen.getByRole('button', { name: '新建应用覆盖' }))
    const drawer = await screen.findByRole('dialog')
    const threshold = (await within(drawer).findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    expect(threshold.value).toBe('80')
    fireEvent.change(threshold, { target: { value: '90' } })
    const sharedLimit = (await within(drawer).findByLabelText(
      '同设备账号观察阈值',
    )) as HTMLInputElement
    expect(sharedLimit.value).toBe('0')
    fireEvent.change(sharedLimit, { target: { value: '4' } })
    fireEvent.click(
      within(drawer).getByRole('button', { name: '保存应用覆盖' }),
    )
    expect(
      await screen.findByText('应用风险覆盖已保存，发布结果以发布任务为准'),
    ).toBeInTheDocument()
    const call = vi
      .mocked(fetch)
      .mock.calls.find(
        (entry) => (entry[1] as RequestInit | undefined)?.method === 'PUT',
      )
    expect(call).toBeTruthy()
    const body = JSON.parse(String((call![1] as RequestInit).body))
    expect(body).toMatchObject({
      scope: 'APPLICATION',
      version: 0,
      mode: 'OBSERVE',
      block_threshold: 90,
      shared_device_account_limit: 4,
      scores: { RECON: 15 },
      risk_levels: { medium: 20, high: 40, critical: 70 },
    })
    expect(body.application_id).toBeUndefined()
  })

  it('编辑与删除均使用当前版本，删除后恢复继承提示', async () => {
    current = {
      ...globalPolicy,
      id: 'override-1',
      application_id: 'app-1',
      scope: 'APPLICATION',
      version: 4,
    }
    renderPanel()
    const select = screen.getByRole('combobox', {
      name: '选择需要配置风险覆盖的应用',
    })
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByText('订单系统（order）'))
    fireEvent.click(await screen.findByRole('button', { name: '编辑应用覆盖' }))
    const drawer = await screen.findByRole('dialog')
    expect(
      (
        (await within(drawer).findByLabelText(
          '阻断阈值（1-100）',
        )) as HTMLInputElement
      ).value,
    ).toBe('80')
    fireEvent.click(
      within(drawer).getByRole('button', { name: '保存应用覆盖' }),
    )
    await waitFor(() => {
      const call = vi
        .mocked(fetch)
        .mock.calls.find(
          (entry) => (entry[1] as RequestInit | undefined)?.method === 'PUT',
        )
      expect(JSON.parse(String((call![1] as RequestInit).body)).version).toBe(4)
    })
    fireEvent.click(
      await screen.findByRole('button', { name: '删除覆盖并继承全局' }),
    )
    const confirm = await screen.findByRole('tooltip')
    fireEvent.click(within(confirm).getByRole('button', { name: /确\s*定|OK/ }))
    await waitFor(() => {
      const call = vi
        .mocked(fetch)
        .mock.calls.find(
          (entry) => (entry[1] as RequestInit | undefined)?.method === 'DELETE',
        )
      expect(String(call?.[0])).toContain('version=5')
    })
    expect(
      await screen.findByText('当前应用未配置覆盖，将继承全局策略'),
    ).toBeInTheDocument()
  })

  it('无编辑权限时不展示写入入口', async () => {
    setPermissions(['risk_policy.read'])
    renderPanel()
    await selectApplication()
    expect(
      screen.queryByRole('button', { name: '新建应用覆盖' }),
    ).not.toBeInTheDocument()
    const writes = vi
      .mocked(fetch)
      .mock.calls.filter((entry) =>
        ['PUT', 'DELETE'].includes(
          (entry[1] as RequestInit | undefined)?.method ?? '',
        ),
      )
    expect(writes).toHaveLength(0)
  })

  it('同设备账号阈值为 1 时拒绝提交', async () => {
    renderPanel()
    await selectApplication()
    fireEvent.click(screen.getByRole('button', { name: '新建应用覆盖' }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(
      await within(drawer).findByLabelText('同设备账号观察阈值'),
      { target: { value: '1' } },
    )
    fireEvent.click(
      within(drawer).getByRole('button', { name: '保存应用覆盖' }),
    )
    expect(
      await screen.findByText('0 表示默认 3；自定义账号数至少为 2'),
    ).toBeInTheDocument()
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(
          (entry) => (entry[1] as RequestInit | undefined)?.method === 'PUT',
        ),
    ).toBe(false)
  })
})
