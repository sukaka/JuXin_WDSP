import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemAlertsPage from '../SystemAlertsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, SystemAlertItem } from '../../../types'

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const OPEN_ALERT: SystemAlertItem = {
  id: 'alert-open-1',
  alert_type: 'GATEWAY_DOWN',
  severity: 'HIGH',
  component: 'GATEWAY',
  title: '网关节点 gw-1 探活失败',
  message: '连续 3 次探活超时',
  status: 'OPEN',
  first_seen_at: '2026-11-24T01:00:00Z',
  last_seen_at: '2026-11-24T01:05:00Z',
  occurrence_count: 3,
  created_at: '2026-11-24T01:00:00Z',
}

const ACK_ALERT: SystemAlertItem = {
  ...OPEN_ALERT,
  id: 'alert-ack-2',
  title: '数据库连接池接近上限',
  status: 'ACKNOWLEDGED',
  acknowledged_by: 'operadmin',
  acknowledged_at: '2026-11-24T01:10:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <ConfigProvider locale={zhCN}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <SystemAlertsPage />
        </AntdApp>
      </QueryClientProvider>
    </ConfigProvider>,
  )
}

describe('SystemAlertsPage 系统告警权限对齐', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/system-alerts/alert-open-1/resolve') && init?.method === 'POST') {
          return Promise.resolve(jsonResponse({ ...OPEN_ALERT, status: 'RESOLVED' }))
        }
        if (url.includes('/system-alerts/alert-open-1')) {
          return Promise.resolve(jsonResponse({ alert: OPEN_ALERT, notes: [] }))
        }
        if (url.includes('/system-alerts/maintenance-windows')) {
          return Promise.resolve(jsonResponse({ items: [], total: 0 }))
        }
        if (url.includes('/system-alerts')) {
          return Promise.resolve(jsonResponse({ items: [OPEN_ALERT, ACK_ALERT], total: 2, page: 1, page_size: 20 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('运维管理员持有 system_alerts.acknowledge 时具备确认、解决、忽略与添加处置备注完整操作', async () => {
    useAuthStore.setState({
      user: {
        id: 'u-oper',
        username: 'operadmin',
        display_name: '运维管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
        permissions: ['system_alerts.read', 'system_alerts.acknowledge'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: 'csrf-1',
      initialized: true,
    })

    renderPage()

    expect(await screen.findByText('网关节点 gw-1 探活失败')).toBeInTheDocument()
    // OPEN 告警有确认/解决/忽略；ACKNOWLEDGED 告警有解决/忽略
    expect(screen.getAllByRole('button', { name: /确\s*认/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /解\s*决/ })).toHaveLength(2)
    expect(screen.getAllByRole('button', { name: /忽\s*略/ })).toHaveLength(2)

    // 打开详情抽屉可见备注输入框
    fireEvent.click(screen.getAllByRole('button', { name: /详\s*情/ })[0])
    expect(await screen.findByPlaceholderText('添加处置备注')).toBeInTheDocument()
  })

  it('审计管理员仅持有 system_alerts.read_audit 时只读，不显示确认/解决/忽略/添加备注', async () => {
    useAuthStore.setState({
      user: {
        id: 'u-aud',
        username: 'auditor',
        display_name: '审计管理员',
        status: 'ACTIVE',
        roles: [{ code: 'AUDIT_ADMIN', name: '审计管理员' }],
        permissions: ['system_alerts.read_audit'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: 'csrf-1',
      initialized: true,
    })

    renderPage()

    expect(await screen.findByText('网关节点 gw-1 探活失败')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /确\s*认/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /解\s*决/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /忽\s*略/ })).not.toBeInTheDocument()

    fireEvent.click(screen.getAllByRole('button', { name: /详\s*情/ })[0])
    await waitFor(() => {
      expect(screen.getByText('连续 3 次探活超时')).toBeInTheDocument()
    })
    expect(screen.queryByPlaceholderText('添加处置备注')).not.toBeInTheDocument()
  })

  it('列表组件与详情抽屉中文化存量英文风险发现码、小写 waf 组件与确认人用户名', async () => {
    const spikeAlert: SystemAlertItem = {
      id: 'alert-spike-1',
      alert_type: 'API_FINDING_SPIKE',
      severity: 'HIGH',
      component: 'API_SECURITY',
      title: 'API风险发现激增',
      message:
        '最近 60 分钟同类型风险发现超过阈值 20：IDENTITY_COOKIE_PRESENT 219 条；CREDENTIAL_COOKIE_SENSITIVE 219 条；AUTH_CREDENTIAL_CONCURRENCY 129 条 等 4 类',
      status: 'ACKNOWLEDGED',
      first_seen_at: '2026-11-27T06:34:51Z',
      last_seen_at: '2026-11-27T11:18:51Z',
      occurrence_count: 568,
      acknowledged_by: '1f028019-4b1b-4c11-a910-9b59ee4e71ac',
      acknowledged_by_username: 'secadmin',
      acknowledged_at: '2026-11-27T11:18:51Z',
      created_at: '2026-11-27T06:34:51Z',
    }
    const wafAlert: SystemAlertItem = {
      id: 'alert-waf-1',
      alert_type: 'SECURITY_EVENT_SPIKE',
      severity: 'HIGH',
      component: 'waf',
      title: '安全事件激增',
      message: '最近 1 分钟 HIGH/CRITICAL 级安全事件 15 条（阈值 10）',
      status: 'RESOLVED',
      resolve_type: 'RECOVERED',
      first_seen_at: '2026-11-27T06:34:51Z',
      last_seen_at: '2026-11-27T11:18:51Z',
      resolved_at: '2026-11-27T11:19:51Z',
      occurrence_count: 2,
      created_at: '2026-11-27T06:34:51Z',
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/system-alerts/alert-spike-1')) {
          return Promise.resolve(jsonResponse({ alert: spikeAlert, notes: [] }))
        }
        if (url.includes('/system-alerts')) {
          return Promise.resolve(jsonResponse({ items: [spikeAlert, wafAlert], total: 2, page: 1, page_size: 20 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({
      user: {
        id: 'u-oper',
        username: 'secadmin',
        display_name: '运维管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
        permissions: ['system_alerts.read', 'system_alerts.acknowledge'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: 'csrf-1',
      initialized: true,
    })

    renderPage()

    expect(await screen.findByText('WAF 防护')).toBeInTheDocument()
    expect(screen.queryByText(/^waf$/)).not.toBeInTheDocument()

    fireEvent.click(screen.getAllByRole('button', { name: /详\s*情/ })[0])
    await waitFor(() => {
      expect(
        screen.getByText(
          '最近 60 分钟同类型风险发现超过阈值 20：携带 Cookie 会话头 219 条；Cookie 携带敏感凭据 219 条；凭据异常并发使用 129 条 等 4 类',
        ),
      ).toBeInTheDocument()
    })
    expect(screen.queryByText(/IDENTITY_COOKIE_PRESENT/)).not.toBeInTheDocument()
    expect(screen.getByText(/secadmin \//)).toBeInTheDocument()
    expect(screen.queryByText(/1f028019-4b1b-4c11-a910-9b59ee4e71ac/)).not.toBeInTheDocument()
  })
})
