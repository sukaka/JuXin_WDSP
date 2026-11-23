import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityEventsPage from '../SecurityEventsPage'
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

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SAMPLE_EVENT = {
  id: '11111111-1111-4111-8111-111111111111',
  request_id: 'req-geo-1',
  occurred_at: '2026-11-20T08:00:00Z',
  application_name_snapshot: '官网',
  domain: 'www.jxdr.cn',
  gateway_node_id: 'gw-1',
  client_ip: '202.96.128.86',
  client_ip_geo: {
    ip: '202.96.128.86',
    scope: 'PUBLIC',
    country_code: 'CN',
    country: '中国',
    province: '广东省',
    city: '广州市',
    isp: '电信',
    label: '中国 广东省 广州市',
  },
  client_port: 54321,
  request_method: 'GET',
  request_uri: '/.git/config',
  request_path: '/.git/config',
  query_summary: '',
  http_version: 'HTTP/1.1',
  content_type: '',
  user_agent_summary: 'curl',
  referer_summary: '',
  attack_type: 'SCANNER',
  severity: 'HIGH',
  anomaly_score: 5,
  action: 'BLOCK',
  response_status: 403,
  rule_match_count: 1,
  disposition_status: 'UNPROCESSED',
  disposition_result: '',
  raw_log_reference: '',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SecurityEventsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function triggerSearch(placeholder: string, value: string) {
  const input = screen.getByPlaceholderText(placeholder)
  fireEvent.change(input, { target: { value } })
  const button = input.closest('.ant-input-search')?.querySelector('.ant-input-search-btn')
  expect(button).toBeTruthy()
  fireEvent.click(button as HTMLElement)
}

describe('SecurityEventsPage 导出与选择导出', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'security_events.export']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/security-events')) {
          return Promise.resolve(jsonResponse({ items: [SAMPLE_EVENT], page: 1, page_size: 20, total: 1 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('导出按钮不再被悬停提示遮挡，且「导出筛选结果」携带完整筛选条件', async () => {
    const openMock = vi.fn()
    vi.stubGlobal('open', openMock)

    renderPage()
    expect(await screen.findByText('www.jxdr.cn')).toBeInTheDocument()

    const exportBtn = screen.getByRole('button', { name: /导\s*出/ })
    fireEvent.mouseEnter(exportBtn)
    expect(screen.queryByText(/仅携带时间范围/)).not.toBeInTheDocument()

    // 填写此前被丢弃的筛选维度（客户端IP、请求路径、请求 ID）
    triggerSearch('客户端IP', '202.96.128.86')
    triggerSearch('请求路径', '/.git/config')
    triggerSearch('请求 ID', 'req-geo-1')

    fireEvent.click(exportBtn)
    fireEvent.click(await screen.findByText('导出筛选结果'))

    expect(openMock).toHaveBeenCalledTimes(1)
    const [url, target] = openMock.mock.calls[0] as [string, string]
    expect(url).toContain('/api/v1/security-events/export?')
    expect(url).toContain('client_ip=202.96.128.86')
    expect(url).toContain('uri=%2F.git%2Fconfig')
    expect(url).toContain('request_id=req-geo-1')
    expect(target).toBe('_blank')
  })

  it('勾选事件后支持「导出已选（仅导出已选 ID）」，未勾选时禁用', async () => {
    const openMock = vi.fn()
    vi.stubGlobal('open', openMock)

    renderPage()
    expect(await screen.findByText('www.jxdr.cn')).toBeInTheDocument()

    // 未勾选时「导出已选」禁用
    const exportBtn = screen.getByRole('button', { name: /导\s*出/ })
    fireEvent.click(exportBtn)
    const disabledItem = await screen.findByText('导出已选（请先勾选）')
    expect(disabledItem.closest('li')).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(disabledItem)
    expect(openMock).not.toHaveBeenCalled()

    // 勾选第一条记录
    const checkboxes = screen.getAllByRole('checkbox')
    // checkboxes[0] 为表头全选，checkboxes[1] 为第一行
    fireEvent.click(checkboxes[1])
    expect(await screen.findByText('已选 1 条')).toBeInTheDocument()

    fireEvent.click(exportBtn)
    fireEvent.click(await screen.findByText('导出已选（1）'))
    expect(openMock).toHaveBeenCalledTimes(1)
    const [url, target] = openMock.mock.calls[0] as [string, string]
    expect(url).toBe(`/api/v1/security-events/export?ids=${SAMPLE_EVENT.id}`)
    expect(target).toBe('_blank')
  })

  it('无 security_events.export 权限时不展示导出按钮与勾选框', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('www.jxdr.cn')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /导\s*出/ })).not.toBeInTheDocument()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
  })

  it('列表展示 IP 归属地与运营商', async () => {
    renderPage()
    expect(await screen.findByText('中国 广东省 广州市')).toBeInTheDocument()
    expect(screen.getByText('电信')).toBeInTheDocument()
  })
})
