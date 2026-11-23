import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ReportSchedulesPanel from '../ReportSchedulesPanel'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { Mock } from 'vitest'

function response(data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

describe('ReportSchedulesPanel', () => {
  beforeEach(() => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'report-admin',
      display_name: '报表管理员',
      status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      permissions: ['reports.read', 'reports.create'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/report-schedules') && init?.method === 'POST') {
          return Promise.resolve(
            response({ schedule: JSON.parse(String(init.body)) }),
          )
        }
        if (url.includes('/report-schedules/') && init?.method === 'PUT') {
          return Promise.resolve(response({ message: '计划已更新' }))
        }
        if (url.includes('/report-schedules')) {
          return Promise.resolve(
            response({
              items: [
                {
                  id: 'schedule-1',
                  name: '风险周报计划',
                  report_type: 'WEEKLY',
                  api_report_type: 'API_RISK',
                  content_scope: 'API',
                  file_format: 'pdf',
                  page_orientation: 'P',
                  time_of_day: '02:00',
                  day_of_week: 1,
                  day_of_month: 1,
                  send_email: false,
                  enabled: true,
                  created_at: '2026-11-01T00:00:00Z',
                  updated_at: '2026-11-01T00:00:00Z',
                },
                {
                  id: 'schedule-legacy-daily',
                  name: '历史日报计划',
                  report_type: 'DAILY',
                  content_scope: 'WAF_API',
                  file_format: 'html',
                  page_orientation: 'P',
                  time_of_day: '03:00',
                  day_of_week: 0,
                  day_of_month: 0,
                  send_email: false,
                  enabled: true,
                  created_at: '2026-11-01T00:00:00Z',
                  updated_at: '2026-11-01T00:00:00Z',
                },
              ],
              page: 1,
              page_size: 20,
              total: 2,
            }),
          )
        }
        if (
          url.includes('/report-templates') ||
          url.includes('/applications')
        ) {
          return Promise.resolve(
            response({ items: [], page: 1, page_size: 100, total: 0 }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示专项类型并在 API 计划中提交真实专项报告配置', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <ReportSchedulesPanel />
        </AntdApp>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('API 风险周报')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /新建定时计划/ }))
    fireEvent.change(await screen.findByLabelText('计划名称'), {
      target: { value: '资产专项计划' },
    })
    fireEvent.click(screen.getByRole('radio', { name: '仅 API 防护' }))
    const select = await screen.findByLabelText('API 专项报告（可选）')
    fireEvent.mouseDown(select)
    const option = await screen.findByText('API 资产周报', {
      selector: '.ant-select-item-option-content',
    })
    fireEvent.click(option)
    const dialog = await screen.findByRole('dialog')
    const confirmButton = dialog.querySelector(
      '.ant-modal-footer .ant-btn-primary',
    )
    expect(confirmButton).toHaveTextContent('OK')
    fireEvent.click(confirmButton as HTMLElement)
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (entry) => (entry[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String((call![1] as RequestInit).body))).toMatchObject({
        name: '资产专项计划',
        report_type: 'WEEKLY',
        content_scope: 'API',
        api_report_type: 'API_ASSET',
        day_of_week: 1,
        day_of_month: 1,
      })
    })
  })

  it('B10-3：定时计划表单不提供 CUSTOM 选项，仅提供日报/周报/月报', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <ReportSchedulesPanel />
        </AntdApp>
      </QueryClientProvider>,
    )
    await screen.findByText('风险周报计划')
    fireEvent.click(screen.getByRole('button', { name: /新建定时计划/ }))
    await screen.findByRole('dialog')
    expect(screen.getByRole('radio', { name: '日报' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '周报' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '月报' })).toBeInTheDocument()
    expect(screen.queryByRole('radio', { name: '自定义' })).not.toBeInTheDocument()
  })

  it('B10-4：编辑历史 day_of_*=0 记录并切换至月报时自动归一化为合法 1..28 / 1..7 提交', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <ReportSchedulesPanel />
        </AntdApp>
      </QueryClientProvider>,
    )
    await screen.findByText('历史日报计划')
    const editButtons = screen.getAllByRole('button', { name: /^编\s*辑$/ })
    fireEvent.click(editButtons[1])
    await screen.findByRole('dialog')

    fireEvent.click(screen.getByRole('radio', { name: '月报' }))
    const domInput = (await screen.findByLabelText('每月日期（1-28）')) as HTMLInputElement
    expect(domInput.value).toBe('1')

    const dialog = await screen.findByRole('dialog')
    const confirmButton = dialog.querySelector(
      '.ant-modal-footer .ant-btn-primary',
    ) as HTMLElement
    fireEvent.click(confirmButton)

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (entry) => (entry[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String((call![1] as RequestInit).body))).toMatchObject({
        report_type: 'MONTHLY',
        day_of_week: 1,
        day_of_month: 1,
      })
    })
  })
})
