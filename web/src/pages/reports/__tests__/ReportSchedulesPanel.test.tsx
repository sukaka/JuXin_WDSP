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
              ],
              page: 1,
              page_size: 20,
              total: 1,
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
      })
    })
  })
})
