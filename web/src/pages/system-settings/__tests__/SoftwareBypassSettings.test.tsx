import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { App as AntdApp } from 'antd'
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import SystemSettingsPage from '../SystemSettingsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, SettingItem } from '../../../types'

const items: SettingItem[] = [
  item('enabled', 'false', 'boolean'),
  item('cpu_threshold_percent', '80', 'integer'),
  item('memory_threshold_percent', '80', 'integer'),
  item('min_hold_seconds', '10', 'integer'),
  item('session_cookie_names', 'JSESSIONID,PHPSESSID', 'string'),
]

function item(key: string, value: string, valueType: string): SettingItem {
  return {
    id: key,
    setting_group: 'software_bypass',
    setting_key: key,
    setting_value: value,
    value_type: valueType,
    is_sensitive: false,
    description: '',
    updated_at: '2026-11-06T00:00:00Z',
    version: 1,
  }
}

function response(body: unknown) {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

describe('SystemSettingsPage · 软件旁路', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'ops',
        display_name: '运维',
        status: 'ACTIVE',
        roles: [],
        permissions: ['system_settings.update'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const group = new URL(
          String(input),
          'http://localhost',
        ).searchParams.get('group')
        if (init?.method === 'PUT') {
          return Promise.resolve(
            response(item('cpu_threshold_percent', '90', 'integer')),
          )
        }
        return Promise.resolve(
          response({ items: group === 'software_bypass' ? items : [] }),
        )
      }),
    )
  })

  afterEach(() => vi.unstubAllGlobals())

  it('展示阈值与透传风险提示，并按整数保存 CPU 阈值', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <SystemSettingsPage />
        </AntdApp>
      </QueryClientProvider>,
    )
    fireEvent.click(screen.getByRole('tab', { name: '软件旁路' }))
    const key = await screen.findByText('cpu_threshold_percent')
    const row = key.closest('tr')!
    expect(within(row).getByRole('spinbutton')).toHaveValue('80')
    expect(
      screen.getByText(/任一资源超过阈值后，新请求将跳过全部检测与防护/),
    ).toBeInTheDocument()
    fireEvent.change(within(row).getByRole('spinbutton'), {
      target: { value: '90' },
    })
    const save = within(row).getByRole('button', { name: /^保\s*存$/ })
    await waitFor(() => expect(save).toBeEnabled())
    fireEvent.click(save)
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (args) => args[1]?.method === 'PUT',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toMatchObject({
        setting_group: 'software_bypass',
        setting_key: 'cpu_threshold_percent',
        setting_value: 90,
        version: 1,
      })
    })
  })
})
