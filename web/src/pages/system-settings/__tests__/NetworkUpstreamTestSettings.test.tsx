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

function networkItem(
  key: string,
  value: string,
  valueType: string,
): SettingItem {
  return {
    id: key,
    setting_group: 'network',
    setting_key: key,
    setting_value: value,
    value_type: valueType,
    is_sensitive: false,
    description: '',
    updated_at: '2026-11-27T00:00:00Z',
    version: 1,
  }
}

const items: SettingItem[] = [
  networkItem('ntp_servers', '', 'string'),
  networkItem('dns_servers', '', 'string'),
  networkItem('upstream_test_allow_private', 'false', 'boolean'),
  networkItem('upstream_test_allowed_private_cidrs', '', 'string'),
]

function jsonOk(body: unknown) {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('SystemSettingsPage · 网络（源站私网测试策略）', () => {
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
          const parsed = JSON.parse(String(init.body)) as {
            setting_key: string
            setting_value: unknown
          }
          return Promise.resolve(
            jsonOk(
              networkItem(
                parsed.setting_key,
                String(parsed.setting_value),
                typeof parsed.setting_value === 'boolean'
                  ? 'boolean'
                  : 'string',
              ),
            ),
          )
        }
        return Promise.resolve(
          jsonOk({ items: group === 'network' ? items : [] }),
        )
      }),
    )
  })

  afterEach(() => vi.unstubAllGlobals())

  it('展示源站私网测试说明并可保存开关与私网 CIDR 白名单', async () => {
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

    fireEvent.click(screen.getByRole('tab', { name: '网络' }))
    const allowKey = await screen.findByText('upstream_test_allow_private')
    expect(
      screen.getByText(/源站连通性测试默认受 SSRF 防护禁止访问私网地址/),
    ).toBeInTheDocument()

    // 1. 开启允许测试私网源站开关并保存
    const allowRow = allowKey.closest('tr')!
    fireEvent.click(within(allowRow).getByRole('switch'))
    const saveAllow = within(allowRow).getByRole('button', { name: /^保\s*存$/ })
    await waitFor(() => expect(saveAllow).toBeEnabled())
    fireEvent.click(saveAllow)
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (args) =>
          args[1]?.method === 'PUT' &&
          String(args[1]?.body).includes('upstream_test_allow_private'),
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toMatchObject({
        setting_group: 'network',
        setting_key: 'upstream_test_allow_private',
        setting_value: true,
        version: 1,
      })
    })

    // 2. 配置私网 CIDR 白名单并保存
    const cidrRow = screen
      .getByText('upstream_test_allowed_private_cidrs')
      .closest('tr')!
    fireEvent.change(within(cidrRow).getByRole('textbox'), {
      target: { value: '172.30.0.0/16' },
    })
    const saveCidr = within(cidrRow).getByRole('button', { name: /^保\s*存$/ })
    await waitFor(() => expect(saveCidr).toBeEnabled())
    fireEvent.click(saveCidr)
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (args) =>
          args[1]?.method === 'PUT' &&
          String(args[1]?.body).includes('upstream_test_allowed_private_cidrs'),
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toMatchObject({
        setting_group: 'network',
        setting_key: 'upstream_test_allowed_private_cidrs',
        setting_value: '172.30.0.0/16',
        version: 1,
      })
    })
  })
})
