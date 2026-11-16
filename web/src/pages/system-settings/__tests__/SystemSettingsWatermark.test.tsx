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

const GROUP = 'gateway_runtime'
const ENABLED_KEY = 'api_file_watermark_enabled'
const INLINE_HTML_KEY = 'api_file_watermark_include_inline_html'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'test-user',
    username: 'settings-tester',
    display_name: '设置测试员',
    status: 'ACTIVE',
    roles: [],
    permissions,
    must_change_password: false,
  }
}

function makeItem(
  settingKey: string,
  settingValue: string,
  valueType = 'string',
): SettingItem {
  return {
    id: `test-${settingKey}`,
    setting_group: GROUP,
    setting_key: settingKey,
    setting_value: settingValue,
    value_type: valueType,
    is_sensitive: false,
    description: `测试设置 ${settingKey}`,
    updated_at: '2026-11-15T00:00:00Z',
    version: 1,
  }
}

function watermarkItems({
  template = 'trace ip={ip} identity={identity}',
  contentTypes = 'application/json',
}: { template?: string; contentTypes?: string } = {}): SettingItem[] {
  return [
    makeItem(ENABLED_KEY, 'false', 'boolean'),
    makeItem('api_file_watermark_template', template),
    makeItem('api_file_watermark_content_types', contentTypes),
    makeItem('api_file_watermark_json_key', '_test_wm'),
    makeItem(INLINE_HTML_KEY, 'false', 'boolean'),
  ]
}

function jsonResponse(body: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function mockFetch(getItems: () => SettingItem[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.includes('/system-settings') && init?.method === 'PUT') {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      const current = getItems().find(
        (item) => item.setting_key === body.setting_key,
      )!
      return Promise.resolve(
        jsonResponse({
          ...current,
          setting_value: String(body.setting_value),
          version: current.version + 1,
        }),
      )
    }
    if (url.includes('/system-settings')) {
      const group = new URL(url, 'http://localhost').searchParams.get('group')
      return Promise.resolve(
        jsonResponse({ items: group === GROUP ? getItems() : [] }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function findPutCall() {
  return (fetch as Mock).mock.calls.find(
    (call) =>
      String(call[0]).includes('/system-settings') && call[1]?.method === 'PUT',
  )
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <SystemSettingsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

async function openWatermarkRow(settingKey: string): Promise<HTMLElement> {
  fireEvent.click(screen.getByRole('tab', { name: '文件与水印' }))
  const keyCell = await screen.findByText(settingKey)
  return keyCell.closest('tr')!
}

async function enableSwitchAndSave(row: HTMLElement) {
  fireEvent.click(within(row).getByRole('switch'))
  const save = within(row).getByRole('button', { name: /^保\s*存$/ })
  await waitFor(() => expect(save).toBeEnabled())
  fireEvent.click(save)
}

describe('SystemSettingsPage · 文件与水印', () => {
  let items: SettingItem[]

  beforeEach(() => {
    items = watermarkItems()
    useAuthStore.setState({
      user: makeUser(['system_settings.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      mockFetch(() => items),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('总开关与内联 HTML 开关按默认 false 渲染为关闭', async () => {
    renderPage()
    const enabledRow = await openWatermarkRow(ENABLED_KEY)
    expect(within(enabledRow).getByRole('switch')).not.toBeChecked()
    const inlineRow = screen.getByText(INLINE_HTML_KEY).closest('tr')!
    expect(within(inlineRow).getByRole('switch')).not.toBeChecked()
  })

  it('文件与水印列表不显示非 api_file_watermark_ 前缀的设置键', async () => {
    items = [
      ...watermarkItems(),
      makeItem('api_runtime_test_worker_count', '2', 'integer'),
    ]
    renderPage()
    await openWatermarkRow(ENABLED_KEY)

    expect(screen.getByText('api_file_watermark_json_key')).toBeInTheDocument()
    expect(
      screen.queryByText('api_runtime_test_worker_count'),
    ).not.toBeInTheDocument()
  })

  it('Content-Type 缺少 text/html 时开启内联 HTML 不发 PUT', async () => {
    items = watermarkItems({ contentTypes: 'application/json, text/plain' })
    renderPage()
    const row = await openWatermarkRow(INLINE_HTML_KEY)
    await enableSwitchAndSave(row)

    expect(
      await screen.findByText(
        '内联 HTML 需将 text/html 加入 Content-Type 白名单',
      ),
    ).toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })

  it('水印模板为空时启用总开关不发 PUT', async () => {
    items = watermarkItems({ template: '   ' })
    renderPage()
    const row = await openWatermarkRow(ENABLED_KEY)
    await enableSwitchAndSave(row)

    expect(
      await screen.findByText('启用水印前请先填写水印模板'),
    ).toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })

  it('模板有效时启用总开关并提交原生 boolean', async () => {
    renderPage()
    const row = await openWatermarkRow(ENABLED_KEY)
    await enableSwitchAndSave(row)

    await waitFor(() => expect(findPutCall()).toBeTruthy())
    const body = JSON.parse(String(findPutCall()![1]?.body)) as Record<
      string,
      unknown
    >
    expect(body).toEqual({
      setting_group: GROUP,
      setting_key: ENABLED_KEY,
      setting_value: true,
      version: 1,
    })
    expect(typeof body.setting_value).toBe('boolean')
  })

  it('只有读取权限时不显示行内保存按钮或编辑控件', async () => {
    useAuthStore.setState({
      user: makeUser(['system_settings.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    const row = await openWatermarkRow(ENABLED_KEY)

    expect(within(row).queryByRole('switch')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /^保\s*存$/ }),
    ).not.toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })
})
