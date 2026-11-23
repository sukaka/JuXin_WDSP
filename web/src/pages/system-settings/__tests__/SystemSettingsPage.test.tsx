import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemSettingsPage from '../SystemSettingsPage'
import { useAuthStore } from '../../../stores/auth'
import type { ApmSettings, CurrentUser, SettingItem } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: 'OPS_ADMIN', name: '运维管理员' }],
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

function makeItem(partial: Partial<SettingItem> & { id: string; setting_key: string }): SettingItem {
  return {
    setting_group: 'logging',
    setting_value: 'true',
    value_type: 'boolean',
    is_sensitive: false,
    description: '',
    updated_at: '2026-08-01T00:00:00Z',
    version: 1,
    ...partial,
  }
}

function loggingItems(address = '192.168.1.10:514'): SettingItem[] {
  return [
    makeItem({ id: 's1', setting_key: 'syslog_enabled' }),
    makeItem({ id: 's2', setting_key: 'syslog_protocol', setting_value: 'udp', value_type: 'string' }),
    makeItem({ id: 's3', setting_key: 'syslog_address', setting_value: address, value_type: 'string', version: 2 }),
    makeItem({ id: 's4', setting_key: 'syslog_forward_security_events' }),
    makeItem({ id: 's5', setting_key: 'syslog_forward_access_control_events' }),
    makeItem({ id: 's6', setting_key: 'syslog_forward_access_logs', setting_value: 'false' }),
    makeItem({ id: 's7', setting_key: 'syslog_forward_operation_audits' }),
    makeItem({ id: 's8', setting_key: 'syslog_forward_login_logs' }),
    makeItem({ id: 's9', setting_key: 'syslog_forward_system_alerts', setting_value: 'false' }),
  ]
}

function mockFetch(items: SettingItem[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/system-settings') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      const item = items.find((i) => i.setting_key === body.setting_key)!
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { ...item, setting_value: body.setting_value, version: item.version + 1 },
        }),
      )
    }
    if (url.includes('/system-settings')) {
      // 按 group 过滤：非 logging 分组返回空列表，避免默认「密码策略」页签渲染相同数据造成重复行
      const group = new URL(url, 'http://localhost').searchParams.get('group')
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: group === 'logging' ? items : [] },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SystemSettingsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 切到「日志记录」页签并等待 syslog_address 行加载完成，返回该行 */
async function openLoggingTab(): Promise<HTMLElement> {
  fireEvent.click(screen.getByRole('tab', { name: '日志记录' }))
  const keyCell = await screen.findByText('syslog_address')
  return keyCell.closest('tr')!
}

function findPutCall() {
  return (fetch as Mock).mock.calls.find(
    (c) => String(c[0]).includes('/system-settings') && c[1]?.method === 'PUT',
  )
}

/** 等待行内保存按钮因草稿变更而启用后点击（InputNumber onChange 为异步，直接点击可能落在禁用态上） */
async function clickSaveWhenEnabled(row: HTMLElement) {
  const btn = within(row).getByRole('button', { name: /^保\s*存$/ })
  await waitFor(() => expect(btn).toBeEnabled())
  fireEvent.click(btn)
}

/** 等待 PUT 发出后解析其请求体（断言在 waitFor 外执行，避免重试吞掉真实差异） */
async function waitForPutBody(): Promise<Record<string, unknown>> {
  await waitFor(() => expect(findPutCall()).toBeTruthy())
  return JSON.parse(String(findPutCall()![1]?.body)) as Record<string, unknown>
}

/** 切到「API 学习」页签并等待指定设置行加载完成，返回该行 */
async function openApiLearningRow(settingKey: string): Promise<HTMLElement> {
  fireEvent.click(screen.getByRole('tab', { name: 'API 学习' }))
  const keyCell = await screen.findByText(settingKey)
  return keyCell.closest('tr')!
}

function apiLearningItems(): SettingItem[] {
  return [
    makeItem({
      id: 'l1',
      setting_group: 'api_learning',
      setting_key: 'min_valid_samples',
      setting_value: '10',
      value_type: 'string',
    }),
    makeItem({
      id: 'l2',
      setting_group: 'api_learning',
      setting_key: 'minimum_success_ratio',
      setting_value: '0',
      value_type: 'string',
    }),
  ]
}

function mockApiLearningFetch(items: SettingItem[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/system-settings') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      const item = items.find((i) => i.setting_key === body.setting_key)!
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { ...item, setting_value: body.setting_value, version: item.version + 1 },
        }),
      )
    }
    if (url.includes('/system-settings')) {
      const group = new URL(url, 'http://localhost').searchParams.get('group')
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: group === 'api_learning' ? items : [] },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

describe('SystemSettingsPage · api_learning 分组学习达标条件', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockApiLearningFetch(apiLearningItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('字符串型数值设置渲染为数值输入框，并展示中文说明与提示条', async () => {
    renderPage()
    const row = await openApiLearningRow('min_valid_samples')
    expect(within(row).getByRole('spinbutton')).toHaveValue('10')
    const desc = within(row).getByText(
      '学习达标条件：有效样本数全局下限，与每个任务的样本目标取较大者',
    )
    // 中文说明在上（黑色加粗），键名 code 在下
    expect(desc).toHaveStyle({ fontWeight: 500 })
    const keyCode = within(row).getByText('min_valid_samples')
    expect(desc.compareDocumentPosition(keyCode) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByText(/全部满足才判定采样完成/)).toBeInTheDocument()
  })

  it('修改有效样本数下限后按字符串数值提交', async () => {
    renderPage()
    const row = await openApiLearningRow('min_valid_samples')
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '50' } })
    await clickSaveWhenEnabled(row)

    const body = await waitForPutBody()
    expect(body.setting_group).toBe('api_learning')
    expect(body.setting_key).toBe('min_valid_samples')
    expect(body.setting_value).toBe('50')
    expect(body.version).toBe(1)
  })

  it('清空数值：提示校验错误且不提交', async () => {
    renderPage()
    const row = await openApiLearningRow('min_valid_samples')
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '' } })
    await clickSaveWhenEnabled(row)

    expect(await screen.findByText('请输入数值')).toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })

  it('成功率输入超出 0~1：数值输入框拦截越界值，不提交', async () => {
    renderPage()
    const row = await openApiLearningRow('minimum_success_ratio')
    // antd InputNumber 带 min/max 时越界输入不触发 onChange，草稿不变、保存按钮保持禁用
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '2' } })
    expect(within(row).getByRole('button', { name: /^保\s*存$/ })).toBeDisabled()
    expect(findPutCall()).toBeUndefined()
  })
})

describe('SystemSettingsPage · logging 分组 syslog 配置', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch(loggingItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.update', 'logging.syslog_test']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('syslog_address 拆分为服务器地址与端口，保存时组合为 host:port 提交', async () => {
    renderPage()
    const row = await openLoggingTab()
    const hostInput = within(row).getByPlaceholderText('IPv4/IPv6 或域名')
    expect(hostInput).toHaveValue('192.168.1.10')
    expect(within(row).getByRole('spinbutton')).toHaveValue('514')

    fireEvent.change(hostInput, { target: { value: 'log.example.com' } })
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '1514' } })
    await clickSaveWhenEnabled(row)

    const body = await waitForPutBody()
    expect(body.setting_group).toBe('logging')
    expect(body.setting_key).toBe('syslog_address')
    expect(body.setting_value).toBe('log.example.com:1514')
    expect(body.version).toBe(2)
  })

  it('IPv6 地址 [2001:db8::1]:5514 拆分渲染，保存时组合为 [host]:port', async () => {
    vi.stubGlobal('fetch', mockFetch(loggingItems('[2001:db8::1]:5514')))
    renderPage()
    const row = await openLoggingTab()
    const hostInput = within(row).getByPlaceholderText('IPv4/IPv6 或域名')
    expect(hostInput).toHaveValue('2001:db8::1')
    expect(within(row).getByRole('spinbutton')).toHaveValue('5514')

    fireEvent.change(hostInput, { target: { value: '2001:db8::2' } })
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '5515' } })
    await clickSaveWhenEnabled(row)

    const body = await waitForPutBody()
    expect(body.setting_key).toBe('syslog_address')
    expect(body.setting_value).toBe('[2001:db8::2]:5515')
  })

  it('服务器地址非法（含协议/路径）：提示校验错误且不提交', async () => {
    renderPage()
    const row = await openLoggingTab()
    fireEvent.change(within(row).getByPlaceholderText('IPv4/IPv6 或域名'), {
      target: { value: 'http://evil.example.com/x' },
    })
    await clickSaveWhenEnabled(row)

    expect(await screen.findByText('服务器地址不能包含协议或路径')).toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })

  it('端口为空：提示校验错误且不提交', async () => {
    renderPage()
    const row = await openLoggingTab()
    fireEvent.change(within(row).getByRole('spinbutton'), { target: { value: '' } })
    await clickSaveWhenEnabled(row)

    expect(await screen.findByText('端口必须为 1-65535 的整数')).toBeInTheDocument()
    expect(findPutCall()).toBeUndefined()
  })

  it('渲染 3 个新增外发开关（操作审计 / 登录日志 / 系统告警）', async () => {
    renderPage()
    await openLoggingTab()
    const expected: [string, string][] = [
      ['syslog_forward_operation_audits', '外发操作审计到 syslog'],
      ['syslog_forward_login_logs', '外发登录日志到 syslog'],
      ['syslog_forward_system_alerts', '外发系统告警到 syslog'],
    ]
    for (const [key, desc] of expected) {
      const row = screen.getByText(key).closest('tr')!
      expect(within(row).getByText(desc)).toBeInTheDocument()
      expect(within(row).getByRole('switch')).toBeInTheDocument()
    }
  })

  it('只读权限渲染布尔值为「已开启/已关闭」、枚举值为选项中文/标签，并展示日志设施号中文说明', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch([
        ...loggingItems(),
        makeItem({
          id: 's10',
          setting_key: 'syslog_facility',
          setting_value: '1',
          value_type: 'integer',
        }),
      ]),
    )
    useAuthStore.setState({
      user: makeUser(['system_settings.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openLoggingTab()

    const enabledRow = screen.getByText('syslog_enabled').closest('tr')!
    expect(within(enabledRow).getByText('已开启')).toBeInTheDocument()
    expect(within(enabledRow).queryByText('true')).not.toBeInTheDocument()

    const disabledRow = screen.getByText('syslog_forward_access_logs').closest('tr')!
    expect(within(disabledRow).getByText('已关闭')).toBeInTheDocument()
    expect(within(disabledRow).queryByText('false')).not.toBeInTheDocument()

    const protoRow = screen.getByText('syslog_protocol').closest('tr')!
    expect(within(protoRow).getByText('UDP')).toBeInTheDocument()

    const facilityRow = screen.getByText('syslog_facility').closest('tr')!
    expect(within(facilityRow).getByText('RFC5424 日志设施号，默认 1（用户级）')).toBeInTheDocument()
  })
})

function makeApmSettings(partial: Partial<ApmSettings> = {}): ApmSettings {
  return {
    enabled: false,
    enabled_source: 'env',
    clickhouse_dsn_set: true,
    clickhouse_dsn_source: 'ui',
    ch_connected: true,
    ...partial,
  }
}

function mockApmFetch(settings: ApmSettings) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/apm/settings') && method === 'PUT') {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: {} }))
    }
    if (url.includes('/apm/settings')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: settings }))
    }
    if (url.includes('/system-settings')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [] } }))
    }
    // 保存成功后面板会调用 useProductStore.load() 刷新 apm_enabled 门控
    if (url.includes('/product/edition')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { edition: 'waf', api_dynamic_protection: false, apm_enabled: true },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function findApmPutCall() {
  return (fetch as Mock).mock.calls.find(
    (c) => String(c[0]).includes('/apm/settings') && c[1]?.method === 'PUT',
  )
}

async function waitForApmPutBody(): Promise<Record<string, unknown>> {
  await waitFor(() => expect(findApmPutCall()).toBeTruthy())
  return JSON.parse(String(findApmPutCall()![1]?.body)) as Record<string, unknown>
}

/** 切到「APM 性能监控」页签并等待设置加载完成 */
async function openApmTab() {
  fireEvent.click(screen.getByRole('tab', { name: 'APM 性能监控' }))
  await screen.findByText('启用 APM 业务性能监控')
}

describe('SystemSettingsPage · APM 性能监控', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockApmFetch(makeApmSettings()))
    useAuthStore.setState({
      user: makeUser(['system_settings.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染开关、DSN 输入框与来源/连接状态标签', async () => {
    renderPage()
    await openApmTab()

    expect(screen.getByRole('switch')).not.toBeChecked()
    // clickhouse_dsn_set=true 时 placeholder 提示留空保持不变，且不回显 DSN 原文
    expect(screen.getByPlaceholderText('已配置（留空保持不变）')).toHaveValue('')
    expect(screen.getByText(/界面设置优先于 \.env 环境变量/)).toBeInTheDocument()
    // 总开关来源 env=环境变量，连接串来源 ui=界面设置，ch_connected=true=已连接
    expect(screen.getByText('环境变量')).toBeInTheDocument()
    expect(screen.getByText('界面设置')).toBeInTheDocument()
    expect(screen.getByText('已连接')).toBeInTheDocument()
  })

  it('无 system_settings.read 权限时不展示 APM 页签', () => {
    useAuthStore.setState({
      user: makeUser(['system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(screen.queryByRole('tab', { name: 'APM 性能监控' })).not.toBeInTheDocument()
  })

  it('切换开关后提交 {enabled: true}，且 DSN 留空时请求体不含 clickhouse_dsn', async () => {
    renderPage()
    await openApmTab()

    fireEvent.click(screen.getByRole('switch'))
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    const body = await waitForApmPutBody()
    expect(body.enabled).toBe(true)
    expect('clickhouse_dsn' in body).toBe(false)
  })

  it('填写 DSN 后提交携带 clickhouse_dsn', async () => {
    renderPage()
    await openApmTab()

    fireEvent.change(screen.getByPlaceholderText('已配置（留空保持不变）'), {
      target: { value: 'clickhouse://apm_writer:secret@10.0.0.8:9000/apm' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    const body = await waitForApmPutBody()
    expect(body.clickhouse_dsn).toBe('clickhouse://apm_writer:secret@10.0.0.8:9000/apm')
    expect('enabled' in body).toBe(false)
  })

  it('显式清空已配置 DSN：Popconfirm 确认后提交空串回退环境变量', async () => {
    renderPage()
    await openApmTab()

    const input = screen.getByPlaceholderText('已配置（留空保持不变）')
    fireEvent.change(input, { target: { value: 'clickhouse://x@h:9000/apm' } })
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    // 二次确认：清除后回退环境变量
    expect(await screen.findByText('清除后将回退到环境变量 APM_CLICKHOUSE_DSN')).toBeInTheDocument()
    expect(findApmPutCall()).toBeUndefined()
    fireEvent.click(screen.getByRole('button', { name: /^清\s*除$/ }))

    const body = await waitForApmPutBody()
    expect(body.clickhouse_dsn).toBe('')
  })
})

// 阶段5 §5.1：block_response 分组（自定义 429/阻断响应页面）
function blockResponseItems(): SettingItem[] {
  return [
    makeItem({ id: 'b1', setting_group: 'block_response', setting_key: 'html_title', setting_value: '', value_type: 'string' }),
    makeItem({ id: 'b2', setting_group: 'block_response', setting_key: 'html_body', setting_value: '', value_type: 'string' }),
    makeItem({ id: 'b3', setting_group: 'block_response', setting_key: 'json_code', setting_value: '', value_type: 'string' }),
    makeItem({ id: 'b4', setting_group: 'block_response', setting_key: 'json_message', setting_value: '', value_type: 'string' }),
  ]
}

function mockBlockResponseFetch(items: SettingItem[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/system-settings') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      const item = items.find((i) => i.setting_key === body.setting_key)!
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { ...item, setting_value: body.setting_value, version: item.version + 1 },
        }),
      )
    }
    if (url.includes('/system-settings')) {
      const group = new URL(url, 'http://localhost').searchParams.get('group')
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: group === 'block_response' ? items : [] },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

describe('SystemSettingsPage · block_response 分组自定义阻断响应页面', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockBlockResponseFetch(blockResponseItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  async function openBlockResponseRow(settingKey: string): Promise<HTMLElement> {
    fireEvent.click(screen.getByRole('tab', { name: '阻断响应页面' }))
    const keyCell = await screen.findByText(settingKey)
    return keyCell.closest('tr')!
  }

  it('页签渲染四个设置项与提示条，正文使用多行输入框', async () => {
    renderPage()
    const bodyRow = await openBlockResponseRow('html_body')
    // html_body 为多行输入（TextArea 带长度上限），其余为单行输入
    expect(within(bodyRow).getByRole('textbox').tagName).toBe('TEXTAREA')
    expect(within(bodyRow).getByRole('textbox')).toHaveAttribute('maxlength', '4096')
    const titleRow = (await screen.findByText('html_title')).closest('tr')!
    expect(within(titleRow).getByRole('textbox').tagName).toBe('INPUT')
    expect(screen.getByText(/发布才下发网关生效/)).toBeInTheDocument()
  })

  it('编辑正文后按原分组与键提交', async () => {
    renderPage()
    const row = await openBlockResponseRow('html_body')
    fireEvent.change(within(row).getByRole('textbox'), {
      target: { value: '<p>系统繁忙</p>' },
    })
    await clickSaveWhenEnabled(row)

    const body = await waitForPutBody()
    expect(body.setting_group).toBe('block_response')
    expect(body.setting_key).toBe('html_body')
    expect(body.setting_value).toBe('<p>系统繁忙</p>')
    expect(body.version).toBe(1)
  })

  it('无 system_settings.update 权限时值为只读文本', async () => {
    useAuthStore.setState({ user: makeUser([]) })
    renderPage()
    const row = await openBlockResponseRow('json_code')
    expect(within(row).queryByRole('textbox')).toBeNull()
    expect(within(row).queryByRole('button', { name: /^保\s*存$/ })).toBeNull()
  })
})

// network 分组：NTP/DNS 服务器（逗号分隔字符串，通用字符串输入框渲染）
function networkItems(): SettingItem[] {
  return [
    makeItem({
      id: 'n1',
      setting_group: 'network',
      setting_key: 'ntp_servers',
      setting_value: 'pool.ntp.org',
      value_type: 'string',
    }),
    makeItem({
      id: 'n2',
      setting_group: 'network',
      setting_key: 'dns_servers',
      setting_value: '',
      value_type: 'string',
    }),
  ]
}

function mockNetworkFetch(items: SettingItem[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/system-settings') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      const item = items.find((i) => i.setting_key === body.setting_key)!
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { ...item, setting_value: body.setting_value, version: item.version + 1 },
        }),
      )
    }
    if (url.includes('/system-settings')) {
      const group = new URL(url, 'http://localhost').searchParams.get('group')
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: group === 'network' ? items : [] },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

describe('SystemSettingsPage · network 分组 NTP/DNS 服务器', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockNetworkFetch(networkItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  async function openNetworkRow(settingKey: string): Promise<HTMLElement> {
    fireEvent.click(screen.getByRole('tab', { name: '网络' }))
    const keyCell = await screen.findByText(settingKey)
    return keyCell.closest('tr')!
  }

  it('页签渲染 NTP/DNS 两个设置项：中文说明、当前值与占位提示', async () => {
    renderPage()
    const ntpRow = await openNetworkRow('ntp_servers')
    expect(within(ntpRow).getByText('NTP 时间同步服务器，逗号分隔，最多 4 个')).toBeInTheDocument()
    expect(within(ntpRow).getByRole('textbox')).toHaveValue('pool.ntp.org')

    const dnsRow = (await screen.findByText('dns_servers')).closest('tr')!
    expect(
      within(dnsRow).getByText('DNS 服务器，逗号分隔，最多 4 个，留空继承宿主机'),
    ).toBeInTheDocument()
    expect(within(dnsRow).getByRole('textbox')).toHaveValue('')
    expect(within(dnsRow).getByPlaceholderText('如 223.5.5.5,223.6.6.6')).toBeInTheDocument()
  })

  it('编辑 NTP 服务器后按 network 分组与键提交逗号分隔字符串', async () => {
    renderPage()
    const row = await openNetworkRow('ntp_servers')
    fireEvent.change(within(row).getByRole('textbox'), {
      target: { value: 'time.aliyun.com,pool.ntp.org' },
    })
    await clickSaveWhenEnabled(row)

    const body = await waitForPutBody()
    expect(body.setting_group).toBe('network')
    expect(body.setting_key).toBe('ntp_servers')
    expect(body.setting_value).toBe('time.aliyun.com,pool.ntp.org')
    expect(body.version).toBe(1)
  })

  it('无 system_settings.update 权限时值为只读文本', async () => {
    useAuthStore.setState({ user: makeUser([]) })
    renderPage()
    const row = await openNetworkRow('dns_servers')
    expect(within(row).queryByRole('textbox')).toBeNull()
    expect(within(row).queryByRole('button', { name: /^保\s*存$/ })).toBeNull()
  })
})

describe('SystemSettingsPage · 原生 JSON boolean/number 设置项（B6-5 / B6-12）', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function nativeLoggingItems(): SettingItem[] {
    return [
      makeItem({ id: 'nb1', setting_key: 'access_log_enabled', setting_value: true, value_type: 'boolean', version: 1 }),
      makeItem({ id: 'nb2', setting_key: 'syslog_enabled', setting_value: false, value_type: 'boolean', version: 2 }),
      makeItem({ id: 'nn1', setting_key: 'body_limit_kb', setting_value: 64, value_type: 'integer', version: 3 }),
      makeItem({ id: 'nn2', setting_key: 'retention_days', setting_value: 30, value_type: 'integer', version: 4 }),
    ]
  }

  function mockNativeFetch(items: SettingItem[]) {
    return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.includes('/system-settings') && method === 'PUT') {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { message: '设置已更新' } }),
        )
      }
      if (url.includes('/system-settings')) {
        const group = new URL(url, 'http://localhost').searchParams.get('group')
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: group === 'logging' ? items : [] },
          }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
  }

  it('原生 boolean true/false 正确渲染 Switch 状态，改回原值取消脏标记，保存提交原生类型', async () => {
    vi.stubGlobal('fetch', mockNativeFetch(nativeLoggingItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '日志记录' }))

    const enabledRow = (await screen.findByText('access_log_enabled')).closest('tr')!
    const enabledSwitch = within(enabledRow).getByRole('switch')
    expect(enabledSwitch).toBeChecked()

    const disabledRow = screen.getByText('syslog_enabled').closest('tr')!
    expect(within(disabledRow).getByRole('switch')).not.toBeChecked()

    const saveBtn = within(enabledRow).getByRole('button', { name: /^保\s*存$/ })
    expect(saveBtn).toBeDisabled()

    // 切换为 false 后再切回 true，保存按钮应恢复禁用（isDirty 使用 String(...) 对比）
    fireEvent.click(enabledSwitch)
    await waitFor(() => expect(saveBtn).toBeEnabled())
    fireEvent.click(enabledSwitch)
    await waitFor(() => expect(saveBtn).toBeDisabled())

    // 修改原生 integer 设置项：不会因 .trim() 抛 TypeError，且提交原生 number
    const limitRow = screen.getByText('body_limit_kb').closest('tr')!
    const spin = within(limitRow).getByRole('spinbutton')
    expect(spin).toHaveValue('64')
    fireEvent.change(spin, { target: { value: '128' } })
    await clickSaveWhenEnabled(limitRow)

    const body = await waitForPutBody()
    expect(body).toEqual({
      setting_group: 'logging',
      setting_key: 'body_limit_kb',
      setting_value: 128,
      version: 3,
    })
    expect(typeof body.setting_value).toBe('number')
  })

  it('只读模式下原生 boolean true/false 正确渲染为「已开启」「已关闭」，原生 number 正常显示', async () => {
    vi.stubGlobal('fetch', mockNativeFetch(nativeLoggingItems()))
    useAuthStore.setState({
      user: makeUser(['system_settings.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '日志记录' }))

    const enabledRow = (await screen.findByText('access_log_enabled')).closest('tr')!
    expect(within(enabledRow).getByText('已开启')).toBeInTheDocument()

    const disabledRow = screen.getByText('syslog_enabled').closest('tr')!
    expect(within(disabledRow).getByText('已关闭')).toBeInTheDocument()

    const limitRow = screen.getByText('body_limit_kb').closest('tr')!
    expect(within(limitRow).getByText('64')).toBeInTheDocument()
  })
})
