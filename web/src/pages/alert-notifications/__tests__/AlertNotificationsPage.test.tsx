import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AlertNotificationsPage from '../AlertNotificationsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, NotificationChannel, SettingItem } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
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

const META = {
  categories: [
    { code: 'infrastructure', name: '基础设施', alert_types: ['CPU_HIGH'] },
    { code: 'storage', name: '存储容量', alert_types: ['DISK_USAGE_HIGH'] },
    { code: 'certificate', name: '证书', alert_types: ['CERT_EXPIRING'] },
    { code: 'collection', name: '采集健康', alert_types: ['COLLECTOR_DOWN'] },
    { code: 'config_publish', name: '配置发布', alert_types: ['PUBLISH_FAILED'] },
    { code: 'api_security', name: 'API安全', alert_types: ['API_RISK_HIGH'] },
    { code: 'ops', name: '运维操作', alert_types: ['BACKUP_FAILED'] },
  ],
  severities: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
}

const CHANNELS: NotificationChannel[] = [
  {
    id: 'ch-1',
    name: '运维值班群',
    type: 'wecom',
    enabled: true,
    min_severity: 'MEDIUM',
    categories: [],
    config: { webhook_url: '********', mention_all: true },
    created_at: '2026-08-01T00:00:00Z',
    updated_at: '2026-08-02T00:00:00Z',
  },
  {
    id: 'ch-2',
    name: '安全邮箱',
    type: 'smtp',
    enabled: false,
    min_severity: 'HIGH',
    categories: ['infrastructure', 'certificate'],
    config: {
      host: 'smtp.example.com',
      port: 465,
      security: 'ssl',
      username: 'alert',
      password: '********',
      from: 'waf@example.com',
      to: ['ops@example.com'],
    },
    created_at: '2026-08-01T00:00:00Z',
    updated_at: '2026-08-02T00:00:00Z',
  },
]

function makeSetting(key: string, value: string, version: number, valueType = 'integer'): SettingItem {
  return {
    id: `st-${key}`,
    setting_group: 'notify',
    setting_key: key,
    setting_value: value,
    value_type: valueType,
    is_sensitive: false,
    description: '',
    updated_at: '2026-08-01T00:00:00Z',
    version,
  }
}

const NOTIFY_SETTINGS: SettingItem[] = [
  makeSetting('notify_rate_limit_per_minute', '10', 1),
  makeSetting('notify_mute_minutes', '30', 2),
  makeSetting('notify_group_window_seconds', '60', 3),
  makeSetting('notify_resolved', 'false', 4, 'boolean'),
]

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/notification-meta')) return ok(META)
    if (url.endsWith('/api/v1/notification-channels') && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      return ok({ id: 'ch-new', created_at: '', updated_at: '', ...body })
    }
    if (url.includes('/notification-channels/') && url.endsWith('/test') && method === 'POST') {
      return ok({ message: '测试消息已发送' })
    }
    if (url.includes('/notification-channels/') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      return ok({ id: url.split('/').pop(), created_at: '', updated_at: '', ...body })
    }
    if (url.includes('/notification-channels/') && method === 'DELETE') {
      return ok({ message: '渠道已删除' })
    }
    if (url.includes('/notification-channels')) return ok({ items: CHANNELS })
    if (url.includes('/system-settings') && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      const item = NOTIFY_SETTINGS.find((i) => i.setting_key === body.setting_key)!
      return ok({ ...item, setting_value: body.setting_value, version: item.version + 1 })
    }
    if (url.includes('/system-settings')) return ok({ items: NOTIFY_SETTINGS })
    return Promise.reject(new Error(`unexpected url: ${url} method=${method}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <AlertNotificationsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function findCalls(part: string, method: string) {
  return (fetch as Mock).mock.calls.filter(
    (c) => String(c[0]).includes(part) && (c[1]?.method ?? 'GET') === method,
  )
}

function bodyOf(call: unknown[]): Record<string, unknown> {
  return JSON.parse(String((call[1] as RequestInit).body)) as Record<string, unknown>
}

describe('AlertNotificationsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['notification.read', 'notification.update', 'notification.test']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染渠道行：类型 Tag、订阅级别、订阅类别与启用开关', async () => {
    renderPage()
    const row1 = (await screen.findByText('运维值班群')).closest('tr')!
    expect(within(row1).getByText('企业微信')).toBeInTheDocument()
    expect(within(row1).getByText('中')).toBeInTheDocument()
    // 空 categories = 全部类别
    expect(within(row1).getByText('全部类别')).toBeInTheDocument()
    expect(within(row1).getByRole('switch')).toBeChecked()

    const row2 = screen.getByText('安全邮箱').closest('tr')!
    expect(within(row2).getByText('邮件')).toBeInTheDocument()
    expect(within(row2).getByText('高')).toBeInTheDocument()
    // 类别 code 映射为中文名，逗号分隔
    expect(within(row2).getByText('基础设施，证书')).toBeInTheDocument()
    expect(within(row2).getByRole('switch')).not.toBeChecked()
  })

  it('新增 Modal：按类型切换渲染对应 config 字段', async () => {
    renderPage()
    await screen.findByText('运维值班群')
    fireEvent.click(screen.getByRole('button', { name: /新\s*增\s*渠\s*道/ }))
    const dialog = await screen.findByRole('dialog')

    // 默认企业微信：Webhook + @所有人
    expect(within(dialog).getByLabelText('Webhook 地址')).toBeInTheDocument()
    expect(within(dialog).getByText('@所有人')).toBeInTheDocument()

    // 切换为邮件（SMTP）（下拉可见选项带 title 属性；隐藏 listbox 选项文本为 value，故按 title 定位）
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByTitle('邮件（SMTP）'))
    expect(await within(dialog).findByLabelText('SMTP 服务器')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('端口')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('发件人')).toBeInTheDocument()
    expect(within(dialog).getByText('收件人')).toBeInTheDocument()

    // 切换为 syslog：展示沿用系统设置说明
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByTitle('syslog'))
    expect(
      await within(dialog).findByText(/沿用系统设置 logging 组的 syslog 配置/),
    ).toBeInTheDocument()
  })

  it('新增企业微信渠道：提交体含扁平字段与 config', async () => {
    renderPage()
    await screen.findByText('运维值班群')
    fireEvent.click(screen.getByRole('button', { name: /新\s*增\s*渠\s*道/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: '值班机器人' } })
    fireEvent.change(within(dialog).getByLabelText('Webhook 地址'), {
      target: { value: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc123' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() =>
      expect(findCalls('/api/v1/notification-channels', 'POST')).toHaveLength(1),
    )
    const body = bodyOf(findCalls('/api/v1/notification-channels', 'POST')[0])
    expect(body.name).toBe('值班机器人')
    expect(body.type).toBe('wecom')
    expect(body.enabled).toBe(true)
    expect(body.min_severity).toBe('MEDIUM')
    expect(body.categories).toEqual([])
    expect(body.config).toEqual({
      webhook_url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc123',
      mention_all: false,
    })
  })

  it('编辑 SMTP 渠道：密值 ******** 原样提交表示不修改', async () => {
    renderPage()
    await screen.findByText('安全邮箱')
    // 第二行（SMTP 渠道）的「编辑」
    fireEvent.click(screen.getAllByRole('button', { name: /^编\s*辑$/ })[1])
    const dialog = await screen.findByRole('dialog')

    // 回显：普通字段原值，密码为掩码
    expect(await within(dialog).findByLabelText('SMTP 服务器')).toHaveValue('smtp.example.com')
    expect(within(dialog).getByLabelText('密码')).toHaveValue('********')

    // 不改动直接保存
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() =>
      expect(findCalls('/notification-channels/ch-2', 'PUT')).toHaveLength(1),
    )
    const body = bodyOf(findCalls('/notification-channels/ch-2', 'PUT')[0])
    expect(body.name).toBe('安全邮箱')
    expect(body.type).toBe('smtp')
    expect(body.enabled).toBe(false)
    expect(body.min_severity).toBe('HIGH')
    expect(body.categories).toEqual(['infrastructure', 'certificate'])
    const config = body.config as Record<string, unknown>
    expect(config.host).toBe('smtp.example.com')
    expect(config.port).toBe(465)
    expect(config.security).toBe('ssl')
    expect(config.password).toBe('********')
    expect(config.to).toEqual(['ops@example.com'])
    // 非本类型字段不得混入
    expect('webhook_url' in config).toBe(false)
  })

  it('新增 Modal：切换为短信渲染 5 个 config 字段', async () => {
    renderPage()
    await screen.findByText('运维值班群')
    fireEvent.click(screen.getByRole('button', { name: /新\s*增\s*渠\s*道/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByTitle('短信'))

    expect(await within(dialog).findByLabelText('网关地址')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('App Key')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('App Secret')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('模板 ID')).toBeInTheDocument()
    expect(within(dialog).getByText('手机号列表')).toBeInTheDocument()
    expect(within(dialog).getByText(/通用 HTTP 网关协议/)).toBeInTheDocument()
  })

  it('新增短信渠道：提交体含扁平字段与 config，app_secret 原样透传', async () => {
    renderPage()
    await screen.findByText('运维值班群')
    fireEvent.click(screen.getByRole('button', { name: /新\s*增\s*渠\s*道/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: '值班短信' } })
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByTitle('短信'))

    fireEvent.change(await within(dialog).findByLabelText('网关地址'), {
      target: { value: 'https://sms.example.com/send' },
    })
    fireEvent.change(within(dialog).getByLabelText('App Key'), { target: { value: 'ak-001' } })
    fireEvent.change(within(dialog).getByLabelText('App Secret'), { target: { value: 'sk-xyz' } })
    fireEvent.change(within(dialog).getByLabelText('模板 ID'), { target: { value: 'TPL_ALERT' } })
    // tags Select（open=false）：输入后回车添加手机号
    const phoneInput = dialog.querySelector('#phones')!
    fireEvent.change(phoneInput, { target: { value: '13800138000' } })
    fireEvent.keyDown(phoneInput, { key: 'Enter' })
    fireEvent.change(phoneInput, { target: { value: '13900139000' } })
    fireEvent.keyDown(phoneInput, { key: 'Enter' })

    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() =>
      expect(findCalls('/api/v1/notification-channels', 'POST')).toHaveLength(1),
    )
    const body = bodyOf(findCalls('/api/v1/notification-channels', 'POST')[0])
    expect(body.name).toBe('值班短信')
    expect(body.type).toBe('sms')
    expect(body.enabled).toBe(true)
    expect(body.min_severity).toBe('MEDIUM')
    expect(body.config).toEqual({
      gateway_url: 'https://sms.example.com/send',
      app_key: 'ak-001',
      app_secret: 'sk-xyz',
      template_id: 'TPL_ALERT',
      phones: ['13800138000', '13900139000'],
    })
  })

  it('新增短信渠道：非法手机号被校验拦截，不发请求', async () => {
    renderPage()
    await screen.findByText('运维值班群')
    fireEvent.click(screen.getByRole('button', { name: /新\s*增\s*渠\s*道/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.change(within(dialog).getByLabelText('名称'), { target: { value: '值班短信' } })
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByTitle('短信'))

    fireEvent.change(await within(dialog).findByLabelText('网关地址'), {
      target: { value: 'https://sms.example.com/send' },
    })
    fireEvent.change(within(dialog).getByLabelText('App Key'), { target: { value: 'ak-001' } })
    fireEvent.change(within(dialog).getByLabelText('模板 ID'), { target: { value: 'TPL_ALERT' } })
    const phoneInput = dialog.querySelector('#phones')!
    fireEvent.change(phoneInput, { target: { value: '12345' } })
    fireEvent.keyDown(phoneInput, { key: 'Enter' })

    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    expect(await within(dialog).findByText('手机号格式不正确：12345')).toBeInTheDocument()
    expect(findCalls('/api/v1/notification-channels', 'POST')).toHaveLength(0)
  })

  it('启用开关：直接 PUT 切换 enabled，config 原样回传', async () => {
    renderPage()
    const row1 = (await screen.findByText('运维值班群')).closest('tr')!
    fireEvent.click(within(row1).getByRole('switch'))

    await waitFor(() =>
      expect(findCalls('/notification-channels/ch-1', 'PUT')).toHaveLength(1),
    )
    const body = bodyOf(findCalls('/notification-channels/ch-1', 'PUT')[0])
    expect(body.enabled).toBe(false)
    expect(body.config).toEqual({ webhook_url: '********', mention_all: true })
  })

  it('发送测试：行内按钮触发 POST test 并透传结果消息', async () => {
    renderPage()
    const row1 = (await screen.findByText('运维值班群')).closest('tr')!
    fireEvent.click(within(row1).getByRole('button', { name: /^测\s*试$/ }))

    await waitFor(() =>
      expect(findCalls('/notification-channels/ch-1/test', 'POST')).toHaveLength(1),
    )
    expect(await screen.findByText('测试消息已发送')).toBeInTheDocument()
  })

  it('风暴抑制参数：修改速率限制后保存，4 个键逐一 PUT', async () => {
    renderPage()
    // 等待抑制参数加载（速率限制初始值 10）
    const spinbuttons = await screen.findAllByRole('spinbutton')
    expect(spinbuttons).toHaveLength(3)
    await waitFor(() => expect(spinbuttons[0]).toHaveValue('10'))

    fireEvent.change(spinbuttons[0], { target: { value: '20' } })
    await waitFor(() => expect(spinbuttons[0]).toHaveValue('20'))
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() => expect(findCalls('/system-settings', 'PUT')).toHaveLength(4))
    const bodies = findCalls('/system-settings', 'PUT').map(bodyOf)
    const byKey = new Map(bodies.map((b) => [b.setting_key, b]))
    expect(byKey.get('notify_rate_limit_per_minute')).toMatchObject({
      setting_group: 'notify',
      setting_value: '20',
      version: 1,
    })
    expect(byKey.get('notify_mute_minutes')).toMatchObject({ setting_value: '30', version: 2 })
    expect(byKey.get('notify_group_window_seconds')).toMatchObject({
      setting_value: '60',
      version: 3,
    })
    expect(byKey.get('notify_resolved')).toMatchObject({ setting_value: 'false', version: 4 })
  })
})
