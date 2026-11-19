import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import CaptureControlCard from '../CaptureControlCard'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { RequestPcapCaptureStatus } from '../../../api/requestPcap'

function status(state: RequestPcapCaptureStatus['state']): RequestPcapCaptureStatus {
  return {
    enabled: state === 'ENABLED', state, interface: 'eth0', ports: [80, 443],
    hot_dir: '/srv/hot', warm_dir: '/srv/warm', request_id: 'capture-1',
    requested_at: '2026-11-18T12:00:00Z', message: state === 'FAILED' ? 'pcapd启动失败' : undefined,
  }
}

function json(body: unknown, code = 200) {
  return new Response(JSON.stringify({ code: 'SUCCESS', data: body }), {
    status: code, headers: { 'Content-Type': 'application/json' },
  })
}

function renderCard(permissions = ['request_pcap.capture_control']) {
  useAuthStore.setState({
    user: { id: 'u1', username: 'admin', display_name: '系统管理员', status: 'ACTIVE',
      roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }], permissions, must_change_password: false } as CurrentUser,
    csrfToken: null, initialized: true,
  })
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <AntdApp><CaptureControlCard /></AntdApp>
  </QueryClientProvider>)
}

function mockApi(initial: RequestPcapCaptureStatus) {
  let current = initial
  const calls: Array<{ url: string; body?: Record<string, unknown> }> = []
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      calls.push({ url, body })
      current = status(body.enabled ? 'PENDING' : 'DISABLED')
      return Promise.resolve(json(current, 202))
    }
    calls.push({ url })
    return Promise.resolve(json(current))
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, set: (next: RequestPcapCaptureStatus['state']) => { current = status(next) } }
}

describe('CaptureControlCard', () => {
  beforeEach(() => vi.unstubAllGlobals())

  it('首次开启保存真实范围，宿主确认后才显示开启', async () => {
    const api = mockApi(status('DISABLED'))
    renderCard()
    const toggle = await screen.findByRole('switch', { name: 'PCAP取证采集开关' })
    await waitFor(() => expect(toggle).toBeEnabled())
    expect(toggle).not.toBeChecked()
    fireEvent.click(toggle)
    fireEvent.change(await screen.findByLabelText('采集网卡'), { target: { value: 'eth0' } })
    fireEvent.change(screen.getByLabelText('采集端口'), { target: { value: '80,443' } })
    fireEvent.change(screen.getByLabelText('SSD 热证据目录'), { target: { value: '/srv/hot' } })
    fireEvent.change(screen.getByLabelText('SAS 温证据目录'), { target: { value: '/srv/warm' } })
    fireEvent.change(screen.getByLabelText('操作理由'), { target: { value: '授权取证' } })
    fireEvent.click(screen.getByRole('button', { name: '开启并保存' }))
    await waitFor(() => expect(api.calls.some((call) => call.body?.enabled === true)).toBe(true))
    const post = api.calls.find((call) => call.body?.enabled === true)!
    expect(post.body).toMatchObject({ interface: 'eth0', ports: [80, 443], hot_dir: '/srv/hot', warm_dir: '/srv/warm', reason: '授权取证' })
    expect(await screen.findByText('执行中')).toBeInTheDocument()
    api.set('ENABLED')
    await waitFor(() => expect(screen.getByRole('switch', { name: 'PCAP取证采集开关' })).toBeChecked())
  })

  it('关闭只停止新抓包，并携带操作理由', async () => {
    const api = mockApi(status('ENABLED'))
    renderCard()
    const toggle = await screen.findByRole('switch', { name: 'PCAP取证采集开关' })
    await waitFor(() => expect(toggle).toBeEnabled())
    fireEvent.click(toggle)
    fireEvent.change(await screen.findByLabelText('停止采集的操作理由'), { target: { value: '采集窗口结束' } })
    fireEvent.click(screen.getByRole('button', { name: '停止采集' }))
    await waitFor(() => expect(api.calls.some((call) => call.body?.enabled === false)).toBe(true))
    expect(api.calls.find((call) => call.body?.enabled === false)?.body?.reason).toBe('采集窗口结束')
    await waitFor(() => expect(screen.getByRole('switch', { name: 'PCAP取证采集开关' })).not.toBeChecked())
  })

  it('执行失败不误显示为开启', async () => {
    mockApi(status('FAILED'))
    renderCard()
    expect(await screen.findByText('pcapd启动失败')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'PCAP取证采集开关' })).not.toBeChecked()
  })

  it('无独立权限时不展示也不发起请求', () => {
    const api = mockApi(status('DISABLED'))
    renderCard([])
    expect(screen.queryByText('PCAP 取证采集')).not.toBeInTheDocument()
    expect(api.calls).toHaveLength(0)
  })

  it('校验端口范围 1..65535、目录占位符更新为规范路径，且表单校验失败不产生未捕获异常', async () => {
    const api = mockApi(status('DISABLED'))
    renderCard()
    const toggle = await screen.findByRole('switch', { name: 'PCAP取证采集开关' })
    await waitFor(() => expect(toggle).toBeEnabled())
    fireEvent.click(toggle)

    expect(await screen.findByPlaceholderText('例如 /srv/jiuzhang-pcap-hot')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('例如 /srv/jiuzhang-pcap-warm')).toBeInTheDocument()

    // 超范围端口 65536 与 0 均被表单拦截，不发起 POST
    fireEvent.change(screen.getByLabelText('采集端口'), { target: { value: '80,65536' } })
    fireEvent.change(screen.getByLabelText('操作理由'), { target: { value: '测试端口范围' } })
    fireEvent.click(screen.getByRole('button', { name: '开启并保存' }))
    expect(await screen.findByText('端口号必须在 1 到 65535 之间')).toBeInTheDocument()
    expect(api.calls.some((c) => c.body !== undefined)).toBe(false)

    fireEvent.change(screen.getByLabelText('采集端口'), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: '开启并保存' }))
    expect(await screen.findByText('端口号必须在 1 到 65535 之间')).toBeInTheDocument()
    expect(api.calls.some((c) => c.body !== undefined)).toBe(false)
  })

  it('弹窗打开期间后台状态刷新不覆盖用户编辑中的输入', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    mockApi(status('DISABLED'))
    useAuthStore.setState({
      user: {
        id: 'u1', username: 'admin', display_name: '系统管理员', status: 'ACTIVE',
        roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
        permissions: ['request_pcap.capture_control'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp><CaptureControlCard /></AntdApp>
      </QueryClientProvider>,
    )
    const toggle = await screen.findByRole('switch', { name: 'PCAP取证采集开关' })
    await waitFor(() => expect(toggle).toBeEnabled())
    fireEvent.click(toggle)

    const ifaceInput = (await screen.findByLabelText('采集网卡')) as HTMLInputElement
    fireEvent.change(ifaceInput, { target: { value: 'ens192' } })
    expect(ifaceInput.value).toBe('ens192')

    // 模拟后台查询刷新返回新对象（interface 仍为 eth0）
    qc.setQueryData(['request-pcap-capture'], { ...status('DISABLED'), interface: 'eth0' })
    await waitFor(() => expect((screen.getByLabelText('采集网卡') as HTMLInputElement).value).toBe('ens192'))
  })
})
