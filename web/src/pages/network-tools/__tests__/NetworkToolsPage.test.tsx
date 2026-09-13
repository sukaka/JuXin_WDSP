import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import NetworkToolsPage from '../NetworkToolsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, NetworkToolJob } from '../../../types'

vi.mock('../../../api/networkTools', () => ({
  networkToolsApi: {
    list: vi.fn(),
    create: vi.fn(),
    get: vi.fn(),
    stop: vi.fn(),
    downloadUrl: vi.fn((id: string) => `/api/v1/network-tools/jobs/${id}/download`),
  },
}))

import { networkToolsApi } from '../../../api/networkTools'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sys',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
    permissions,
    must_change_password: false,
  }
}

function makeJob(partial: Partial<NetworkToolJob> & { id: string }): NetworkToolJob {
  return {
    node: 'node-1',
    action: 'ping',
    target: '8.8.8.8',
    params: { count: 4 },
    status: 'SUCCESS',
    result_text: '',
    failure_message: '',
    created_at: '2026-09-13T01:00:00Z',
    duration_ms: 12,
    ...partial,
  }
}

function mockList(items: NetworkToolJob[]) {
  vi.mocked(networkToolsApi.list).mockResolvedValue({
    items,
    page: 1,
    page_size: 20,
    total: items.length,
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <NetworkToolsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 打开指定 aria-label 的 Select 下拉 */
function openSelect(label: string) {
  fireEvent.mouseDown(screen.getByLabelText(label))
}

/** 点击下拉项（与触发器内已选文案消歧：取 .ant-select-item-option-content 内的节点） */
async function pickOption(text: string) {
  const options = await screen.findAllByText(text)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('NetworkToolsPage', () => {
  beforeEach(() => {
    vi.mocked(networkToolsApi.list).mockReset()
    vi.mocked(networkToolsApi.create).mockReset()
    vi.mocked(networkToolsApi.get).mockReset()
    vi.mocked(networkToolsApi.stop).mockReset()
    mockList([])
    vi.mocked(networkToolsApi.create).mockImplementation((body) =>
      Promise.resolve(makeJob({ id: 'j-new', action: body.action, target: body.target })),
    )
    vi.mocked(networkToolsApi.stop).mockResolvedValue({ message: 'ok' })
    useAuthStore.setState({
      user: makeUser(['network_tools.execute', 'network_tools.download']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('表单按动作动态显隐：ping 次数 / tcp_probe 端口 / traceroute 最大跳数 / capture 抓包参数', async () => {
    renderPage()
    // 默认 ping：次数可见，端口/最大跳数/抓包参数不可见
    expect(screen.getByLabelText('次数')).toBeInTheDocument()
    expect(screen.queryByLabelText('端口')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('最大跳数')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('网口')).not.toBeInTheDocument()

    openSelect('动作')
    await pickOption('TCP 端口探测')
    expect(screen.getByLabelText('端口')).toBeInTheDocument()
    expect(screen.queryByLabelText('次数')).not.toBeInTheDocument()

    openSelect('动作')
    await pickOption('Traceroute')
    expect(screen.getByLabelText('最大跳数')).toBeInTheDocument()
    expect(screen.queryByLabelText('端口')).not.toBeInTheDocument()

    openSelect('动作')
    await pickOption('DNS 查询')
    expect(screen.queryByLabelText('端口')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('次数')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('最大跳数')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('网口')).not.toBeInTheDocument()

    openSelect('动作')
    await pickOption('流量抓包')
    expect(screen.getByLabelText('网口')).toBeInTheDocument()
    expect(screen.getByLabelText('抓包时长')).toBeInTheDocument()
    expect(screen.getByLabelText('过滤协议')).toBeInTheDocument()
    expect(screen.getByLabelText('过滤端口')).toBeInTheDocument()
    expect(screen.getByLabelText('过滤主机')).toBeInTheDocument()
    // 抓包展示数据安全提示
    expect(screen.getByText(/抓包在网关节点上执行/)).toBeInTheDocument()
  })

  it('前端校验拒绝非法目标：协议/路径与不合法主机名均不提交', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('目标'), { target: { value: 'http://evil.com/x' } })
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    expect(await screen.findByText('目标地址不能包含协议或路径')).toBeInTheDocument()
    expect(networkToolsApi.create).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('目标'), { target: { value: 'bad_host!!' } })
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    expect(await screen.findByText('目标需为 IPv4/IPv6 地址或合法主机名')).toBeInTheDocument()
    expect(networkToolsApi.create).not.toHaveBeenCalled()
  })

  it('提交 ping：仅携带动作与次数参数', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('目标'), { target: { value: '8.8.8.8' } })
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    await waitFor(() => expect(networkToolsApi.create).toHaveBeenCalledTimes(1))
    expect(networkToolsApi.create).toHaveBeenCalledWith({
      action: 'ping',
      target: '8.8.8.8',
      count: 4,
    })
    expect(await screen.findByText('诊断任务已创建，正在后台执行')).toBeInTheDocument()
  })

  it('提交 tcp_probe：端口必填并随请求提交', async () => {
    renderPage()
    openSelect('动作')
    await pickOption('TCP 端口探测')
    fireEvent.change(screen.getByLabelText('目标'), { target: { value: '10.0.0.1' } })
    // 未填端口：拦截不提交
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    expect(await screen.findByText('请输入探测端口')).toBeInTheDocument()
    expect(networkToolsApi.create).not.toHaveBeenCalled()
    // 填端口后提交
    fireEvent.change(screen.getByLabelText('端口'), { target: { value: '443' } })
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    await waitFor(() => expect(networkToolsApi.create).toHaveBeenCalledTimes(1))
    expect(networkToolsApi.create).toHaveBeenCalledWith({
      action: 'tcp_probe',
      target: '10.0.0.1',
      port: 443,
    })
  })

  it('提交 capture：网口必填，可选过滤参数缺省不携带', async () => {
    renderPage()
    openSelect('动作')
    await pickOption('流量抓包')
    fireEvent.change(screen.getByLabelText('目标'), { target: { value: '10.0.0.2' } })
    // 未填网口：拦截不提交
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    expect(await screen.findByText('请输入抓包网口')).toBeInTheDocument()
    expect(networkToolsApi.create).not.toHaveBeenCalled()
    // 填网口后提交：默认时长 10 秒，未设置的过滤参数不出现在请求体
    fireEvent.change(screen.getByLabelText('网口'), { target: { value: 'eth0' } })
    fireEvent.click(screen.getByRole('button', { name: /开始诊断/ }))
    await waitFor(() => expect(networkToolsApi.create).toHaveBeenCalledTimes(1))
    expect(networkToolsApi.create).toHaveBeenCalledWith({
      action: 'capture',
      target: '10.0.0.2',
      iface: 'eth0',
      duration_sec: 10,
    })
  })

  it('列表渲染动作与状态 Tag、参数摘要与耗时', async () => {
    mockList([
      makeJob({ id: 'j1', action: 'ping', target: '8.8.8.8', status: 'PENDING', params: { count: 4 } }),
      makeJob({ id: 'j2', action: 'tcp_probe', target: '10.0.0.1', status: 'RUNNING', params: { port: 443 } }),
      makeJob({ id: 'j3', action: 'traceroute', target: '1.1.1.1', status: 'SUCCESS', params: { max_hops: 30 } }),
      makeJob({ id: 'j4', action: 'dns_query', target: 'example.com', status: 'FAILED', params: {} }),
      makeJob({ id: 'j5', action: 'capture', target: '10.0.0.2', status: 'STOPPED', params: { iface: 'eth0', duration_sec: 10 } }),
      makeJob({ id: 'j6', action: 'ping', target: '192.168.1.1', status: 'TIMEOUT', params: { count: 4 } }),
    ])
    renderPage()
    // 状态 Tag（等待首行加载后断言全部）
    expect(await screen.findByText('排队中')).toBeInTheDocument()
    expect(screen.getByText('执行中')).toBeInTheDocument()
    expect(screen.getByText('成功')).toBeInTheDocument()
    expect(screen.getByText('失败')).toBeInTheDocument()
    expect(screen.getByText('已停止')).toBeInTheDocument()
    expect(screen.getByText('超时')).toBeInTheDocument()
    // 动作 Tag
    expect(screen.getByText('TCP 端口探测')).toBeInTheDocument()
    expect(screen.getByText('Traceroute')).toBeInTheDocument()
    expect(screen.getByText('DNS 查询')).toBeInTheDocument()
    expect(screen.getByText('流量抓包')).toBeInTheDocument()
    // 参数摘要与耗时（getByText 匹配时空白归一化为单空格）
    expect(screen.getByText('port=443')).toBeInTheDocument()
    expect(screen.getByText('iface=eth0 duration_sec=10')).toBeInTheDocument()
    expect(screen.getAllByText('12 ms').length).toBeGreaterThan(0)
  })

  it('停止按钮仅 PENDING/RUNNING 展示，点击调用停止接口', async () => {
    mockList([
      makeJob({ id: 'j-run', status: 'RUNNING' }),
      makeJob({ id: 'j-done', status: 'SUCCESS' }),
    ])
    renderPage()
    const runningCell = await screen.findByText('执行中')
    const runningRow = runningCell.closest('tr')!
    const stopBtn = within(runningRow).getByRole('button', { name: /^停\s*止$/ })
    fireEvent.click(stopBtn)
    await waitFor(() => expect(networkToolsApi.stop).toHaveBeenCalledWith('j-run'))
    // 成功行不展示停止按钮
    const doneRow = screen.getByText('成功').closest('tr')!
    expect(within(doneRow).queryByRole('button', { name: /^停\s*止$/ })).toBeNull()
  })

  it('下载 pcap：仅 capture 且 SUCCESS 展示，点击 window.open 下载地址', async () => {
    const openSpy = vi.fn()
    vi.stubGlobal('open', openSpy)
    mockList([
      makeJob({ id: 'j-cap', action: 'capture', target: '10.0.0.2', status: 'SUCCESS', params: { iface: 'eth0' } }),
      makeJob({ id: 'j-ping', action: 'ping', target: '8.8.8.8', status: 'SUCCESS' }),
      makeJob({ id: 'j-cap-run', action: 'capture', target: '10.0.0.3', status: 'RUNNING', params: { iface: 'eth0' } }),
    ])
    renderPage()
    await screen.findAllByText('流量抓包')
    const downloadBtns = screen.getAllByRole('button', { name: /下载 pcap/ })
    // 仅 capture+SUCCESS 一行展示
    expect(downloadBtns).toHaveLength(1)
    fireEvent.click(downloadBtns[0])
    expect(openSpy).toHaveBeenCalledWith('/api/v1/network-tools/jobs/j-cap/download', '_blank')
  })

  it('无 network_tools.download 权限时隐藏下载按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['network_tools.execute']),
      csrfToken: null,
      initialized: true,
    })
    mockList([
      makeJob({ id: 'j-cap', action: 'capture', target: '10.0.0.2', status: 'SUCCESS', params: { iface: 'eth0' } }),
    ])
    renderPage()
    await screen.findByText('流量抓包')
    expect(screen.queryByRole('button', { name: /下载 pcap/ })).not.toBeInTheDocument()
  })

  it('详情抽屉：参数与执行输出等宽展示，失败原因红色提示', async () => {
    mockList([
      makeJob({
        id: 'j-fail',
        action: 'ping',
        target: 'no-such-host.example',
        status: 'FAILED',
        result_text: 'ping: unknown host no-such-host.example',
        failure_message: '目标主机无法解析',
      }),
    ])
    renderPage()
    const row = (await screen.findByText('失败')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: '详情' }))
    // 失败原因红色 Alert
    const err = await screen.findByText('目标主机无法解析')
    expect(err.closest('.ant-alert-error')).toBeTruthy()
    // result_text 等宽 <pre> 展示
    const output = screen.getByText('ping: unknown host no-such-host.example')
    expect(output.tagName).toBe('PRE')
    // 参数 JSON 展示
    expect(screen.getByText(/"count": 4/)).toBeInTheDocument()
  })

  it('抓包详情：capture_packets 渲染数据包表格（行数/协议 Tag/端口拼接）', async () => {
    const job = makeJob({
      id: 'j-cap',
      action: 'capture',
      target: '10.0.0.2',
      status: 'SUCCESS',
      params: { iface: 'eth0', duration_sec: 10 },
      result_text: 'captured 3 packets',
      capture_size: 1024,
    })
    mockList([job])
    vi.mocked(networkToolsApi.get).mockResolvedValue({
      ...job,
      capture_packets: [
        {
          no: 1,
          ts: '2026-09-13T01:00:00.123456Z',
          src: '10.0.0.1',
          dst: '10.0.0.2',
          sport: 51234,
          dport: 443,
          proto: 'TCP',
          flags: 'SYN,ACK',
          length: 74,
          preview: 'GET / HTTP/1.1',
        },
        {
          no: 2,
          ts: '2026-09-13T01:00:01.000000Z',
          src: '10.0.0.2',
          dst: '8.8.8.8',
          sport: 53000,
          dport: 53,
          proto: 'UDP',
          flags: '',
          length: 60,
          preview: '',
        },
        {
          no: 3,
          ts: '2026-09-13T01:00:02.500000Z',
          src: '10.0.0.9',
          dst: '10.0.0.2',
          sport: null,
          dport: null,
          proto: 'ICMP',
          flags: '',
          length: 98,
          preview: 'echo-request',
        },
      ],
    })
    renderPage()
    const row = (await screen.findByText('流量抓包')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: '详情' }))
    // 摘要说明与行数（3 条数据行）
    expect(await screen.findByText(/共 3 个数据包/)).toBeInTheDocument()
    expect(document.querySelectorAll('.ant-drawer .ant-table-tbody > tr.ant-table-row')).toHaveLength(3)
    // 端口拼接 ip:port；ICMP 无端口仅展示 IP
    expect(screen.getByText('10.0.0.1:51234')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.2:443')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.9')).toBeInTheDocument()
    // 协议 Tag 着色
    expect(screen.getByText('TCP').closest('.ant-tag-blue')).toBeTruthy()
    expect(screen.getByText('UDP').closest('.ant-tag-green')).toBeTruthy()
    expect(screen.getByText('ICMP').closest('.ant-tag-orange')).toBeTruthy()
    // 标志与时间格式化
    expect(screen.getByText('SYN,ACK')).toBeInTheDocument()
    expect(screen.getAllByText(/\d{2}:\d{2}:\d{2}\.\d{3}/).length).toBe(3)
    // 数据预览（空预览显示占位）
    expect(screen.getByText('GET / HTTP/1.1')).toBeInTheDocument()
    // 表格后仍展示任务参数与执行输出
    expect(screen.getByText('captured 3 packets')).toBeInTheDocument()
  })

  it('抓包详情：capture_packets 为 null 时不渲染表格，result_text 与下载按钮回退不变', async () => {
    const job = makeJob({
      id: 'j-cap-null',
      action: 'capture',
      target: '10.0.0.2',
      status: 'SUCCESS',
      params: { iface: 'eth0' },
      result_text: 'captured 0 packets',
    })
    mockList([job])
    vi.mocked(networkToolsApi.get).mockResolvedValue({ ...job, capture_packets: null })
    renderPage()
    const row = (await screen.findByText('流量抓包')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: '详情' }))
    // 执行输出正常展示，无数据包表格
    expect(await screen.findByText('captured 0 packets')).toBeInTheDocument()
    expect(screen.queryByText('数据包')).not.toBeInTheDocument()
    expect(screen.queryByText(/个数据包/)).not.toBeInTheDocument()
    // 下载按钮仍在（列表行）
    expect(screen.getByRole('button', { name: /下载 pcap/ })).toBeInTheDocument()
  })

  it('非抓包任务详情不渲染数据包表格，也不拉取任务详情接口', async () => {
    mockList([makeJob({ id: 'j-ping', action: 'ping', status: 'SUCCESS', result_text: 'pong' })])
    renderPage()
    const row = (await screen.findByText('成功')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: '详情' }))
    expect(await screen.findByText('pong')).toBeInTheDocument()
    expect(screen.queryByText('数据包')).not.toBeInTheDocument()
    expect(networkToolsApi.get).not.toHaveBeenCalled()
  })
})
