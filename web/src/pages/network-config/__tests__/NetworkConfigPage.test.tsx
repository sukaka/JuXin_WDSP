import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import NetworkConfigPage from '../NetworkConfigPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, NetworkConfigData, NodeInterfacesNode } from '../../../types'

vi.mock('../../../api/networkConfig', () => ({
  networkConfigApi: {
    get: vi.fn(),
    save: vi.fn(),
  },
}))

vi.mock('../../../api/nodeInterfaces', () => ({
  nodeInterfacesApi: {
    list: vi.fn(),
  },
}))

import { networkConfigApi } from '../../../api/networkConfig'
import { nodeInterfacesApi } from '../../../api/nodeInterfaces'

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

const nodes: NodeInterfacesNode[] = [
  {
    node_name: 'node-1',
    interfaces: [
      {
        ifname: 'eth0',
        mac: '00:11:22:33:44:01',
        pci_path: '0000:03:00.0',
        driver: 'igb',
        media_type: 'TP',
        link_speed: 1000,
        operstate: 'up',
        sort_order: 1,
        role: 'MANAGEMENT',
        present: true,
      },
      {
        ifname: 'eth1',
        mac: '00:11:22:33:44:02',
        pci_path: '0000:03:00.1',
        driver: 'igb',
        media_type: 'TP',
        link_speed: 1000,
        operstate: 'up',
        sort_order: 2,
        role: 'TRAFFIC',
        present: true,
      },
      {
        ifname: 'eth2',
        mac: '00:11:22:33:44:03',
        pci_path: '0000:04:00.0',
        driver: 'ixgbe',
        media_type: 'FIBRE',
        link_speed: 10000,
        operstate: 'up',
        sort_order: 3,
        role: '',
        present: true,
      },
      {
        ifname: 'eth3',
        mac: '00:11:22:33:44:04',
        pci_path: '0000:04:00.1',
        driver: 'ixgbe',
        media_type: 'FIBRE',
        link_speed: 0,
        operstate: 'down',
        sort_order: 4,
        role: '',
        present: false,
      },
    ],
  },
  {
    node_name: 'node-2',
    interfaces: [
      {
        ifname: 'eno1',
        mac: '00:11:22:33:44:11',
        pci_path: '0000:05:00.0',
        driver: 'e1000',
        media_type: 'TP',
        link_speed: 1000,
        operstate: 'up',
        sort_order: 1,
        role: '',
        present: true,
      },
      {
        ifname: 'eno2',
        mac: '00:11:22:33:44:12',
        pci_path: '0000:05:00.1',
        driver: 'e1000',
        media_type: 'TP',
        link_speed: 1000,
        operstate: 'up',
        sort_order: 2,
        role: '',
        present: true,
      },
    ],
  },
]

const EMPTY_CONFIG: NetworkConfigData = {
  desired: { bridges: [], ip_forward: false, routes: [] },
  status: null,
}

/** 各节点网络配置 mock；未配置的节点返回空期望配置 */
let configs: Record<string, NetworkConfigData> = {}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <NetworkConfigPage />
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

/** 确认弹窗中点击「确认保存」（保存配置属高危下发，须二次确认） */
async function confirmSave() {
  fireEvent.click(await screen.findByRole('button', { name: '确认保存' }))
}

describe('NetworkConfigPage', () => {
  beforeEach(() => {
    vi.mocked(networkConfigApi.get).mockReset()
    vi.mocked(networkConfigApi.save).mockReset()
    vi.mocked(nodeInterfacesApi.list).mockReset()
    configs = {}
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({ nodes })
    vi.mocked(networkConfigApi.get).mockImplementation((nodeName?: string) =>
      Promise.resolve(configs[nodeName ?? ''] ?? EMPTY_CONFIG),
    )
    vi.mocked(networkConfigApi.save).mockResolvedValue(EMPTY_CONFIG)
    useAuthStore.setState({
      user: makeUser(['system_health.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  it('渲染期望网桥与静态路由：成员口 Tag、ip_forward 开关、未上报状态提示', async () => {
    configs['node-1'] = {
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: true,
        routes: [{ dst: '10.10.0.0/16', via: '172.30.10.2' }],
      },
      status: null,
    }
    renderPage()
    // 期望网桥：名称与成员口 Tag
    expect(await screen.findByText('br0')).toBeInTheDocument()
    expect(screen.getByText('eth1')).toBeInTheDocument()
    expect(screen.getByText('eth2')).toBeInTheDocument()
    // 静态路由：目的网段与下一跳
    expect(screen.getByText('10.10.0.0/16')).toBeInTheDocument()
    expect(screen.getByText('172.30.10.2')).toBeInTheDocument()
    // ip_forward 开启
    expect(screen.getByRole('switch', { name: '内核三层转发' })).toHaveAttribute('aria-checked', 'true')
    // 未上报执行状态
    expect(screen.getByText('节点尚未上报执行状态')).toBeInTheDocument()
    // 无本地修改时保存按钮不可用
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled()
  })

  it('新建网桥：名称自动建议 br0，保存提交体为全量期望配置', async () => {
    renderPage()
    // 等待节点网口加载完成（新建表单出现）
    const nameInput = await screen.findByLabelText('网桥名称')
    expect(nameInput).toHaveValue('br0')
    // 选择两个成员口（管理口 eth0 与离线口 eth3 不可选，见专项用例）
    openSelect('成员口')
    await pickOption('eth1（电口）')
    await pickOption('eth2（光口）')
    fireEvent.click(screen.getByRole('button', { name: /新建网桥/ }))
    // 本地期望列表出现 br0，名称建议更新为 br1，保存按钮可用
    expect(await screen.findByText('br0')).toBeInTheDocument()
    expect(screen.getByLabelText('网桥名称')).toHaveValue('br1')
    const saveBtn = screen.getByRole('button', { name: /保存配置/ })
    expect(saveBtn).toBeEnabled()
    fireEvent.click(saveBtn)
    // 高危下发前须二次确认
    await confirmSave()
    await waitFor(() => expect(networkConfigApi.save).toHaveBeenCalledTimes(1))
    expect(networkConfigApi.save).toHaveBeenCalledWith(
      {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: false,
        routes: [],
      },
      'node-1',
    )
    // 保存成功后回到未修改状态
    await waitFor(() => expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled())
  })

  it('成员口选项排除管理口与离线口，并标注介质类型', async () => {
    renderPage()
    await screen.findByLabelText('网桥名称')
    openSelect('成员口')
    await waitFor(() => {
      expect(document.querySelectorAll('.ant-select-item-option-content').length).toBeGreaterThan(0)
    })
    const texts = Array.from(document.querySelectorAll('.ant-select-item-option-content')).map(
      (el) => el.textContent,
    )
    // 在线非管理口可选，标注介质类型
    expect(texts).toContain('eth1（电口）')
    expect(texts).toContain('eth2（光口）')
    // 管理口与离线口不可选
    expect(texts).not.toContain('eth0（电口）')
    expect(texts).not.toContain('eth3（光口）')
  })

  it('执行状态：整体失败徽标与错误行红色 Alert', async () => {
    configs['node-1'] = {
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: true,
        routes: [{ dst: '10.10.0.0/16', via: '172.30.10.2' }],
      },
      status: {
        applied_at: '2026-08-19T02:03:04Z',
        ok: false,
        bridges: [{ name: 'br0', state: 'error', message: '创建网桥失败：权限不足' }],
        ip_forward: 'ok',
        routes: [{ dst: '10.10.0.0/16', via: '172.30.10.2', state: 'ok', message: '' }],
        message: '部分配置执行失败',
      },
    }
    renderPage()
    // 整体徽标与应用时间
    expect(await screen.findByText('整体执行失败')).toBeInTheDocument()
    expect(screen.getByText(/应用时间：/)).toBeInTheDocument()
    // 网桥错误行：红色 Alert 展示失败原因
    const bridgeErr = screen.getByText('创建网桥失败：权限不足')
    expect(bridgeErr.closest('.ant-alert-error')).toBeTruthy()
    // 整体 message 同样以红色 Alert 展示
    const overallErr = screen.getByText('部分配置执行失败')
    expect(overallErr.closest('.ant-alert-error')).toBeTruthy()
    // 网桥状态失败，三层转发与路由成功
    expect(screen.getByText('失败')).toBeInTheDocument()
    expect(screen.getAllByText('成功')).toHaveLength(2)
  })

  it('有未保存修改时切换节点：确认放弃后加载目标节点配置', async () => {
    configs['node-2'] = {
      desired: {
        bridges: [{ name: 'br1', ports: ['eno1', 'eno2'] }],
        ip_forward: true,
        routes: [],
      },
      status: null,
    }
    renderPage()
    const nameInput = await screen.findByLabelText('网桥名称')
    // 本地新建网桥形成未保存修改
    openSelect('成员口')
    await pickOption('eth1（电口）')
    await pickOption('eth2（光口）')
    fireEvent.click(screen.getByRole('button', { name: /新建网桥/ }))
    expect(screen.getByText('有未保存的修改')).toBeInTheDocument()
    expect(nameInput).toHaveValue('br1')
    // 切换节点弹出确认，确认后丢弃本地修改并加载 node-2 配置
    openSelect('节点')
    await pickOption('node-2')
    fireEvent.click(await screen.findByRole('button', { name: '放弃修改' }))
    expect(await screen.findByText('br1')).toBeInTheDocument()
    expect(screen.queryByText('有未保存的修改')).not.toBeInTheDocument()
    expect(networkConfigApi.save).not.toHaveBeenCalled()
  })

  it('保存配置二次确认：弹窗提示影响面，取消后不下发', async () => {
    renderPage()
    await screen.findByLabelText('网桥名称')
    // 等节点清单与 node-1 配置加载完成（currentNode 解析后再点击开关，否则编辑态挂在空节点名下会被覆盖）
    await screen.findByText('节点尚未上报执行状态')
    // 开启内核三层转发形成未保存修改
    fireEvent.click(screen.getByRole('switch', { name: '内核三层转发' }))
    expect(screen.getByText('有未保存的修改')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }))
    // 确认弹窗说明影响面（下发节点执行、可能流量中断）
    // antd v6 的 modal.confirm 标题会渲染两处（对话框标题 + 确认体标题），用 *AllBy* 断言
    expect((await screen.findAllByText('高风险操作确认')).length).toBeGreaterThan(0)
    expect(screen.getByText(/下发到节点「node-1」立即执行/)).toBeInTheDocument()
    expect(networkConfigApi.save).not.toHaveBeenCalled()
    // 取消：不调用保存接口，本地修改保留
    fireEvent.click(screen.getByRole('button', { name: /^取\s*消$/ }))
    await waitFor(() =>
      expect(screen.queryAllByText('高风险操作确认')).toHaveLength(0),
    )
    expect(networkConfigApi.save).not.toHaveBeenCalled()
    expect(screen.getByText('有未保存的修改')).toBeInTheDocument()
  })

  it('开启端口联动：保存提交体含 link_pair 缺省参数', async () => {
    configs['node-1'] = {
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: false,
        routes: [],
      },
      status: null,
    }
    renderPage()
    // 期望网桥渲染后开启端口联动
    expect(await screen.findByText('br0')).toBeInTheDocument()
    const lpSwitch = screen.getByRole('switch', { name: '端口联动-br0' })
    expect(lpSwitch).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(lpSwitch)
    expect(lpSwitch).toHaveAttribute('aria-checked', 'true')
    // 参数摘要按缺省值展示
    expect(screen.getByText('1000ms / 5000ms / 20次/h')).toBeInTheDocument()
    // 保存提交体含 link_pair（高危下发前二次确认）
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }))
    await confirmSave()
    await waitFor(() => expect(networkConfigApi.save).toHaveBeenCalledTimes(1))
    expect(networkConfigApi.save).toHaveBeenCalledWith(
      {
        bridges: [
          {
            name: 'br0',
            ports: ['eth1', 'eth2'],
            link_pair: { enabled: true, hold_down_ms: 1000, hold_up_ms: 5000, max_flaps_per_hour: 20 },
          },
        ],
        ip_forward: false,
        routes: [],
      },
      'node-1',
    )
  })

  it('执行状态：端口联动状态表（含状态徽标与故障口/配对口）', async () => {
    configs['node-1'] = {
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: false,
        routes: [],
      },
      status: {
        applied_at: '2026-08-19T02:03:04Z',
        ok: true,
        bridges: [{ name: 'br0', state: 'ok' }],
        ip_forward: 'skipped',
        routes: [],
        link_pairs: [
          {
            bridge: 'br0',
            state: 'PROPAGATED_DOWN',
            down_port: 'eth1',
            propagated_port: 'eth2',
            propagated_by_linkpair: true,
            flap_count_hour: 1,
            last_event_at: '2026-08-19T02:03:00Z',
            message: 'eth1 链路故障持续 1000ms，配对口 eth2 已联动 down（等待上游切路）',
          },
        ],
        message: 'applied',
      },
    }
    renderPage()
    expect(await screen.findByText('已联动断开')).toBeInTheDocument()
    expect(screen.getByText('eth1 / eth2')).toBeInTheDocument()
    expect(screen.getByText('1 次')).toBeInTheDocument()
    expect(screen.getByText(/配对口 eth2 已联动 down/)).toBeInTheDocument()
  })

  it('SUPPRESSED 抑制态解锁保存：无本地修改时允许「保存配置」与「重新下发 / 复位抑制」', async () => {
    configs['node-1'] = {
      default_node: 'node-1',
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'], link_pair: { enabled: true, hold_down_ms: 1000, hold_up_ms: 5000, max_flaps_per_hour: 20 } }],
        ip_forward: false,
        routes: [],
      },
      status: {
        applied_at: '2026-08-19T02:03:04Z',
        ok: true,
        bridges: [{ name: 'br0', state: 'ok' }],
        ip_forward: 'skipped',
        routes: [],
        link_pairs: [
          {
            bridge: 'br0',
            state: 'SUPPRESSED',
            flap_count_hour: 21,
            message: '联动频率超限，已进入抑制态',
          },
        ],
        message: 'applied',
      },
    }
    renderPage()
    expect(await screen.findByText('已抑制')).toBeInTheDocument()
    // 未编辑（!dirty）情况下保存按钮与复位抑制按钮均可用
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeEnabled()
    const resetBtn = screen.getByRole('button', { name: /重新下发 \/ 复位抑制/ })
    expect(resetBtn).toBeEnabled()

    fireEvent.click(resetBtn)
    await confirmSave()
    await waitFor(() => expect(networkConfigApi.save).toHaveBeenCalledTimes(1))
    expect(networkConfigApi.save).toHaveBeenCalledWith(configs['node-1'].desired, 'node-1')
  })

  it('网桥名校验对齐 br0~br99，拒绝 lan-br0 与 br100', async () => {
    renderPage()
    const nameInput = await screen.findByLabelText('网桥名称')
    openSelect('成员口')
    await pickOption('eth1（电口）')
    await pickOption('eth2（光口）')

    fireEvent.change(nameInput, { target: { value: 'lan-br0' } })
    fireEvent.click(screen.getByRole('button', { name: /新建网桥/ }))
    expect(await screen.findByText(/仅允许 br0 ~ br99/)).toBeInTheDocument()
    expect(screen.queryByText('lan-br0')).not.toBeInTheDocument()

    fireEvent.change(nameInput, { target: { value: 'br100' } })
    fireEvent.click(screen.getByRole('button', { name: /新建网桥/ }))
    expect(screen.queryByText('br100')).not.toBeInTheDocument()

    // 合法桥名 br99 可以正常加入
    fireEvent.change(nameInput, { target: { value: 'br99' } })
    fireEvent.click(screen.getByRole('button', { name: /新建网桥/ }))
    expect(await screen.findByText('br99')).toBeInTheDocument()
  })

  it('成员口选择排除 MIRROR 镜像口，并禁用已分配给其他网桥的端口', async () => {
    const nodesWithMirror: NodeInterfacesNode[] = [
      {
        node_name: 'node-1',
        interfaces: [
          ...nodes[0].interfaces!,
          {
            ifname: 'eth4',
            mac: '00:11:22:33:44:05',
            pci_path: '0000:05:00.0',
            driver: 'ixgbe',
            media_type: 'FIBRE',
            link_speed: 10000,
            operstate: 'up',
            sort_order: 5,
            role: 'MIRROR',
            present: true,
          },
          {
            ifname: 'eth5',
            mac: '00:11:22:33:44:06',
            pci_path: '0000:05:00.1',
            driver: 'ixgbe',
            media_type: 'TP',
            link_speed: 1000,
            operstate: 'up',
            sort_order: 6,
            role: 'TRAFFIC',
            present: true,
          },
        ],
      },
    ]
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({ nodes: nodesWithMirror })
    configs['node-1'] = {
      default_node: 'node-1',
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: false,
        routes: [],
      },
      status: null,
    }
    renderPage()
    expect(await screen.findByText('br0')).toBeInTheDocument()
    openSelect('成员口')
    await waitFor(() => {
      expect(document.querySelectorAll('.ant-select-item-option').length).toBeGreaterThan(0)
    })
    const optionEls = Array.from(document.querySelectorAll('.ant-select-item-option'))
    const texts = optionEls.map((el) => el.textContent ?? '')
    // 镜像口 eth4 被彻底排除
    expect(texts.some((t) => t.includes('eth4'))).toBe(false)
    // 未分配业务口 eth5 可选
    const eth5Opt = optionEls.find((el) => el.textContent?.includes('eth5'))
    expect(eth5Opt).toBeTruthy()
    expect(eth5Opt?.getAttribute('aria-disabled')).not.toBe('true')
    // 已加入 br0 的 eth1 / eth2 展示已用标注且处于禁用状态
    const eth1Opt = optionEls.find((el) => el.textContent?.includes('eth1（电口 · 已用于 br0）'))
    const eth2Opt = optionEls.find((el) => el.textContent?.includes('eth2（光口 · 已用于 br0）'))
    expect(eth1Opt).toBeTruthy()
    expect(eth2Opt).toBeTruthy()
    expect(eth1Opt?.getAttribute('aria-disabled')).toBe('true')
    expect(eth2Opt?.getAttribute('aria-disabled')).toBe('true')
  })

  it('静态路由严格限制 IPv4：拒绝 IPv6 CIDR 与 IPv6 下一跳，接受合法 IPv4 路由', async () => {
    renderPage()
    await screen.findByLabelText('目的网段')
    const dstInput = screen.getByLabelText('目的网段')
    const viaInput = screen.getByLabelText('下一跳')
    const addBtn = screen.getByRole('button', { name: /添加路由/ })

    // IPv6 CIDR 被拦截
    fireEvent.change(dstInput, { target: { value: '2001:db8::/32' } })
    fireEvent.change(viaInput, { target: { value: '172.30.10.2' } })
    fireEvent.click(addBtn)
    expect(await screen.findByText(/仅支持 IPv4/)).toBeInTheDocument()
    expect(screen.queryByText('2001:db8::/32')).not.toBeInTheDocument()

    // IPv6 下一跳被拦截
    fireEvent.change(dstInput, { target: { value: '10.20.0.0/16' } })
    fireEvent.change(viaInput, { target: { value: '2001:db8::1' } })
    fireEvent.click(addBtn)
    expect(await screen.findByText(/下一跳必须为合法 IPv4 地址/)).toBeInTheDocument()
    expect(screen.queryByText('10.20.0.0/16')).not.toBeInTheDocument()

    // 合法 IPv4 路由可添加
    fireEvent.change(viaInput, { target: { value: '172.30.10.2' } })
    fireEvent.click(addBtn)
    expect(await screen.findByText('10.20.0.0/16')).toBeInTheDocument()
    expect(screen.getByText('172.30.10.2')).toBeInTheDocument()
  })

  it('非本机默认节点切入只读态：展示说明提示并禁用编辑与保存操作', async () => {
    configs['node-1'] = { ...EMPTY_CONFIG, default_node: 'node-1' }
    configs['node-2'] = {
      default_node: 'node-1',
      desired: {
        bridges: [{ name: 'br1', ports: ['eno1', 'eno2'] }],
        ip_forward: true,
        routes: [{ dst: '10.30.0.0/16', via: '172.30.10.1' }],
      },
      status: null,
    }
    renderPage()
    await screen.findByLabelText('网桥名称')

    openSelect('节点')
    await pickOption('node-2')

    expect(await screen.findByText('当前节点「node-2」仅支持只读查看')).toBeInTheDocument()
    expect(screen.getByText('非本网关节点暂不支持通过本地边车卷读取执行状态')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /新建网桥/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: '删除网桥-br1' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: '端口联动-br1' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: '内核三层转发' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /添加路由/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: '删除路由-10.30.0.0/16' })).toBeDisabled()
  })

  it('执行状态展示透明串接牵引状态卡（ACTIVE 与 DEGRADED）且缺省时不报错', async () => {
    configs['node-1'] = {
      default_node: 'node-1',
      desired: { bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }], ip_forward: false, routes: [] },
      status: {
        applied_at: '2026-11-24T06:25:00Z',
        ok: true,
        bridges: [{ name: 'br0', state: 'ok' }],
        ip_forward: 'skipped',
        routes: [],
        transparent: {
          state: 'DEGRADED',
          enabled: true,
          redirect_active: false,
          listen_port: 15000,
          ports: [80, 443],
          bridges: ['br0'],
          tproxyd_healthy: false,
          caddy_healthy: true,
          bridge_nf_ready: true,
          message: 'tproxyd 探活连续失败，已撤回 REDIRECT 规则进入直通放行',
          updated_at: '2026-11-24T06:25:00Z',
        },
        message: 'applied',
      },
    }
    renderPage()
    expect(await screen.findByText('透明串接牵引')).toBeInTheDocument()
    expect(screen.getByText('已降级')).toBeInTheDocument()
    expect(screen.getByText('REDIRECT 未生效')).toBeInTheDocument()
    expect(screen.getByText('牵引端口：80, 443')).toBeInTheDocument()
    expect(screen.getByText('tproxyd 异常')).toBeInTheDocument()
    expect(screen.getByText('Caddy 正常')).toBeInTheDocument()
    const degMsg = screen.getByText(/tproxyd 探活连续失败/)
    expect(degMsg.closest('.ant-alert-error')).toBeTruthy()
  })

  it('透明串接处于 INACTIVE 未启用态时，不把未探测的 false 布尔值渲染为红色异常标签', async () => {
    configs['node-1'] = {
      default_node: 'node-1',
      desired: { bridges: [], ip_forward: false, routes: [] },
      status: {
        applied_at: '2026-11-24T06:25:00Z',
        ok: true,
        bridges: [],
        ip_forward: 'skipped',
        routes: [],
        transparent: {
          state: 'INACTIVE',
          enabled: false,
          redirect_active: false,
          tproxyd_healthy: false,
          caddy_healthy: false,
          bridge_nf_ready: false,
          message: '透明串接未启用',
        },
        message: 'applied',
      },
    }
    renderPage()
    expect(await screen.findByText('透明串接牵引')).toBeInTheDocument()
    expect(screen.getByText('未启用')).toBeInTheDocument()
    expect(screen.getByText('透明串接未启用')).toBeInTheDocument()
    expect(screen.queryByText(/tproxyd/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Caddy/)).not.toBeInTheDocument()
    expect(screen.queryByText(/br_netfilter/)).not.toBeInTheDocument()
    expect(screen.queryByText(/REDIRECT/)).not.toBeInTheDocument()
  })
})
