import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import HaGroupsPage from '../HaGroupsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, HaGroup } from '../../../types'

vi.mock('../../../api/haGroups', () => ({
  haGroupsApi: {
    list: vi.fn(),
    create: vi.fn(),
    get: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    failback: vi.fn(),
    listEvents: vi.fn(),
  },
}))

vi.mock('../../../api/apiNodes', () => ({
  apiNodesApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../../api/nodeInterfaces', () => ({
  nodeInterfacesApi: {
    list: vi.fn(),
  },
}))

vi.mock('../../../api/networkConfig', () => ({
  networkConfigApi: {
    get: vi.fn(),
  },
}))

import { haGroupsApi } from '../../../api/haGroups'
import { apiNodesApi } from '../../../api/apiNodes'
import { nodeInterfacesApi } from '../../../api/nodeInterfaces'
import { networkConfigApi } from '../../../api/networkConfig'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

const NODES = {
  items: [
    { id: 'node-a', node_name: 'gw-a' },
    { id: 'node-b', node_name: 'gw-b' },
  ],
}

const GROUP: HaGroup = {
  id: 'g1',
  name: 'ha-main',
  state: 'ENABLED',
  vrid: 51,
  iface: 'eth0',
  vips: ['192.168.31.100/24'],
  preempt: false,
  advert_int_ms: 1000,
  unicast: false,
  unicast_peers: [],
  track_interfaces: [],
  has_auth_pass: true,
  members: [
    { node_id: 'node-a', node_name: 'gw-a', priority: 120 },
    { node_id: 'node-b', node_name: 'gw-b', priority: 100 },
  ],
  version: 3,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <HaGroupsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('HaGroupsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiNodesApi.list).mockResolvedValue(NODES as never)
    vi.mocked(haGroupsApi.list).mockResolvedValue({ items: [GROUP], status: null })
    vi.mocked(haGroupsApi.listEvents).mockResolvedValue({
      items: [],
      page: 1,
      page_size: 20,
      total: 0,
    })
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({ nodes: [] })
    vi.mocked(networkConfigApi.get).mockResolvedValue({
      desired: { bridges: [], ip_forward: false, routes: [] },
      status: null,
    })
    useAuthStore.setState({
      user: makeUser(['ha.read', 'ha.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  it('渲染主备组列表：组名/VIP/成员优先级/回切与删除按钮，不展示危险批量删除按钮', async () => {
    renderPage()
    expect(await screen.findByText('ha-main')).toBeInTheDocument()
    expect(screen.getByText('192.168.31.100/24')).toBeInTheDocument()
    expect(screen.getByText('gw-a（120）')).toBeInTheDocument()
    expect(screen.getByText('gw-b（100）')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '回切-ha-main' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '删除-ha-main' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: /批量删除/ })).not.toBeInTheDocument()
    expect(screen.getByText(/havipd 未运行或未下发配置/)).toBeInTheDocument()
  })

  it('单节点运行状态回退：状态徽标与 status.events 漂移时间线', async () => {
    vi.mocked(haGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      status: {
        group: 'ha-main',
        node: 'gw-b',
        state: 'MASTER',
        keepalived_running: true,
        vips_present: ['192.168.31.100/24'],
        priority: 100,
        last_transition_at: '2026-08-19T02:03:00Z',
        events: [
          {
            at: '2026-08-19T02:03:00Z',
            from: 'BACKUP',
            to: 'MASTER',
            detail: '持有 VIP: 192.168.31.100/24',
          },
        ],
      },
    })
    renderPage()
    expect(await screen.findByText('主节点（持有 VIP）')).toBeInTheDocument()
    expect(screen.getByText('keepalived 运行中')).toBeInTheDocument()
    expect(screen.getByText('备节点（待命） → 主节点（持有 VIP）')).toBeInTheDocument()
  })

  it('多节点汇聚状态与脑裂告警：展示全部成员状态卡片与红色脑裂横幅', async () => {
    vi.mocked(haGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      status: null,
      split_brain: true,
      node_statuses: {
        'gw-a': {
          node_name: 'gw-a',
          source: 'local',
          fresh: true,
          updated_at: '2026-11-24T12:00:00Z',
          status: {
            group: 'ha-main',
            node: 'gw-a',
            state: 'MASTER',
            keepalived_running: true,
            vips_present: ['192.168.31.100/24'],
            priority: 120,
          },
        },
        'gw-b': {
          node_name: 'gw-b',
          source: 'remote',
          fresh: true,
          updated_at: '2026-11-24T12:00:02Z',
          status: {
            group: 'ha-main',
            node: 'gw-b',
            state: 'MASTER',
            keepalived_running: true,
            vips_present: ['192.168.31.100/24'],
            priority: 100,
          },
        },
      },
    })
    renderPage()
    const sbBanner = await screen.findByText(/检测到主备双主脑裂（HA_SPLIT_BRAIN）/)
    expect(sbBanner.closest('.ant-alert-error')).toBeTruthy()
    expect(screen.getByText('成员节点运行状态')).toBeInTheDocument()
    expect(screen.getByText('本机')).toBeInTheDocument()
    expect(screen.getByText('远端')).toBeInTheDocument()
    expect(screen.getAllByText('主节点（持有 VIP）')).toHaveLength(2)
    // 脑裂态不盲判唯一 VIP 持有方
    expect(screen.getByText('VIP 持有：未知')).toBeInTheDocument()
  })

  it('持久化事件时间线与类型筛选：调用 GET /ha/events 并支持切换 event_type', async () => {
    vi.mocked(haGroupsApi.listEvents).mockResolvedValue({
      items: [
        {
          id: 11,
          group_id: 'g1',
          group_name: 'ha-main',
          node_name: 'gw-b',
          event_type: 'FAILBACK',
          detail: { message: '已交换成员优先级并重新下发', operator: 'admin' },
          occurred_at: '2026-11-24T10:00:00Z',
        },
      ],
      page: 1,
      page_size: 20,
      total: 1,
    })
    renderPage()
    expect(await screen.findByText('人工回切')).toBeInTheDocument()
    expect(screen.getByText(/已交换成员优先级并重新下发；操作人：admin/)).toBeInTheDocument()

    // 切换事件类型筛选
    fireEvent.mouseDown(screen.getByLabelText('事件类型筛选'))
    await waitFor(() =>
      expect(
        document.querySelectorAll(
          '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content',
        ).length,
      ).toBeGreaterThan(0),
    )
    const splitOpt = Array.from(
      document.querySelectorAll(
        '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content',
      ),
    ).find((el) => el.textContent === '双主脑裂')
    expect(splitOpt).toBeTruthy()
    fireEvent.click(splitOpt as HTMLElement)

    await waitFor(() =>
      expect(haGroupsApi.listEvents).toHaveBeenCalledWith(
        expect.objectContaining({ event_type: 'SPLIT_BRAIN' }),
      ),
    )
  })

  it('新建主备组：提交体含成员、VIP 与 track_interfaces，并展示逐节点同步结果', async () => {
    vi.mocked(haGroupsApi.create).mockResolvedValue({
      group: GROUP,
      sync_results: [
        { node_name: 'gw-a', scope: 'local', status: 'SUCCESS' },
        { node_name: 'gw-b', scope: 'remote', status: 'FAILED', error: 'dial tcp timeout' },
      ],
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建主备组/ }))
    fireEvent.change(await screen.findByPlaceholderText('如 ha-main'), { target: { value: 'ha-new' } })
    fireEvent.change(screen.getByPlaceholderText('如 eth0'), { target: { value: 'eth1' } })

    // VIP（tags 输入回车）
    const vipInput = document.querySelector<HTMLInputElement>('#vips')
    expect(vipInput).toBeTruthy()
    fireEvent.change(vipInput!, { target: { value: '10.0.0.100/24' } })
    fireEvent.keyDown(vipInput!, { key: 'Enter', code: 'Enter' })

    const clickOpenDropdownOption = async (text: string) => {
      await waitFor(() =>
        expect(
          document.querySelectorAll(
            '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content',
          ).length,
        ).toBeGreaterThan(0),
      )
      const opt = Array.from(
        document.querySelectorAll(
          '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content',
        ),
      ).find((el) => el.textContent === text)
      expect(opt).toBeTruthy()
      fireEvent.click(opt as HTMLElement)
    }

    // 跟踪接口（tags 模式：输入后选择下拉条目）
    const trackInput = document.querySelector<HTMLInputElement>('#track_interfaces')
    expect(trackInput).toBeTruthy()
    fireEvent.mouseDown(trackInput!)
    fireEvent.change(trackInput!, { target: { value: 'eth2' } })
    await clickOpenDropdownOption('eth2')

    fireEvent.mouseDown(screen.getByLabelText('成员节点1'))
    await clickOpenDropdownOption('gw-a')
    fireEvent.mouseDown(screen.getByLabelText('成员节点2'))
    await clickOpenDropdownOption('gw-b')

    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    await waitFor(() => expect(haGroupsApi.create).toHaveBeenCalledTimes(1))
    const body = vi.mocked(haGroupsApi.create).mock.calls[0][0]
    expect(body.name).toBe('ha-new')
    expect(body.iface).toBe('eth1')
    expect(body.vips).toEqual(['10.0.0.100/24'])
    expect(body.track_interfaces).toEqual(['eth2'])
    expect(body.members).toHaveLength(2)
    expect(body.auth_pass).toBeUndefined()

    // 展示逐节点同步结果（含远端失败原因）
    expect(await screen.findByText('创建主备组节点同步结果')).toBeInTheDocument()
    expect(screen.getByText('同步成功')).toBeInTheDocument()
    expect(screen.getByText('同步失败')).toBeInTheDocument()
    expect(screen.getByText('dial tcp timeout')).toBeInTheDocument()
  })

  it('编辑主备组：openEdit 重置残留字段，不勾选清除时留空不改认证串，勾选清除时提交空串', async () => {
    vi.mocked(haGroupsApi.update).mockResolvedValue({
      group: GROUP,
      sync_results: [{ node_name: 'gw-a', scope: 'local', status: 'SUCCESS' }],
    })
    renderPage()

    // 第一次打开编辑并输入非法字符后取消，验证下次 openEdit 不会残留
    fireEvent.click(await screen.findByRole('button', { name: '编辑-ha-main' }))
    const pwdInput = await screen.findByPlaceholderText('已配置（留空不变更）')
    fireEvent.change(pwdInput, { target: { value: 'bad pass' } })
    fireEvent.click(screen.getByRole('button', { name: /^取\s*消$/ }))

    // 第二次打开编辑：密码框已重置为空，直接保存应不携带 auth_pass
    fireEvent.click(screen.getByRole('button', { name: '编辑-ha-main' }))
    const pwdInput2 = await screen.findByPlaceholderText('已配置（留空不变更）')
    expect((pwdInput2 as HTMLInputElement).value).toBe('')
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    await waitFor(() => expect(haGroupsApi.update).toHaveBeenCalledTimes(1))
    expect(vi.mocked(haGroupsApi.update).mock.calls[0][1].auth_pass).toBeUndefined()

    // 第三次打开编辑：勾选「清除已有 VRRP 认证串」，提交 auth_pass: ''
    fireEvent.click(screen.getByRole('button', { name: '编辑-ha-main' }))
    const clearCheckbox = await screen.findByLabelText('清除已有 VRRP 认证串')
    fireEvent.click(clearCheckbox)
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    await waitFor(() => expect(haGroupsApi.update).toHaveBeenCalledTimes(2))
    expect(vi.mocked(haGroupsApi.update).mock.calls[1][1].auth_pass).toBe('')
  })

  it('表单前端校验：拦截非法 auth_pass、非 IPv4 CIDR 的 VIP 与非整秒 advert_int_ms', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建主备组/ }))
    fireEvent.change(await screen.findByPlaceholderText('如 ha-main'), { target: { value: 'ha-val' } })
    fireEvent.change(screen.getByPlaceholderText('如 eth0'), { target: { value: 'eth0' } })

    const vipInput = document.querySelector<HTMLInputElement>('#vips')!
    fireEvent.change(vipInput, { target: { value: '2001:db8::1/64' } })
    fireEvent.keyDown(vipInput, { key: 'Enter', code: 'Enter' })

    const pwdInput = screen.getByPlaceholderText('可选')
    fireEvent.change(pwdInput, { target: { value: 'abc{1}' } })

    const advertInput = document.querySelector<HTMLInputElement>('#advert_int_ms')!
    fireEvent.change(advertInput, { target: { value: '1500' } })

    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))

    expect(await screen.findByText(/格式非法，需 IPv4 CIDR/)).toBeInTheDocument()
    expect(screen.getByText(/仅允许 1~8 位字母、数字及/)).toBeInTheDocument()
    expect(screen.getByText(/需为 1000~10000ms 且为 1000 的整秒倍数/)).toBeInTheDocument()
    expect(haGroupsApi.create).not.toHaveBeenCalled()
  })

  it('回切：确认后调用 failback（持有方未知时退回低优先级成员）', async () => {
    vi.mocked(haGroupsApi.failback).mockResolvedValue({ message: '已回切' })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '回切-ha-main' }))
    fireEvent.click(await screen.findByRole('button', { name: '确认回切' }))
    await waitFor(() => expect(haGroupsApi.failback).toHaveBeenCalledWith('g1', 'node-b'))
  })

  it('nopreempt 故障转移后：优先依据 node_statuses 判定 VIP 持有方并回切至原主节点', async () => {
    vi.mocked(haGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      status: null,
      split_brain: false,
      node_statuses: {
        'gw-a': {
          node_name: 'gw-a',
          source: 'local',
          fresh: true,
          status: {
            group: 'ha-main',
            node: 'gw-a',
            state: 'BACKUP',
            keepalived_running: true,
            vips_present: [],
            priority: 120,
          },
        },
        'gw-b': {
          node_name: 'gw-b',
          source: 'remote',
          fresh: true,
          status: {
            group: 'ha-main',
            node: 'gw-b',
            state: 'MASTER',
            keepalived_running: true,
            vips_present: ['192.168.31.100/24'],
            priority: 100,
          },
        },
      },
    })
    vi.mocked(haGroupsApi.failback).mockResolvedValue({
      message: '已回切',
      sync_results: [
        { node_name: 'gw-a', scope: 'local', status: 'SUCCESS' },
        { node_name: 'gw-b', scope: 'remote', status: 'SUCCESS' },
      ],
    })
    renderPage()
    expect(await screen.findByText('VIP 持有：gw-b')).toBeInTheDocument()
    expect(screen.getByText('gw-b（100）·持有 VIP')).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: '回切-ha-main' }))
    expect((await screen.findAllByText('将 VIP 回切到节点「gw-a」？')).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: '确认回切' }))
    await waitFor(() => expect(haGroupsApi.failback).toHaveBeenCalledWith('g1', 'node-a'))
  })

  it('无 ha.manage 权限时操作按钮禁用', async () => {
    useAuthStore.setState({ user: makeUser(['ha.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('ha-main')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /新建主备组/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '回切-ha-main' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '删除-ha-main' })).toBeDisabled()
  })

  it('VIP 承载网卡自动排除网桥成员口并拦截手工填报桥接口，同时在 track_interfaces 自动推荐网桥成员口', async () => {
    useAuthStore.setState({
      user: makeUser(['ha.read', 'ha.manage', 'system_health.read']),
      csrfToken: null,
      initialized: true,
    })
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({
      nodes: [
        {
          node_name: 'gw-a',
          interfaces: [
            {
              ifname: 'eth0',
              mac: '00:11:22:33:44:01',
              pci_path: '0000:01:00.0',
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
              pci_path: '0000:01:00.1',
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
              pci_path: '0000:01:00.2',
              driver: 'igb',
              media_type: 'TP',
              link_speed: 1000,
              operstate: 'up',
              sort_order: 3,
              role: 'TRAFFIC',
              present: true,
            },
            {
              ifname: 'eth3',
              mac: '00:11:22:33:44:04',
              pci_path: '0000:01:00.3',
              driver: 'ixgbe',
              media_type: 'FIBRE',
              link_speed: 10000,
              operstate: 'up',
              sort_order: 4,
              role: 'MIRROR',
              present: true,
            },
            {
              ifname: 'eth4',
              mac: '00:11:22:33:44:05',
              pci_path: '0000:01:00.4',
              driver: 'igb',
              media_type: 'TP',
              link_speed: 1000,
              operstate: 'up',
              sort_order: 5,
              role: '',
              present: true,
            },
          ],
        },
      ],
    })
    vi.mocked(networkConfigApi.get).mockResolvedValue({
      default_node: 'gw-a',
      desired: {
        bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
        ip_forward: false,
        routes: [],
      },
      status: null,
    })

    renderPage()
    expect(await screen.findByText(/并通过协同代理（hasyncd）推送至已登记的远端成员节点/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /新建主备组/ }))
    const ifaceInput = await screen.findByPlaceholderText('如 eth0')
    expect(screen.getByText(/已排除网桥成员口（eth1、eth2）/)).toBeInTheDocument()

    // 展开承载网卡 AutoComplete 下拉：仅含非桥接、非镜像在线网口 eth0 / eth4
    fireEvent.mouseDown(ifaceInput)
    await waitFor(() =>
      expect(
        document.querySelectorAll('.ant-select-item-option-content').length,
      ).toBeGreaterThan(0),
    )
    const opts = Array.from(document.querySelectorAll('.ant-select-item-option-content')).map(
      (el) => el.textContent,
    )
    expect(opts).toContain('eth0（管理口）')
    expect(opts).toContain('eth4')
    expect(opts.some((t) => t?.includes('eth1'))).toBe(false)
    expect(opts.some((t) => t?.includes('eth2'))).toBe(false)
    expect(opts.some((t) => t?.includes('eth3'))).toBe(false)

    // 展开 track_interfaces 下拉：自动推荐网桥成员口 eth1 / eth2
    fireEvent.mouseDown(screen.getByLabelText('关联跟踪接口'))
    await waitFor(() =>
      expect(
        Array.from(
          document.querySelectorAll(
            '.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content',
          ),
        ).some((el) => el.textContent?.includes('eth1（网桥 br0 成员口 · 推荐）')),
      ).toBe(true),
    )

    // 手工输入桥成员口 eth1 到承载网卡：出现告警且阻止表单提交
    fireEvent.change(screen.getByPlaceholderText('如 ha-main'), { target: { value: 'ha-bridge' } })
    fireEvent.change(ifaceInput, { target: { value: 'eth1' } })
    expect(
      await screen.findByText(/接口「eth1」已分配给网桥「br0」，不能作为 VIP 承载网卡/),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    expect(
      await screen.findByText(/接口 eth1 为网桥 br0 成员口，不得作为 VIP 承载网卡/),
    ).toBeInTheDocument()
    expect(haGroupsApi.create).not.toHaveBeenCalled()
  })
})
