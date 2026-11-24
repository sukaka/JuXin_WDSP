import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import NodeInterfacesPage from '../NodeInterfacesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, NodeInterfacesNode } from '../../../types'

vi.mock('../../../api/nodeInterfaces', () => ({
  nodeInterfacesApi: {
    list: vi.fn(),
    saveOrder: vi.fn(),
  },
}))

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
        ip_addresses: ['192.168.10.2/24', '2408:8207::2/64'],
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
        ip_addresses: ['10.0.1.5/24'],
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
        ip_addresses: [],
        pci_path: '0000:04:00.0',
        driver: 'ixgbe',
        media_type: 'FIBRE',
        link_speed: 0,
        operstate: 'down',
        sort_order: 3,
        role: '',
        present: true,
      },
      {
        ifname: 'eth3',
        mac: '00:11:22:33:44:04',
        ip_addresses: [],
        pci_path: '0000:04:00.1',
        driver: 'ixgbe',
        media_type: 'FIBRE',
        link_speed: 10000,
        operstate: 'up',
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
        media_type: 'UNKNOWN',
        link_speed: 1000,
        operstate: 'up',
        sort_order: 1,
        role: '',
        present: true,
      },
    ],
  },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <NodeInterfacesPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('NodeInterfacesPage', () => {
  beforeEach(() => {
    vi.mocked(nodeInterfacesApi.list).mockReset()
    vi.mocked(nodeInterfacesApi.saveOrder).mockReset()
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({ nodes })
    vi.mocked(nodeInterfacesApi.saveOrder).mockResolvedValue({ nodes })
  })

  it('渲染节点分组与接口行：介质标签、速率、断开与已离线标注', async () => {
    useAuthStore.setState({
      user: makeUser(['system_health.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('eth0')).toBeInTheDocument()
    // 节点 Tabs
    expect(screen.getByRole('tab', { name: 'node-1' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'node-2' })).toBeInTheDocument()
    // 默认展示 node-1：接口名 / IP 地址 / MAC / PCI / 驱动
    expect(screen.getByText('eth1')).toBeInTheDocument()
    expect(screen.getByText('192.168.10.2/24')).toBeInTheDocument()
    expect(screen.getByText('2408:8207::2/64')).toBeInTheDocument()
    expect(screen.getByText('10.0.1.5/24')).toBeInTheDocument()
    expect(screen.getByText('00:11:22:33:44:01')).toBeInTheDocument()
    expect(screen.getByText('0000:03:00.0')).toBeInTheDocument()
    expect(screen.getAllByText('igb')).toHaveLength(2)
    // 介质类型：电口 ×2、光口 ×2
    expect(screen.getAllByText('电口')).toHaveLength(2)
    expect(screen.getAllByText('光口')).toHaveLength(2)
    // 速率：在线口显示速率，DOWN 口显示断开
    expect(screen.getAllByText('1000 Mb/s')).toHaveLength(2)
    expect(screen.getByText('断开')).toBeInTheDocument()
    expect(screen.getByText('10000 Mb/s')).toBeInTheDocument()
    // present=false 标注已离线，在线口标注在线
    expect(screen.getByText('已离线')).toBeInTheDocument()
    expect(screen.getAllByText('在线')).toHaveLength(3)
    // 未改动前保存按钮不可用
    expect(screen.getByRole('button', { name: /保存排序/ })).toBeDisabled()
  })

  it('上下移动后保存：PUT 提交体为当前顺序与角色', async () => {
    useAuthStore.setState({
      user: makeUser(['system_health.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('eth0')).toBeInTheDocument()
    // 第一行下移：eth0 与 eth1 交换
    fireEvent.click(screen.getAllByRole('button', { name: '下移' })[0])
    const saveBtn = screen.getByRole('button', { name: /保存排序/ })
    expect(saveBtn).toBeEnabled()
    fireEvent.click(saveBtn)
    await waitFor(() => expect(nodeInterfacesApi.saveOrder).toHaveBeenCalledTimes(1))
    expect(nodeInterfacesApi.saveOrder).toHaveBeenCalledWith({
      node_name: 'node-1',
      items: [
        { ifname: 'eth1', sort_order: 1, role: 'TRAFFIC' },
        { ifname: 'eth0', sort_order: 2, role: 'MANAGEMENT' },
        { ifname: 'eth2', sort_order: 3, role: '' },
        { ifname: 'eth3', sort_order: 4, role: '' },
      ],
    })
    // 保存成功后回到未修改状态
    await waitFor(() => expect(screen.getByRole('button', { name: /保存排序/ })).toBeDisabled())
  })

  it('无 system_settings.update 权限：隐藏保存按钮，排序与角色控件禁用', async () => {
    useAuthStore.setState({
      user: makeUser(['system_health.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('eth0')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存排序/ })).not.toBeInTheDocument()
    for (const btn of screen.getAllByRole('button', { name: '上移' })) {
      expect(btn).toBeDisabled()
    }
    for (const btn of screen.getAllByRole('button', { name: '下移' })) {
      expect(btn).toBeDisabled()
    }
    expect(screen.getByLabelText('角色-eth0')).toBeDisabled()
  })

  it('有未保存修改时切换节点：确认放弃后切换并丢弃本地修改', async () => {
    useAuthStore.setState({
      user: makeUser(['system_health.read', 'system_settings.update']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('eth0')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: '下移' })[0])
    expect(screen.getByText('有未保存的修改')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'node-2' }))
    // 弹出确认框，确认后切换到 node-2
    fireEvent.click(await screen.findByRole('button', { name: '放弃修改' }))
    expect(await screen.findByText('eno1')).toBeInTheDocument()
    expect(screen.queryByText('eth0')).not.toBeInTheDocument()
    // 本地修改已丢弃，未发起保存
    expect(nodeInterfacesApi.saveOrder).not.toHaveBeenCalled()
  })

  it('虚拟网卡在线但速率为 0 时显示「未知」而非「断开」，且展示主机 IP', async () => {
    vi.mocked(nodeInterfacesApi.list).mockResolvedValue({
      nodes: [
        {
          node_name: 'gateway-poc-01',
          interfaces: [
            {
              ifname: 'eth0',
              mac: '00:16:3e:6c:fd:83',
              ip_addresses: ['172.16.0.10/24'],
              pci_path: '',
              driver: 'virtio_net',
              media_type: 'UNKNOWN',
              link_speed: 0,
              operstate: 'up',
              sort_order: 1,
              role: '',
              present: true,
            },
          ],
        },
      ],
    })
    useAuthStore.setState({
      user: makeUser(['system_health.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('eth0')).toBeInTheDocument()
    expect(screen.getByText('172.16.0.10/24')).toBeInTheDocument()
    expect(screen.queryByText('断开')).not.toBeInTheDocument()
    // 介质类型与速率均为「未知」
    expect(screen.getAllByText('未知')).toHaveLength(2)
  })
})
