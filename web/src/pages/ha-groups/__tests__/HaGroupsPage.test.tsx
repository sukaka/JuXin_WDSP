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
  },
}))

vi.mock('../../../api/apiNodes', () => ({
  apiNodesApi: {
    list: vi.fn(),
  },
}))

import { haGroupsApi } from '../../../api/haGroups'
import { apiNodesApi } from '../../../api/apiNodes'

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
    useAuthStore.setState({
      user: makeUser(['ha.read', 'ha.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  it('渲染主备组列表：组名/VIP/成员优先级/回切与删除按钮', async () => {
    renderPage()
    expect(await screen.findByText('ha-main')).toBeInTheDocument()
    expect(screen.getByText('192.168.31.100/24')).toBeInTheDocument()
    expect(screen.getByText('gw-a（120）')).toBeInTheDocument()
    expect(screen.getByText('gw-b（100）')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '回切-ha-main' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '删除-ha-main' })).toBeEnabled()
    // 未上报状态时展示提示
    expect(screen.getByText(/havipd 未运行或未下发配置/)).toBeInTheDocument()
  })

  it('运行状态：状态徽标与漂移时间线', async () => {
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
          { at: '2026-08-19T02:03:00Z', from: 'BACKUP', to: 'MASTER', detail: '持有 VIP: 192.168.31.100/24' },
        ],
      },
    })
    renderPage()
    expect(await screen.findByText('MASTER（持有 VIP）')).toBeInTheDocument()
    expect(screen.getByText('keepalived 运行中')).toBeInTheDocument()
    expect(screen.getByText('BACKUP → MASTER')).toBeInTheDocument()
  })

  it('新建主备组：提交体含成员与 VIP，保存后关闭弹窗并刷新', async () => {
    vi.mocked(haGroupsApi.create).mockResolvedValue({ group: GROUP })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建主备组/ }))
    // 填写表单
    fireEvent.change(await screen.findByPlaceholderText('如 ha-main'), { target: { value: 'ha-new' } })
    fireEvent.change(screen.getByPlaceholderText('如 eth0'), { target: { value: 'eth1' } })
    // VIP（tags 输入回车）
    const vipInput = document.querySelector<HTMLInputElement>('#vips')
    expect(vipInput).toBeTruthy()
    fireEvent.change(vipInput!, { target: { value: '10.0.0.100/24' } })
    fireEvent.keyDown(vipInput!, { key: 'Enter', code: 'Enter' })
    // 成员节点（单选 Select 选中后其下拉自动隐藏；选项点击限定在当前展开的下拉内）
    const clickOpenDropdownOption = async (text: string) => {
      await waitFor(() =>
        expect(
          document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content').length,
        ).toBeGreaterThan(0),
      )
      const opt = Array.from(
        document.querySelectorAll('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content'),
      ).find((el) => el.textContent === text)
      expect(opt).toBeTruthy()
      fireEvent.click(opt as HTMLElement)
    }
    fireEvent.mouseDown(screen.getByLabelText('成员节点1'))
    await clickOpenDropdownOption('gw-a')
    fireEvent.mouseDown(screen.getByLabelText('成员节点2'))
    await clickOpenDropdownOption('gw-b')
    // 提交
    fireEvent.click(screen.getByRole('button', { name: '保存并下发' }))
    await waitFor(() => expect(haGroupsApi.create).toHaveBeenCalledTimes(1))
    const body = vi.mocked(haGroupsApi.create).mock.calls[0][0]
    expect(body.name).toBe('ha-new')
    expect(body.iface).toBe('eth1')
    expect(body.vips).toEqual(['10.0.0.100/24'])
    expect(body.members).toHaveLength(2)
    expect(body.auth_pass).toBeUndefined()
  })

  it('回切：确认后调用 failback（持有方未知时退回低优先级成员）', async () => {
    vi.mocked(haGroupsApi.failback).mockResolvedValue({ message: '已回切' })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '回切-ha-main' }))
    // 确认弹窗的确定按钮
    fireEvent.click(await screen.findByRole('button', { name: '确认回切' }))
    await waitFor(() => expect(haGroupsApi.failback).toHaveBeenCalledWith('g1', 'node-b'))
  })

  it('nopreempt 故障转移后：回切目标为未持有 VIP 的原主节点，并展示当前持有方', async () => {
    // 配置 node-a=120 > node-b=100，但 VIP 实际在 gw-b（本节点状态 MASTER=gw-b）
    vi.mocked(haGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      status: {
        group: 'ha-main',
        node: 'gw-b',
        state: 'MASTER',
        keepalived_running: true,
        vips_present: ['192.168.31.100/24'],
        priority: 100,
      },
    })
    vi.mocked(haGroupsApi.failback).mockResolvedValue({ message: '已回切' })
    renderPage()
    // 按钮旁展示当前 VIP 持有节点，成员列标记持有方
    expect(await screen.findByText('VIP 持有：gw-b')).toBeInTheDocument()
    expect(screen.getByText('gw-b（100）·持有 VIP')).toBeInTheDocument()
    // 回切目标 = 未持有 VIP 的原主节点 gw-a（而非低优先级的持有方 gw-b）
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
})
