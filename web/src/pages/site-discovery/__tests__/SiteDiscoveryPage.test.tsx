import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SiteDiscoveryPage from '../SiteDiscoveryPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { SiteDiscoveryItem } from '../../../api/siteDiscovery'

vi.mock('../../../api/siteDiscovery', () => ({
  siteDiscoveryApi: {
    list: vi.fn(),
    confirm: vi.fn(),
    ignore: vi.fn(),
    restore: vi.fn(),
  },
}))

import { siteDiscoveryApi } from '../../../api/siteDiscovery'

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

function makeItem(overrides: Partial<SiteDiscoveryItem>): SiteDiscoveryItem {
  return {
    id: 'd-0',
    domain: 'shop.example.com',
    ip: '10.0.0.5',
    port: 443,
    protocol: 'HTTPS',
    source_mode: 'MIRROR',
    gateway_node: 'gw-1',
    seen_count: 123,
    client_count: 17,
    first_seen: '2026-08-20T04:00:00Z',
    last_seen: '2026-08-21T04:00:30Z',
    status: 'NEW',
    confirmed_by: '',
    confirmed_at: null,
    created_at: '2026-08-20T04:00:00Z',
    updated_at: '2026-08-21T04:00:30Z',
    ...overrides,
  }
}

const items: SiteDiscoveryItem[] = [
  makeItem({ id: 'd-1' }),
  // 无 SNI 的 HTTPS 握手：域名为空串，页面展示「未识别」
  makeItem({ id: 'd-2', domain: '', ip: '10.0.0.9', port: 8080, protocol: 'HTTP', source_mode: 'ROUTED' }),
  makeItem({ id: 'd-3', domain: 'api.example.com', source_mode: 'TRANSPARENT', status: 'CONFIRMED' }),
  makeItem({ id: 'd-4', domain: 'old.example.com', status: 'IGNORED' }),
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <SiteDiscoveryPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 点击占位文本所属 Select 的下拉项（与表头同文案时按 .ant-select-placeholder 消歧） */
async function selectOption(placeholder: string, optionText: string) {
  const candidates = screen.getAllByText(placeholder)
  const target = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
  fireEvent.mouseDown(target)
  const options = await screen.findAllByText(optionText)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('SiteDiscoveryPage', () => {
  beforeEach(() => {
    vi.mocked(siteDiscoveryApi.list).mockReset()
    vi.mocked(siteDiscoveryApi.confirm).mockReset()
    vi.mocked(siteDiscoveryApi.ignore).mockReset()
    vi.mocked(siteDiscoveryApi.restore).mockReset()
    vi.mocked(siteDiscoveryApi.list).mockResolvedValue({ items, page: 1, page_size: 20, total: items.length })
    vi.mocked(siteDiscoveryApi.confirm).mockResolvedValue(makeItem({ id: 'd-1', status: 'CONFIRMED' }))
    vi.mocked(siteDiscoveryApi.ignore).mockResolvedValue(makeItem({ id: 'd-1', status: 'IGNORED' }))
    vi.mocked(siteDiscoveryApi.restore).mockResolvedValue(makeItem({ id: 'd-4', status: 'NEW' }))
    useAuthStore.setState({
      user: makeUser(['site_discovery.read', 'site_discovery.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  it('列表渲染：域名/IP/端口/协议/来源模式/节点/计数/时间/状态列', async () => {
    const { container } = renderPage()
    expect(await screen.findByText('shop.example.com')).toBeInTheDocument()
    const row = screen.getByText('shop.example.com').closest('tr') as HTMLElement
    expect(within(row).getByText('10.0.0.5')).toBeInTheDocument()
    expect(within(row).getByText('443')).toBeInTheDocument()
    expect(within(row).getByText('HTTPS')).toBeInTheDocument()
    expect(within(row).getByText('镜像旁路')).toBeInTheDocument()
    expect(within(row).getByText('gw-1')).toBeInTheDocument()
    expect(within(row).getByText('123')).toBeInTheDocument()
    expect(within(row).getByText('17')).toBeInTheDocument()
    expect(within(row).getByText('新发现')).toBeInTheDocument()

    // 空域名置灰显示「未识别」；路由牵引/透明串接中文映射
    const noDomainRow = screen.getByText('10.0.0.9').closest('tr') as HTMLElement
    expect(within(noDomainRow).getByText('未识别')).toBeInTheDocument()
    expect(within(noDomainRow).getByText('路由牵引')).toBeInTheDocument()
    const confirmedRow = screen.getByText('api.example.com').closest('tr') as HTMLElement
    expect(within(confirmedRow).getByText('透明串接')).toBeInTheDocument()
    expect(within(confirmedRow).getByText('已确认')).toBeInTheDocument()
    const ignoredRow = screen.getByText('old.example.com').closest('tr') as HTMLElement
    expect(within(ignoredRow).getByText('已忽略')).toBeInTheDocument()

    // 表头列名齐全（限定 thead 断言，避免与筛选占位文案冲突）
    const thead = container.querySelector('.ant-table-thead') as HTMLElement
    for (const title of ['域名', 'IP', '端口', '协议', '来源模式', '网关节点', '命中次数', '客户端数', '首次发现', '最近发现', '状态', '操作']) {
      expect(within(thead).getByText(title)).toBeInTheDocument()
    }
  })

  it('筛选参数传递：默认 status=NEW，切换协议/来源模式与关键字搜索', async () => {
    renderPage()
    await waitFor(() => expect(siteDiscoveryApi.list).toHaveBeenCalled())
    // 初始查询默认携带 status=NEW 与分页参数
    expect(siteDiscoveryApi.list).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: 'NEW', page: 1, page_size: 20 }),
    )

    await selectOption('协议', 'HTTPS')
    await waitFor(() =>
      expect(siteDiscoveryApi.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: 'NEW', protocol: 'HTTPS', page: 1 }),
      ),
    )

    await selectOption('来源模式', '镜像旁路')
    await waitFor(() =>
      expect(siteDiscoveryApi.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ protocol: 'HTTPS', source_mode: 'MIRROR', page: 1 }),
      ),
    )

    const search = screen.getByPlaceholderText('搜索域名或 IP')
    fireEvent.change(search, { target: { value: 'example.com' } })
    fireEvent.keyDown(search, { key: 'Enter', code: 'Enter' })
    await waitFor(() =>
      expect(siteDiscoveryApi.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ keyword: 'example.com', page: 1 }),
      ),
    )
  })

  it('行操作按状态显示：NEW 确认/忽略，CONFIRMED 忽略/恢复，IGNORED 恢复', async () => {
    renderPage()
    const newRow = (await screen.findByText('shop.example.com')).closest('tr') as HTMLElement
    expect(within(newRow).getByRole('button', { name: '确认' })).toBeInTheDocument()
    expect(within(newRow).getByRole('button', { name: '忽略' })).toBeInTheDocument()
    expect(within(newRow).queryByRole('button', { name: '恢复' })).not.toBeInTheDocument()

    const confirmedRow = screen.getByText('api.example.com').closest('tr') as HTMLElement
    expect(within(confirmedRow).queryByRole('button', { name: '确认' })).not.toBeInTheDocument()
    expect(within(confirmedRow).getByRole('button', { name: '忽略' })).toBeInTheDocument()
    expect(within(confirmedRow).getByRole('button', { name: '恢复' })).toBeInTheDocument()

    const ignoredRow = screen.getByText('old.example.com').closest('tr') as HTMLElement
    expect(within(ignoredRow).queryByRole('button', { name: '确认' })).not.toBeInTheDocument()
    expect(within(ignoredRow).queryByRole('button', { name: '忽略' })).not.toBeInTheDocument()
    expect(within(ignoredRow).getByRole('button', { name: '恢复' })).toBeInTheDocument()
  })

  it('确认/忽略/恢复调用对应 API 并刷新列表', async () => {
    renderPage()
    const newRow = (await screen.findByText('shop.example.com')).closest('tr') as HTMLElement
    const listCallsBefore = vi.mocked(siteDiscoveryApi.list).mock.calls.length

    fireEvent.click(within(newRow).getByRole('button', { name: '确认' }))
    await waitFor(() => expect(siteDiscoveryApi.confirm).toHaveBeenCalledWith('d-1'))
    expect(siteDiscoveryApi.ignore).not.toHaveBeenCalled()
    // 操作成功后失效查询，列表重新拉取
    await waitFor(() =>
      expect(vi.mocked(siteDiscoveryApi.list).mock.calls.length).toBeGreaterThan(listCallsBefore),
    )

    fireEvent.click(within(newRow).getByRole('button', { name: '忽略' }))
    await waitFor(() => expect(siteDiscoveryApi.ignore).toHaveBeenCalledWith('d-1'))

    const ignoredRow = screen.getByText('old.example.com').closest('tr') as HTMLElement
    fireEvent.click(within(ignoredRow).getByRole('button', { name: '恢复' }))
    await waitFor(() => expect(siteDiscoveryApi.restore).toHaveBeenCalledWith('d-4'))
  })
})
