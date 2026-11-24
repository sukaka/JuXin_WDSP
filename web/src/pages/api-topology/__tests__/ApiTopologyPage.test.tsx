import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import type { ApiGraphEdge, ApiTopologyGroup } from '../../../api/apiSecurity'
import ApiTopologyPage from '../ApiTopologyPage'

vi.mock('../../../components/EChart', () => ({
  default: ({ ariaLabel }: { ariaLabel: string }) => (
    <div data-testid="echart-stub" aria-label={ariaLabel} />
  ),
}))

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function buildLargeDataset(): { applications: ApiTopologyGroup[]; edges: ApiGraphEdge[] } {
  const endpoints = [
    {
      id: 'ep-long',
      endpoint_key: 'GET /admin-api/infra/file/{id}/get/{id}/favicon_264x263_1789992768080.jpg',
      http_method: 'GET',
      normalized_path: '/admin-api/infra/file/{id}/get/{id}/favicon_264x263_1789992768080.jpg',
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
      application_id: 'app-site',
      hit_count: 980,
      open_findings_count: 2,
    },
    {
      id: 'ep-sys-1',
      endpoint_key: 'POST /admin-api/system/tenant/get-id-by-name',
      http_method: 'POST',
      normalized_path: '/admin-api/system/tenant/get-id-by-name',
      asset_status: 'DISCOVERED',
      learning_status: 'LEARNING',
      application_id: 'app-site',
      hit_count: 420,
      open_findings_count: 0,
    },
    {
      id: 'ep-probe-1',
      endpoint_key: 'GET /.env',
      http_method: 'GET',
      normalized_path: '/.env',
      asset_status: 'IGNORED',
      learning_status: 'NOT_STARTED',
      application_id: 'app-site',
      hit_count: 5,
      open_findings_count: 0,
    },
    ...Array.from({ length: 120 }, (_, i) => ({
      id: `ep-bulk-${i}`,
      endpoint_key: `GET /admin-api/customer/record/item-${i}`,
      http_method: 'GET',
      normalized_path: `/admin-api/customer/record/item-${i}`,
      asset_status: 'DISCOVERED',
      learning_status: 'NOT_STARTED',
      application_id: 'app-site',
      hit_count: 100 - (i % 50),
      open_findings_count: 0,
    })),
  ]

  const edges: ApiGraphEdge[] = [
    {
      id: 'edge-1',
      caller_fingerprint: 'fp-caller-abcdef1234567890',
      source_endpoint_id: 'ep-sys-1',
      target_endpoint_id: 'ep-long',
      call_count: 88,
      identity_count: 4,
      first_seen_at: '2026-11-23T01:00:00Z',
      last_seen_at: '2026-11-23T09:30:00Z',
    },
  ]

  return {
    applications: [
      {
        application_id: 'app-site',
        application_name: '官网',
        endpoints,
      },
    ],
    edges,
  }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/api-topology']}>
          <ApiTopologyPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApiTopologyPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('海量接口按路径分组与分页展示，不平铺撑长页面，且长路径带单行省略容器与详情抽屉', async () => {
    const dataset = buildLargeDataset()
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(dataset))),
    )
    renderPage()

    expect(await screen.findByText('API 调用拓扑')).toBeInTheDocument()
    // 汇总带展示总接口数 123
    expect(await screen.findByText('123 个接口')).toBeInTheDocument()

    // 接口列表按默认每页 10 条分页渲染，不会一次性把 123 个全部平铺进 DOM
    const workspace = screen.getByLabelText('接口与拓扑展示区')
    const endpointRows = within(workspace).getAllByRole('row')
    // 1 行表头 + 10 行数据
    expect(endpointRows.length).toBeLessThanOrEqual(12)

    // 长 API 路径渲染在严格省略容器中，且点击详情后抽屉完整展示路径与上下游调用边
    const longPath = '/admin-api/infra/file/{id}/get/{id}/favicon_264x263_1789992768080.jpg'
    const pathEl = within(workspace).getByText(longPath)
    expect(pathEl).toHaveClass('api-topology-path-text')

    const firstRow = pathEl.closest('tr') as HTMLElement
    fireEvent.click(within(firstRow).getByRole('button', { name: '详情' }))

    const drawerTitle = await screen.findByText('接口拓扑详情', { selector: '.ant-drawer-title' })
    const drawer = drawerTitle.closest('.ant-drawer') as HTMLElement
    expect(within(drawer).getByText(longPath)).toBeInTheDocument()
    expect(within(drawer).getByText('上游调用关系（共 1 条）')).toBeInTheDocument()
    expect(within(drawer).getByText('POST /admin-api/system/tenant/get-id-by-name')).toBeInTheDocument()
  })

  it('支持路径树下钻、快速过滤与切换至拓扑图画布', async () => {
    const dataset = buildLargeDataset()
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(dataset))),
    )
    renderPage()

    await screen.findByText('123 个接口')
    const nav = screen.getByLabelText('路径分组导航')

    // 点击「根路径与单段」只看 /.env
    fireEvent.click(within(nav).getByRole('button', { name: /根路径与单段/ }))
    const workspace = screen.getByLabelText('接口与拓扑展示区')
    expect(within(workspace).getByText('/.env')).toBeInTheDocument()
    expect(within(workspace).getByText('1 / 123 个接口')).toBeInTheDocument()

    // 返回全部后点击「仅有风险」，仅保留含未闭环风险的接口
    fireEvent.click(within(workspace).getByRole('button', { name: /返回全部/ }))
    fireEvent.click(within(workspace).getByRole('button', { name: '仅有风险' }))
    expect(within(workspace).getByText('1 / 123 个接口')).toBeInTheDocument()

    // 重置筛选并切换到拓扑图模式，渲染模块聚合画布
    fireEvent.click(within(workspace).getByRole('button', { name: '重置筛选' }))
    fireEvent.click(within(workspace).getByRole('radio', { name: /拓扑图/ }))
    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    expect(within(workspace).getByText('模块聚合拓扑')).toBeInTheDocument()
  })

  it('时间窗与最小调用数会向后端透传查询参数，并能打开中文化的调用边详情抽屉', async () => {
    const dataset = buildLargeDataset()
    const requestedUrls: string[] = []
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      requestedUrls.push(String(input))
      return Promise.resolve(jsonResponse(dataset))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    await screen.findByText('123 个接口')

    // 切换时间窗为近 24 小时，确认请求携带 start & end
    fireEvent.click(screen.getByRole('radio', { name: '近 24 小时' }))
    await waitFor(() => {
      expect(
        requestedUrls.some(
          (u) => u.includes('/api-security/topology?') && u.includes('start=') && u.includes('end='),
        ),
      ).toBe(true)
    })

    // 打开调用边明细抽屉，核对中文字段标签与解析后的接口键
    const edgeButtons = await screen.findAllByRole('button', { name: '详情' })
    fireEvent.click(edgeButtons[edgeButtons.length - 1])
    const drawerTitle = await screen.findByText('调用边详情', { selector: '.ant-drawer-title' })
    const drawer = drawerTitle.closest('.ant-drawer') as HTMLElement
    expect(within(drawer).getByText('调用方指纹')).toBeInTheDocument()
    expect(within(drawer).getByText('目标接口')).toBeInTheDocument()
    expect(within(drawer).getByText('涉及身份数')).toBeInTheDocument()
  })

  it('多应用模式下展示应用切换卡片并按选中应用联动接口与调用边', async () => {
    const multiDataset: { applications: ApiTopologyGroup[]; edges: ApiGraphEdge[] } = {
      applications: [
        {
          application_id: 'app-a',
          application_name: '官网门户',
          endpoints: [
            {
              id: 'a-1',
              endpoint_key: 'GET /portal/home',
              http_method: 'GET',
              normalized_path: '/portal/home',
              asset_status: 'CONFIRMED',
              learning_status: 'LEARNED',
              application_id: 'app-a',
              hit_count: 50,
              open_findings_count: 0,
            },
          ],
        },
        {
          application_id: 'app-b',
          application_name: '支付网关',
          endpoints: [
            {
              id: 'b-1',
              endpoint_key: 'POST /pay/v1/orders',
              http_method: 'POST',
              normalized_path: '/pay/v1/orders',
              asset_status: 'DISCOVERED',
              learning_status: 'NOT_STARTED',
              application_id: 'app-b',
              hit_count: 120,
              open_findings_count: 1,
            },
          ],
        },
      ],
      edges: [
        {
          id: 'edge-b',
          caller_fingerprint: 'fp-pay-caller-0011223344',
          target_endpoint_id: 'b-1',
          call_count: 30,
          identity_count: 2,
          last_seen_at: '2026-11-23T09:00:00Z',
        },
      ],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(multiDataset))),
    )
    renderPage()

    const appList = await screen.findByRole('tablist', { name: '应用筛选' })
    expect(within(appList).getByRole('tab', { name: /全部应用/ })).toHaveAttribute(
      'aria-selected',
      'true',
    )

    // 切换到「支付网关」
    fireEvent.click(within(appList).getByRole('tab', { name: /支付网关/ }))
    const workspace = screen.getByLabelText('接口与拓扑展示区')
    expect(within(workspace).getByText('/pay/v1/orders')).toBeInTheDocument()
    expect(within(workspace).queryByText('/portal/home')).not.toBeInTheDocument()
  })
})
