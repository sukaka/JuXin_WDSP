import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SharedDeviceAccountsDrawer from '../SharedDeviceAccountsDrawer'
import type {
  SharedDeviceAccount,
  SharedDeviceGroup,
  SharedDeviceQuery,
} from '../../../api/apiGroupControl'

const graphProps = vi.hoisted(
  () =>
    [] as {
      group: SharedDeviceGroup
      accounts: SharedDeviceAccount[]
    }[],
)

vi.mock('../SharedDeviceRelationshipGraph', () => ({
  default: (props: {
    group: SharedDeviceGroup
    accounts: SharedDeviceAccount[]
  }) => {
    graphProps.push(props)
    return (
      <div data-testid="shared-device-relationship-graph">
        {props.accounts.map((account) => account.principal_ref).join(',')}
      </div>
    )
  },
}))

const group: SharedDeviceGroup = {
  application_id: '11111111-1111-1111-1111-111111111111',
  application_name: '巡店协作平台',
  device_fingerprint: 'b3c7a91e'.repeat(4),
  distinct_accounts: 3,
  event_count: 18,
  signal_count: 2,
  endpoint_count: 4,
  gateway_node_count: 2,
  first_seen_at: '2026-11-14T08:00:00Z',
  last_seen_at: '2026-11-14T09:00:00Z',
}

const query: SharedDeviceQuery = {
  start: '2026-11-14T00:00:00Z',
  end: '2026-11-15T00:00:00Z',
  min_accounts: 2,
  page: 1,
  page_size: 20,
}

const firstPageAccounts: SharedDeviceAccount[] = [
  {
    principal_ref: '0123456789abcdef'.repeat(4),
    event_count: 7,
    signal_count: 1,
    endpoint_count: 2,
    first_seen_at: '2026-11-14T08:00:00Z',
    last_seen_at: '2026-11-14T09:00:00Z',
  },
  {
    principal_ref: '89abcdef01234567'.repeat(4),
    event_count: 5,
    signal_count: 0,
    endpoint_count: 1,
    first_seen_at: '2026-11-14T08:10:00Z',
    last_seen_at: '2026-11-14T09:10:00Z',
  },
]

const secondPageAccounts: SharedDeviceAccount[] = [
  {
    principal_ref: 'fedcba9876543210'.repeat(4),
    event_count: 4,
    signal_count: 1,
    endpoint_count: 1,
    first_seen_at: '2026-11-14T08:20:00Z',
    last_seen_at: '2026-11-14T09:20:00Z',
  },
]

function response(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function accountsResponse(
  items: SharedDeviceAccount[],
  page = 1,
  total = 45,
): Response {
  return response({
    items,
    page,
    page_size: 20,
    total,
    partial: false,
    data_scope: 'NOTABLE_SECURITY_EVENTS',
  })
}

function renderDrawer() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <SharedDeviceAccountsDrawer
          group={group}
          query={query}
          onClose={() => {}}
        />
      </AntdApp>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  graphProps.length = 0
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('SharedDeviceAccountsDrawer', () => {
  it('默认展示明细分页列表且不渲染关系图', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(accountsResponse(firstPageAccounts))),
    )
    renderDrawer()

    expect(
      await screen.findByTitle(firstPageAccounts[0].principal_ref),
    ).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: '明细列表' })).toBeChecked()
    expect(
      screen.getByRole('columnheader', { name: /^关联安全事件/ }),
    ).toBeInTheDocument()
    expect(
      screen.queryByTestId('shared-device-relationship-graph'),
    ).not.toBeInTheDocument()
    expect(graphProps).toHaveLength(0)
  })

  it('切换关系图后仅传递当前分页真实返回的主体和当前分组', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input) => {
        const url = new URL(String(input), 'http://test.local')
        const page = Number(url.searchParams.get('page'))
        return Promise.resolve(
          accountsResponse(
            page === 2 ? secondPageAccounts : firstPageAccounts,
            page,
          ),
        )
      }),
    )
    renderDrawer()

    expect(
      await screen.findByTitle(firstPageAccounts[0].principal_ref),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('2'))
    expect(
      await screen.findByTitle(secondPageAccounts[0].principal_ref),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('radio', { name: '关系图' }))

    expect(
      await screen.findByTestId('shared-device-relationship-graph'),
    ).toHaveTextContent(secondPageAccounts[0].principal_ref)
    const currentGraphProps = graphProps[graphProps.length - 1]
    expect(currentGraphProps.group).toBe(group)
    expect(currentGraphProps.accounts).toEqual(secondPageAccounts)
    expect(currentGraphProps.accounts).toHaveLength(1)
    expect(screen.getByText(/关系图仅展示当前第 2 页/)).toBeInTheDocument()
    expect(screen.getByText(/不自动拼接其他页/)).toBeInTheDocument()
  })

  it('查询错误时保留错误提示且不显示关系图', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              code: 'SERVICE_UNAVAILABLE',
              message: '主体关联暂不可用',
            }),
            {
              status: 503,
              headers: { 'Content-Type': 'application/json' },
            },
          ),
        ),
      ),
    )
    renderDrawer()

    expect(await screen.findByText('加载主体关联失败')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '关系图' }))

    expect(screen.getByText('主体关联暂不可用')).toBeInTheDocument()
    expect(
      screen.queryByTestId('shared-device-relationship-graph'),
    ).not.toBeInTheDocument()
    expect(graphProps).toHaveLength(0)
  })

  it('当前页为空时展示明确空态且不伪造关系图节点', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(accountsResponse([], 1, 0))),
    )
    renderDrawer()

    expect(
      await screen.findByText('当前设备与时间范围内暂无可信主体关联记录'),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '关系图' }))

    expect(
      screen.getByText('当前页暂无可信主体，无法生成关系图'),
    ).toBeInTheDocument()
    expect(
      screen.queryByTestId('shared-device-relationship-graph'),
    ).not.toBeInTheDocument()
    expect(graphProps).toHaveLength(0)
  })
})
