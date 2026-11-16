import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import GroupControlTrend from '../GroupControlTrend'

let latestOption: unknown

vi.mock('../../../components/EChart', () => ({
  default: (props: { option: unknown; ariaLabel: string }) => {
    latestOption = props.option
    return <div role="img" aria-label={props.ariaLabel} />
  },
}))

const query = {
  start: '2026-11-14T00:00:00Z',
  end: '2026-11-15T00:00:00Z',
  application_id: '11111111-1111-1111-1111-111111111111',
  device_fingerprint: 'b3c7a91e'.repeat(4),
  min_accounts: 3,
  page: 1,
  page_size: 20,
}

function response(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function renderTrend() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <GroupControlTrend query={query} />
    </QueryClientProvider>,
  )
}

afterEach(() => {
  latestOption = undefined
  vi.unstubAllGlobals()
})

describe('GroupControlTrend', () => {
  it('将真实时间桶映射为设备分组和观察信号序列', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          response({
            items: [
              {
                bucket: '2026-11-14T00:00:00Z',
                group_count: 2,
                signal_count: 3,
                event_count: 9,
              },
              {
                bucket: '2026-11-14T01:00:00Z',
                group_count: 4,
                signal_count: 5,
                event_count: 12,
              },
            ],
            start: query.start,
            end: query.end,
            bucket: 'hour',
            partial: true,
            data_scope: 'NOTABLE_SECURITY_EVENTS',
          }),
        ),
      ),
    )
    renderTrend()
    expect(
      await screen.findByRole('img', {
        name: '共享设备分组与群控观察信号趋势',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(/未采集时段保持为空/)).toBeInTheDocument()

    const option = latestOption as {
      xAxis: { data: string[] }
      series: Array<{ name: string; data: number[] }>
    }
    expect(option.xAxis.data).toHaveLength(2)
    expect(option.series[0].data).toEqual([2, 4])
    expect(option.series[1].data).toEqual([3, 5])
    const url = new URL(
      String(vi.mocked(fetch).mock.calls[0][0]),
      'http://test.local',
    )
    expect(url.pathname).toBe('/api/v1/api-security/group-control/trends')
    expect(url.searchParams.get('application_id')).toBe(query.application_id)
    expect(url.searchParams.get('device_fingerprint')).toBe(
      query.device_fingerprint,
    )
    expect(url.searchParams.get('min_accounts')).toBe('3')
    expect(url.searchParams.has('page')).toBe(false)
  })

  it('无观测时显示空态而不生成零值序列', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          response({
            items: [],
            start: query.start,
            end: query.end,
            bucket: 'hour',
            partial: true,
            data_scope: 'NOTABLE_SECURITY_EVENTS',
          }),
        ),
      ),
    )
    renderTrend()
    expect(
      await screen.findByText('当前时间范围暂无达到阈值的群控趋势观测'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(latestOption).toBeUndefined()
  })

  it('趋势读取失败时展示错误而不绘制图表', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              code: 'SERVICE_UNAVAILABLE',
              message: '趋势读取暂不可用',
            }),
            { status: 503, headers: { 'Content-Type': 'application/json' } },
          ),
        ),
      ),
    )
    renderTrend()
    expect(await screen.findByText('加载群控趋势失败')).toBeInTheDocument()
    expect(screen.getByText('趋势读取暂不可用')).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1))
    expect(
      screen.queryByRole('img', { name: '共享设备分组与群控观察信号趋势' }),
    ).not.toBeInTheDocument()
  })
})
