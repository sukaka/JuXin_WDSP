import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import TableRefreshControl from '../TableRefreshControl'

async function openAutoRefreshPopover() {
  fireEvent.click(screen.getByRole('button', { name: '自动刷新' }))
  await act(async () => {
    await vi.advanceTimersByTimeAsync(50)
  })
  expect(screen.getByText('启用自动刷新')).toBeInTheDocument()
}

describe('TableRefreshControl', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('点击刷新按钮触发 onRefresh，且进行中不并发重入', async () => {
    let resolveFirst: (() => void) | undefined
    const onRefresh = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveFirst = resolve
        }),
    )
    render(<TableRefreshControl onRefresh={onRefresh} />)

    const refreshBtn = screen.getByRole('button', { name: '刷新列表' })
    fireEvent.click(refreshBtn)
    fireEvent.click(refreshBtn)
    expect(onRefresh).toHaveBeenCalledTimes(1)

    await act(async () => {
      resolveFirst?.()
      await Promise.resolve()
    })

    fireEvent.click(refreshBtn)
    expect(onRefresh).toHaveBeenCalledTimes(2)
  })

  it('打开自动刷新设置可自定义秒数并按设定秒数自动刷新，关闭或卸载即停止', async () => {
    const onRefresh = vi.fn()
    const { unmount } = render(
      <TableRefreshControl onRefresh={onRefresh} storageKey="demo-list" />,
    )

    // 默认未打开弹窗，不向页面 DOM 暴露多余的 spinbutton
    expect(screen.queryByRole('spinbutton')).toBeNull()

    await openAutoRefreshPopover()

    // 自定义间隔为 5 秒
    const input = screen.getByRole('spinbutton', { name: '自动刷新间隔（秒）' })
    fireEvent.change(input, { target: { value: '5' } })
    fireEvent.blur(input)

    expect(JSON.parse(localStorage.getItem('smart-table-refresh:demo-list')!)).toEqual({
      intervalSeconds: 5,
    })

    // 未开启开关时不会自动触发
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    expect(onRefresh).not.toHaveBeenCalled()

    // 开启自动刷新开关
    const toggle = screen.getByRole('switch', { name: '自动刷新开关' })
    fireEvent.click(toggle)
    expect(screen.getByRole('button', { name: '自动刷新' })).toHaveTextContent('自动刷新 5秒')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_999)
    })
    expect(onRefresh).toHaveBeenCalledTimes(0)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1)
    })
    expect(onRefresh).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    expect(onRefresh).toHaveBeenCalledTimes(3)

    // 关闭开关后停止刷新
    fireEvent.click(toggle)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(onRefresh).toHaveBeenCalledTimes(3)

    // 再次开启并卸载，确认定时器被清理
    fireEvent.click(toggle)
    unmount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(onRefresh).toHaveBeenCalledTimes(3)
  })

  it('快捷间隔按钮与超界秒数失焦钳制（3–3600 秒）生效', async () => {
    render(<TableRefreshControl onRefresh={vi.fn()} storageKey="clamp-list" />)
    await openAutoRefreshPopover()

    fireEvent.click(screen.getByRole('button', { name: '30秒' }))
    expect(JSON.parse(localStorage.getItem('smart-table-refresh:clamp-list')!)).toEqual({
      intervalSeconds: 30,
    })

    const input = screen.getByRole('spinbutton', { name: '自动刷新间隔（秒）' })
    fireEvent.change(input, { target: { value: '1' } })
    fireEvent.blur(input)
    expect(JSON.parse(localStorage.getItem('smart-table-refresh:clamp-list')!)).toEqual({
      intervalSeconds: 3,
    })

    fireEvent.change(input, { target: { value: '9999' } })
    fireEvent.blur(input)
    expect(JSON.parse(localStorage.getItem('smart-table-refresh:clamp-list')!)).toEqual({
      intervalSeconds: 3600,
    })
  })

  it('标签页切至后台（visibilityState=hidden）时暂停自动刷新', async () => {
    const onRefresh = vi.fn()
    render(<TableRefreshControl onRefresh={onRefresh} defaultIntervalSeconds={5} />)

    await openAutoRefreshPopover()
    fireEvent.click(screen.getByRole('switch', { name: '自动刷新开关' }))

    const spy = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(onRefresh).toHaveBeenCalledTimes(0)

    spy.mockReturnValue('visible')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000)
    })
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('未传 onRefresh 时默认刷新当前页活跃 React Query（排除全局 ai-status）', async () => {
    vi.useRealTimers()
    const listFetcher = vi.fn(async () => ['item-1'])
    const aiStatusFetcher = vi.fn(async () => ({ enabled: true }))

    function Host() {
      const listQuery = useQuery({ queryKey: ['demo-page-list'], queryFn: listFetcher })
      useQuery({ queryKey: ['ai-status'], queryFn: aiStatusFetcher })
      return (
        <div>
          <span>{listQuery.data?.[0] ?? ''}</span>
          <TableRefreshControl />
        </div>
      )
    }

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <Host />
      </QueryClientProvider>,
    )

    await screen.findByText('item-1')
    expect(listFetcher).toHaveBeenCalledTimes(1)
    expect(aiStatusFetcher).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: '刷新列表' }))

    await vi.waitFor(() => {
      expect(listFetcher).toHaveBeenCalledTimes(2)
    })
    expect(aiStatusFetcher).toHaveBeenCalledTimes(1)
  })
})
