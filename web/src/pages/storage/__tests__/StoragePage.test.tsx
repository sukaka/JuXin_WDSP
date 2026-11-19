import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import StoragePage from '../StoragePage'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <StoragePage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('StoragePage 分区详情中文化', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/system-health/storage')) {
          return Promise.resolve(
            jsonResponse({
              postgres_size_bytes: 1024 * 1024 * 64,
              db_connections: 8,
              reports_size_bytes: 4096,
              reports_file_count: 2,
              backups_size_bytes: 8192,
              backups_file_count: 1,
              valkey_used_memory_bytes: 1024 * 512,
              valkey_max_memory_bytes: 1024 * 1024 * 16,
              disk_total_bytes: 1024 * 1024 * 1024 * 100,
              disk_free_bytes: 1024 * 1024 * 1024 * 60,
              partitions: [{ name: 'access_logs_2026_10', size_bytes: 5 * 1024 * 1024 }],
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('双击分区行打开详情抽屉，展示「分区名称」「占用大小」与可读字节大小', async () => {
    renderPage()
    const cell = await screen.findByText('access_logs_2026_10')
    fireEvent.doubleClick(cell.closest('tr')!)

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('分区名称')).toBeInTheDocument()
    expect(within(drawer).getByText('占用大小')).toBeInTheDocument()
    expect(within(drawer).getByText('access_logs_2026_10')).toBeInTheDocument()
    expect(within(drawer).getByText('5.00 MB')).toBeInTheDocument()
    expect(within(drawer).queryByText('size_bytes')).not.toBeInTheDocument()
  })
})
