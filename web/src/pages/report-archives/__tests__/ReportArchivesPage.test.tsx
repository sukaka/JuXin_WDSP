import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ReportArchivesPage from '../ReportArchivesPage'
import type { ReportArchiveItem } from '../../../types'

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
        <ReportArchivesPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ReportArchivesPage (B5-02)', () => {
  beforeEach(() => {
    const items: ReportArchiveItem[] = [
      {
        archive_id: 'arch-11111111-1111-1111-1111-111111111111',
        report_job_id: 'job-11111111-1111-1111-1111-111111111111',
        report_no: 'JZ-202611-0001',
        report_type: 'MONTHLY',
        status: 'SUCCESS',
        file_format: 'pdf',
        file_hash: 'abcdef1234567890abcdef1234567890',
        file_size: 2048,
        archived_by: 'sec_admin',
        archived_at: '2026-11-20T08:00:00Z',
        note: '月度合规归档',
      },
      {
        archive_id: 'arch-22222222-2222-2222-2222-222222222222',
        report_job_id: 'job-22222222-2222-2222-2222-222222222222',
        report_no: 'JZ-202611-0002',
        report_type: 'WEEKLY',
        status: 'SUCCESS',
        file_format: 'html',
        file_hash: '1234567890abcdef1234567890abcdef',
        file_size: 512,
        archived_by: 'auditor',
        archived_at: '2026-11-19T08:00:00Z',
        note: '周报归档',
      },
    ]
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse({ items, page: 1, page_size: 20, total: 2 }))),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('使用 archive_id 作为表格 rowKey 并渲染 file_format / file_size / file_hash 等字段', async () => {
    renderPage()

    expect(await screen.findByText('JZ-202611-0001')).toBeInTheDocument()
    expect(screen.getByText('JZ-202611-0002')).toBeInTheDocument()
    expect(screen.getByText('PDF 文档')).toBeInTheDocument()
    expect(screen.getByText('网页')).toBeInTheDocument()
    expect(screen.getByText('2.00 KB')).toBeInTheDocument()
    expect(screen.getByText('512 B')).toBeInTheDocument()
    expect(screen.getByText('月度合规归档')).toBeInTheDocument()
    expect(screen.getByText('sec_admin')).toBeInTheDocument()

    expect(
      document.querySelector('tr[data-row-key="arch-11111111-1111-1111-1111-111111111111"]'),
    ).toBeInTheDocument()
    expect(
      document.querySelector('tr[data-row-key="arch-22222222-2222-2222-2222-222222222222"]'),
    ).toBeInTheDocument()
  })

  it('后端 items 为 null 时安全渲染空表格', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse({ items: null, page: 1, page_size: 20, total: 0 }))),
    )

    renderPage()
    expect(await screen.findByText('报告归档')).toBeInTheDocument()
    expect(screen.queryByText('加载报告归档失败')).not.toBeInTheDocument()
  })
})
