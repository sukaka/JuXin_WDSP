import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiFileAssetsPage from '../ApiFileAssetsPage'

const contentHash =
  'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'
const identityFingerprint = 'test-hmac-identity-0001'

function response(data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <ApiFileAssetsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function mockRequests() {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = String(input)
    if (url.includes('/api-security/file-assets/stats')) {
      return Promise.resolve(
        response({
          days: 7,
          summary: {
            upload_assets: 1,
            download_assets: 2,
            upload_transfers: 3,
            download_transfers: 4,
            sensitive_file_count: 1,
          },
        }),
      )
    }
    if (url.includes('/api-security/file-assets/lineage')) {
      return Promise.resolve(
        response({
          sha256: contentHash,
          days: 7,
          total: 2,
          upload_assets: 1,
          download_assets: 1,
          truncated: false,
          items: [
            {
              id: 'upload-asset',
              direction: 'UPLOAD',
              filename: 'report.docx',
              endpoint_key: 'POST /v1/imports',
              last_seen: '2026-11-15T01:00:00Z',
              transfer_count: 3,
            },
            {
              id: 'download-asset',
              direction: 'DOWNLOAD',
              filename: 'report.docx',
              endpoint_key: 'GET /v1/exports',
              last_seen: '2026-11-15T02:00:00Z',
              transfer_count: 4,
            },
          ],
        }),
      )
    }
    return Promise.resolve(
      response({
        items: [
          {
            id: 'asset-1',
            endpoint_key: 'GET /v1/exports',
            direction: 'DOWNLOAD',
            filename: 'report.docx',
            extension: 'docx',
            mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size_bytes: 2048,
            sha256: contentHash,
            identity_fingerprint: 'test:identity',
            client_ip_masked: '192.0.2.0',
            sensitive_types: ['data_export'],
            first_seen: '2026-11-15T01:00:00Z',
            last_seen: '2026-11-15T02:00:00Z',
            transfer_count: 4,
            created_at: '2026-11-15T01:00:00Z',
            updated_at: '2026-11-15T02:00:00Z',
          },
        ],
        page: 1,
        page_size: 20,
        total: 1,
      }),
    )
  })
}

describe('ApiFileAssetsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
    mockRequests()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示真实资产与统计，提交内容指纹/身份指纹/扩展名/方向/敏感筛选并打开内容关联', async () => {
    renderPage()
    expect(await screen.findByText('report.docx')).toBeInTheDocument()
    expect(screen.getByText('上传资产')).toBeInTheDocument()
    expect(screen.getByText('下载资产')).toBeInTheDocument()
    expect(screen.getByText('敏感文件')).toBeInTheDocument()
    expect(screen.getByText('data_export')).toBeInTheDocument()
    expect(screen.getByText('2.0 KiB')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('文件内容 SHA-256'), {
      target: { value: contentHash.toUpperCase() },
    })
    fireEvent.change(screen.getByLabelText('文件扩展名'), {
      target: { value: '.docx' },
    })
    fireEvent.change(screen.getByLabelText('身份指纹'), {
      target: { value: `  ${identityFingerprint}  ` },
    })
    const directionPlaceholder = screen.getByText('传输方向')
    fireEvent.mouseDown(
      directionPlaceholder.closest('.ant-select') as HTMLElement,
    )
    const downloadOption = await screen.findByText('下载', {
      selector: '.ant-select-item-option-content',
    })
    fireEvent.click(downloadOption)
    fireEvent.click(screen.getByRole('switch', { name: '仅敏感文件' }))
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))

    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.map((call) => String(call[0]))
      expect(
        calls.some(
          (url) =>
            url.includes('/api-security/file-assets?') &&
            url.includes('sha256=' + contentHash) &&
            url.includes('extension=docx') &&
            url.includes('identity_fingerprint=' + identityFingerprint) &&
            url.includes('direction=DOWNLOAD') &&
            url.includes('sensitive_only=true') &&
            url.includes('page=1'),
        ),
      ).toBe(true)
    })

    fireEvent.click(await screen.findByRole('button', { name: '内容关联' }))
    const drawer = await screen.findByRole('dialog')
    expect(drawer).toHaveTextContent('同内容文件传输关联')
    expect(
      await screen.findByText('共 2 条关联资产（上传 1，下载 1）'),
    ).toBeInTheDocument()
    expect(drawer).toHaveTextContent('GET /v1/exports')
    await waitFor(() => {
      expect(
        vi
          .mocked(fetch)
          .mock.calls.some((call) =>
            String(call[0]).includes(
              '/api-security/file-assets/lineage?sha256=' + contentHash,
            ),
          ),
      ).toBe(true)
    })
  })

  it('重置清空身份指纹并移除查询参数', async () => {
    renderPage()
    await screen.findByText('report.docx')
    fireEvent.change(screen.getByLabelText('身份指纹'), {
      target: { value: identityFingerprint },
    })
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    await waitFor(() => {
      expect(
        vi
          .mocked(fetch)
          .mock.calls.some((call) =>
            String(call[0]).includes(
              'identity_fingerprint=' + identityFingerprint,
            ),
          ),
      ).toBe(true)
    })

    const beforeReset = vi.mocked(fetch).mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: /重\s*置/ }))
    expect(screen.getByLabelText('身份指纹')).toHaveValue('')
    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.slice(beforeReset)
      expect(
        calls.some((call) => {
          const url = String(call[0])
          return (
            url.includes('/api-security/file-assets?') &&
            url.includes('page=1') &&
            !url.includes('identity_fingerprint=')
          )
        }),
      ).toBe(true)
    })
  })

  it('身份指纹仅含空白时提交其他筛选但不发送该参数', async () => {
    renderPage()
    await screen.findByText('report.docx')
    fireEvent.change(screen.getByLabelText('身份指纹'), {
      target: { value: '   ' },
    })
    fireEvent.change(screen.getByLabelText('文件扩展名'), {
      target: { value: 'docx' },
    })
    const beforeQuery = vi.mocked(fetch).mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))

    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.slice(beforeQuery)
      expect(
        calls.some((call) => {
          const url = String(call[0])
          return (
            url.includes('/api-security/file-assets?') &&
            url.includes('extension=docx') &&
            !url.includes('identity_fingerprint=')
          )
        }),
      ).toBe(true)
    })
  })

  it('无效 SHA-256 给出提示且不会发起筛选请求', async () => {
    renderPage()
    await screen.findByText('report.docx')
    const before = vi.mocked(fetch).mock.calls.length
    fireEvent.change(screen.getByLabelText('文件内容 SHA-256'), {
      target: { value: 'not-a-sha256' },
    })
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    expect(
      await screen.findByText('SHA-256 需为 64 位十六进制字符串'),
    ).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls).toHaveLength(before)
  })

  it('无完整内容指纹时禁用关联入口', async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/api-security/file-assets/stats')) {
        return Promise.resolve(response({ days: 7, summary: {} }))
      }
      return Promise.resolve(
        response({
          items: [
            {
              id: 'asset-unknown',
              endpoint_key: 'GET /v1/stream',
              direction: 'DOWNLOAD',
              filename: 'stream.docx',
              extension: 'docx',
              mime: 'application/octet-stream',
              size_bytes: 128,
              sha256: null,
              identity_fingerprint: '',
              client_ip_masked: '',
              sensitive_types: [],
              first_seen: '2026-11-15T01:00:00Z',
              last_seen: '2026-11-15T01:00:00Z',
              transfer_count: 1,
              created_at: '2026-11-15T01:00:00Z',
              updated_at: '2026-11-15T01:00:00Z',
            },
          ],
          page: 1,
          page_size: 20,
          total: 1,
        }),
      )
    })
    renderPage()
    expect(await screen.findByText('stream.docx')).toBeInTheDocument()
    expect(screen.getByText('未完整观测')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '内容关联' })).toBeDisabled()
  })
})
