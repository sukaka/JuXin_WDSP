import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import FileLineagePanel from '../FileLineagePanel'
import type {
  ApiFileLineage,
  ApiFileLineageItem,
} from '../../../api/apiFileSignature'

const DOCUMENT_SHA256 =
  '3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7'
const HMAC_FINGERPRINT =
  'hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const MASKED_DOCUMENTATION_IP = '203.0.113.***'

const documentedItem: ApiFileLineageItem = {
  id: 'asset-upload',
  direction: 'UPLOAD',
  filename: 'quarterly-report.docx',
  identity_fingerprint: HMAC_FINGERPRINT,
  client_ip_masked: MASKED_DOCUMENTATION_IP,
  endpoint_key: 'POST /v1/documents',
  last_seen: '2026-11-15T01:00:00Z',
  transfer_count: 2,
}

function makeLineage(items: ApiFileLineageItem[]): ApiFileLineage {
  return {
    sha256: DOCUMENT_SHA256,
    days: 30,
    total: items.length,
    upload_assets: items.filter((item) => item.direction === 'UPLOAD').length,
    download_assets: items.filter((item) => item.direction === 'DOWNLOAD')
      .length,
    truncated: false,
    items,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function successResponse(items: ApiFileLineageItem[]): Response {
  return jsonResponse(200, {
    code: 'SUCCESS',
    message: 'ok',
    data: makeLineage(items),
  })
}

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <FileLineagePanel sha256={DOCUMENT_SHA256} />
    </QueryClientProvider>,
  )
}

describe('FileLineagePanel', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示接口返回的身份指纹和脱敏来源 IP，并保留关联边界说明', async () => {
    vi.mocked(fetch).mockResolvedValue(successResponse([documentedItem]))
    renderPanel()

    expect(await screen.findByText(HMAC_FINGERPRINT)).toBeInTheDocument()
    expect(screen.getByText(MASKED_DOCUMENTATION_IP)).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: '身份指纹' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: '来源 IP（脱敏）' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        '按完整文件内容指纹关联实际上传与下载，不代表业务所有权或创建者。',
      ),
    ).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith(
      `/api/v1/api-security/file-assets/lineage?sha256=${DOCUMENT_SHA256}`,
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('空身份指纹和来源 IP 分别明确显示匿名与未知', async () => {
    vi.mocked(fetch).mockResolvedValue(
      successResponse([
        {
          ...documentedItem,
          id: 'asset-anonymous',
          filename: 'anonymous-upload.docx',
          identity_fingerprint: '',
          client_ip_masked: '',
        },
      ]),
    )
    renderPanel()

    const row = (await screen.findByText('anonymous-upload.docx')).closest(
      'tr',
    ) as HTMLElement
    expect(within(row).getByText('匿名')).toBeInTheDocument()
    expect(within(row).getByText('未知')).toBeInTheDocument()
    expect(within(row).queryByText(HMAC_FINGERPRINT)).not.toBeInTheDocument()
    expect(
      within(row).queryByText(MASKED_DOCUMENTATION_IP),
    ).not.toBeInTheDocument()
  })

  it('关联接口失败时展示真实错误，不从错误响应构造资产记录', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(500, {
        code: 'INTERNAL_ERROR',
        message: '关联证据暂不可用',
        data: makeLineage([documentedItem]),
      }),
    )
    renderPanel()

    expect(await screen.findByText('关联证据暂不可用')).toBeInTheDocument()
    expect(screen.getByText('加载数据失败')).toBeInTheDocument()
    expect(screen.queryByText('quarterly-report.docx')).not.toBeInTheDocument()
    expect(screen.queryByText(HMAC_FINGERPRINT)).not.toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})
