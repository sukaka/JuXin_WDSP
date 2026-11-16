import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { webcrypto } from 'node:crypto'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SignatureVerificationCard from '../SignatureVerificationCard'

function jsonResponse(status: number, data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function renderCard(canVerify = true) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <SignatureVerificationCard canVerify={canVerify} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function selectFile(file: File) {
  const input = document.querySelector<HTMLInputElement>('input[type="file"]')
  expect(input).toBeTruthy()
  fireEvent.change(input as HTMLInputElement, { target: { files: [file] } })
}

async function submitFile(file: File) {
  selectFile(file)
  await screen.findByText(file.name)
  await waitFor(() =>
    expect(screen.getByRole('button', { name: '验证签名' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: '验证签名' }))
}

const validSignature = {
  valid: true,
  kid: 'k2026',
  signed_at: '2026-11-15T02:00:00Z',
  identity_fp_prefix: 'test:fp',
}

function mockLineage(response: Response) {
  vi.mocked(fetch).mockImplementation((input) => {
    if (String(input).includes('/api-security/file-assets/lineage')) {
      return Promise.resolve(response)
    }
    return Promise.resolve(jsonResponse(200, validSignature))
  })
}

describe('SignatureVerificationCard', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
    vi.stubGlobal('crypto', webcrypto)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('读取 OOXML 文件并提交真实验证请求，展示有效结果与同内容传输关联', async () => {
    const file = new File(
      [new Uint8Array([0x50, 0x4b, 0x05, 0x06])],
      'report.docx',
      {
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      },
    )
    mockLineage(
      jsonResponse(200, {
        sha256: 'content-fingerprint',
        days: 7,
        total: 2,
        upload_assets: 1,
        download_assets: 1,
        truncated: false,
        items: [
          {
            id: 'asset-upload',
            direction: 'UPLOAD',
            filename: 'report.docx',
            endpoint_key: 'POST /v1/imports',
            last_seen: '2026-11-15T01:00:00Z',
            transfer_count: 3,
          },
          {
            id: 'asset-download',
            direction: 'DOWNLOAD',
            filename: 'report.docx',
            endpoint_key: 'GET /v1/exports',
            last_seen: '2026-11-15T02:00:00Z',
            transfer_count: 4,
          },
        ],
      }),
    )
    renderCard()
    selectFile(file)
    await screen.findByText('report.docx')
    fireEvent.change(screen.getByLabelText('身份指纹（可选）'), {
      target: { value: 'test:fp' },
    })
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '验证签名' })).toBeEnabled(),
    )
    fireEvent.click(screen.getByRole('button', { name: '验证签名' }))

    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
    const [input, init] = vi.mocked(fetch).mock.calls[0]
    expect(String(input)).toContain(
      '/api/v1/api-security/file-signature/verify',
    )
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      filename: 'report.docx',
      content_format: 'ooxml_zip',
      content_base64: 'UEsFBg==',
      identity_fp: 'test:fp',
    })
    expect(
      await screen.findByText('签名有效，文件完整性与来源校验通过'),
    ).toBeInTheDocument()
    expect(screen.getByText('k2026')).toBeInTheDocument()
    expect(screen.getByText('test:fp')).toBeInTheDocument()
    expect(
      await screen.findByText('共 2 条关联资产（上传 1，下载 1）'),
    ).toBeInTheDocument()
    expect(screen.getByText('GET /v1/exports')).toBeInTheDocument()
    expect(screen.getByText('POST /v1/imports')).toBeInTheDocument()
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
    expect(String(vi.mocked(fetch).mock.calls[1][0])).toMatch(
      /\/api-security\/file-assets\/lineage\?sha256=[0-9a-f]{64}$/,
    )
  })

  it('拒绝不支持的扩展名、空文件及超过 2 MiB 的文件，不发起请求', async () => {
    renderCard()
    selectFile(
      new File(['plain text'], 'report.pdf', { type: 'application/pdf' }),
    )
    expect(
      await screen.findByText('仅支持 DOCX、XLSX、PPTX 文件'),
    ).toBeInTheDocument()
    selectFile(new File([], 'empty.xlsx'))
    expect(await screen.findByText('文件不能为空')).toBeInTheDocument()
    selectFile(new File([new Uint8Array(2 * 1024 * 1024 + 1)], 'large.pptx'))
    expect(await screen.findByText('文件不能超过 2 MiB')).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '验证签名' })).toBeDisabled()
  })

  it('显示签名失败原因且不查询关联；无读取权限时禁用选择与验证', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(200, { valid: false, reason: '签名不匹配' }),
    )
    const { unmount } = renderCard()
    await submitFile(new File(['signed'], 'notes.pptx'))
    expect(await screen.findByText('签名验证未通过')).toBeInTheDocument()
    expect(screen.getByText('签名不匹配')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(1)
    unmount()

    renderCard(false)
    expect(
      screen.getByText('当前账号无文件验证权限（api_data.read）'),
    ).toBeInTheDocument()
    expect(document.querySelector('input[type="file"]')).toBeDisabled()
    expect(screen.getByRole('button', { name: '验证签名' })).toBeDisabled()
  })

  it('没有关联记录时如实展示空结果', async () => {
    mockLineage(
      jsonResponse(200, {
        sha256: 'content-fingerprint',
        days: 7,
        total: 0,
        upload_assets: 0,
        download_assets: 0,
        truncated: false,
        items: [],
      }),
    )
    renderCard()
    await submitFile(new File(['signed'], 'empty.docx'))
    expect(
      await screen.findByText('暂无相同内容的传输记录'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('共 0 条关联资产（上传 0，下载 0）'),
    ).toBeInTheDocument()
  })

  it('关联查询失败时保留签名有效结论并显示错误', async () => {
    mockLineage(
      new Response(
        JSON.stringify({ code: 'INTERNAL_ERROR', message: '关联暂不可用' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    renderCard()
    await submitFile(new File(['signed'], 'error.docx'))
    expect(
      await screen.findByText('签名有效，文件完整性与来源校验通过'),
    ).toBeInTheDocument()
    expect(await screen.findByText(/关联暂不可用/)).toBeInTheDocument()
  })
})
