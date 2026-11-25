import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { applicationsApi } from '../../../api/applications'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesPage from '../CertificatesPage'
import type { CertificateDetail, CertificateItem, CurrentUser } from '../../../types'

vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))
vi.mock('../../../api/certificates', () => ({
  certificatesApi: {
    list: vi.fn(),
    get: vi.fn(),
    upload: vi.fn(),
    remove: vi.fn(),
    applications: vi.fn(),
    bind: vi.fn(),
    unbind: vi.fn(),
  },
}))

const intlCert: CertificateItem = {
  id: 'cert-intl-1',
  name: '国际主证书',
  certificate_type: 'SERVER',
  protocol_type: 'INTERNATIONAL',
  common_name: 'shop.example.com',
  subject: 'CN=shop.example.com',
  issuer: "CN=R10,O=Let's Encrypt",
  serial_number: 'INTL-001',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-06-01T00:00:00Z',
  effective_not_after: '2027-06-01T00:00:00Z',
  fingerprint_sha256: 'aaaa1111',
  public_key_algorithm: 'ECDSA',
  public_key_bits: 256,
  signature_algorithm: 'ECDSA-SHA256',
  san_domains: ['shop.example.com'],
  status: 'VALID',
  usage_count: 1,
  managed_by: 'MANUAL',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  version: 1,
}

const gmCert: CertificateDetail = {
  id: 'cert-gm-1',
  name: '国密双证书-商城',
  certificate_type: 'SERVER',
  protocol_type: 'SM_TLCP',
  common_name: 'gm.shop.example.com',
  subject: 'CN=gm.shop.example.com,O=Sign',
  issuer: 'CN=SM2 CA',
  serial_number: 'GM-SIGN-01',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2028-01-01T00:00:00Z',
  effective_not_after: '2027-03-01T00:00:00Z',
  fingerprint_sha256: 'sign-sha256-0001',
  public_key_algorithm: 'SM2',
  public_key_bits: 256,
  signature_algorithm: 'SM2-WITH-SM3',
  san_domains: ['gm.shop.example.com'],
  enc_common_name: 'enc.gm.shop.example.com',
  enc_subject: 'CN=enc.gm.shop.example.com,O=Enc',
  enc_issuer: 'CN=SM2 CA',
  enc_serial_number: 'GM-ENC-02',
  enc_not_before: '2026-01-01T00:00:00Z',
  enc_not_after: '2027-03-01T00:00:00Z',
  enc_fingerprint_sha256: 'enc-sha256-0002',
  status: 'VALID',
  usage_count: 0,
  managed_by: 'MANUAL',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  version: 1,
  application_ids: [],
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <CertificatesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificatesPage 国密双证书管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: {
        permissions: [
          'certificates.read',
          'certificates.create',
          'certificates.bind',
          'certificates.delete',
          'applications.read',
        ],
      } as CurrentUser,
      initialized: true,
    })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [intlCert, gmCert],
      total: 2,
      page: 1,
      page_size: 20,
    })
    vi.mocked(certificatesApi.get).mockResolvedValue(gmCert)
    vi.mocked(certificatesApi.applications).mockResolvedValue({
      application_ids: [],
      count: 0,
    })
    vi.mocked(certificatesApi.upload).mockResolvedValue(gmCert)
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 100,
    })
  })

  it('列表展示协议类型标签并支持按国密协议筛选及查看加密证书详情', async () => {
    renderPage()

    expect(await screen.findByText('国际主证书')).toBeInTheDocument()
    expect(screen.getByText('国密双证书-商城')).toBeInTheDocument()
    expect(screen.getByText('通用国际')).toBeInTheDocument()
    expect(screen.getByText('国密 SM2/TLCP')).toBeInTheDocument()

    // 按协议筛选 SM_TLCP
    fireEvent.mouseDown(screen.getByLabelText('协议类型'))
    fireEvent.click(await screen.findByText('国密双证书(SM2)'))
    await waitFor(() => {
      expect(vi.mocked(certificatesApi.list)).toHaveBeenCalledWith(
        expect.objectContaining({ protocol_type: 'SM_TLCP', page: 1 }),
      )
    })

    // 打开国密证书详情抽屉，展示签名与加密双证书元数据
    fireEvent.click(await screen.findByText('国密双证书-商城'))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('加密证书信息（SM2 加密）')).toBeInTheDocument()
    expect(within(drawer).getByText('enc.gm.shop.example.com')).toBeInTheDocument()
    expect(within(drawer).getByText('GM-ENC-02')).toBeInTheDocument()
    expect(within(drawer).getByText('enc-sha256-0002')).toBeInTheDocument()
    expect(within(drawer).getByText('sign-sha256-0001')).toBeInTheDocument()
  })

  it('上传国密双证书：校验 PEM 并以 SM_TLCP + enc_cert_pem/enc_key_pem 提交', async () => {
    renderPage()
    expect(await screen.findByText('国际主证书')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /上传证书/ }))
    const dialog = await screen.findByRole('dialog')

    // 切换到国密双证书模式
    fireEvent.click(within(dialog).getByText('国密协议双证书 (SM2 签名+加密)'))
    expect(await within(dialog).findByLabelText('签名证书 PEM')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('签名私钥 PEM')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('加密证书 PEM')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('加密私钥 PEM')).toBeInTheDocument()

    // 填写非法 PEM 校验应拦住提交
    fireEvent.change(within(dialog).getByLabelText('证书名称'), {
      target: { value: '国密双证测试' },
    })
    fireEvent.change(within(dialog).getByLabelText('签名证书 PEM'), {
      target: { value: 'NOT-A-PEM' },
    })
    fireEvent.change(within(dialog).getByLabelText('签名私钥 PEM'), {
      target: { value: '-----BEGIN SM2 PRIVATE KEY-----\nSIGNKEY\n-----END SM2 PRIVATE KEY-----' },
    })
    fireEvent.change(within(dialog).getByLabelText('加密证书 PEM'), {
      target: { value: '-----BEGIN CERTIFICATE-----\nENCCERT\n-----END CERTIFICATE-----' },
    })
    fireEvent.change(within(dialog).getByLabelText('加密私钥 PEM'), {
      target: { value: '-----BEGIN SM2 PRIVATE KEY-----\nENCKEY\n-----END SM2 PRIVATE KEY-----' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    expect(
      await within(dialog).findByText('签名证书 PEM格式不正确，应为 PEM 文本'),
    ).toBeInTheDocument()
    expect(certificatesApi.upload).not.toHaveBeenCalled()

    // 修正签名证书 PEM 后提交成功
    fireEvent.change(within(dialog).getByLabelText('签名证书 PEM'), {
      target: { value: '-----BEGIN CERTIFICATE-----\nSIGNCERT\n-----END CERTIFICATE-----' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.upload)).toHaveBeenCalledWith({
        name: '国密双证测试',
        protocol_type: 'SM_TLCP',
        cert_pem: '-----BEGIN CERTIFICATE-----\nSIGNCERT\n-----END CERTIFICATE-----',
        key_pem: '-----BEGIN SM2 PRIVATE KEY-----\nSIGNKEY\n-----END SM2 PRIVATE KEY-----',
        enc_cert_pem: '-----BEGIN CERTIFICATE-----\nENCCERT\n-----END CERTIFICATE-----',
        enc_key_pem: '-----BEGIN SM2 PRIVATE KEY-----\nENCKEY\n-----END SM2 PRIVATE KEY-----',
        chain_pem: '',
      })
    })
  })
})
