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
    uploadFiles: vi.fn(),
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

function makeFile(name: string, content: string): File {
  return new File([content], name, { type: 'application/x-pem-file' })
}

describe('CertificatesPage 证书文件上传与国密双证书管理', () => {
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
    vi.mocked(certificatesApi.uploadFiles).mockResolvedValue(gmCert)
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

  it('上传通用协议证书：以文件上传而非粘贴文本提交，选择证书文件后自动填充证书名称并支持校验与移除', async () => {
    vi.mocked(certificatesApi.uploadFiles).mockResolvedValue(intlCert)
    renderPage()
    expect(await screen.findByText('国际主证书')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /上传证书/ }))
    const dialog = await screen.findByRole('dialog')

    // 弹窗中不再存在粘贴 PEM 的 textarea
    expect(dialog.querySelectorAll('textarea')).toHaveLength(0)

    // 未选文件直接提交应触发必填校验
    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))
    expect(await within(dialog).findByText('请上传证书文件')).toBeInTheDocument()
    expect(within(dialog).getByText('请上传私钥文件')).toBeInTheDocument()
    expect(certificatesApi.uploadFiles).not.toHaveBeenCalled()

    // 非法格式（.pfx）与空文件应被拒绝
    const pfxFile = makeFile('bundle.pfx', 'binary')
    fireEvent.change(within(dialog).getByLabelText('证书文件'), {
      target: { files: [pfxFile] },
    })
    expect(await screen.findByText(/暂不支持 PFX\/P12/)).toBeInTheDocument()

    const emptyKey = makeFile('empty.key', '')
    fireEvent.change(within(dialog).getByLabelText('私钥文件'), {
      target: { files: [emptyKey] },
    })
    expect(await screen.findByText('文件内容不能为空')).toBeInTheDocument()

    // 上传有效证书文件：自动填充证书名称（去除扩展名）
    const certFile = makeFile('portal.example.com.pem', '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----')
    const keyFile = makeFile('portal.example.com.key', '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----')
    const chainFile = makeFile('ca-chain.crt', '-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----')

    fireEvent.change(within(dialog).getByLabelText('证书文件'), {
      target: { files: [certFile] },
    })
    await waitFor(() => {
      expect(within(dialog).getByLabelText('证书名称')).toHaveValue('portal.example.com')
    })
    expect(within(dialog).getByText('portal.example.com.pem')).toBeInTheDocument()

    // 测试移除后再重新选择私钥文件
    fireEvent.change(within(dialog).getByLabelText('私钥文件'), {
      target: { files: [keyFile] },
    })
    expect(await within(dialog).findByText('portal.example.com.key')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '移除 portal.example.com.key' }))
    await waitFor(() => {
      expect(within(dialog).queryByText('portal.example.com.key')).not.toBeInTheDocument()
    })
    fireEvent.change(within(dialog).getByLabelText('私钥文件'), {
      target: { files: [keyFile] },
    })
    expect(await within(dialog).findByText('portal.example.com.key')).toBeInTheDocument()

    fireEvent.change(within(dialog).getByLabelText('证书链文件（可选）'), {
      target: { files: [chainFile] },
    })
    expect(await within(dialog).findByText('ca-chain.crt')).toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.uploadFiles)).toHaveBeenCalledWith({
        name: 'portal.example.com',
        protocol_type: 'INTERNATIONAL',
        cert_file: expect.objectContaining({ name: 'portal.example.com.pem' }),
        key_file: expect.objectContaining({ name: 'portal.example.com.key' }),
        chain_file: expect.objectContaining({ name: 'ca-chain.crt' }),
      })
    })
  })

  it('上传国密双证书：通过文件上传提交 SM_TLCP 签名与加密双证四文件', async () => {
    renderPage()
    expect(await screen.findByText('国际主证书')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /上传证书/ }))
    const dialog = await screen.findByRole('dialog')

    // 切换到国密双证书模式
    fireEvent.click(within(dialog).getByText('国密协议双证书 (SM2 签名+加密)'))
    expect(await within(dialog).findByLabelText('签名证书文件')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('签名私钥文件')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('加密证书文件')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('加密私钥文件')).toBeInTheDocument()

    fireEvent.change(within(dialog).getByLabelText('证书名称'), {
      target: { value: '国密双证测试' },
    })

    const signCert = makeFile('sm2.sign.crt', '-----BEGIN CERTIFICATE-----\nSIGN\n-----END CERTIFICATE-----')
    const signKey = makeFile('sm2.sign.key', '-----BEGIN SM2 PRIVATE KEY-----\nSIGNKEY\n-----END SM2 PRIVATE KEY-----')
    const encCert = makeFile('sm2.enc.crt', '-----BEGIN CERTIFICATE-----\nENC\n-----END CERTIFICATE-----')
    const encKey = makeFile('sm2.enc.key', '-----BEGIN SM2 PRIVATE KEY-----\nENCKEY\n-----END SM2 PRIVATE KEY-----')

    fireEvent.change(within(dialog).getByLabelText('签名证书文件'), {
      target: { files: [signCert] },
    })
    fireEvent.change(within(dialog).getByLabelText('签名私钥文件'), {
      target: { files: [signKey] },
    })
    fireEvent.change(within(dialog).getByLabelText('加密证书文件'), {
      target: { files: [encCert] },
    })
    fireEvent.change(within(dialog).getByLabelText('加密私钥文件'), {
      target: { files: [encKey] },
    })

    // 已有手填名称时，选择证书文件不得覆盖原名称
    expect(within(dialog).getByLabelText('证书名称')).toHaveValue('国密双证测试')

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.uploadFiles)).toHaveBeenCalledWith({
        name: '国密双证测试',
        protocol_type: 'SM_TLCP',
        cert_file: expect.objectContaining({ name: 'sm2.sign.crt' }),
        key_file: expect.objectContaining({ name: 'sm2.sign.key' }),
        enc_cert_file: expect.objectContaining({ name: 'sm2.enc.crt' }),
        enc_key_file: expect.objectContaining({ name: 'sm2.enc.key' }),
        chain_file: null,
      })
    })
  })
})
