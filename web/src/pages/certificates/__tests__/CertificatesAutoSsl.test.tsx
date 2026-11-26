import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { acmeApi } from '../../../api/acme'
import { applicationsApi } from '../../../api/applications'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesPage from '../CertificatesPage'
import type { AcmeConfig, AcmeOrderItem, CertificateItem, CurrentUser } from '../../../types'

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
vi.mock('../../../api/acme', () => ({
  acmeApi: {
    getConfig: vi.fn(),
    updateConfig: vi.fn(),
    testConfig: vi.fn(),
    listOrders: vi.fn(),
    renewCertificate: vi.fn(),
    getAppAutoSsl: vi.fn(),
    updateAppAutoSsl: vi.fn(),
    issueAppCert: vi.fn(),
  },
}))

const acmeCert: CertificateItem = {
  id: 'cert-acme-1',
  name: 'acme-shop-20261125',
  certificate_type: 'SERVER',
  common_name: 'shop.example.com',
  subject: 'CN=shop.example.com',
  issuer: "CN=R10,O=Let's Encrypt",
  serial_number: '1001',
  not_before: '2026-11-01T00:00:00Z',
  not_after: '2027-01-30T00:00:00Z',
  fingerprint_sha256: 'abc123',
  public_key_algorithm: 'ECDSA',
  public_key_bits: 256,
  signature_algorithm: 'ECDSA-SHA256',
  san_domains: ['shop.example.com'],
  status: 'VALID',
  usage_count: 1,
  managed_by: 'ACME',
  acme_provider: 'LETSENCRYPT',
  auto_renew: true,
  renew_before_days: 30,
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
  version: 1,
}

const baseConfig: AcmeConfig = {
  enabled: false,
  provider: 'LETSENCRYPT',
  directory_url: '',
  effective_directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
  custom_directory_allowlist: '',
  email: 'ops@example.com',
  tos_agreed: true,
  eab_kid: '',
  eab_hmac_configured: false,
  key_type: 'EC256',
  renew_before_days: 30,
  auto_publish: true,
  version: 1,
}

const sampleOrder: AcmeOrderItem = {
  id: 'ord-1',
  application_id: 'app-1',
  app_code: 'shop',
  app_name: '商城站点',
  trigger_type: 'AUTO_INIT',
  provider: 'LETSENCRYPT',
  directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
  challenge_type: 'HTTP01',
  domains: ['shop.example.com'],
  status: 'SUCCEEDED',
  error_code: '',
  error_message: '',
  request_id: 'req-1',
  created_at: '2026-11-25T00:00:00Z',
  updated_at: '2026-11-25T00:01:00Z',
  finished_at: '2026-11-25T00:01:00Z',
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <MemoryRouter>
          <CertificatesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificatesPage Auto-SSL (ACME)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: {
        permissions: [
          'certificates.read',
          'certificates.create',
          'certificates.update',
          'certificates.bind',
          'certificates.delete',
          'applications.read',
        ],
      } as CurrentUser,
      initialized: true,
    })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [acmeCert],
      total: 1,
      page: 1,
      page_size: 20,
    })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 100,
    })
    vi.mocked(acmeApi.getConfig).mockResolvedValue(baseConfig)
    vi.mocked(acmeApi.updateConfig).mockResolvedValue({ ...baseConfig, enabled: true, version: 2 })
    vi.mocked(acmeApi.testConfig).mockResolvedValue({
      reachable: true,
      directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
      latency_ms: 42,
      external_account_required: false,
      message: 'ACME 目录连通正常',
    })
    vi.mocked(acmeApi.listOrders).mockResolvedValue({
      items: [sampleOrder],
      total: 1,
      page: 1,
      page_size: 20,
    })
    vi.mocked(acmeApi.renewCertificate).mockResolvedValue({
      ...sampleOrder,
      id: 'ord-2',
      trigger_type: 'MANUAL_RENEW',
      status: 'PENDING',
    })
  })

  it('展示 ACME 托管标签并支持打开全局 ACME 设置与连通性测试', async () => {
    renderPage()

    expect(await screen.findByText('acme-shop-20261125')).toBeInTheDocument()
    expect(screen.getByText('ACME 自动')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '立即续约' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /自动证书（ACME）设置/ }))
    expect(await screen.findByText('自动申请与续约 SSL 证书（ACME）全局设置')).toBeInTheDocument()
    expect(await screen.findByDisplayValue('ops@example.com')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '测试目录连通性' }))
    expect(await screen.findByText(/连接正常（延迟 42 ms）/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '保存配置' }))
    await waitFor(() => {
      expect(vi.mocked(acmeApi.updateConfig)).toHaveBeenCalled()
    })
  })

  it('切换到自动申请与续约记录 Tab 展示历史任务', async () => {
    renderPage()
    expect(await screen.findByText('acme-shop-20261125')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: '自动申请与续约记录' }))
    expect(await screen.findByText('首次自动申请')).toBeInTheDocument()
    expect(screen.getByText('商城站点（shop）')).toBeInTheDocument()
  })
})
