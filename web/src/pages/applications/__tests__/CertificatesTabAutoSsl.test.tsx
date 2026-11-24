import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { acmeApi } from '../../../api/acme'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesTab from '../detail/CertificatesTab'
import type { AppAutoSslStatus, ApplicationItem, CurrentUser } from '../../../types'

vi.mock('../../../api/certificates', () => ({
  certificatesApi: {
    applicationCertificate: vi.fn(),
  },
}))
vi.mock('../../../api/acme', () => ({
  acmeApi: {
    getAppAutoSsl: vi.fn(),
    updateAppAutoSsl: vi.fn(),
    issueAppCert: vi.fn(),
  },
}))

const app = {
  id: 'app-1',
  code: 'shop',
  name: '商城站点',
} as ApplicationItem

const readyAutoSsl: AppAutoSslStatus = {
  application_id: 'app-1',
  enabled: false,
  challenge_type: 'HTTP01',
  renew_before_days: null,
  effective_renew_before_days: 30,
  global_acme_enabled: true,
  global_provider: 'LETSENCRYPT',
  auto_publish: true,
  https_domains: ['shop.example.com'],
  last_status: '',
  last_error: '',
  fail_count: 0,
  has_active_order: false,
  ready: true,
  warnings: [
    {
      code: 'HTTP01_PORT80_REQUIREMENT',
      level: 'info',
      message: 'HTTP-01 验证要求待签发域名已解析至本网关公网 IP，且 TCP 80 端口对 CA 验证节点可达',
    },
  ],
}

function renderTab() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <MemoryRouter>
          <CertificatesTab application={app} />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificatesTab Auto-SSL', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: {
        permissions: ['certificates.read', 'certificates.bind', 'certificates.create'],
      } as CurrentUser,
      initialized: true,
    })
    vi.mocked(certificatesApi.applicationCertificate).mockResolvedValue({ certificate: null })
    vi.mocked(acmeApi.getAppAutoSsl).mockResolvedValue(readyAutoSsl)
    vi.mocked(acmeApi.updateAppAutoSsl).mockResolvedValue({ ...readyAutoSsl, enabled: true })
    vi.mocked(acmeApi.issueAppCert).mockResolvedValue({
      id: 'ord-new',
      application_id: 'app-1',
      trigger_type: 'MANUAL_ISSUE',
      provider: 'LETSENCRYPT',
      directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
      challenge_type: 'HTTP01',
      domains: ['shop.example.com'],
      status: 'PENDING',
      error_code: '',
      error_message: '',
      request_id: 'req-1',
      created_at: '2026-11-25T00:00:00Z',
      updated_at: '2026-11-25T00:00:00Z',
    })
  })

  it('无证书站点支持开启自动 SSL 开关并点击立即申请证书', async () => {
    renderTab()

    expect(await screen.findByText('自动申请与到期续约 SSL 证书（ACME HTTP-01）')).toBeInTheDocument()
    expect(await screen.findByText('shop.example.com')).toBeInTheDocument()

    // 切换开关开启自动 SSL
    const toggle = screen.getByRole('switch')
    fireEvent.click(toggle)
    await waitFor(() => {
      expect(vi.mocked(acmeApi.updateAppAutoSsl)).toHaveBeenCalledWith('app-1', {
        enabled: true,
        challenge_type: 'HTTP01',
        renew_before_days: null,
      })
    })

    // 点击立即申请证书
    fireEvent.click(screen.getByRole('button', { name: /立即申请证书/ }))
    await waitFor(() => {
      expect(vi.mocked(acmeApi.issueAppCert)).toHaveBeenCalledWith('app-1')
    })
  })
})
