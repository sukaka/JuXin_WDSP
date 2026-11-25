import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../../api/client'
import { acmeApi } from '../../../api/acme'
import { tlsConfigApi } from '../../../api/applications'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesTab from '../detail/CertificatesTab'
import type {
  AppTLSConfigResult,
  ApplicationItem,
  CertificateItem,
  CurrentUser,
} from '../../../types'

vi.mock('../../../api/certificates', () => ({
  certificatesApi: {
    applicationCertificate: vi.fn(),
    list: vi.fn(),
    bind: vi.fn(),
    unbind: vi.fn(),
  },
}))
vi.mock('../../../api/acme', () => ({
  acmeApi: {
    getAppAutoSsl: vi.fn(),
    updateAppAutoSsl: vi.fn(),
    issueAppCert: vi.fn(),
  },
}))
vi.mock('../../../api/applications', () => ({
  tlsConfigApi: {
    get: vi.fn(),
    update: vi.fn(),
  },
}))

const app = { id: 'app-gm-1', code: 'bank', name: '网银门户' } as ApplicationItem

const intlCert: CertificateItem = {
  id: 'cert-intl-1',
  name: '网银国际证书',
  certificate_type: 'SERVER',
  protocol_type: 'INTERNATIONAL',
  common_name: 'bank.example.com',
  subject: 'CN=bank.example.com',
  issuer: 'DigiCert',
  serial_number: '1001',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-06-01T00:00:00Z',
  effective_not_after: '2027-06-01T00:00:00Z',
  fingerprint_sha256: 'intl-fp',
  public_key_algorithm: 'RSA',
  public_key_bits: 2048,
  signature_algorithm: 'SHA256-RSA',
  san_domains: ['bank.example.com'],
  status: 'VALID',
  usage_count: 1,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  version: 1,
}

const gmCert: CertificateItem = {
  id: 'cert-gm-1',
  name: '网银国密双证',
  certificate_type: 'SERVER',
  protocol_type: 'SM_TLCP',
  common_name: 'bank.example.com',
  subject: 'CN=bank.example.com',
  issuer: 'CFCA SM2',
  serial_number: 'SM-SIGN-99',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2027-09-01T00:00:00Z',
  effective_not_after: '2027-08-01T00:00:00Z',
  fingerprint_sha256: 'gm-sign-fp',
  public_key_algorithm: 'SM2',
  public_key_bits: 256,
  signature_algorithm: 'SM2-WITH-SM3',
  san_domains: ['bank.example.com'],
  enc_common_name: 'enc.bank.example.com',
  enc_serial_number: 'SM-ENC-99',
  enc_not_after: '2027-08-01T00:00:00Z',
  enc_fingerprint_sha256: 'gm-enc-fp',
  status: 'VALID',
  usage_count: 1,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  version: 1,
}

const baseTlsConfig: AppTLSConfigResult = {
  configured: true,
  version: 2,
  config: {
    tls_protocol_mode: 'AUTO_DETECT',
    allowed_tls_versions: ['TLCP1.1', 'TLS1.2', 'TLS1.3'],
    legacy_ssl_analysis_versions: ['SSLv2', 'SSLv2_v3', 'SSLv3'],
    http_versions: ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2'],
    upstream_http_version: 'AUTO',
    upstream_tls_min_version: 'TLS1.2',
    session_analysis_enabled: true,
  },
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <CertificatesTab application={app} />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificatesTab 双槽位绑定与协议降级策略', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: {
        permissions: [
          'certificates.read',
          'certificates.bind',
          'applications.read',
          'applications.update',
          'gateway_configs.preview',
        ],
      } as CurrentUser,
      initialized: true,
    })
    vi.mocked(certificatesApi.applicationCertificate).mockResolvedValue({
      certificate: intlCert,
      gm_certificate: gmCert,
      bindings: { international: intlCert, gm: gmCert },
    })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [gmCert],
      total: 1,
      page: 1,
      page_size: 100,
    })
    vi.mocked(certificatesApi.bind).mockResolvedValue({ message: '证书已绑定' })
    vi.mocked(acmeApi.getAppAutoSsl).mockResolvedValue({
      application_id: app.id,
      enabled: false,
      challenge_type: 'HTTP01',
      renew_before_days: null,
      effective_renew_before_days: 30,
      global_acme_enabled: true,
      global_provider: 'LETSENCRYPT',
      auto_publish: true,
      https_domains: ['bank.example.com'],
      last_status: '',
      last_error: '',
      fail_count: 0,
      has_active_order: false,
      ready: true,
      warnings: [],
    })
    vi.mocked(tlsConfigApi.get).mockResolvedValue(baseTlsConfig)
    vi.mocked(tlsConfigApi.update).mockResolvedValue({
      ...baseTlsConfig,
      version: 3,
      message: '协议与加密策略配置已保存',
    })
  })

  it('同时展示国际槽位与国密双证书槽位，且国密绑定弹窗按 SM_TLCP 筛选', async () => {
    renderTab()

    expect(await screen.findByText('网银国际证书')).toBeInTheDocument()
    expect(screen.getByText('网银国密双证')).toBeInTheDocument()
    expect(screen.getByText('enc.bank.example.com')).toBeInTheDocument()
    expect(
      screen.getByText(/ACME 自动申请与续约仅管理「通用协议证书（国际槽位）」/),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /替换国密双证书/ }))
    expect(await screen.findByText('绑定或替换国密双证书')).toBeInTheDocument()
    await waitFor(() => {
      expect(vi.mocked(certificatesApi.list)).toHaveBeenCalledWith({
        page: 1,
        page_size: 100,
        protocol_type: 'SM_TLCP',
      })
    })
  })

  it('配置 TLS/HTTP 降级策略并保存携带乐观锁 version，成功后提示配置发布', async () => {
    renderTab()

    expect(
      await screen.findByText('协议与加密策略（TLS / HTTP 降级与自识别）'),
    ).toBeInTheDocument()
    expect(await screen.findByText('版本 v2')).toBeInTheDocument()

    // 取消勾选 HTTP/2 触发降级说明，勾选 TLS 1.0 触发弱协议告警
    fireEvent.click(screen.getByLabelText('HTTP/2'))
    expect(
      await screen.findByText(/强制对该站点执行现网 HTTP\/1.1 协议降级/),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByLabelText('TLS 1.0（弱协议）'))
    expect(
      await screen.findByText('已启用弱安全协议（TLS 1.0 / TLS 1.1）'),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /保存协议策略/ }))

    await waitFor(() => {
      expect(vi.mocked(tlsConfigApi.update)).toHaveBeenCalledWith('app-gm-1', {
        tls_protocol_mode: 'AUTO_DETECT',
        allowed_tls_versions: ['TLCP1.1', 'TLS1.0', 'TLS1.2', 'TLS1.3'],
        legacy_ssl_analysis_versions: ['SSLv2', 'SSLv2_v3', 'SSLv3'],
        http_versions: ['HTTP/1.0', 'HTTP/1.1'],
        upstream_http_version: 'AUTO',
        upstream_tls_min_version: 'TLS1.2',
        session_analysis_enabled: true,
        version: 2,
      })
    })
    expect(
      await screen.findByText('协议与加密策略已保存，尚未发布至网关'),
    ).toBeInTheDocument()
  })

  it('保存遇到 409 版本冲突时展示提示并刷新配置；无更新权限时隐藏保存按钮', async () => {
    vi.mocked(tlsConfigApi.update).mockRejectedValueOnce(
      new ApiError('配置已被其他人修改', 'RESOURCE_CONFLICT', 409),
    )
    renderTab()
    await screen.findByText('版本 v2')

    fireEvent.click(screen.getByRole('button', { name: /保存协议策略/ }))
    expect(
      await screen.findByText('配置已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()
  })

  it('仅有 applications.read 无 applications.update 时隐藏协议策略保存按钮', async () => {
    useAuthStore.setState({
      user: {
        permissions: ['certificates.read', 'applications.read'],
      } as CurrentUser,
      initialized: true,
    })
    renderTab()
    expect(
      await screen.findByText('协议与加密策略（TLS / HTTP 降级与自识别）'),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /保存协议策略/ }),
    ).not.toBeInTheDocument()
  })
})
