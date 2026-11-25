import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesTab from '../detail/CertificatesTab'
import type { ApplicationItem, CertificateItem, CurrentUser } from '../../../types'

vi.mock('../../../api/certificates', () => ({
  certificatesApi: {
    applicationCertificate: vi.fn(),
    applications: vi.fn(),
    list: vi.fn(),
    bind: vi.fn(),
    unbind: vi.fn(),
  },
}))

const application = { id: 'app-1', name: '订单系统', code: 'shop' } as ApplicationItem
const certificate = {
  id: 'cert-1',
  name: '订单证书',
  common_name: 'shop.example.com',
  status: 'VALID',
  san_domains: ['shop.example.com'],
} as CertificateItem

function renderTab() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <MemoryRouter>
          <CertificatesTab application={application} />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificatesTab', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(certificatesApi.applicationCertificate).mockResolvedValue({ certificate })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [certificate], total: 1, page: 1, page_size: 100,
    })
  })

  it('有绑定权限时可替换和解绑，且不再显示后端无 API 的旧文案', async () => {
    useAuthStore.setState({
      user: { permissions: ['certificates.read', 'certificates.bind'] } as CurrentUser,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('订单证书')).toBeInTheDocument()
    expect(screen.queryByText(/后端未提供证书绑定/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '替换证书' }))
    expect(await screen.findByText('绑定或替换证书')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '解绑证书' })).toBeInTheDocument()
  })

  it('无 certificates.bind 权限时不显示写操作', async () => {
    useAuthStore.setState({
      user: { permissions: ['certificates.read'] } as CurrentUser,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('订单证书')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '替换证书' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解绑证书' })).not.toBeInTheDocument()
  })

  it('未绑定时显示空状态和绑定入口', async () => {
    vi.mocked(certificatesApi.applicationCertificate).mockResolvedValue({ certificate: null })
    useAuthStore.setState({
      user: { permissions: ['certificates.read', 'certificates.bind'] } as CurrentUser,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('当前应用未绑定证书')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '绑定证书' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解绑证书' })).not.toBeInTheDocument()
  })

  it('无 certificates.read 权限时不调用证书查询接口', () => {
    useAuthStore.setState({
      user: { permissions: ['applications.read'] } as CurrentUser,
      initialized: true,
    })
    renderTab()

    expect(screen.getByText('缺少「证书查看」权限，无法查看证书绑定信息')).toBeInTheDocument()
    expect(certificatesApi.applicationCertificate).not.toHaveBeenCalled()
    expect(certificatesApi.list).not.toHaveBeenCalled()
  })

  it('已绑定证书以凭证卡片展示 SAN 域名并支持打开详情抽屉', async () => {
    vi.mocked(certificatesApi.applicationCertificate).mockResolvedValue({
      certificate: {
        ...certificate,
        issuer: 'Let\'s Encrypt R11',
        san_domains: ['shop.example.com', 'www.shop.example.com'],
      } as CertificateItem,
    })
    useAuthStore.setState({
      user: { permissions: ['certificates.read', 'certificates.bind'] } as CurrentUser,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('订单证书')).toBeInTheDocument()
    expect(screen.getByText('www.shop.example.com')).toBeInTheDocument()
    expect(screen.getByText('Let\'s Encrypt R11')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /查看详情/ }))
    expect(await screen.findByText('证书详情')).toBeInTheDocument()
  })
})
