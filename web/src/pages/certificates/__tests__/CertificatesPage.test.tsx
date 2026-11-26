import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { applicationsApi } from '../../../api/applications'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificatesPage from '../CertificatesPage'
import type { ApplicationItem, CertificateItem, CurrentUser } from '../../../types'

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

const certificate = {
  id: 'cert-1',
  name: '订单证书',
  common_name: 'shop.example.com',
  san_domains: ['shop.example.com'],
  status: 'VALID',
  usage_count: 0,
} as CertificateItem
const application = { id: 'app-1', name: '订单系统', code: 'shop' } as ApplicationItem

describe('CertificatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: {
        permissions: ['certificates.read', 'certificates.bind', 'certificates.delete', 'applications.read'],
      } as CurrentUser,
      initialized: true,
    })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [certificate], total: 1, page: 1, page_size: 100,
    })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [application], total: 1, page: 1, page_size: 100,
    })
    vi.mocked(certificatesApi.bind).mockResolvedValue({ message: '证书已绑定' })
  })

  it('证书列表直接提供绑定入口并保存到所选应用', async () => {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <MemoryRouter>
            <CertificatesPage />
          </MemoryRouter>
        </AntdApp>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('订单证书')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '绑定/替换' }))
    fireEvent.mouseDown(await screen.findByLabelText('选择应用'))
    fireEvent.click(await screen.findByText('订单系统（shop）'))
    fireEvent.click(screen.getByRole('button', { name: '保存绑定' }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.bind)).toHaveBeenCalledWith('cert-1', 'app-1')
    })
    expect(await screen.findByText('绑定关系已保存，尚未发布')).toBeInTheDocument()
  })
})
