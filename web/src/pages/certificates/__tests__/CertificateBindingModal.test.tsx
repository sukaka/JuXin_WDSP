import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../../api/client'
import { applicationsApi } from '../../../api/applications'
import { certificatesApi } from '../../../api/certificates'
import { useAuthStore } from '../../../stores/auth'
import CertificateBindingModal from '../CertificateBindingModal'
import type { ApplicationItem, CertificateItem, CurrentUser } from '../../../types'

vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))
vi.mock('../../../api/certificates', () => ({
  certificatesApi: {
    applications: vi.fn(),
    list: vi.fn(),
    bind: vi.fn(),
    unbind: vi.fn(),
  },
}))

const application = {
  id: 'app-1',
  code: 'shop',
  name: '订单系统',
} as ApplicationItem
const otherApplication = {
  id: 'app-2',
  code: 'other',
  name: '其他系统',
} as ApplicationItem
const certificate = {
  id: 'cert-1',
  name: '旧证书',
  common_name: 'shop.example.com',
  status: 'VALID',
} as CertificateItem
const replacement = {
  id: 'cert-2',
  name: '新证书',
  common_name: 'shop.example.com',
  status: 'VALID',
} as CertificateItem

function renderModal(operation: 'bind' | 'unbind', withApplication: boolean) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <MemoryRouter initialEntries={['/']}>
          <Routes>
            <Route
              path="/"
              element={
                <CertificateBindingModal
                  open
                  operation={operation}
                  application={withApplication ? application : undefined}
                  certificate={withApplication ? undefined : certificate}
                  onClose={vi.fn()}
                />
              }
            />
            <Route path="/config-publish" element={<div>配置发布页</div>} />
          </Routes>
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('CertificateBindingModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({
      user: { permissions: ['certificates.bind', 'gateway_configs.preview'] } as CurrentUser,
      initialized: true,
    })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [application, otherApplication],
      total: 2,
      page: 1,
      page_size: 100,
    })
    vi.mocked(certificatesApi.list).mockResolvedValue({
      items: [certificate, replacement],
      total: 2,
      page: 1,
      page_size: 100,
    })
    vi.mocked(certificatesApi.applications).mockResolvedValue({
      application_ids: ['app-1'],
      count: 1,
    })
    vi.mocked(certificatesApi.bind).mockResolvedValue({ message: '证书已绑定' })
    vi.mocked(certificatesApi.unbind).mockResolvedValue({ message: '证书已解绑' })
  })

  it('应用侧选择新证书，保存后进入真实发布入口', async () => {
    renderModal('bind', true)

    fireEvent.mouseDown(await screen.findByLabelText('选择证书'))
    fireEvent.click(await screen.findByText('新证书（shop.example.com）'))
    fireEvent.click(screen.getByRole('button', { name: '保存绑定' }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.bind)).toHaveBeenCalledWith('cert-2', 'app-1')
    })
    expect(await screen.findByText('绑定关系已保存，尚未发布')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '去配置发布' }))
    expect(await screen.findByText('配置发布页')).toBeInTheDocument()
  })

  it('证书侧解绑只列出当前活动绑定应用', async () => {
    renderModal('unbind', false)

    fireEvent.mouseDown(await screen.findByLabelText('选择应用'))
    expect(await screen.findByText('订单系统（shop）')).toBeInTheDocument()
    expect(screen.queryByText('其他系统（other）')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('订单系统（shop）'))
    fireEvent.click(screen.getByRole('button', { name: '确认解绑' }))

    await waitFor(() => {
      expect(vi.mocked(certificatesApi.unbind)).toHaveBeenCalledWith('cert-1', 'app-1')
    })
    expect(await screen.findByText('解绑关系已保存，尚未发布')).toBeInTheDocument()
  })

  it('域名不匹配等后端错误必须展示且不能显示保存成功', async () => {
    vi.mocked(certificatesApi.bind).mockRejectedValue(
      new ApiError('证书域名不匹配：other.example.com', 'INVALID_ARGUMENT', 400),
    )
    renderModal('bind', true)

    fireEvent.mouseDown(await screen.findByLabelText('选择证书'))
    fireEvent.click(await screen.findByText('新证书（shop.example.com）'))
    fireEvent.click(screen.getByRole('button', { name: '保存绑定' }))

    expect(await screen.findByText(/证书域名不匹配/)).toBeInTheDocument()
    expect(screen.queryByText('绑定关系已保存，尚未发布')).not.toBeInTheDocument()
  })
})
