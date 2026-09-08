import { afterEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { RequireLicense } from '../RequireLicense'
import { useLicenseStore } from '../../stores/license'
import type { LicenseState } from '../../types'

function makeState(partial: Partial<LicenseState>): LicenseState {
  return {
    valid: false,
    product: '',
    quotas: { max_applications: 0, max_api_endpoints: 0, max_qps: 0 },
    features: [],
    expires_at: null,
    license_id: '',
    customer: '',
    license_type: '',
    reason: '',
    host_fingerprint: '',
    ...partial,
  }
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/dashboard"
          element={
            <RequireLicense>
              <div>应用页</div>
            </RequireLicense>
          }
        />
        <Route
          path="/license"
          element={
            <RequireLicense>
              <div>授权管理页</div>
            </RequireLicense>
          }
        />
      </Routes>
    </MemoryRouter>,
  )
}

describe('RequireLicense 授权守卫', () => {
  afterEach(() => {
    useLicenseStore.getState().reset()
  })

  it('状态未加载完成时显示全屏 Loading，不渲染子页面也不跳转', () => {
    useLicenseStore.setState({ status: null, initialized: false })
    const { container } = renderAt('/dashboard')
    expect(container.querySelector('.ant-spin')).toBeTruthy()
    expect(screen.queryByText('应用页')).not.toBeInTheDocument()
    expect(screen.queryByText('授权管理页')).not.toBeInTheDocument()
  })

  it('授权无效时重定向到 /license', async () => {
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    renderAt('/dashboard')
    expect(await screen.findByText('授权管理页')).toBeInTheDocument()
    expect(screen.queryByText('应用页')).not.toBeInTheDocument()
  })

  it('授权状态加载失败（status=null）同样锁定到 /license', async () => {
    useLicenseStore.setState({ status: null, initialized: true })
    renderAt('/dashboard')
    expect(await screen.findByText('授权管理页')).toBeInTheDocument()
    expect(screen.queryByText('应用页')).not.toBeInTheDocument()
  })

  it('授权无效时 /license 本身保持可访问', () => {
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '授权已到期' }),
      initialized: true,
    })
    renderAt('/license')
    expect(screen.getByText('授权管理页')).toBeInTheDocument()
  })

  it('授权有效时放行业务路由', () => {
    useLicenseStore.setState({
      status: makeState({ valid: true, product: 'waf', license_type: 'FORMAL' }),
      initialized: true,
    })
    renderAt('/dashboard')
    expect(screen.getByText('应用页')).toBeInTheDocument()
    expect(screen.queryByText('授权管理页')).not.toBeInTheDocument()
  })
})
