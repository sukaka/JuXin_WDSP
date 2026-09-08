import { afterEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { RequireApm } from '../RequireApm'
import { useProductStore } from '../../stores/product'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/apm-overview"
          element={
            <RequireApm>
              <div>APM 页面</div>
            </RequireApm>
          }
        />
        <Route path="*" element={<div>404 页</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('RequireApm 能力守卫', () => {
  afterEach(() => {
    useProductStore.getState().reset()
  })

  it('产品能力未初始化时显示全屏 Loading，不渲染子页面也不跳转', () => {
    useProductStore.setState({ initialized: false })
    const { container } = renderAt('/apm-overview')
    expect(container.querySelector('.ant-spin')).toBeTruthy()
    expect(screen.queryByText('APM 页面')).not.toBeInTheDocument()
    expect(screen.queryByText('404 页')).not.toBeInTheDocument()
  })

  it('apm_enabled 关闭时按不存在处理（重定向到 /404）', async () => {
    useProductStore.setState({ apmEnabled: false, initialized: true })
    renderAt('/apm-overview')
    expect(await screen.findByText('404 页')).toBeInTheDocument()
    expect(screen.queryByText('APM 页面')).not.toBeInTheDocument()
  })

  it('apm_enabled 开启时放行 APM 路由', () => {
    useProductStore.setState({ apmEnabled: true, initialized: true })
    renderAt('/apm-overview')
    expect(screen.getByText('APM 页面')).toBeInTheDocument()
    expect(screen.queryByText('404 页')).not.toBeInTheDocument()
  })
})
