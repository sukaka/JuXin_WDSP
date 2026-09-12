import { afterEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { RequireWebWaf } from '../RequireWebWaf'
import { useProductStore } from '../../stores/product'

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/protection-policies"
          element={
            <RequireWebWaf>
              <div>WAF 域页面</div>
            </RequireWebWaf>
          }
        />
        <Route path="/403" element={<div>无权限页</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('RequireWebWaf 产品形态守卫', () => {
  afterEach(() => {
    useProductStore.getState().reset()
  })

  it('产品能力未初始化时显示全屏 Loading，不渲染子页面也不跳转', () => {
    useProductStore.setState({ initialized: false })
    const { container } = renderAt('/protection-policies')
    expect(container.querySelector('.ant-spin')).toBeTruthy()
    expect(screen.queryByText('WAF 域页面')).not.toBeInTheDocument()
    expect(screen.queryByText('无权限页')).not.toBeInTheDocument()
  })

  it('纯 API 形态（webWafEnabled=false）重定向到 /403', async () => {
    useProductStore.setState({ edition: 'api', webWafEnabled: false, initialized: true })
    renderAt('/protection-policies')
    expect(await screen.findByText('无权限页')).toBeInTheDocument()
    expect(screen.queryByText('WAF 域页面')).not.toBeInTheDocument()
  })

  it('WAF/WDSP 形态（webWafEnabled=true）放行 WAF 域路由', () => {
    useProductStore.setState({ edition: 'waf', webWafEnabled: true, initialized: true })
    renderAt('/protection-policies')
    expect(screen.getByText('WAF 域页面')).toBeInTheDocument()
    expect(screen.queryByText('无权限页')).not.toBeInTheDocument()
  })
})
