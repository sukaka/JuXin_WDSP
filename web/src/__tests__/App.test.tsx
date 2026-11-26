import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Link, useLocation } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { useAuthStore } from '../stores/auth'

vi.mock('../router', () => ({
  default: function MockAppRoutes() {
    const { modal, message } = AntdApp.useApp()
    const location = useLocation()

    const openModalWithLink = () => {
      let inst: ReturnType<typeof modal.warning> | null = null
      inst = modal.warning({
        title: '例外草稿已创建，但启用门禁未通过',
        content: (
          <Link to="/exceptions" onClick={() => inst?.destroy()}>
            前往例外策略页面完善后启用
          </Link>
        ),
      })
    }

    const openMessageWithLink = () => {
      message.success({
        content: <Link to="/config-publish">前往配置发布</Link>,
        duration: 5,
      })
    }

    return (
      <div>
        <div data-testid="current-path">{location.pathname}</div>
        <button type="button" onClick={openModalWithLink}>
          打开含链接弹窗
        </button>
        <button type="button" onClick={openMessageWithLink}>
          打开含链接提示
        </button>
      </div>
    )
  },
}))

import App from '../App'

describe('App provider nesting', () => {
  beforeEach(() => {
    window.history.pushState({}, '', '/security-events')
    useAuthStore.setState({ user: null, csrfToken: null, initialized: true })
  })

  afterEach(() => {
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('AntdApp.useApp() 的 modal 与 message 可正常渲染 react-router Link 并完成站内跳转', async () => {
    render(<App />)

    expect(screen.getByTestId('current-path')).toHaveTextContent('/security-events')

    fireEvent.click(screen.getByRole('button', { name: '打开含链接弹窗' }))
    const exceptionLink = await screen.findByRole('link', { name: '前往例外策略页面完善后启用' })
    expect(exceptionLink).toHaveAttribute('href', '/exceptions')

    fireEvent.click(exceptionLink)
    await waitFor(() => {
      expect(screen.getByTestId('current-path')).toHaveTextContent('/exceptions')
    })

    fireEvent.click(screen.getByRole('button', { name: '打开含链接提示' }))
    const publishLink = await screen.findByRole('link', { name: '前往配置发布' })
    expect(publishLink).toHaveAttribute('href', '/config-publish')

    fireEvent.click(publishLink)
    await waitFor(() => {
      expect(screen.getByTestId('current-path')).toHaveTextContent('/config-publish')
    })
  })
})
