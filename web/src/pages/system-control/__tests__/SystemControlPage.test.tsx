import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemControlPage from '../SystemControlPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const ALL_PERMISSIONS = ['system.reboot', 'system.shutdown', 'system.factory_reset']

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'admin',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetchOk() {
  return vi.fn(() =>
    Promise.resolve(jsonResponse(202, { code: 'SUCCESS', message: 'ok', data: { message: '指令已受理' } })),
  )
}

function mockFetchError() {
  return vi.fn(() =>
    Promise.resolve(jsonResponse(403, { code: 'FORBIDDEN', message: '密码错误', data: null })),
  )
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SystemControlPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function findPostCall(urlPart: string) {
  return (fetch as Mock).mock.calls.find(
    (c) => String(c[0]).includes(urlPart) && c[1]?.method === 'POST',
  )
}

async function waitForPostBody(urlPart: string): Promise<Record<string, unknown>> {
  await waitFor(() => expect(findPostCall(urlPart)).toBeTruthy())
  return JSON.parse(String(findPostCall(urlPart)![1]?.body)) as Record<string, unknown>
}

describe('SystemControlPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetchOk())
    useAuthStore.setState({
      user: makeUser(ALL_PERMISSIONS),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染系统重启 / 系统关机 / 恢复出厂设置三个操作区', () => {
    renderPage()
    expect(screen.getByText('系统重启')).toBeInTheDocument()
    expect(screen.getByText('系统关机')).toBeInTheDocument()
    // 「恢复出厂设置」同时作为分区标题与按钮文案出现
    expect(screen.getAllByText('恢复出厂设置').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByRole('button', { name: /立即重启/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /立即关机/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /恢复出厂设置/ })).toBeInTheDocument()
  })

  it('无对应权限时不展示该操作区', () => {
    useAuthStore.setState({ user: makeUser(['system.reboot']), csrfToken: null, initialized: true })
    renderPage()
    expect(screen.getByText('系统重启')).toBeInTheDocument()
    expect(screen.queryByText('系统关机')).not.toBeInTheDocument()
    expect(screen.queryByText('恢复出厂设置')).not.toBeInTheDocument()
  })

  it('点击立即重启弹出密码确认弹窗，密码为空时确认按钮禁用', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /立即重启/ }))
    expect(await screen.findByText('高风险操作确认：系统重启')).toBeInTheDocument()

    const okButton = screen.getByRole('button', { name: /确认执行/ })
    expect(okButton).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText('请输入当前账号密码'), { target: { value: 'secret' } })
    expect(okButton).toBeEnabled()
  })

  it('密码确认后调用 reboot 接口并提示指令已受理', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /立即重启/ }))
    fireEvent.change(await screen.findByPlaceholderText('请输入当前账号密码'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: /确认执行/ }))

    const body = await waitForPostBody('/system/reboot')
    expect(body.password).toBe('secret')
    expect(await screen.findByText(/重启指令已受理/)).toBeInTheDocument()
  })

  it('恢复出厂设置需输入「恢复出厂」确认文字才可确认，请求体携带 confirmText', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /恢复出厂设置/ }))
    expect(await screen.findByText('高风险操作确认：恢复出厂设置')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('请输入当前账号密码'), { target: { value: 'secret' } })
    const okButton = screen.getByRole('button', { name: /确认执行/ })
    expect(okButton).toBeDisabled()

    const confirmInput = screen.getByPlaceholderText('请输入「恢复出厂」以确认')
    fireEvent.change(confirmInput, { target: { value: '恢复出' } })
    expect(okButton).toBeDisabled()
    expect(screen.getAllByText('请输入「恢复出厂」以确认').length).toBeGreaterThan(0)

    fireEvent.change(confirmInput, { target: { value: '恢复出厂' } })
    expect(okButton).toBeEnabled()
    fireEvent.click(okButton)

    const body = await waitForPostBody('/system/factory-reset')
    expect(body.password).toBe('secret')
    expect(body.confirmText).toBe('恢复出厂')
    expect(await screen.findByText(/初始管理员账号重新登录/)).toBeInTheDocument()
  })

  it('接口报错时展示后端错误信息', async () => {
    vi.stubGlobal('fetch', mockFetchError())
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /立即关机/ }))
    fireEvent.change(await screen.findByPlaceholderText('请输入当前账号密码'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /确认执行/ }))

    await waitForPostBody('/system/shutdown')
    expect(await screen.findByText('密码错误')).toBeInTheDocument()
  })

  it('取消弹窗后清空内部输入状态', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /立即重启/ }))
    fireEvent.change(await screen.findByPlaceholderText('请输入当前账号密码'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: /取\s*消/ }))
    await waitFor(() => expect(screen.queryByText('高风险操作确认：系统重启')).not.toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /立即重启/ }))
    const passwordInput = (await screen.findByPlaceholderText('请输入当前账号密码')) as HTMLInputElement
    expect(passwordInput.value).toBe('')
    expect(screen.getByRole('button', { name: /确认执行/ })).toBeDisabled()
  })
})
