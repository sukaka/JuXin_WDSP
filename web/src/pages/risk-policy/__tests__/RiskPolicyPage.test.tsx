import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RiskPolicyPage from '../RiskPolicyPage'
import RiskPolicyGuidePage from '../RiskPolicyGuidePage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
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

const POLICY = {
  id: 'rp-1',
  scope: 'GLOBAL',
  enabled: true,
  mode: 'OBSERVE',
  version: 3,
  block_threshold: 80,
  rate_limit_threshold: 60,
  rate_limit_rps: 5,
  signal_window_seconds: 86400,
  scores: {
    RECON: 15,
    WAF: 50,
    HEADLESS: 10,
  },
  risk_levels: { medium: 20, high: 40, critical: 70 },
  updated_by: 'admin',
  updated_at: '2026-08-31T10:00:00Z',
}

function mockFetch(put?: { status: number; body: unknown }) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }),
      )
    if (url.includes('/security/risk-policy')) {
      if (init?.method === 'PUT') {
        if (put) return Promise.resolve(jsonResponse(put.status, put.body))
        return ok({ policy: { ...POLICY, version: POLICY.version + 1 } })
      }
      return ok({ policy: POLICY })
    }
    if (url.includes('/applications')) {
      return ok({ items: [], page: 1, page_size: 100, total: 0 })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <RiskPolicyPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('RiskPolicyPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GET 回填：阈值、风险等级、信号分值与开关按策略渲染', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    // 等 GET 回填生效（useEffect setFieldsValue 异步刷新）
    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    expect(
      (screen.getByLabelText('限速阈值（1-100）') as HTMLInputElement).value,
    ).toBe('60')
    expect(
      (screen.getByLabelText('挑战阈值（0 关闭）') as HTMLInputElement).value,
    ).toBe('0')
    expect(
      (screen.getByLabelText('限速速率（次/秒）') as HTMLInputElement).value,
    ).toBe('5')
    expect(
      (screen.getByLabelText('统计窗口（秒）') as HTMLInputElement).value,
    ).toBe('86400')
    expect(
      (screen.getByLabelText('中风险下限') as HTMLInputElement).value,
    ).toBe('20')
    expect(
      (screen.getByLabelText('严重风险下限') as HTMLInputElement)
        .value,
    ).toBe('70')
    expect(screen.getByRole('switch')).toBeChecked()
    // 信号分值键值对回填（AutoComplete/InputNumber 按表单项 id 定位）
    await waitFor(() =>
      expect(
        (document.getElementById('score_entries_0_key') as HTMLInputElement)
          .value,
      ).toBe('RECON'),
    )
    expect(
      (document.getElementById('score_entries_0_value') as HTMLInputElement)
        .value,
    ).toBe('15')
    expect(
      (document.getElementById('score_entries_1_key') as HTMLInputElement)
        .value,
    ).toBe('WAF')
    expect(
      (document.getElementById('score_entries_2_value') as HTMLInputElement)
        .value,
    ).toBe('10')
    // 顶部新标签页使用说明链接
    const guideLink = screen.getByRole('link', { name: /使用说明/ })
    expect(guideLink).toHaveAttribute('href', '/risk-policy/guide')
    expect(guideLink).toHaveAttribute('target', '_blank')
    // 高级参数默认折叠，展开后可见信号分值操作按钮
    expect(
      screen.queryAllByRole('button', { name: '删除此信号分值' }),
    ).toHaveLength(0)
    fireEvent.click(
      screen.getByText(
        '高级参数：统计窗口、风险等级与信号分值（默认已调优，一般无需修改）',
      ),
    )
    expect(
      screen.getAllByRole('button', { name: '删除此信号分值' }),
    ).toHaveLength(3)
    // 顶部说明与页脚版本信息
    expect(screen.getByText(/风险分为身份级跨请求累计/)).toBeInTheDocument()
    expect(screen.getByText(/版本 v3/)).toBeInTheDocument()
  }, 15000)

  it('说明页渲染核心说明内容', () => {
    render(
      <AntdApp>
        <RiskPolicyGuidePage />
      </AntdApp>,
    )
    expect(screen.getByText('风险策略使用说明')).toBeInTheDocument()
    expect(screen.getByText(/一、日常怎么用/)).toBeInTheDocument()
  })

  it('无 risk_policy.edit 权限时不展示保存按钮且表单禁用', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByLabelText('阻断阈值（1-100）')
    expect(
      screen.queryByRole('button', { name: '保存策略' }),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.getByLabelText('挑战阈值（0 关闭）')).toBeDisabled()
    expect(
      screen.queryByRole('button', { name: '添加信号' }),
    ).not.toBeInTheDocument()
  }, 15000)

  it('PUT 成功：显式提交 challenge_threshold=0 并携带 version', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    // 等 GET 回填生效后再提交（未回填时必填校验会拦截 PUT）
    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    // 切换为 PROTECT：出现警示文案，提交体 mode 随之变化
    fireEvent.mouseDown(screen.getByLabelText('防护模式'))
    fireEvent.click(await screen.findByText('防护（达阈限速/挑战/阻断）'))
    expect(await screen.findByText('将对达阈身份实断')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))

    expect(await screen.findByText('风险策略已保存')).toBeInTheDocument()
    const putCall = fetchMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === 'PUT',
    )
    expect(putCall).toBeDefined()
    const body = JSON.parse(
      String((putCall![1] as RequestInit).body),
    ) as Record<string, unknown>
    expect(body.version).toBe(3)
    expect(body.scope).toBe('GLOBAL')
    expect(body.mode).toBe('PROTECT')
    expect(body.enabled).toBe(true)
    expect(body.block_threshold).toBe(80)
    expect(body.rate_limit_threshold).toBe(60)
    expect(body.challenge_threshold).toBe(0)
    expect(body.rate_limit_rps).toBe(5)
    expect(body.signal_window_seconds).toBe(86400)
    expect(body.scores).toEqual({ RECON: 15, WAF: 50, HEADLESS: 10 })
    expect(body.risk_levels).toEqual({ medium: 20, high: 40, critical: 70 })
    // 只读字段不下发
    expect(body.id).toBeUndefined()
    expect(body.updated_by).toBeUndefined()
    expect(body.updated_at).toBeUndefined()
  }, 15000)

  it('挑战阈值提供 0-100 边界并拒绝不大于限速阈值的倒置配置', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    const challenge = screen.getByLabelText(
      '挑战阈值（0 关闭）',
    ) as HTMLInputElement
    expect(challenge.value).toBe('0')
    expect(challenge).toHaveAttribute('aria-valuemin', '0')
    expect(challenge).toHaveAttribute('aria-valuemax', '100')

    fireEvent.change(challenge, { target: { value: '60' } })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(
      await screen.findByText('须满足：限速阈值 < 挑战阈值 < 阻断阈值'),
    ).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(
        (call) => (call[1] as RequestInit | undefined)?.method === 'PUT',
      ),
    ).toBe(false)
  }, 15000)

  it('挑战阈值拒绝达到阻断阈值，严格介于限速和阻断之间的值可保存', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    const challenge = screen.getByLabelText(
      '挑战阈值（0 关闭）',
    ) as HTMLInputElement
    fireEvent.change(challenge, { target: { value: '80' } })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(
      await screen.findByText('须满足：限速阈值 < 挑战阈值 < 阻断阈值'),
    ).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(
        (call) => (call[1] as RequestInit | undefined)?.method === 'PUT',
      ),
    ).toBe(false)

    fireEvent.change(challenge, { target: { value: '61' } })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    expect(await screen.findByText('风险策略已保存')).toBeInTheDocument()
    const putCall = fetchMock.mock.calls.find(
      (call) => (call[1] as RequestInit | undefined)?.method === 'PUT',
    )
    const body = JSON.parse(String((putCall![1] as RequestInit).body))
    expect(body.challenge_threshold).toBe(61)
  }, 15000)

  it('信号分值表重复 signal_type：提交前拦截并提示，不发起 PUT', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    // 将第二行（WAF）改为与第一行重复的 RECON
    const dupKey = document.getElementById(
      'score_entries_1_key',
    ) as HTMLInputElement
    fireEvent.change(dupKey, { target: { value: 'RECON' } })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))

    expect(
      await screen.findByText('信号分值表存在重复信号类型：RECON'),
    ).toBeInTheDocument()
    // 两行重复的键输入框均回显行级错误
    await waitFor(() =>
      expect(
        screen.getAllByText('信号类型「RECON」重复，请合并或删除重复行').length,
      ).toBe(2),
    )
    // 未发起 PUT
    expect(
      fetchMock.mock.calls.some(
        (c) => (c[1] as RequestInit | undefined)?.method === 'PUT',
      ),
    ).toBe(false)
  }, 15000)

  it('PUT 409 冲突：提示策略已被他人修改', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      mockFetch({
        status: 409,
        body: {
          code: 'RESOURCE_CONFLICT',
          message: '版本冲突',
          request_id: 'r1',
        },
      }),
    )
    renderPage()

    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))

    expect(
      await screen.findByText('策略已被他人修改，请刷新后重试'),
    ).toBeInTheDocument()
  }, 15000)

  it('PUT 400：字段级错误回显到对应表单项（含 scores.X 键值对行）', async () => {
    useAuthStore.setState({
      user: makeUser(['risk_policy.read', 'risk_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      mockFetch({
        status: 400,
        body: {
          code: 'VALIDATION_ERROR',
          message: '参数校验失败',
          request_id: 'r2',
          details: [
            { field: 'block_threshold', message: '阻断阈值必须大于限速阈值' },
            { field: 'scores.RECON', message: '分值超出允许范围' },
          ],
        },
      }),
    )
    renderPage()

    const block = (await screen.findByLabelText(
      '阻断阈值（1-100）',
    )) as HTMLInputElement
    await waitFor(() => expect(block.value).toBe('80'))
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))

    // 字段错误回显到对应表单项（scores.RECON 定位到 RECON 行的分值输入框）
    expect(
      await screen.findByText('阻断阈值必须大于限速阈值'),
    ).toBeInTheDocument()
    expect(await screen.findByText('分值超出允许范围')).toBeInTheDocument()
    expect(await screen.findByText('参数校验失败')).toBeInTheDocument()
  }, 15000)
})
