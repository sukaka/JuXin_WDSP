import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiShadowZombiePage from '../ApiShadowZombiePage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
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

const finding = {
  id: 'f1',
  finding_type: 'SHADOW',
  severity: 'LOW',
  status: 'NEW',
  title: 'endpoint not in known baseline (shadow candidate)',
  endpoint_id: 'ep-1234567890abcdef',
  endpoint_key: 'POST /v1/internal/sync',
  request_id: 'req-shadow-1',
  detail: { detector: 'lifecycle', rule_id: 'lifecycle.new_endpoint' },
  first_seen_at: '2026-08-01T02:00:00Z',
  last_seen_at: '2026-08-10T02:00:00Z',
}

const detailData = {
  finding: {
    ...finding,
    subject_type: 'IP',
    subject_id: 'fp-ip-1',
    risk_score: 15,
    risk_level: 'LOW',
    count: 4,
    evidence: { endpoint_key: 'POST /v1/internal/sync' },
    model_version: 'mv-1',
    policy_version: 'pv-1',
  },
  related_request_ids: ['req-shadow-1'],
  related_request_note: '同 API（同身份）近期运行时事件的请求 ID，近似关联',
}

const lifecycleEvents = [
  {
    id: 'le-1',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'LEARNING',
    to_status: 'LEARNED',
    reason: '学习自动完成',
    actor: 'system',
    created_at: '2026-08-05T02:00:00Z',
  },
  {
    id: 'le-2',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'LEARNED',
    to_status: 'ZOMBIE',
    reason: '连续 30 天无流量',
    actor: 'system',
    created_at: '2026-08-10T02:00:00Z',
  },
  {
    id: 'le-3',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'ZOMBIE',
    to_status: 'MERGED',
    reason: '人工合并到主接口',
    actor: 'secops',
    created_at: '2026-08-11T02:00:00Z',
  },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiShadowZombiePage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiShadowZombiePage', () => {
  let postCalls: { url: string; body: unknown }[]

  beforeEach(() => {
    postCalls = []
    useAuthStore.setState({ user: null, csrfToken: null, initialized: true })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (init?.method === 'POST') {
          postCalls.push({ url, body: init.body ? JSON.parse(String(init.body)) : undefined })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { finding } }))
        }
        if (url.includes('/lifecycle-events')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: lifecycleEvents, page: 1, page_size: 50, total: lifecycleEvents.length },
            }),
          )
        }
        if (/\/api-security\/findings\/[\w-]+(\?|$)/.test(url)) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: detailData }))
        }
        if (url.includes('/api-security/findings')) {
          const isCount = url.includes('page_size=1')
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: isCount ? [] : [finding],
                page: 1,
                page_size: isCount ? 1 : 20,
                total: 1,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('卡片标题、英文风险标题与接口键、生命周期时间线均展示中文/可读标签', async () => {
    renderPage()

    expect(screen.getByText('影子与僵尸 API')).toBeInTheDocument()
    expect(screen.queryByText('Shadow 与 Zombie API')).not.toBeInTheDocument()
    // 英文标题自动映射为中文，接口列优先展示 METHOD /path
    expect(await screen.findByText('接口不在已知基线中（影子 API 候选）')).toBeInTheDocument()
    expect(screen.queryByText('endpoint not in known baseline (shadow candidate)')).not.toBeInTheDocument()
    expect(screen.getByText('POST /v1/internal/sync')).toBeInTheDocument()
    // 无 api_risk.handle 权限时不渲染行内「确认」按钮
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()

    const btn = await screen.findByRole('button', { name: '生命周期' })
    fireEvent.click(btn)

    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('接口生命周期：POST /v1/internal/sync')).toBeInTheDocument()
    expect(await within(drawer).findByText('学习中')).toBeInTheDocument()
    expect(within(drawer).getAllByText('已完成学习').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getAllByText('僵尸接口').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getByText('已合并')).toBeInTheDocument()
    expect(within(drawer).getAllByText(/系统 ·/).length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getByText(/secops ·/)).toBeInTheDocument()
    expect(within(drawer).queryByText('LEARNING')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('ZOMBIE')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('MERGED')).not.toBeInTheDocument()
    expect(within(drawer).queryByText(/^system ·/)).not.toBeInTheDocument()
  })

  it('有 api_risk.handle 权限：待确认行可直接点击「确认」调用 POST /findings/{id}/confirm', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_risk.read', 'api_risk.handle']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const confirmBtn = await screen.findByRole('button', { name: /^确\s*认$/ })
    fireEvent.click(confirmBtn)
    // 二次确认弹窗使用中文化标题
    expect(
      await screen.findByText(/确定确认风险「接口不在已知基线中（影子 API 候选）」吗/),
    ).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => expect(postCalls).toHaveLength(1))
    expect(postCalls[0].url).toContain('/api-security/findings/f1/confirm')
    expect(postCalls[0].body).toEqual({})
  })

  it('点击「详情」打开风险处置抽屉，可标记误报或跳转查看生命周期', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_risk.read', 'api_risk.handle']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /^详\s*情$/ }))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('风险详情：接口不在已知基线中（影子 API 候选）')).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: /^确\s*认$/ })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '标记误报' })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: /^忽\s*略$/ })).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: '查看生命周期' })).toBeInTheDocument()

    // 在抽屉内直接标记误报
    fireEvent.click(within(drawer).getByRole('button', { name: '标记误报' }))
    fireEvent.change(await screen.findByPlaceholderText(/说明判定为误报的依据/), {
      target: { value: '灰度发布新接口' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^确\s*定$/ }))

    await waitFor(() => expect(postCalls).toHaveLength(1))
    expect(postCalls[0].url).toContain('/api-security/findings/f1/false-positive')
    expect(postCalls[0].body).toEqual({ reason: '灰度发布新接口' })
  })

  it('点击顶部统计卡片可切换下方列表的 finding_type 筛选', async () => {
    renderPage()
    await screen.findByText('接口不在已知基线中（影子 API 候选）')

    fireEvent.click(screen.getByText('僵尸 API'))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('finding_type=ZOMBIE') && u.includes('page_size=20'))).toBe(true)
    })
  })
})
