import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiLearningPage from '../ApiLearningPage'
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

const endpointsData = {
  items: [
    {
      id: 'e1',
      http_method: 'POST',
      normalized_path: '/v1/orders/{id}',
      endpoint_key: 'POST /v1/orders/{id}',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNING',
      is_api: true,
      hit_count: 12,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const runningStatus = {
  learning_status: 'LEARNING',
  job: {
    id: 'j1',
    status: 'RUNNING',
    sample_target: 500,
    collected_count: 320,
    valid_count: 280,
    excluded_count: 40,
    last_error: '',
    started_at: '2026-07-20T02:00:00Z',
    stopped_at: null,
  },
  samples_total: 320,
  samples_valid: 280,
  samples_excluded: 40,
}

const notStartedStatus = {
  learning_status: 'NOT_STARTED',
  job: null,
}

const samplesData = {
  items: [
    {
      id: 's1',
      api_endpoint_id: 'e1',
      request_id: 'r1',
      sample_hash: 'abcdef1234567890',
      source_fingerprint: '',
      identity_fingerprint: '',
      response_status: 200,
      accepted: true,
      exclude_reason: '',
      collected_at: '2026-07-22T08:00:00Z',
    },
    {
      id: 's2',
      api_endpoint_id: 'e1',
      request_id: 'r2',
      sample_hash: '0011223344556677',
      source_fingerprint: '',
      identity_fingerprint: '',
      response_status: null,
      accepted: false,
      exclude_reason: 'CONTENT_TYPE',
      collected_at: '2026-07-22T08:01:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

let statusBody: unknown = runningStatus

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiLearningPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiLearningPage', () => {
  beforeEach(() => {
    statusBody = runningStatus
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/learning/status')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: statusBody }))
        }
        if (url.includes('/learning/samples')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: samplesData }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染学习任务卡片与样本表格：中文状态、哈希截断、分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_learning.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('学习中')).toBeInTheDocument()
    expect(await screen.findByText('运行中')).toBeInTheDocument()
    expect(screen.getByText('500')).toBeInTheDocument()
    expect(screen.getByText('320')).toBeInTheDocument()
    expect(screen.getByText('abcdef1234…')).toBeInTheDocument()
    expect(screen.getByText('已采纳')).toBeInTheDocument()
    expect(screen.getByText('已排除')).toBeInTheDocument()
    expect(screen.getByText('CONTENT_TYPE')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无学习任务：显示空态与「未开始」状态', async () => {
    statusBody = notStartedStatus
    useAuthStore.setState({ user: makeUser(['api_learning.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('未开始')).toBeInTheDocument()
    expect(screen.getByText(/暂无学习任务/)).toBeInTheDocument()
  })

  it('无 start/stop 权限：不显示「启动学习」与「停止学习」', async () => {
    useAuthStore.setState({ user: makeUser(['api_learning.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('学习中')
    expect(screen.queryByRole('button', { name: /启动学习/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /停止学习/ })).not.toBeInTheDocument()
  })

  it('有 stop 权限且学习中：显示「停止学习」，不显示「启动学习」', async () => {
    useAuthStore.setState({
      user: makeUser(['api_learning.read', 'api_learning.stop']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByRole('button', { name: /停止学习/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /启动学习/ })).not.toBeInTheDocument()
  })

  it('有 start 权限且未开始学习：显示「启动学习」', async () => {
    statusBody = notStartedStatus
    useAuthStore.setState({
      user: makeUser(['api_learning.read', 'api_learning.start']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByRole('button', { name: /启动学习/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /停止学习/ })).not.toBeInTheDocument()
  })

  it('启动学习：确认弹窗默认样本目标 100，修改后随请求提交 sample_target', async () => {
    statusBody = notStartedStatus
    useAuthStore.setState({
      user: makeUser(['api_learning.read', 'api_learning.start']),
      csrfToken: null,
      initialized: true,
    })
    // 包装 beforeEach 的 fetch stub 旁路记录请求（含 body）
    const calls: { url: string; body?: string }[] = []
    const inner = globalThis.fetch
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), body: init?.body ? String(init.body) : undefined })
      return inner(input, init)
    })
    renderPage()
    // 等待接口自动选中后按钮可用（disabled={!endpointId}；轮询重新查询按钮）
    await waitFor(
      () => expect(screen.getByRole('button', { name: /启动学习/ })).toBeEnabled(),
      { timeout: 3000 },
    )
    fireEvent.click(screen.getByRole('button', { name: /启动学习/ }))
    // 确认弹窗含样本目标输入（默认 100）
    const input = (await screen.findByRole('spinbutton')) as HTMLInputElement
    expect(input.value).toBe('100')
    fireEvent.change(input, { target: { value: '500' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      const startCall = calls.find((c) => c.url.includes('/learning/start'))
      expect(startCall).toBeTruthy()
      expect(JSON.parse(startCall?.body ?? '')).toEqual({ sample_target: 500 })
    })
  })
})
