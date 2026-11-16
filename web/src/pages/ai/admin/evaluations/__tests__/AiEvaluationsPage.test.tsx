import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AiEvaluationsPage from '../AiEvaluationsPage'
import { useAuthStore } from '../../../../../stores/auth'
import type { CurrentUser } from '../../../../../types'

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

const feedbackItems = [
  {
    task_type: 'EVENT_ANALYSIS',
    feedback_type: 'HALLUCINATION',
    total: 10,
    negative: 4,
    negative_rate: 40,
  },
  {
    task_type: 'GENERAL_SECURITY_QA',
    feedback_type: 'GENERAL',
    total: 5,
    negative: 0,
    negative_rate: 0,
  },
]

let feedbackUrls: string[]
let feedbackResponder: () => Promise<Response>

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <AiEvaluationsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AiEvaluationsPage · 反馈质量卡片', () => {
  beforeEach(() => {
    feedbackUrls = []
    feedbackResponder = () =>
      Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: feedbackItems } }),
      )
    useAuthStore.setState({
      user: makeUser(['ai.evaluations.run']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const path = new URL(url, 'http://localhost').pathname
        const method = init?.method ?? 'GET'
        if (method === 'GET' && path.endsWith('/ai/feedback/summary')) {
          feedbackUrls.push(url)
          return feedbackResponder()
        }
        if (method === 'GET' && path.endsWith('/ai/evaluation-sets')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [] } }),
          )
        }
        if (method === 'GET' && path.endsWith('/ai/evaluation-runs')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 20, total: 0 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('默认拉取近 7 天聚合并按任务类型×反馈类型渲染表格（无 comment 列）', async () => {
    renderPage()
    expect(await screen.findByText('反馈质量')).toBeInTheDocument()
    await waitFor(() => expect(feedbackUrls).toHaveLength(1))
    expect(feedbackUrls[0]).toContain('/api/v1/ai/feedback/summary')
    expect(feedbackUrls[0]).toContain('days=7')

    const card = screen.getByText('反馈质量').closest('.ant-card') as HTMLElement
    // 任务类型/反馈类型中文标签 + 聚合计数 + 负向率百分比
    expect(await within(card).findByText('事件分析')).toBeInTheDocument()
    expect(within(card).getByText('幻觉')).toBeInTheDocument()
    expect(within(card).getByText('10')).toBeInTheDocument()
    expect(within(card).getByText('4')).toBeInTheDocument()
    expect(within(card).getByText('40.0%')).toBeInTheDocument()
    expect(within(card).getByText('安全问答')).toBeInTheDocument()
    expect(within(card).getByText('一般')).toBeInTheDocument()
    expect(within(card).getByText('0.0%')).toBeInTheDocument()
    // 聚合视图不含反馈原文列
    expect(within(card).queryByText('评论')).not.toBeInTheDocument()
    expect(within(card).queryByText('comment', { exact: false })).not.toBeInTheDocument()
  })

  it('切换「近 30 天」后以 days=30 重新拉取', async () => {
    renderPage()
    await screen.findByText('反馈质量')
    await waitFor(() => expect(feedbackUrls).toHaveLength(1))
    fireEvent.click(screen.getByText('近 30 天'))
    await waitFor(() => expect(feedbackUrls.length).toBeGreaterThanOrEqual(2))
    expect(feedbackUrls[feedbackUrls.length - 1]).toContain('days=30')
  })

  it('反馈汇总接口失败时展示错误告警（不静默吞错）', async () => {
    feedbackResponder = () =>
      Promise.resolve(
        jsonResponse(500, { code: 'INTERNAL', message: 'feedback db down', data: null }),
      )
    renderPage()
    const card = (await screen.findByText('反馈质量')).closest('.ant-card') as HTMLElement
    expect(await within(card).findByText('加载反馈质量统计失败')).toBeInTheDocument()
    expect(within(card).getByText('feedback db down')).toBeInTheDocument()
  })
})
