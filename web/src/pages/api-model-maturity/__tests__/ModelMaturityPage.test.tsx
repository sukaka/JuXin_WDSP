import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ModelMaturityPage from '../ModelMaturityPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const maturityData = {
  generated_at: '2026-08-07T10:00:00Z',
  models: [
    {
      key: 'parameter',
      name: '参数模型',
      stage: 'LEARNING',
      metrics: { sample_count: 1200, coverage: 0.85 },
      summary: '参数模型正在学习请求与响应参数约束。',
    },
    {
      key: 'identity',
      name: '身份模型',
      stage: 'CANDIDATE',
      metrics: { identity_total: 320 },
      summary: '身份画像候选已生成，待人工确认。',
    },
    {
      key: 'access_env',
      name: '访问环境模型',
      stage: 'CONFIRMED',
      metrics: { env_signals: 12 },
      summary: '访问环境基线已确认。',
    },
    {
      key: 'access_object',
      name: '访问对象模型',
      stage: 'ENFORCING',
      metrics: { object_total: 58 },
      summary: '访问对象模型已生效并参与检测。',
    },
  ],
}

let responseBody: unknown = maturityData
let responseStatus = 200
let fetchMock: ReturnType<typeof vi.fn>

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ModelMaturityPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ModelMaturityPage', () => {
  beforeEach(() => {
    responseBody = maturityData
    responseStatus = 200
    fetchMock = vi.fn(() =>
      Promise.resolve(jsonResponse(responseStatus, { code: 'SUCCESS', message: 'ok', data: responseBody })),
    )
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染四个模型卡片：名称、阶段徽章、指标与摘要', async () => {
    renderPage()
    expect(await screen.findByText('参数模型')).toBeInTheDocument()
    expect(screen.getByText('身份模型')).toBeInTheDocument()
    expect(screen.getByText('访问环境模型')).toBeInTheDocument()
    expect(screen.getByText('访问对象模型')).toBeInTheDocument()
    // 阶段徽章：学习中 → 候选 → 已确认 → 已生效
    expect(screen.getByText('学习中')).toBeInTheDocument()
    expect(screen.getByText('候选')).toBeInTheDocument()
    expect(screen.getByText('已确认')).toBeInTheDocument()
    expect(screen.getByText('已生效')).toBeInTheDocument()
    // 指标网格：键与值（antd Statistic 默认千分位分组；小数值拆分在整数/小数 span 中，按容器断言）
    expect(screen.getByText('sample_count')).toBeInTheDocument()
    expect(screen.getByText('1,200')).toBeInTheDocument()
    const coverageTitle = screen.getByText('coverage')
    expect(coverageTitle.closest('.ant-statistic')).toHaveTextContent('0.85')
    // 摘要与生成时间
    expect(screen.getByText('参数模型正在学习请求与响应参数约束。')).toBeInTheDocument()
    expect(screen.getByText(/生成时间：/)).toBeInTheDocument()
  })

  it('无模型数据：显示空态', async () => {
    responseBody = { generated_at: '2026-08-07T10:00:00Z', models: [] }
    renderPage()
    expect(await screen.findByText('暂无模型成熟度数据')).toBeInTheDocument()
  })

  it('403 无权限：显示降级提示而非模型卡片', async () => {
    responseStatus = 403
    responseBody = null
    fetchMock.mockImplementation(() =>
      Promise.resolve(jsonResponse(403, { code: 'FORBIDDEN', message: '无权限' })),
    )
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
    expect(screen.queryByText('参数模型')).not.toBeInTheDocument()
  })

  it('点击刷新按钮重新拉取数据', async () => {
    renderPage()
    await screen.findByText('参数模型')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /刷新/ }))
    await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2))
  })
})
