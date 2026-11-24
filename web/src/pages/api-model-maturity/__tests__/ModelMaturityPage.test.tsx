import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
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
      Promise.resolve(
        jsonResponse(responseStatus, {
          code: 'SUCCESS',
          message: 'ok',
          data: responseBody,
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染四个模型卡片、生命周期、核心指标与阶段统计', async () => {
    renderPage()

    const parameterCard = await screen.findByRole('article', {
      name: '参数模型',
    })
    const identityCard = screen.getByRole('article', { name: '身份模型' })
    const environmentCard = screen.getByRole('article', {
      name: '访问环境模型',
    })
    const objectCard = screen.getByRole('article', { name: '访问对象模型' })

    const currentStages = [
      [parameterCard, '学习中'],
      [identityCard, '候选'],
      [environmentCard, '已确认'],
      [objectCard, '已生效'],
    ] as const
    for (const [card, stage] of currentStages) {
      const name = card.getAttribute('aria-label')
      const lifecycle = within(card).getByRole('list', {
        name: `${name}成熟度阶段`,
      })
      expect(within(lifecycle).getByText(stage).closest('li')).toHaveAttribute(
        'aria-current',
        'step',
      )
    }

    const summary = screen.getByRole('region', { name: '成熟度阶段统计' })
    expect(within(summary).getByText('模型总数')).toBeInTheDocument()
    expect(within(summary).getByText('4')).toBeInTheDocument()
    for (const stage of ['学习中', '候选', '已确认', '已生效']) {
      const stageCount = within(summary).getByText(stage).closest('div')
      expect(stageCount).toHaveTextContent('1')
    }

    expect(within(parameterCard).getByText('sample_count')).toBeInTheDocument()
    expect(within(parameterCard).getByText('1,200')).toBeInTheDocument()
    expect(within(parameterCard).getByText('coverage')).toBeInTheDocument()
    expect(within(parameterCard).getByText('85%')).toBeInTheDocument()
    expect(
      within(parameterCard).getByText('参数模型正在学习请求与响应参数约束。'),
    ).toBeInTheDocument()
    expect(
      within(parameterCard).getByRole('button', { name: /查看参数模型/ }),
    ).toBeInTheDocument()
    expect(screen.getByText(/更新于/)).toBeInTheDocument()
  })

  it('无模型数据：显示空态', async () => {
    responseBody = { generated_at: '2026-08-07T10:00:00Z', models: [] }
    renderPage()
    expect(await screen.findByText('暂无模型成熟度数据')).toBeInTheDocument()
  })

  it('覆盖率核心指标统一显示为百分比，次要指标继续完整展示', async () => {
    responseBody = {
      generated_at: '2026-08-07T10:00:00Z',
      models: [
        {
          key: 'identity',
          name: '身份模型',
          stage: 'CONFIRMED',
          metrics: {
            identity_coverage_24h: 0.5,
            events_24h: 4,
            events_with_identity_24h: 2,
            distinct_identities_24h: 1,
          },
          summary: '身份覆盖率已达标',
        },
        {
          key: 'access_env',
          name: '访问环境模型',
          stage: 'CONFIRMED',
          metrics: {
            endpoint_coverage: 1,
            endpoints_total: 697,
            profiles_total: 1179,
          },
          summary: '环境画像覆盖率已达标',
        },
        {
          key: 'access_object',
          name: '访问对象模型',
          stage: 'CANDIDATE',
          metrics: {
            object_endpoint_coverage: 0.0947,
            object_models_total: 131,
          },
          summary: '对象模型正在沉淀',
        },
      ],
    }

    renderPage()
    const identityCard = await screen.findByRole('article', {
      name: '身份模型',
    })
    const environmentCard = screen.getByRole('article', {
      name: '访问环境模型',
    })
    const objectCard = screen.getByRole('article', { name: '访问对象模型' })

    expect(within(identityCard).getByText('50%')).toBeInTheDocument()
    expect(
      within(identityCard).getByText('近 24 小时事件数'),
    ).toBeInTheDocument()
    expect(within(environmentCard).getByText('100%')).toBeInTheDocument()
    expect(within(environmentCard).getByText('端点总数')).toBeInTheDocument()
    expect(within(environmentCard).getByText('1,179')).toBeInTheDocument()
    expect(within(objectCard).getByText('9.47%')).toBeInTheDocument()
    expect(within(objectCard).getByText('对象模型总数')).toBeInTheDocument()
    expect(within(environmentCard).getAllByText('端点画像覆盖率')).toHaveLength(
      1,
    )
  })

  it('403 无权限：显示降级提示而非模型卡片', async () => {
    responseStatus = 403
    responseBody = null
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        jsonResponse(403, { code: 'FORBIDDEN', message: '无权限' }),
      ),
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
    await waitFor(() =>
      expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2),
    )
  })

  it('后端成熟度指标键与缺省模型名中文化展示，不回退原始 snake_case', async () => {
    responseBody = {
      generated_at: '2026-08-07T10:00:00Z',
      models: [
        {
          key: 'parameter',
          name: '',
          stage: 'LEARNING',
          metrics: { parameters_total: 42, with_recommended: 18 },
          summary: '参数统计中',
        },
        {
          key: 'access_object',
          name: '',
          stage: 'ENFORCING',
          metrics: { object_models_total: 11, resource_signal_events_24h: 256 },
          summary: '对象模型运行中',
        },
      ],
    }
    renderPage()
    expect(await screen.findByText('参数模型')).toBeInTheDocument()
    expect(screen.getByText('访问对象模型')).toBeInTheDocument()
    expect(screen.getByText('参数总数')).toBeInTheDocument()
    expect(screen.getByText('已产出推荐约束')).toBeInTheDocument()
    expect(screen.getByText('对象模型总数')).toBeInTheDocument()
    expect(screen.getByText('近 24 小时对象信号事件')).toBeInTheDocument()
    expect(screen.queryByText('parameters_total')).not.toBeInTheDocument()
    expect(screen.queryByText('object_models_total')).not.toBeInTheDocument()
  })
})
