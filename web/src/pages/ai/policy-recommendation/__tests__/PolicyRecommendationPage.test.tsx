import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import PolicyRecommendationPage from '../PolicyRecommendationPage'
import { useAuthStore } from '../../../../stores/auth'
import type { CurrentUser } from '../../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'secadmin',
  display_name: '安全管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
  permissions: ['ai.policy_recommendation.use', 'ai.draft.exception'],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const DRAFT_ID = '11111111-2222-3333-4444-555555555555'

const DRAFT = {
  id: DRAFT_ID,
  task_id: 'task-1',
  recommendation_type: 'EXCEPTION',
  target_type: 'RULE',
  target_id: '942100',
  summary: '建议为 942100 增加 URI 例外',
  evidence_references: null,
  risk_level: 'MEDIUM',
  status: 'DRAFT',
  draft_reference: DRAFT_ID,
  created_by_ai: true,
  reviewed_by: null,
  reviewed_at: null,
  created_at: '2026-10-21T01:00:00Z',
}

function stubFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    if (url.includes(`/ai/recommendations/${DRAFT_ID}/accept`) && method === 'POST') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { message: '推荐已接受，请在对应业务页面完成人工校验与发布' },
        }),
      )
    }
    if (url.includes(`/ai/recommendations/${DRAFT_ID}/reject`) && method === 'POST') {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { message: '推荐已拒绝' } }),
      )
    }
    if (url.includes(`/ai/drafts/${DRAFT_ID}`)) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { draft: DRAFT } }),
      )
    }
    if (url.includes('/ai/drafts')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: [DRAFT], page: 1, page_size: 20, total: 1 },
        }),
      )
    }
    return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
  })
}

function renderPage(entry = '/ai/policy-recommendation') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <AntdApp>
          <PolicyRecommendationPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function clickModalButton(title: string, buttonName: RegExp) {
  // antd v6 confirm 同时渲染 .ant-modal-title 与 .ant-modal-confirm-title 两份标题文本
  const titles = await screen.findAllByText(title)
  const modalEl = titles[0].closest('.ant-modal') as HTMLElement
  expect(modalEl).not.toBeNull()
  fireEvent.click(within(modalEl).getByRole('button', { name: buttonName }))
}

describe('PolicyRecommendationPage 草稿闭环', () => {
  let fetchMock: ReturnType<typeof stubFetch>

  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-token')
    localStorage.clear()
    fetchMock = stubFetch()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('草稿详情提供采纳操作：确认后调用 accept，提示未生效并给例外页面入口', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    const acceptBtn = await within(drawer).findByRole('button', { name: /采\s*纳/ })
    fireEvent.click(acceptBtn)

    await clickModalButton('采纳草稿确认', /采\s*纳/)

    // 确认后调用 accept 接口
    await screen.findAllByText('草稿已采纳（尚未生效）')
    expect(
      fetchMock.mock.calls.some(
        (c) =>
          String(c[0]).includes(`/ai/recommendations/${DRAFT_ID}/accept`) &&
          (c[1]?.method ?? 'GET') === 'POST',
      ),
    ).toBe(true)
    // 不伪装成已生效：成功提示明确未生效，并给出按类型的跳转入口
    expect(screen.getAllByText(/配置不会自动生效/).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: '前往例外策略页面' })).toBeInTheDocument()
  })

  it('草稿详情提供拒绝操作：确认后调用 reject', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(await within(drawer).findByRole('button', { name: /拒\s*绝/ }))

    await clickModalButton('拒绝草稿确认', /拒\s*绝/)

    await screen.findByText('草稿已拒绝')
    expect(
      fetchMock.mock.calls.some(
        (c) =>
          String(c[0]).includes(`/ai/recommendations/${DRAFT_ID}/reject`) &&
          (c[1]?.method ?? 'GET') === 'POST',
      ),
    ).toBe(true)
  })

  it('深链 ?draft_id= 直接打开对应草稿详情抽屉', async () => {
    renderPage(`/ai/policy-recommendation?draft_id=${DRAFT_ID}`)
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('草稿详情')).toBeInTheDocument()
    expect(within(drawer).getByText('建议为 942100 增加 URI 例外')).toBeInTheDocument()
    expect(within(drawer).getByRole('button', { name: /采\s*纳/ })).toBeInTheDocument()
  })

  it('支持 NOISE_REDUCTION 草稿类型筛选与 NOISE_CLUSTER 中文展示', async () => {
    const NOISE_DRAFT = {
      ...DRAFT,
      id: '22222222-3333-4444-5555-666666666666',
      recommendation_type: 'NOISE_REDUCTION',
      target_type: 'NOISE_CLUSTER',
      target_id: 'cluster-1',
      summary: '高频误报降噪簇建议收敛规则',
    }
    const noiseFetch = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.includes(`/ai/drafts/${NOISE_DRAFT.id}`)) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { draft: NOISE_DRAFT } }),
        )
      }
      if (url.includes('/ai/drafts')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [NOISE_DRAFT], page: 1, page_size: 20, total: 1 },
          }),
        )
      }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
    })
    vi.stubGlobal('fetch', noiseFetch)

    renderPage()
    // 表格行渲染「智能降噪」
    expect(await screen.findByText('智能降噪')).toBeInTheDocument()

    // 详情抽屉渲染「降噪簇」
    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('降噪簇')).toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }))

    // 类型下拉筛选选中「智能降噪」后触发 recommendation_type=NOISE_REDUCTION 查询
    const typeCombo = screen.getAllByRole('combobox').find((el) => {
      const select = el.closest('.ant-select')
      return select?.textContent?.includes('类型')
    })
    if (!typeCombo) throw new Error('未找到草稿类型下拉框')
    fireEvent.mouseDown(typeCombo)
    const option = await screen.findByTitle('智能降噪')
    fireEvent.click(option)

    expect(
      noiseFetch.mock.calls.some((c) => String(c[0]).includes('recommendation_type=NOISE_REDUCTION')),
    ).toBe(true)
  })

  it('B4-04：What-If remove_exception 按 page_size=100 请求并在 total > 100 时翻页拉全', async () => {
    useAuthStore.getState().setSession(
      {
        ...fakeUser,
        permissions: ['ai.policy_recommendation.use', 'ai.what_if.use', 'ai.draft.exception'],
      },
      'csrf-token',
    )
    const page1Items = Array.from({ length: 100 }, (_, i) => ({
      id: `exc-${i + 1}`,
      name: `例外-${i + 1}`,
    }))
    const page2Items = [
      { id: 'exc-101', name: '例外-101' },
      { id: 'exc-102', name: '例外-102' },
    ]
    const paginatedFetch = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.includes('/exceptions')) {
        if (url.includes('page=2')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: page2Items, page: 2, page_size: 100, total: 102 },
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: page1Items, page: 1, page_size: 100, total: 102 },
          }),
        )
      }
      if (url.includes('/ai/drafts')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [], page: 1, page_size: 20, total: 0 },
          }),
        )
      }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
    })
    vi.stubGlobal('fetch', paginatedFetch)

    renderPage()
    const scenarioCombo = await screen.findByRole('combobox', { name: '模拟场景' })
    fireEvent.mouseDown(scenarioCombo)
    const removeOpt = await screen.findByTitle('删除例外')
    fireEvent.click(removeOpt)

    await waitFor(() => {
      const excCalls = paginatedFetch.mock.calls
        .map((c) => String(c[0]))
        .filter((u) => u.includes('/exceptions'))
      expect(excCalls.some((u) => u.includes('page=1') && u.includes('page_size=100'))).toBe(true)
      expect(excCalls.some((u) => u.includes('page=2') && u.includes('page_size=100'))).toBe(true)
      expect(excCalls.some((u) => u.includes('page_size=200'))).toBe(false)
    })

    const excCombo = await screen.findByRole('combobox', { name: '例外' })
    fireEvent.mouseDown(excCombo)
    fireEvent.change(excCombo, { target: { value: '例外-102' } })
    expect(await screen.findByText(/例外-102/)).toBeInTheDocument()
  })
})
