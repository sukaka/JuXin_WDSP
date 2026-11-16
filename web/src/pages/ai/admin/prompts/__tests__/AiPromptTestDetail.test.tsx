import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AiPromptsPage from '../AiPromptsPage'
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

const prompt = {
  id: 'p1',
  code: 'dispatcher.system',
  name: '总调度系统提示词',
  prompt_type: 'SYSTEM',
  status: 'ACTIVE',
  current_version_id: null,
  created_at: '2026-09-01T00:00:00Z',
}

const versions = [
  {
    id: 'v1',
    prompt_id: 'p1',
    version_number: 1,
    content: '你是安全运营助手。',
    content_hash: 'hash',
    change_summary: '',
    test_result: '',
    adversarial_result: '',
    adversarial_detail: null,
    created_at: '2026-09-01T00:00:00Z',
    published_at: null,
    is_current: false,
  },
]

/** 带 test_detail 的版本测试响应：一个未通过集（含逐用例摘要与失败原因）+ 一个通过集 + 静态检查 */
const TEST_DETAIL_RESPONSE = {
  test_result: 'FAILED',
  checks: [{ name: '长度检查', passed: true }],
  test_detail: {
    sets: [
      {
        code: 'event_analysis_v1',
        name: '事件分析回归集',
        score: 0.62,
        threshold: 0.8,
        passed: false,
        total: 5,
        passed_count: 3,
        model_code: 'gpt-4o-mini',
        message: '得分低于阈值',
        cases: [
          { id: 'case-1', question: '942100 是什么规则', passed: true },
          { id: 'case-2', question: '分析该安全事件', passed: false, message: '回答缺少证据引用' },
        ],
      },
      {
        code: 'qa_v1',
        name: '安全问答集',
        score: 0.95,
        threshold: 0.8,
        passed: true,
        total: 4,
        passed_count: 4,
        model_code: 'gpt-4o-mini',
      },
    ],
    static_checks: [
      { name: '长度检查', passed: true },
      { name: '占位符检查', passed: false, message: '缺少 {input} 占位符' },
    ],
  },
}

let testCalls: string[]
let testDetailResponse: unknown = TEST_DETAIL_RESPONSE

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <AiPromptsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function openVersionsDrawer(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByRole('button', { name: '版本' }))
  await screen.findByText('v1')
  const drawer = document.body.querySelector('.ant-drawer-section') as HTMLElement | null
  if (!drawer) throw new Error('未找到版本管理抽屉')
  return drawer
}

/** 点击 v1 行的「测试」按钮并等待结果弹窗 */
async function runTestAndGetDialog(): Promise<HTMLElement> {
  const drawer = await openVersionsDrawer()
  const cell = within(drawer).getByText('v1')
  const row = cell.closest('tr')
  if (!row) throw new Error('未找到版本行 v1')
  fireEvent.click(within(row).getByRole('button', { name: '测试' }))
  await waitFor(() => expect(testCalls).toHaveLength(1))
  await screen.findByText('静态检查')
  const dialog = screen
    .getAllByRole('dialog')
    .find((d) => within(d).queryByText('静态检查'))
  if (!dialog) throw new Error('未找到测试结果弹窗')
  return dialog
}

describe('AiPromptsPage · Prompt 版本回归测试明细（test_detail）', () => {
  beforeEach(() => {
    testCalls = []
    testDetailResponse = TEST_DETAIL_RESPONSE
    useAuthStore.setState({
      user: makeUser(['ai.prompts.create', 'ai.prompts.test']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.includes('/ai/prompts/versions/v1/test')) {
          testCalls.push(url)
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: testDetailResponse }),
          )
        }
        if (method === 'GET' && url.includes('/ai/prompts/p1/versions')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: versions } }),
          )
        }
        if (method === 'GET' && url.includes('/ai/prompts')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [prompt] } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('带 test_detail 的响应：模型回归与静态检查分区展示，整体结果取 test_result', async () => {
    renderPage()
    const dialog = await runTestAndGetDialog()
    expect(testCalls[0]).toBe('/api/v1/ai/prompts/versions/v1/test')
    // 整体结论来自 test_result=FAILED（antd modal 标题渲染多处，按集合断言）；两个分区标题同时存在
    expect(within(dialog).getAllByText('测试未通过').length).toBeGreaterThan(0)
    expect(within(dialog).getByText('模型回归测试')).toBeInTheDocument()
    expect(within(dialog).getByText('静态检查')).toBeInTheDocument()
  })

  it('回归集卡片：分数/阈值/通过数/模型/失败原因如实展示', async () => {
    renderPage()
    const dialog = await runTestAndGetDialog()
    // 未通过集
    expect(within(dialog).getByText('事件分析回归集')).toBeInTheDocument()
    expect(within(dialog).getByText('event_analysis_v1')).toBeInTheDocument()
    expect(within(dialog).getByText('0.62')).toBeInTheDocument()
    expect(within(dialog).getAllByText(/阈值/)).toHaveLength(3)
    expect(within(dialog).getAllByText(/0\.80/)).toHaveLength(2)
    expect(within(dialog).getByText('通过用例 3/5')).toBeInTheDocument()
    expect(within(dialog).getByText(/失败原因：得分低于阈值/)).toBeInTheDocument()
    expect(within(dialog).getByText('未通过')).toBeInTheDocument()
    // 通过集与模型编码
    expect(within(dialog).getByText('安全问答集')).toBeInTheDocument()
    expect(within(dialog).getByText('通过用例 4/4')).toBeInTheDocument()
    expect(within(dialog).getAllByText('gpt-4o-mini')).toHaveLength(2)
    expect(within(dialog).getByText('通过')).toBeInTheDocument()
    // 静态检查与模型回归分区，静态项不被称作回归
    expect(within(dialog).getByText(/占位符检查/)).toBeInTheDocument()
    expect(within(dialog).getByText(/缺少 \{input\} 占位符/)).toBeInTheDocument()
  })

  it('逐用例摘要默认折叠，点击后展开失败用例原因', async () => {
    renderPage()
    const dialog = await runTestAndGetDialog()
    // 折叠面板内容懒渲染：展开前不在 DOM 中
    expect(within(dialog).queryByText('case-2')).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByText('逐用例摘要（2 条）'))
    expect(await within(dialog).findByText('case-2')).toBeInTheDocument()
    expect(within(dialog).getByText(/分析该安全事件/)).toBeInTheDocument()
    expect(within(dialog).getByText('回答缺少证据引用')).toBeInTheDocument()
  })

  it('旧版响应（无 test_detail）：保持静态测试标题且不出现实回归分区', async () => {
    testDetailResponse = {
      test_result: 'PASSED',
      checks: [{ name: '长度检查', passed: true }],
    }
    renderPage()
    await openVersionsDrawer()
    const cell = within(
      document.body.querySelector('.ant-drawer-section') as HTMLElement,
    ).getByText('v1')
    const row = cell.closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: '测试' }))
    await waitFor(() => expect(testCalls).toHaveLength(1))
    expect((await screen.findAllByText('静态测试通过')).length).toBeGreaterThan(0)
    expect(screen.queryByText('模型回归测试')).not.toBeInTheDocument()
    expect(screen.getByText('长度检查')).toBeInTheDocument()
  })
})
