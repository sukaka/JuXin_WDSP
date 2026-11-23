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

/** 与后端 PromptVersionTest 契约一致的真实响应（含顶层 regression 与 test_detail.regression/static_checks/failure_summary） */
const TEST_DETAIL_REGRESSION = {
  model: 'qwen2.5:3b',
  failure_summary: 'eval_insufficient_data（得分 66.67 < 阈值 80）；eval_api_security_analysis（评估集未部署）',
  sets: [
    {
      code: 'eval_prompt_injection',
      threshold: 100,
      score: 100,
      passed: true,
      total: 4,
      passed_count: 4,
      case_errors: 0,
      run_id: 'run-1111',
    },
    {
      code: 'eval_insufficient_data',
      threshold: 80,
      score: 66.67,
      passed: false,
      total: 3,
      passed_count: 2,
      case_errors: 1,
      run_id: 'run-2222',
    },
    {
      code: 'eval_api_security_analysis',
      threshold: 80,
      score: 0,
      passed: false,
      total: 0,
      passed_count: 0,
      case_errors: 0,
      error: '评估集未部署',
    },
  ],
}

const TEST_DETAIL_RESPONSE = {
  test_result: 'FAILED',
  checks: [
    { name: '非空与长度（≤50000 字符）', passed: true },
    { name: '禁止内容扫描（密钥/Shell/越权/思维链）', passed: true },
  ],
  regression: TEST_DETAIL_REGRESSION,
  test_detail: {
    static_checks: [
      { name: '非空与长度（≤50000 字符）', passed: true },
      { name: '禁止内容扫描（密钥/Shell/越权/思维链）', passed: true },
    ],
    regression: TEST_DETAIL_REGRESSION,
    failure_summary: TEST_DETAIL_REGRESSION.failure_summary,
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

  it('带 test_detail.regression 的响应：展示模型回归测试、模型、失败摘要与静态检查', async () => {
    renderPage()
    const dialog = await runTestAndGetDialog()
    expect(testCalls[0]).toBe('/api/v1/ai/prompts/versions/v1/test')
    expect(within(dialog).getAllByText('测试未通过').length).toBeGreaterThan(0)
    expect(within(dialog).getByText('模型回归测试')).toBeInTheDocument()
    expect(within(dialog).getByText('静态检查')).toBeInTheDocument()
    expect(within(dialog).getByText(/失败摘要：eval_insufficient_data/)).toBeInTheDocument()
    expect(within(dialog).getAllByText('qwen2.5:3b').length).toBeGreaterThanOrEqual(3)
  })

  it('回归集卡片：展示百分制得分/阈值、通过用例、case_errors、run_id 与集合级 error', async () => {
    renderPage()
    const dialog = await runTestAndGetDialog()
    // 评估集名称与编码
    expect(within(dialog).getByText('Prompt Injection防护集')).toBeInTheDocument()
    expect(within(dialog).getByText('eval_prompt_injection')).toBeInTheDocument()
    expect(within(dialog).getByText('数据不足集')).toBeInTheDocument()
    expect(within(dialog).getByText('eval_insufficient_data')).toBeInTheDocument()
    expect(within(dialog).getByText('API 安全分析集')).toBeInTheDocument()
    expect(within(dialog).getByText('eval_api_security_analysis')).toBeInTheDocument()

    // 百分制得分 / 阈值与通过用例
    expect(within(dialog).getByText('100.00')).toBeInTheDocument()
    expect(within(dialog).getByText('66.67')).toBeInTheDocument()
    expect(within(dialog).getByText('通过用例 4/4')).toBeInTheDocument()
    expect(within(dialog).getByText('通过用例 2/3')).toBeInTheDocument()
    expect(within(dialog).getByText('用例异常 1')).toBeInTheDocument()
    expect(within(dialog).getByText('run-1111')).toBeInTheDocument()
    expect(within(dialog).getByText('run-2222')).toBeInTheDocument()
    expect(within(dialog).getByText(/失败原因：评估集未部署/)).toBeInTheDocument()
    expect(within(dialog).getByText('通过')).toBeInTheDocument()
    expect(within(dialog).getAllByText('未通过')).toHaveLength(2)
  })

  it('静态检查未通过跳过回归时：展示 failure_summary 与「已跳过模型回归」', async () => {
    testDetailResponse = {
      test_result: 'FAILED',
      checks: [
        { name: '非空与长度（≤50000 字符）', passed: true },
        { name: '禁止内容扫描（密钥/Shell/越权/思维链）', passed: false, message: '命中禁止内容' },
      ],
      test_detail: {
        static_checks: [
          { name: '非空与长度（≤50000 字符）', passed: true },
          { name: '禁止内容扫描（密钥/Shell/越权/思维链）', passed: false, message: '命中禁止内容' },
        ],
        failure_summary: '静态检查未通过，跳过真实回归（候选内容不安全不进模型）',
      },
    }
    renderPage()
    const dialog = await runTestAndGetDialog()
    expect(within(dialog).getByText('模型回归测试')).toBeInTheDocument()
    expect(
      within(dialog).getByText('失败摘要：静态检查未通过，跳过真实回归（候选内容不安全不进模型）'),
    ).toBeInTheDocument()
    expect(within(dialog).getByText('已跳过模型回归')).toBeInTheDocument()
    expect(within(dialog).getByText(/命中禁止内容/)).toBeInTheDocument()
  })

  it('旧版响应（无 test_detail）：保持静态测试标题且不出现模型回归分区', async () => {
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
