import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
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
import ApiLLMPage from '../ApiLLMPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为捕获 option 的桩组件 */
const chartProps = vi.hoisted(
  () => [] as { option: unknown; height?: number }[],
)
vi.mock('../../../components/EChart', () => ({
  default: (props: { option: unknown; height?: number }) => {
    chartProps.push(props)
    return <div data-testid="echart-stub" />
  },
}))

function lastChartOption(): {
  xAxis: { data: string[] }
  series: { name: string; data: number[] }[]
} {
  const last = chartProps[chartProps.length - 1]
  expect(last).toBeTruthy()
  return JSON.parse(JSON.stringify(last.option))
}

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

const statsData = {
  days: 7,
  summary: {
    observations: 120,
    with_findings: 5,
    total_tokens: 34000,
    stream_calls: 12,
    distinct_models: 3,
  },
  by_model: [
    { model: 'gpt-4o', observations: 80, total_tokens: 20000, findings: 3 },
    { model: '', observations: 40, total_tokens: 14000, findings: 2 },
  ],
  token_trend: [{ day: '2026-08-19', observations: 120, total_tokens: 34000 }],
  findings_by_rule: [{ rule_id: 'llm.pii.id_card', count: 5 }],
}

/** 带命中的 LLM 调用观测 */
const obs1 = {
  id: 'ob-1',
  occurred_at: '2026-08-19T10:00:00Z',
  endpoint_key: 'POST /v1/chat/completions',
  model: 'gpt-4o',
  identity_fingerprint: 'fp-1',
  prompt_len_bucket: '257-1024',
  total_tokens: 512,
  stream: true,
  mcp_method: '',
  findings: [
    {
      detector: 'api_llm',
      rule_id: 'llm.pii.id_card',
      category: 'sensitive',
      severity: 'HIGH',
      message: '响应含疑似身份证号',
      evidence: { field: 'content' },
      score_delta: 30,
    },
  ],
  created_at: '2026-08-19T10:00:01Z',
}

/** 未声明模型的 MCP 端点观测（findings 为空） */
const obs2 = {
  id: 'ob-2',
  occurred_at: '2026-08-19T09:00:00Z',
  endpoint_key: 'POST /v1/mcp',
  model: '',
  identity_fingerprint: '',
  prompt_len_bucket: '0',
  total_tokens: 0,
  stream: false,
  mcp_method: 'tools/call',
  findings: null,
  created_at: '2026-08-19T09:00:01Z',
}

const observationsData = {
  items: [obs1, obs2],
  page: 1,
  page_size: 20,
  total: 2,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiLLMPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 在指定 placeholder 的 Input.Search 上输入并触发搜索 */
function triggerSearch(placeholder: string, value: string) {
  const input = screen.getByPlaceholderText(placeholder)
  fireEvent.change(input, { target: { value } })
  const wrapper = input.closest('.ant-input-search')
  const btn = wrapper?.querySelector('.ant-input-search-btn')
  expect(btn).toBeTruthy()
  fireEvent.click(btn as HTMLElement)
}

describe('ApiLLMPage', () => {
  beforeEach(() => {
    chartProps.length = 0
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (url.includes('/api-security/llm/stats')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: statsData,
            }),
          )
        }
        if (url.includes('/api-security/llm/observations')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: observationsData,
            }),
          )
        }
        if (url.includes('/api-security/llm/security-policies/builtin-rules')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                prompt_paths: ['messages[].content', 'prompt'],
                output_paths: ['choices[].message.content'],
                max_output_texts: 32,
                max_output_text_bytes: 65536,
                categories: [
                  {
                    key: 'prompt_injection',
                    title: '提示词注入攻击防护规则',
                    scope: 'input',
                    policy_switches: ['prompt_injection_enabled'],
                    inspected_paths: ['messages[].content', 'prompt'],
                    notes: 'RE2 线性时间匹配',
                    rules: [
                      {
                        id: 'ignore_previous_instructions',
                        name: '英文忽略前序指令',
                        description: '检测忽略先前指令注入',
                        pattern: '(?i)ignore\\s+previous\\s+instructions',
                        engine_rule_id: 'llm.prompt_injection',
                        observe_action: 'OBSERVE / LOW (+5)',
                        protect_action: 'BLOCK / HIGH (+50)',
                      },
                    ],
                  },
                  {
                    key: 'pii_detection',
                    title: '敏感个人信息（PII）识别规则',
                    scope: 'input_and_output',
                    policy_switches: ['pii_detection_enabled', 'output_pii_enabled'],
                    inspected_paths: ['messages[].content'],
                    notes: '不留存原文',
                    rules: [
                      {
                        id: 'PHONE',
                        name: '中国大陆 11 位手机号',
                        description: '匹配手机号',
                        pattern: '(?:^|[^0-9])1[3-9][0-9]{9}(?:$|[^0-9])',
                        engine_rule_id: 'llm.pii_detected',
                        observe_action: 'OBSERVE / MEDIUM',
                        protect_action: '输入 OBSERVE；输出 BLOCK',
                      },
                    ],
                  },
                ],
              },
            }),
          )
        }
        if (url.includes('/api-security/llm/security-policies')) {
          const policy = {
            id: 'policy-1',
            application_id: 'app-1',
            name: '客服助手输入保护',
            mode: 'OBSERVE',
            prompt_injection_enabled: true,
            input_content_enabled: true,
            pii_detection_enabled: true,
            output_content_enabled: true,
            output_pii_enabled: true,
            blocked_topics: ['恶意爬虫'],
            max_prompt_bytes: 1024,
            max_output_tokens: 2048,
            enabled: true,
            version: 1,
            created_at: '2026-08-19T10:00:00Z',
            updated_at: '2026-08-19T10:00:00Z',
          }
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data:
                init?.method === 'POST'
                  ? policy
                  : { items: [policy], total: 1 },
            }),
          )
        }
        if (url.includes('/applications')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [{ id: 'app-1', name: '智能客服', code: 'ai-service' }],
                page: 1,
                page_size: 100,
                total: 1,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({
      user: makeUser(['api_runtime.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('stats 卡片：观测总数/命中/token 合计/流式/模型数', async () => {
    renderPage()
    await screen.findByText('POST /v1/chat/completions')
    const statOf = (title: string) =>
      screen.getByText(title).closest('.ant-statistic') as HTMLElement
    expect(statOf('观测总数').textContent).toContain('120')
    expect(statOf('命中观测').textContent).toContain('5')
    expect(statOf('Token 合计').textContent).toContain('34,000')
    expect(statOf('流式调用').textContent).toContain('12')
    expect(statOf('涉及模型').textContent).toContain('3')
  })

  it('模型分布图：按观测数双柱（命中并列），空模型归入「未声明」', async () => {
    renderPage()
    await screen.findByText('POST /v1/chat/completions')
    await waitFor(() => expect(chartProps.length).toBeGreaterThan(0))
    const option = lastChartOption()
    expect(option.xAxis.data).toEqual(['gpt-4o', '未声明'])
    expect(option.series[0].data).toEqual([80, 40])
    expect(option.series[1].data).toEqual([3, 2])
  })

  it('观测列表：模型/端点/prompt 桶/tokens/流式/MCP 方法/findings 标签', async () => {
    renderPage()
    const row1 = (await screen.findByText('POST /v1/chat/completions')).closest(
      'tr',
    ) as HTMLElement
    expect(within(row1).getByText('gpt-4o')).toBeInTheDocument()
    expect(within(row1).getByText('257-1024')).toBeInTheDocument()
    expect(within(row1).getByText('512')).toBeInTheDocument()
    expect(within(row1).getByText('流式')).toBeInTheDocument()
    expect(within(row1).getByText('敏感个人信息（身份证号）')).toBeInTheDocument()
    expect(within(row1).queryByText('llm.pii.id_card')).not.toBeInTheDocument()
    // 未声明模型行：Tag 占位 + MCP 方法展示
    const row2 = screen.getByText('POST /v1/mcp').closest('tr') as HTMLElement
    expect(within(row2).getByText('未声明')).toBeInTheDocument()
    expect(within(row2).getByText('tools/call')).toBeInTheDocument()
  })

  it('过滤：model/endpoint_key/findings_only 分别携带对应查询参数', async () => {
    renderPage()
    await screen.findByText('POST /v1/chat/completions')

    triggerSearch('模型（精确匹配，如 gpt-4o）', 'gpt-4o')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('model=gpt-4o'))).toBe(true)
    })

    triggerSearch('API 键（精确匹配）', 'POST /v1/mcp')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('endpoint_key='))).toBe(true)
    })

    fireEvent.click(screen.getByRole('checkbox', { name: '仅看命中观测' }))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('findings_only=true'))).toBe(true)
    })
  })

  it('AI 安全策略页签展示真实策略并提交新建表单', async () => {
    useAuthStore.setState({
      user: makeUser([
        'api_runtime.read',
        'api_llm_security.read',
        'api_llm_security.manage',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '安全策略' }))
    await screen.findByText('客服助手输入保护')
    expect(screen.getByText('智能客服')).toBeInTheDocument()
    expect(screen.getByText('恶意爬虫')).toBeInTheDocument()
    expect(screen.getByText('2,048 Token')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '新建策略' }))
    await screen.findByText('新建 AI 安全策略')
    expect(screen.getByLabelText('应用')).toBeInTheDocument()
    expect(screen.getByLabelText('策略名称')).toBeInTheDocument()
    expect(screen.getByText('提示词注入攻击防护')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByLabelText('应用'))
    fireEvent.click(await screen.findByText('智能客服（ai-service）'))
    fireEvent.change(screen.getByLabelText('策略名称'), {
      target: { value: '客服助手生产策略' },
    })
    fireEvent.change(screen.getByLabelText('单次输出 Token 上限'), {
      target: { value: '4096' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))
    await waitFor(() => {
      const createCall = (fetch as Mock).mock.calls.find((call) => {
        const init = call[1] as RequestInit | undefined
        return (
          String(call[0]).includes('/api-security/llm/security-policies') &&
          init?.method === 'POST'
        )
      })
      expect(createCall).toBeTruthy()
      const body = JSON.parse(String((createCall![1] as RequestInit).body))
      expect(body).toMatchObject({
        application_id: 'app-1',
        name: '客服助手生产策略',
        mode: 'OBSERVE',
        prompt_injection_enabled: true,
        input_content_enabled: true,
        pii_detection_enabled: true,
        output_content_enabled: true,
        output_pii_enabled: true,
        max_prompt_bytes: 0,
        max_output_tokens: 4096,
      })
    })
  })

  it('AI 安全策略页签支持查看网关内置检测正则与单条策略生效内容', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_llm_security.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '安全策略' }))
    await screen.findByText('客服助手输入保护')

    fireEvent.click(screen.getByRole('button', { name: '查看内置检测规则' }))
    expect(await screen.findByText('网关内置 AI 安全检测规则（真实正则）')).toBeInTheDocument()
    expect(await screen.findByText('ignore_previous_instructions')).toBeInTheDocument()
    expect(screen.getByText('(?i)ignore\\s+previous\\s+instructions')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '策略内容' }))
    expect(await screen.findByText('AI 安全策略实际内容：客服助手输入保护')).toBeInTheDocument()
    expect(screen.getByText('网关实际下发配置（api_llm_security JSON）')).toBeInTheDocument()
    expect(screen.getByText(/"prompt_injection_enabled": true/)).toBeInTheDocument()
  })
})
