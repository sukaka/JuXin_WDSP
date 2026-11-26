import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  AI_CRAWL_LIMITS,
} from '../../../api/aiCrawl'
import AiCrawlTab from '../detail/AiCrawlTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-1'
const APP_CODE = 'shop'

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

const UNCONFIGURED = {
  policy: {
    id: '',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'OFF',
    version: 0,
    default_ai_action: 'ALLOW',
    content_signal: 'ai-train=no, search=yes, ai-input=no',
    verify_web_bot_auth: true,
    labyrinth_enabled: false,
    labyrinth_inject_links: false,
    labyrinth_max_depth: 5,
    labyrinth_max_concurrency: 256,
    labyrinth_delay_ms: 150,
    http_402: {
      message: '',
      price_hint: '',
      contact_url: '',
      receipt_header: '',
    },
    rules: null,
    updated_by: '',
    created_at: '',
    updated_at: '',
  },
  summary: { state: 'NOT_CONFIGURED', draft_version: 0, published_version: 0 },
}

const DRAFT_PENDING = {
  policy: {
    id: 'ac-1',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'PROTECT',
    version: 4,
    default_ai_action: 'TARPIT',
    content_signal: 'ai-train=no, search=yes, ai-input=no',
    verify_web_bot_auth: true,
    labyrinth_enabled: true,
    labyrinth_inject_links: true,
    labyrinth_max_depth: 6,
    labyrinth_max_concurrency: 128,
    labyrinth_delay_ms: 200,
    http_402: {
      message: '商业抓取需授权',
      price_hint: '0.002 USD / req',
      contact_url: 'https://shop.example.com/license',
      receipt_header: 'X-Crawl-Receipt',
    },
    rules: [
      {
        id: 'rule-allow-search',
        name: '允许已验签搜索引擎',
        category: 'SEARCH_ENGINE',
        agent_id: 'openai-searchbot',
        ua_patterns: ['OAI-SearchBot'],
        require_verified_sig: true,
        action: 'ALLOW',
        exempt_bot_challenge: true,
        rate_limit_rpm: 0,
        priority: 10,
      },
    ],
    updated_by: 'secops',
    created_at: '2026-11-10T00:00:00Z',
    updated_at: '2026-11-20T12:00:00Z',
  },
  summary: { state: 'DRAFT_PENDING', draft_version: 4, published_version: 2 },
}

function mockFetch(getData: unknown = UNCONFIGURED, putStatus = 200) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/ai-crawl-policy`)) {
      if (method === 'PUT') {
        if (putStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, {
              code: 'RESOURCE_CONFLICT',
              message: '策略已被其他人修改，请刷新后重试',
              data: null,
            }),
          )
        }
        if (putStatus === 400) {
          return Promise.resolve(
            jsonResponse(400, {
              code: 'INVALID_ARGUMENT',
              message: '参数校验失败',
              details: [
                {
                  field: 'labyrinth_max_depth',
                  message: '迷宫深度须在 1~16 之间',
                },
              ],
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              policy: { ...UNCONFIGURED.policy, version: 1 },
            },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: getData }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <AiCrawlTab appId={APP_ID} appCode={APP_CODE} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('AiCrawlTab', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('未配置空态：展示默认 OFF 模式、状态摘要与应用标识', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置 AI 爬虫治理策略，当前维持默认行为'),
    ).toBeInTheDocument()
    expect(screen.getByText('关闭（不治理 AI 爬虫）')).toBeInTheDocument()
    expect(screen.getByText('无草稿')).toBeInTheDocument()
    expect(screen.getByText('未随发布下发')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()
    expect(AI_CRAWL_LIMITS.maxLabyrinthMaxDepth).toBe(16)
    expect(AI_CRAWL_LIMITS.maxLabyrinthMaxConcurrency).toBe(4096)
    expect(AI_CRAWL_LIMITS.minRulePriority).toBe(0)
  })

  it('OFF 模式下添加规则仍要求填写规则名称，且允许 priority=0', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.click(screen.getByRole('button', { name: /添加治理规则/ }))
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：开启 AI 训练爬虫迷宫拖延与 Content-Signal 声明',
      ),
      { target: { value: '校验规则名必填' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(await screen.findByText('请输入规则名称')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('规则名称'), {
      target: { value: '零优先级规则' },
    })
    fireEvent.change(screen.getByLabelText('优先级'), {
      target: { value: '0' },
    })
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith(`/applications/${APP_ID}/ai-crawl-policy`) &&
          c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as {
        rules: { name: string; priority: number }[]
      }
      expect(body.rules[0].name).toBe('零优先级规则')
      expect(body.rules[0].priority).toBe(0)
    })
  })

  it('草稿待发布态：回显迷宫参数、HTTP 402 与优先级规则并按精确 DTO 契约提交 PUT', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('v4')).toBeInTheDocument()
    expect(screen.getByText('v2')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByLabelText('迷宫最大深度')).toHaveValue('6')
    })
    expect(screen.getByLabelText('并发信号量上限')).toHaveValue('128')
    expect(screen.getByLabelText('单跳拖延时长（ms）')).toHaveValue('200')
    expect(screen.getByLabelText('402 提示说明')).toHaveValue('商业抓取需授权')
    expect(screen.getByText('允许已验签搜索引擎')).toBeInTheDocument()

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：开启 AI 训练爬虫迷宫拖延与 Content-Signal 声明',
      ),
      { target: { value: '启用 AI 爬虫治理与迷宫策略' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('草稿已保存；发布并获节点回执后才会生效'),
    ).toBeInTheDocument()

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith(`/applications/${APP_ID}/ai-crawl-policy`) &&
          c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<
        string,
        unknown
      >
      expect(body.expected_version).toBe(4)
      expect(body.mode).toBe('PROTECT')
      expect(body.default_ai_action).toBe('TARPIT')
      expect(body.content_signal).toBe('ai-train=no, search=yes, ai-input=no')
      expect(body.verify_web_bot_auth).toBe(true)
      expect(body.labyrinth_enabled).toBe(true)
      expect(body.labyrinth_inject_links).toBe(true)
      expect(body.labyrinth_max_depth).toBe(6)
      expect(body.labyrinth_max_concurrency).toBe(128)
      expect(body.labyrinth_delay_ms).toBe(200)
      expect('labyrinth_key_hex' in body).toBe(false)
      expect(body.http_402).toEqual({
        message: '商业抓取需授权',
        price_hint: '0.002 USD / req',
        contact_url: 'https://shop.example.com/license',
        receipt_header: 'X-Crawl-Receipt',
      })
      expect(body.rules).toEqual([
        {
          id: 'rule-allow-search',
          name: '允许已验签搜索引擎',
          category: 'SEARCH_ENGINE',
          agent_id: 'openai-searchbot',
          ua_patterns: ['OAI-SearchBot'],
          require_verified_sig: true,
          action: 'ALLOW',
          exempt_bot_challenge: true,
          rate_limit_rpm: 0,
          priority: 10,
        },
      ])
      expect(body.reason).toBe('启用 AI 爬虫治理与迷宫策略')
    })
  })

  it('409 冲突提示刷新重试，400 字段级错误回显到对应表单项', async () => {
    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 409))
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：开启 AI 训练爬虫迷宫拖延与 Content-Signal 声明',
      ),
      { target: { value: '冲突测试' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()

    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 400))
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('迷宫深度须在 1~16 之间'),
    ).toBeInTheDocument()
  })

  it('只读权限（无 ai_crawl.manage）隐藏保存按钮与变更理由', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    expect(
      screen.queryByRole('button', { name: '保存草稿' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('变更理由')).not.toBeInTheDocument()
  })

  it('GET 403 展示无权限提示', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(403, {
            code: 'FORBIDDEN',
            message: '无权限',
            data: null,
          }),
        ),
      ),
    )
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
