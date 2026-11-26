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
import AiCrawlPage from '../AiCrawlPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

const SAMPLE_DIRECTORIES = [
  {
    id: 'dir-1',
    slug: 'openai-searchbot',
    name: 'OpenAI SearchBot',
    category: 'AI_ASSISTANT',
    signature_agent: 'https://chatgpt.com',
    directory_url:
      'https://chatgpt.com/.well-known/http-message-signatures-directory',
    keys: [
      {
        kid: 'k-openai-1',
        alg: 'ed25519',
        public_key_pem:
          '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtest\n-----END PUBLIC KEY-----',
      },
    ],
    is_builtin: true,
    enabled: true,
    last_synced_at: '2026-11-20T10:00:00Z',
    last_sync_error: '',
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-20T10:00:00Z',
  },
  {
    id: 'dir-2',
    slug: 'corp-partner-bot',
    name: '合作方检索爬虫',
    category: 'SEARCH_ENGINE',
    signature_agent: 'https://partner.example.com',
    directory_url: '',
    keys: [],
    is_builtin: false,
    enabled: true,
    last_synced_at: null,
    last_sync_error: '',
    created_at: '2026-11-05T00:00:00Z',
    updated_at: '2026-11-06T00:00:00Z',
  },
]

function mockFetch(items = SAMPLE_DIRECTORIES) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.endsWith('/api/v1/ai-crawl/directories') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items },
        }),
      )
    }
    if (url.endsWith('/api/v1/ai-crawl/directories') && method === 'POST') {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(201, {
          code: 'SUCCESS',
          message: 'created',
          data: {
            directory: {
              id: 'dir-new',
              ...payload,
              is_builtin: false,
              last_sync_error: '',
              created_at: '2026-11-25T00:00:00Z',
              updated_at: '2026-11-25T00:00:00Z',
            },
          },
        }),
      )
    }
    if (
      url.endsWith('/api/v1/ai-crawl/directories/import') &&
      method === 'POST'
    ) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { imported: 1, items: [] },
        }),
      )
    }
    if (
      url.endsWith('/api/v1/ai-crawl/directories/dir-1/sync') &&
      method === 'POST'
    ) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            directory: SAMPLE_DIRECTORIES[0],
            keys_count: 2,
          },
        }),
      )
    }
    if (
      url.endsWith('/api/v1/ai-crawl/directories/dir-2') &&
      method === 'DELETE'
    ) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { deleted: true, id: 'dir-2' },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <AiCrawlPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('AiCrawlPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示目录元数据、内置标记、密钥计数与离线标记', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('OpenAI SearchBot')).toBeInTheDocument()
    expect(screen.getByText('openai-searchbot')).toBeInTheDocument()
    expect(screen.getByText('内置')).toBeInTheDocument()
    expect(screen.getByText('AI 助手爬虫')).toBeInTheDocument()
    expect(screen.getByText('1 把')).toBeInTheDocument()
    expect(screen.getByText('合作方检索爬虫')).toBeInTheDocument()
    expect(screen.getByText('搜索引擎爬虫')).toBeInTheDocument()
    expect(screen.getByText('离线静态密钥')).toBeInTheDocument()
  })

  it('只读权限（仅 ai_crawl.read）隐藏新建、离线导入与操作按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('OpenAI SearchBot')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /新建爬虫目录/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /导入离线密钥包/ }),
    ).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /同步/ })).not.toBeInTheDocument()
  })

  it('手动同步远程目录调用 POST /ai-crawl/directories/{id}/sync 并提示密钥数', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('OpenAI SearchBot')).toBeInTheDocument()
    const syncButtons = screen.getAllByRole('button', { name: /同步/ })
    fireEvent.click(syncButtons[0])
    expect(
      await screen.findByText('同步完成：OpenAI SearchBot（共 2 个公钥）'),
    ).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) =>
          String(c[0]).endsWith('/api/v1/ai-crawl/directories/dir-1/sync') &&
          c[1]?.method === 'POST',
      ),
    ).toBe(true)
  })

  it('离线 JSON 导入弹窗校验非法 JSON 并提交合法目录包', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('OpenAI SearchBot')
    fireEvent.click(screen.getByRole('button', { name: /导入离线密钥包/ }))

    const textarea = await screen.findByLabelText('离线密钥包 JSON')
    fireEvent.change(textarea, { target: { value: '{not-valid-json' } })
    fireEvent.click(screen.getByRole('button', { name: '确认导入' }))
    expect(
      await screen.findByText('JSON 格式不合法，请检查语法'),
    ).toBeInTheDocument()

    const validBundle = JSON.stringify({
      directories: [
        {
          slug: 'offline-bot',
          name: '离线测试爬虫',
          category: 'AI_AGENT',
          signature_agent: 'https://offline.example.com',
          enabled: true,
          keys: [],
        },
      ],
    })
    fireEvent.change(textarea, { target: { value: validBundle } })
    fireEvent.click(screen.getByRole('button', { name: '确认导入' }))
    expect(
      await screen.findByText('成功导入 1 条爬虫公钥目录'),
    ).toBeInTheDocument()

    const importCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/ai-crawl/directories/import') &&
        c[1]?.method === 'POST',
    )
    expect(importCall).toBeTruthy()
    const body = JSON.parse(String(importCall![1]?.body)) as {
      directories: { slug: string }[]
    }
    expect(body.directories[0].slug).toBe('offline-bot')
  })

  it('新建抽屉拒绝私钥 PEM 并可提交自定义爬虫目录', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('OpenAI SearchBot')
    fireEvent.click(screen.getByRole('button', { name: /新建爬虫目录/ }))

    fireEvent.change(await screen.findByPlaceholderText('如 openai-searchbot'), {
      target: { value: 'custom-agent' },
    })
    fireEvent.change(screen.getByPlaceholderText('如 OpenAI SearchBot'), {
      target: { value: '自定义智能体' },
    })
    // signature_agent 为可选，不填也可正常创建
    fireEvent.click(screen.getByRole('button', { name: /添加公钥/ }))
    fireEvent.change(
      await screen.findByPlaceholderText('如 jwk-thumbprint-or-kid'),
      { target: { value: 'k1' } },
    )
    const pemInput = screen.getByLabelText('公钥 PEM')
    fireEvent.change(pemInput, {
      target: {
        value: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
      },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建目录' }))
    expect(
      await screen.findByText('禁止粘贴私钥材料，仅允许公钥 PEM'),
    ).toBeInTheDocument()

    fireEvent.change(pemInput, {
      target: {
        value: '-----BEGIN PUBLIC KEY-----\npub\n-----END PUBLIC KEY-----',
      },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建目录' }))
    expect(await screen.findByText('爬虫目录已创建')).toBeInTheDocument()
    const postCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/ai-crawl/directories') &&
        c[1]?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    const body = JSON.parse(String(postCall![1]?.body)) as {
      slug: string
      keys: { kid: string; alg: string }[]
    }
    expect(body.slug).toBe('custom-agent')
    expect(body.keys[0].kid).toBe('k1')
    expect(body.keys[0].alg).toBe('ed25519')
  })

  it('内置目录禁止删除，自定义目录确认删除后调用 DELETE', async () => {
    useAuthStore.setState({
      user: makeUser(['ai_crawl.read', 'ai_crawl.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('OpenAI SearchBot')).toBeInTheDocument()
    const deleteButtons = screen.getAllByRole('button', { name: /删除/ })
    expect(deleteButtons[0]).toBeDisabled()
    expect(deleteButtons[1]).not.toBeDisabled()

    fireEvent.click(deleteButtons[1])
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))
    expect(await screen.findByText('爬虫目录已删除')).toBeInTheDocument()
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some(
          (c) =>
            String(c[0]).endsWith('/api/v1/ai-crawl/directories/dir-2') &&
            c[1]?.method === 'DELETE',
        ),
      ).toBe(true)
    })
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
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
