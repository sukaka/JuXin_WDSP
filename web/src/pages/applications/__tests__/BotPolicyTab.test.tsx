import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BotPolicyTab from '../detail/BotPolicyTab'
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
    application_id: APP_ID,
    mode: 'OFF',
    version: 0,
    selectors: null,
    signal_rules: null,
    challenge: null,
    route_reservation: null,
    updated_by: '',
    created_at: '0001-01-01T00:00:00Z',
    updated_at: '0001-01-01T00:00:00Z',
  },
  summary: {
    state: 'NOT_CONFIGURED',
    draft_version: 0,
    published: { found: false, version_no: 0, version_id: '', policy_version: 0 },
    nodes: [],
  },
}

const DRAFT_PENDING = {
  policy: {
    id: 'p1',
    application_id: APP_ID,
    mode: 'OBSERVE',
    version: 3,
    selectors: [{ path_prefix: '/docs' }],
    signal_rules: {
      min_independent_groups: 2,
      require_behavior_group: true,
      rules: [
        {
          id: 'high_4xx_ratio',
          group: 'request_behavior',
          metric: 'status_family_ratio',
          params: { family: '4xx' },
          window_seconds: 300,
          weight: 1,
          threshold: 0.5,
        },
      ],
    },
    challenge: {
      type: 'JS',
      nonce_ttl_seconds: 90,
      clearance_ttl_seconds: 900,
      difficulty: 14,
      max_attempts: 3,
      key_ref: 'bot-hmac-2026',
    },
    route_reservation: { state: 'ENABLED', namespace: '/_wdsp/bot/v1/' },
    updated_by: 'secops',
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-05T10:00:00Z',
  },
  summary: {
    state: 'DRAFT_PENDING',
    draft_version: 3,
    published: { found: true, version_no: 7, version_id: 'v7', policy_version: 1 },
    nodes: [],
  },
}

/** 已发布但部分节点未同步到新批次（BOT-023 部分生效可区分） */
const PARTIAL_NODES = {
  policy: { ...DRAFT_PENDING.policy, mode: 'PROTECT', version: 5 },
  summary: {
    state: 'PUBLISHED',
    draft_version: 5,
    published: { found: true, version_no: 9, version_id: 'v9', policy_version: 5 },
    nodes: [
      {
        node_name: 'gw-node-a',
        last_sync_result: 'SUCCESS',
        last_sync_version_id: 'v9',
        effective: true,
      },
      {
        node_name: 'gw-node-b',
        last_sync_result: 'FAILED',
        last_sync_version_id: 'v8',
        effective: false,
      },
    ],
  },
}

const PREFLIGHT_FAIL = {
  policy: UNCONFIGURED.policy,
  checks: [
    { name: 'structure', status: 'PASS', message: '结构校验通过' },
    {
      name: 'route_conflicts',
      status: 'SKIP',
      message: 'OFF 且保留已解除：不注册保留路由，无冲突面',
    },
    {
      name: 'shared_state',
      status: 'FAIL',
      message: '共享状态存储（Valkey）未配置：PROTECT 发布会把网关置于全站 fail-closed 503，拒绝发布',
    },
    {
      name: 'signing_key',
      status: 'WARN',
      message: '签名密钥未就绪：OBSERVE 不签发挑战不阻断',
    },
  ],
  conflicts: [
    {
      type: 'l7_deny_rule',
      status: 'FAIL',
      message: 'L7 拒绝规则 "deny-all"（动作 block）覆盖保留端点 /_wdsp/bot/v1/verify：挑战提交会被拒绝形成循环',
      ref: 'deny-all',
    },
  ],
  publishable: false,
}

function mockFetch(getData: unknown = UNCONFIGURED, putStatus = 200) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/bot-policy/preflight`)) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: PREFLIGHT_FAIL,
        }),
      )
    }
    if (url.includes(`/applications/${APP_ID}/bot-policy`)) {
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
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              policy: { ...UNCONFIGURED.policy, version: 1, mode: 'OFF' },
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
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <BotPolicyTab appId={APP_ID} appCode={APP_CODE} />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function grant(permissions: string[]) {
  useAuthStore.setState({
    user: makeUser(permissions),
    csrfToken: null,
    initialized: true,
  })
}

describe('BotPolicyTab', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('未配置空态：展示未配置状态、默认 OFF 与提示，不冒充已开启，zero-time 显示 -', async () => {
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置 Bot 策略，当前不观测、不挑战'),
    ).toBeInTheDocument()
    expect(screen.getByText('无草稿')).toBeInTheDocument()
    expect(screen.getByText('未成功发布')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()
    expect(screen.queryByText(/0001-01-01|0000-12-31/)).not.toBeInTheDocument()
    const recentUpdatedLabel = screen.getByText('最近更新')
    const recentUpdatedRow = recentUpdatedLabel.closest('tr')
    expect(recentUpdatedRow?.textContent).toContain('-')
  })

  it('草稿待发布态：展示草稿与已发布版本差异提示与恢复入口', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('草稿已保存，尚未生效')).toBeInTheDocument()
    expect(screen.getByText(/发布批次 #7 · 策略 v1/)).toBeInTheDocument()
    expect(screen.getByText(/· secops/)).toBeInTheDocument()
    // 恢复入口：重新预检按钮 + 前往配置发布链接
    expect(
      screen.getAllByRole('button', { name: '重新预检' }).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getAllByRole('link', { name: '前往配置发布' }).length,
    ).toBeGreaterThan(0)
  })

  it('部分节点未生效：状态可区分并给出恢复入口（BOT-023）', async () => {
    vi.stubGlobal('fetch', mockFetch(PARTIAL_NODES))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    expect(await screen.findByText('部分节点未生效')).toBeInTheDocument()
    expect(screen.getByText('gw-node-a')).toBeInTheDocument()
    expect(screen.getByText('gw-node-b')).toBeInTheDocument()
    expect(screen.getByText('已生效最新批次')).toBeInTheDocument()
    expect(screen.getByText('未同步到最新批次')).toBeInTheDocument()
    expect(screen.getByText('同步失败')).toBeInTheDocument()
  })

  it('保存成功：PUT 携带 expected_version / 默认段 / reason', async () => {
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText('说明本次变更原因，如：对 /docs 开启 Bot 挑战观察'),
      { target: { value: '初始接入' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('草稿已保存；发布并获节点回执后才会生效'),
    ).toBeInTheDocument()
    const putCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).includes(`/applications/${APP_ID}/bot-policy`) &&
        c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
    expect(body.expected_version).toBe(0)
    expect(body.mode).toBe('OFF')
    expect(body.reason).toBe('初始接入')
    expect(body.selectors).toEqual([])
    const sr = body.signal_rules as Record<string, unknown>
    expect(sr.require_behavior_group).toBe(true)
    expect(sr.min_independent_groups).toBe(2)
    const ch = body.challenge as Record<string, unknown>
    expect(ch.type).toBe('JS')
    expect(ch.difficulty).toBe(14)
    const rr = body.route_reservation as Record<string, unknown>
    expect(rr.state).toBe('RELEASED')
    expect(rr.namespace).toBe('/_wdsp/bot/v1/')
  })

  it('409 冲突：提示刷新后重试', async () => {
    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 409))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText('说明本次变更原因，如：对 /docs 开启 Bot 挑战观察'),
      { target: { value: '初始接入' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()
  })

  it('预检结果：逐检查项 FAIL/WARN/SKIP 与 publishable 门禁理由、冲突列表可区分', async () => {
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    await screen.findByText('未配置')
    fireEvent.click(screen.getByRole('button', { name: '发布预检' }))
    expect(
      await screen.findByText('存在未通过项，发布链路将以同口径拒绝'),
    ).toBeInTheDocument()
    // 依赖故障（共享状态 FAIL）与密钥 WARN 分开展示
    expect(screen.getByText('共享状态存储（Valkey）')).toBeInTheDocument()
    expect(screen.getByText(/fail-closed 503/)).toBeInTheDocument()
    expect(screen.getByText('签名密钥就绪')).toBeInTheDocument()
    // 冲突列表：类型标签 + 规则定位 + 原因
    expect(screen.getByText('L7 拒绝规则')).toBeInTheDocument()
    expect(screen.getByText('deny-all')).toBeInTheDocument()
    expect(screen.getByText(/挑战提交会被拒绝形成循环/)).toBeInTheDocument()
  })

  it('XSS 纯文本：节点名与冲突消息中的标签按文本转义展示', async () => {
    const xss = '<img src=x onerror=alert(1)>'
    const data = {
      policy: PARTIAL_NODES.policy,
      summary: {
        ...PARTIAL_NODES.summary,
        nodes: [
          {
            node_name: xss,
            last_sync_result: 'FAILED',
            last_sync_version_id: null,
            effective: false,
          },
        ],
      },
    }
    vi.stubGlobal('fetch', mockFetch(data))
    grant(['bot_policy.read', 'bot_policy.edit'])
    const { container } = renderTab()
    // 原始字符串作为文本节点渲染（React 转义），不产生真实 <img> 元素
    expect(await screen.findByText(xss)).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(container.innerHTML).not.toContain('<img src=x onerror')
  })

  it('未知值安全回退：未知 mode/state/检查状态原样展示不崩溃', async () => {
    const data = {
      policy: { ...UNCONFIGURED.policy, mode: 'FUTURE_MODE' },
      summary: {
        state: 'FUTURE_STATE',
        draft_version: 0,
        published: {
          found: false,
          version_no: 0,
          version_id: '',
          policy_version: 0,
        },
        nodes: [
          {
            node_name: 'gw-x',
            last_sync_result: 'FUTURE_SYNC',
            last_sync_version_id: null,
            effective: false,
          },
        ],
      },
    }
    vi.stubGlobal('fetch', mockFetch(data))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    expect(await screen.findByText('FUTURE_MODE')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_STATE')).toBeInTheDocument()
    expect(screen.getByText('FUTURE_SYNC')).toBeInTheDocument()
  })

  it('只读权限（无 bot_policy.edit）：隐藏保存/预检与变更理由', async () => {
    grant(['bot_policy.read'])
    renderTab()
    await screen.findByText('未配置')
    expect(
      screen.queryByRole('button', { name: '保存草稿' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '发布预检' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('变更理由')).not.toBeInTheDocument()
    // 挑战页预览对只读用户仍可见（BOT-006 核对入口）
    expect(screen.getByText(/终端用户挑战页体验预览/)).toBeInTheDocument()
  })

  it('GET 403：展示无权限提示', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(403, { code: 'FORBIDDEN', message: '无权限', data: null }),
        ),
      ),
    )
    grant(['bot_policy.read'])
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('挑战页预览：错误态/重试/JS 不可用文案可读（BOT-006 静态核对）', async () => {
    grant(['bot_policy.read'])
    renderTab()
    await screen.findByText('未配置')
    // 展开预览折叠面板
    fireEvent.click(screen.getByText(/终端用户挑战页体验预览/))
    expect(
      await screen.findByText('正在完成安全验证，请稍候…'),
    ).toBeInTheDocument()
    // 手动重试态
    fireEvent.click(screen.getByText('手动重试（超时/失败可恢复）'))
    expect(await screen.findByText('需要手动操作')).toBeInTheDocument()
    expect(screen.getByText(/计算超时/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    // JS 不可用态
    fireEvent.click(screen.getByText('JavaScript 不可用'))
    expect(
      await screen.findByText(/此安全验证需要启用 JavaScript/),
    ).toBeInTheDocument()
    // 服务故障态
    fireEvent.click(screen.getByText('服务故障（503）'))
    expect(await screen.findByText('服务暂不可用')).toBeInTheDocument()
    expect(screen.getByText(/安全验证服务暂时不可用/)).toBeInTheDocument()
  })

  it('节点同步状态为空/UNKNOWN 显示「未同步」，信号参数选项展示中文标签', async () => {
    const data = {
      policy: {
        ...DRAFT_PENDING.policy,
        signal_rules: {
          min_independent_groups: 2,
          require_behavior_group: true,
          rules: [
            {
              id: 'ua_bot',
              group: 'client_claim',
              metric: 'ua_class_match',
              params: { class: 'BOT' },
              window_seconds: 300,
              weight: 1,
              threshold: 0,
            },
            {
              id: 'tls_ver',
              group: 'client_claim',
              metric: 'tls_client_hint',
              params: { field: 'cipher_suite', equals: 'TLS_AES_128_GCM_SHA256' },
              window_seconds: 300,
              weight: 1,
              threshold: 0,
            },
          ],
        },
      },
      summary: {
        ...PARTIAL_NODES.summary,
        nodes: [
          {
            node_name: 'gw-node-c',
            last_sync_result: '',
            last_sync_version_id: null,
            effective: false,
          },
        ],
      },
    }
    vi.stubGlobal('fetch', mockFetch(data))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    expect(await screen.findByText('未同步')).toBeInTheDocument()
    expect(await screen.findByText('爬虫/机器人')).toBeInTheDocument()
    expect(await screen.findByText('密码套件')).toBeInTheDocument()
    expect(screen.queryByText('BOT')).not.toBeInTheDocument()
    expect(screen.queryByText('cipher_suite')).not.toBeInTheDocument()
  })

  it('实时信号组覆盖条展示当前规则对应的信号组计数与覆盖状态', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    grant(['bot_policy.read', 'bot_policy.edit'])
    renderTab()
    await screen.findByText('草稿待发布')
    const coverage = screen.getByTestId('bot-signal-coverage')
    expect(coverage.textContent).toContain('请求行为组：1 条')
    expect(coverage.textContent).toContain('已覆盖 1 / 2 组')
    expect(coverage.textContent).toContain('含行为组')
  })
})
