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
  SEMANTIC_GUARD_LIMITS,
  type SemanticGuardStatus,
} from '../../../api/semanticGuard'
import {
  formatShortSha256,
  mapSemanticGuardFieldErrorPath,
  validateSemanticSocketPath,
  validateSemanticThresholds,
} from '../../../utils/semanticGuard'
import {
  AUDIT_MODULE_LABELS,
  AUDIT_OBJECT_TYPE_LABELS,
  DECISION_REASON_CODE_LABELS,
  PERMISSION_MODULE_LABELS,
} from '../../../utils/i18nLabels'
import SemanticGuardTab from '../detail/SemanticGuardTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-sem-1'
const APP_CODE = 'llm-gateway'

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

const STATUS_ONLINE_ONNX: SemanticGuardStatus = {
  available: true,
  status: 'ok',
  socket_path: '/var/run/caddy/sidecars/semantic.sock',
  model_id: 'deberta-v3-prompt-guard-int8',
  model_sha256:
    'a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff',
  backend: 'onnxruntime',
}

const STATUS_ONLINE_FALLBACK: SemanticGuardStatus = {
  available: true,
  status: 'ok',
  socket_path: '/var/run/caddy/sidecars/semantic.sock',
  model_id: 'heuristic-lexicon-v1',
  model_sha256: '',
  backend: 'heuristic_fallback',
}

const STATUS_OFFLINE: SemanticGuardStatus = {
  available: false,
  status: 'unavailable',
  socket_path: '/var/run/caddy/sidecars/semantic.sock',
  model_id: '',
  model_sha256: '',
  backend: '',
  error: 'dial unix /var/run/caddy/sidecars/semantic.sock: no such file or directory',
}

const UNCONFIGURED = {
  policy: {
    id: '',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'OFF',
    version: 0,
    socket_path: '/var/run/caddy/sidecars/semantic.sock',
    timeout_ms: 15,
    max_concurrency: 32,
    max_input_runes: 4096,
    observe_threshold: 0.5,
    block_threshold: 0.85,
    fail_policy: 'FAIL_OPEN',
    inspect_llm_prompts: true,
    inspect_mcp_content: true,
    inspect_web_grayzone: false,
    circuit_failure_threshold: 5,
    circuit_open_seconds: 30,
    updated_by: '',
    created_at: '',
    updated_at: '',
  },
  summary: { state: 'NOT_CONFIGURED', draft_version: 0, published_version: 0 },
}

const DRAFT_PENDING = {
  policy: {
    id: 'sem-pol-1',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'PROTECT',
    version: 3,
    socket_path: '/run/jiuzhang/semantic.sock',
    timeout_ms: 25,
    max_concurrency: 48,
    max_input_runes: 6144,
    observe_threshold: 0.55,
    block_threshold: 0.88,
    fail_policy: 'FAIL_CLOSED',
    inspect_llm_prompts: true,
    inspect_mcp_content: true,
    inspect_web_grayzone: true,
    circuit_failure_threshold: 8,
    circuit_open_seconds: 45,
    updated_by: 'secops',
    created_at: '2026-11-20T00:00:00Z',
    updated_at: '2026-11-26T10:00:00Z',
  },
  summary: { state: 'DRAFT_PENDING', draft_version: 3, published_version: 1 },
}

function mockFetch(options?: {
  policyData?: unknown
  statusData?: SemanticGuardStatus
  putStatus?: number
}) {
  const policyData = options?.policyData ?? UNCONFIGURED
  const statusData = options?.statusData ?? STATUS_OFFLINE
  const putStatus = options?.putStatus ?? 200

  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/semantic-guard/status')) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: statusData }),
      )
    }
    if (url.includes(`/applications/${APP_ID}/semantic-guard-policy`)) {
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
                  field: 'socket_path',
                  message: 'Socket 路径不在受控目录范围内',
                },
              ],
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { policy: { ...DRAFT_PENDING.policy, version: 4 } },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: policyData }),
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
        <SemanticGuardTab appId={APP_ID} appCode={APP_CODE} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('SemanticGuardTab（应用级本地离线 ONNX/SLM 语义防火墙）', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('在线 ONNX 状态：展示 model_id、截断 model_sha256、ONNX 后端标签并支持手动刷新', async () => {
    const fetchMock = mockFetch({ statusData: STATUS_ONLINE_ONNX })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()

    expect(
      await screen.findByText('本地 ONNX 语义推理引擎在线就绪'),
    ).toBeInTheDocument()
    expect(screen.getByText('ONNX Runtime 本地推理')).toBeInTheDocument()
    expect(screen.getByText('deberta-v3-prompt-guard-int8')).toBeInTheDocument()
    expect(screen.getByText('a1b2c3d4e5f6…')).toBeInTheDocument()

    const callsBefore = fetchMock.mock.calls.filter((c) =>
      String(c[0]).includes('/semantic-guard/status'),
    ).length
    fireEvent.click(screen.getByRole('button', { name: /刷新状态/ }))
    await waitFor(() => {
      const callsAfter = fetchMock.mock.calls.filter((c) =>
        String(c[0]).includes('/semantic-guard/status'),
      ).length
      expect(callsAfter).toBeGreaterThan(callsBefore)
    })
  })

  it('离线/未部署状态与启发式降级状态：如实展示离线警告与降级标签，不伪装在线', async () => {
    vi.stubGlobal('fetch', mockFetch({ statusData: STATUS_OFFLINE }))
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    const { unmount } = renderTab()

    expect(
      await screen.findByText('本地语义推理引擎未部署或当前离线'),
    ).toBeInTheDocument()
    expect(screen.getByText('未部署 / 离线')).toBeInTheDocument()
    expect(screen.getByText(/no such file or directory/)).toBeInTheDocument()
    expect(
      screen.queryByText('本地 ONNX 语义推理引擎在线就绪'),
    ).not.toBeInTheDocument()
    unmount()

    vi.stubGlobal('fetch', mockFetch({ statusData: STATUS_ONLINE_FALLBACK }))
    renderTab()
    expect(
      await screen.findByText('本地语义推理引擎在线（启发式降级模式）'),
    ).toBeInTheDocument()
    expect(screen.getByText('启发式降级引擎')).toBeInTheDocument()
  })

  it('未配置空态：展示默认 OFF 模式、三个检测通道开关与前后端对齐上限常量', async () => {
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置本地语义防火墙策略，当前维持默认透传行为'),
    ).toBeInTheDocument()
    expect(screen.getByText('LLM 提示词语义检测')).toBeInTheDocument()
    expect(screen.getByText('MCP 工具/返回语义检测')).toBeInTheDocument()
    expect(screen.getByText('Web 灰区样本复检')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()

    expect(SEMANTIC_GUARD_LIMITS.minTimeoutMs).toBe(5)
    expect(SEMANTIC_GUARD_LIMITS.maxTimeoutMs).toBe(200)
    expect(SEMANTIC_GUARD_LIMITS.defaultTimeoutMs).toBe(15)
    expect(SEMANTIC_GUARD_LIMITS.minMaxConcurrency).toBe(1)
    expect(SEMANTIC_GUARD_LIMITS.maxMaxConcurrency).toBe(256)
    expect(SEMANTIC_GUARD_LIMITS.defaultMaxConcurrency).toBe(32)
    expect(SEMANTIC_GUARD_LIMITS.minMaxInputRunes).toBe(256)
    expect(SEMANTIC_GUARD_LIMITS.maxMaxInputRunes).toBe(8192)
    expect(SEMANTIC_GUARD_LIMITS.defaultMaxInputRunes).toBe(4096)
    expect(SEMANTIC_GUARD_LIMITS.minObserveThreshold).toBe(0.1)
    expect(SEMANTIC_GUARD_LIMITS.maxObserveThreshold).toBe(0.99)
    expect(SEMANTIC_GUARD_LIMITS.defaultObserveThreshold).toBe(0.5)
    expect(SEMANTIC_GUARD_LIMITS.minBlockThreshold).toBe(0.5)
    expect(SEMANTIC_GUARD_LIMITS.maxBlockThreshold).toBe(0.99)
    expect(SEMANTIC_GUARD_LIMITS.defaultBlockThreshold).toBe(0.85)
    expect(SEMANTIC_GUARD_LIMITS.minCircuitFailureThreshold).toBe(1)
    expect(SEMANTIC_GUARD_LIMITS.maxCircuitFailureThreshold).toBe(100)
    expect(SEMANTIC_GUARD_LIMITS.defaultCircuitFailureThreshold).toBe(5)
    expect(SEMANTIC_GUARD_LIMITS.minCircuitOpenSeconds).toBe(5)
    expect(SEMANTIC_GUARD_LIMITS.maxCircuitOpenSeconds).toBe(300)
    expect(SEMANTIC_GUARD_LIMITS.defaultCircuitOpenSeconds).toBe(30)
    expect(SEMANTIC_GUARD_LIMITS.defaultSocketPath).toBe(
      '/var/run/caddy/sidecars/semantic.sock',
    )
  })

  it('草稿待发布态：按精确 DTO 契约提交 PUT（含 expected_version 与 reason），并透传自定义 socket_path 探测状态', async () => {
    const fetchMock = mockFetch({
      policyData: DRAFT_PENDING,
      statusData: STATUS_ONLINE_ONNX,
    })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()

    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()
    expect(
      screen.getByText('强制执行 + 故障闭环（FAIL_CLOSED）提示'),
    ).toBeInTheDocument()

    // 自定义 socket_path 应带入状态探测查询参数
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some((c) =>
          String(c[0]).includes(
            '/semantic-guard/status?socket_path=%2Frun%2Fjiuzhang%2Fsemantic.sock',
          ),
        ),
      ).toBe(true)
    })

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为 LLM 与 MCP 入口开启本地离线语义防火墙观察模式',
      ),
      { target: { value: '上线离线 ONNX 语义防火墙防护' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText(
        '本地语义防火墙策略草稿已保存；发布并获节点回执后才会生效',
      ),
    ).toBeInTheDocument()

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith(
            `/applications/${APP_ID}/semantic-guard-policy`,
          ) && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body))
      expect(body).toEqual({
        mode: 'PROTECT',
        expected_version: 3,
        socket_path: '/run/jiuzhang/semantic.sock',
        timeout_ms: 25,
        max_concurrency: 48,
        max_input_runes: 6144,
        block_threshold: 0.88,
        observe_threshold: 0.55,
        fail_policy: 'FAIL_CLOSED',
        inspect_llm_prompts: true,
        inspect_mcp_content: true,
        inspect_web_grayzone: true,
        circuit_failure_threshold: 8,
        circuit_open_seconds: 45,
        reason: '上线离线 ONNX 语义防火墙防护',
      })
    })
  })

  it('跨字段校验 observe_threshold <= block_threshold 与 socket_path 路径穿越拦截', async () => {
    const fetchMock = mockFetch({ policyData: UNCONFIGURED })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')

    // 输入非法观察阈值 > 阻断阈值（0.95 > 0.85）
    const observeInput = screen.getByLabelText('观察阈值')
    fireEvent.change(observeInput, { target: { value: '0.95' } })
    fireEvent.blur(observeInput)

    // 输入目录穿越 Socket 路径
    const socketInput = screen.getByLabelText('本地 Unix Socket 路径')
    fireEvent.change(socketInput, {
      target: { value: '/var/run/caddy/sidecars/../etc/passwd' },
    })

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为 LLM 与 MCP 入口开启本地离线语义防火墙观察模式',
      ),
      { target: { value: '测试非法参数拦截' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))

    expect(
      await screen.findByText('观察阈值不能高于阻断阈值'),
    ).toBeInTheDocument()
    expect(
      await screen.findByText('Socket 路径不能包含上级目录穿越片段（..）'),
    ).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((c) => c[1]?.method === 'PUT'),
    ).toBe(false)
  })

  it('409 版本冲突提示刷新重试，400 字段级错误映射回表单', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ policyData: UNCONFIGURED, putStatus: 409 }),
    )
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read', 'semantic_guard.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为 LLM 与 MCP 入口开启本地离线语义防火墙观察模式',
      ),
      { target: { value: '冲突验证' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()

    vi.stubGlobal(
      'fetch',
      mockFetch({ policyData: UNCONFIGURED, putStatus: 400 }),
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('Socket 路径不在受控目录范围内'),
    ).toBeInTheDocument()
  })

  it('只读权限（仅 semantic_guard.read）隐藏保存按钮与变更理由', async () => {
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read']),
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
          jsonResponse(403, { code: 'FORBIDDEN', message: '无权限', data: null }),
        ),
      ),
    )
    useAuthStore.setState({
      user: makeUser(['semantic_guard.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('Socket 路径安全校验、阈值校验、错误映射与 i18n 词表对齐后端约束', () => {
    expect(
      validateSemanticSocketPath('/var/run/caddy/sidecars/semantic.sock'),
    ).toBeNull()
    expect(validateSemanticSocketPath('/run/jiuzhang/semantic.sock')).toBeNull()
    expect(validateSemanticSocketPath('')).toContain('请填写')
    expect(validateSemanticSocketPath('/tmp/semantic.sock')).toContain(
      '/var/run/caddy/sidecars/',
    )
    expect(
      validateSemanticSocketPath('/var/run/caddy/sidecars/'),
    ).toContain('结尾')
    expect(
      validateSemanticSocketPath('/var/run/caddy/sidecars/../evil.sock'),
    ).toContain('..')
    expect(
      validateSemanticSocketPath('/var/run/caddy/sidecars/./semantic.sock'),
    ).toContain('非法目录片段')
    expect(validateSemanticSocketPath('http://127.0.0.1:8080/v1')).toContain(
      '禁止 HTTP/TCP',
    )
    expect(validateSemanticSocketPath('tcp://127.0.0.1:9000')).toContain(
      '禁止 HTTP/TCP',
    )
    expect(
      validateSemanticSocketPath('/var/run/caddy/sidecars/bad\n.sock'),
    ).toContain('控制字符')

    expect(validateSemanticThresholds(0.5, 0.85)).toBeNull()
    expect(validateSemanticThresholds(0.85, 0.85)).toBeNull()
    expect(validateSemanticThresholds(0.9, 0.85)).toContain('不能高于阻断阈值')
    expect(validateSemanticThresholds(0.05, 0.85)).toContain('观察阈值须在')
    expect(validateSemanticThresholds(0.5, 0.4)).toContain('阻断阈值须在')

    expect(
      formatShortSha256(
        'a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff',
      ),
    ).toBe('a1b2c3d4e5f6…')
    expect(formatShortSha256('')).toBe('-')

    expect(mapSemanticGuardFieldErrorPath('socket_path')).toEqual([
      'socket_path',
    ])
    expect(mapSemanticGuardFieldErrorPath('observe_threshold')).toEqual([
      'observe_threshold',
    ])
    expect(mapSemanticGuardFieldErrorPath('circuit_open_seconds')).toEqual([
      'circuit_open_seconds',
    ])
    expect(mapSemanticGuardFieldErrorPath('unknown_field')).toBeNull()

    expect(PERMISSION_MODULE_LABELS.semantic_guard).toBe('本地语义防火墙')
    expect(AUDIT_MODULE_LABELS.semantic_guard).toBe('本地语义防火墙')
    expect(AUDIT_OBJECT_TYPE_LABELS.semantic_guard_policy).toBe(
      '本地语义防火墙策略',
    )
    expect(DECISION_REASON_CODE_LABELS.SEMANTIC_OBSERVED).toBe(
      '本地语义防火墙观测',
    )
    expect(DECISION_REASON_CODE_LABELS.SEMANTIC_BLOCKED).toBe(
      '本地语义防火墙阻断',
    )
    expect(DECISION_REASON_CODE_LABELS.SEMANTIC_UNAVAILABLE).toBe(
      '本地语义推理引擎不可用',
    )
  })
})
