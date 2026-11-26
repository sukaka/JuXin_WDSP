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
  WASM_PLUGIN_GLOBAL_SCOPE_QUERY,
  WASM_PLUGIN_LIMITS,
  type WasmPluginItem,
  type WasmPluginVersionItem,
} from '../../../api/wasmPlugins'
import {
  arrayBufferToBase64,
  formatShortSha256,
  formatWasmSizeKiB,
  hasValidWasmMagicHeader,
  mapWasmPluginFieldErrorPath,
  validateExpectedSha256,
  validateWasmBinaryBuffer,
  validateWasmPathPrefixes,
  validateWasmPluginName,
  WASM_MAGIC_HEADER,
} from '../../../utils/wasmPlugins'
import {
  AUDIT_MODULE_LABELS,
  AUDIT_OBJECT_TYPE_LABELS,
  COMMON_DETAIL_VALUE_LABELS,
  DECISION_REASON_CODE_LABELS,
  PERMISSION_MODULE_LABELS,
} from '../../../utils/i18nLabels'
import WasmPluginsPage from '../WasmPluginsPage'
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

const SHA_1 =
  '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff'
const SHA_2 =
  'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'

const SAMPLE_APPS = [
  {
    id: 'app-pay-1',
    code: 'payment-api',
    name: '支付核心服务',
  },
]

const SAMPLE_PLUGINS: WasmPluginItem[] = [
  {
    id: 'wp-1',
    application_id: null,
    name: 'global-header-guard',
    description: '全局自定义请求头完整性校验插件',
    version: 2,
    abi_version: 'wdsp_v1',
    mode: 'PROTECT',
    sha256: SHA_1,
    wasm_size: 4096,
    priority: 10,
    timeout_ms: 2,
    max_memory_kb: 4096,
    max_body_bytes: 65536,
    fail_policy: 'FAIL_CLOSED',
    path_prefixes: ['/api/v1/'],
    updated_by: 'secops',
    created_at: '2026-11-20T08:00:00Z',
    updated_at: '2026-11-25T10:30:00Z',
  },
  {
    id: 'wp-2',
    application_id: 'app-pay-1',
    name: 'payment-signature-check',
    description: '支付回调验签观测插件',
    version: 1,
    abi_version: 'wdsp_v1',
    mode: 'OBSERVE',
    sha256: SHA_2,
    wasm_size: 12288,
    priority: 100,
    timeout_ms: 5,
    max_memory_kb: 2048,
    max_body_bytes: 16384,
    fail_policy: 'FAIL_OPEN',
    path_prefixes: ['/pay/callback'],
    updated_by: 'secops',
    created_at: '2026-11-21T08:00:00Z',
    updated_at: '2026-11-24T09:00:00Z',
  },
]

const SAMPLE_VERSIONS: WasmPluginVersionItem[] = [
  {
    id: 'ver-2',
    plugin_id: 'wp-1',
    version: 2,
    abi_version: 'wdsp_v1',
    mode: 'PROTECT',
    sha256: SHA_1,
    wasm_size: 4096,
    reason: '切换至强制阻断模式',
    created_by: 'secops',
    created_at: '2026-11-25T10:30:00Z',
  },
  {
    id: 'ver-1',
    plugin_id: 'wp-1',
    version: 1,
    abi_version: 'wdsp_v1',
    mode: 'OBSERVE',
    sha256: SHA_2,
    wasm_size: 3072,
    reason: '首次上线观察',
    created_by: 'secops',
    created_at: '2026-11-20T08:00:00Z',
  },
]

interface MockFetchOptions {
  items?: WasmPluginItem[]
  postStatus?: number
  putStatus?: number
  rollbackStatus?: number
}

function mockFetch(options: MockFetchOptions = {}) {
  const items = options.items ?? SAMPLE_PLUGINS
  const postStatus = options.postStatus ?? 201
  const putStatus = options.putStatus ?? 200
  const rollbackStatus = options.rollbackStatus ?? 200

  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'

    if (url.includes('/api/v1/applications') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: SAMPLE_APPS, total: SAMPLE_APPS.length, page: 1, page_size: 200 },
        }),
      )
    }

    if (url.includes('/api/v1/wasm-plugins/wp-1/rollback') && method === 'POST') {
      if (rollbackStatus === 409) {
        return Promise.resolve(
          jsonResponse(409, {
            code: 'RESOURCE_CONFLICT',
            message: '插件版本已冲突，请刷新',
            data: null,
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            plugin: {
              ...SAMPLE_PLUGINS[0],
              version: 3,
              mode: 'OBSERVE',
              sha256: SHA_2,
            },
          },
        }),
      )
    }

    if (url.endsWith('/api/v1/wasm-plugins/wp-1') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            plugin: SAMPLE_PLUGINS[0],
            versions: SAMPLE_VERSIONS,
          },
        }),
      )
    }

    if (url.endsWith('/api/v1/wasm-plugins/wp-1') && method === 'PUT') {
      if (putStatus === 409) {
        return Promise.resolve(
          jsonResponse(409, {
            code: 'RESOURCE_CONFLICT',
            message: '插件版本已被他人更新，请刷新后重试',
            data: null,
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            plugin: { ...SAMPLE_PLUGINS[0], version: 3 },
          },
        }),
      )
    }

    if (url.endsWith('/api/v1/wasm-plugins/wp-2') && method === 'DELETE') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { deleted: true, id: 'wp-2' },
        }),
      )
    }

    if (url.startsWith('/api/v1/wasm-plugins') && method === 'POST') {
      if (postStatus === 400) {
        return Promise.resolve(
          jsonResponse(400, {
            code: 'INVALID_ARGUMENT',
            message: '参数校验失败',
            details: [
              { field: 'wasm_base64', message: 'Wasm 模块缺少 wdsp_on_request 导出' },
            ],
          }),
        )
      }
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(201, {
          code: 'SUCCESS',
          message: 'created',
          data: {
            plugin: {
              ...SAMPLE_PLUGINS[0],
              id: 'wp-new',
              name: String(payload.name ?? 'new-plugin'),
              version: 1,
            },
          },
        }),
      )
    }

    if (url.startsWith('/api/v1/wasm-plugins') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items, total: items.length, page: 1, page_size: 20 },
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
        <WasmPluginsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function makeWasmFile(bytes: Uint8Array, name = 'detector.wasm'): File {
  const file = new File([bytes], name, { type: 'application/wasm' })
  Object.defineProperty(file, 'arrayBuffer', {
    value: () =>
      Promise.resolve(
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      ),
  })
  return file
}

describe('WasmPluginsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示插件名称、作用域、版本、wdsp_v1、模式、截断 SHA-256、KiB 体积与沙箱护栏', async () => {
    useAuthStore.setState({
      user: makeUser([
        'wasm_plugins.read',
        'wasm_plugins.manage',
        'applications.read',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('global-header-guard')).toBeInTheDocument()
    expect(screen.getByText('payment-signature-check')).toBeInTheDocument()
    expect(screen.getByText('全局')).toBeInTheDocument()
    expect(
      await screen.findByText('支付核心服务 (payment-api)'),
    ).toBeInTheDocument()
    expect(screen.getByText('v2')).toBeInTheDocument()
    expect(screen.getAllByText('wdsp_v1').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('强制执行')).toBeInTheDocument()
    expect(screen.getByText('观察中')).toBeInTheDocument()
    expect(screen.getByText('111122223333…')).toBeInTheDocument()
    expect(screen.getByText('4.00 KiB')).toBeInTheDocument()
    expect(screen.getByText('12.0 KiB')).toBeInTheDocument()
    expect(screen.getByText('2ms')).toBeInTheDocument()
    expect(screen.getByText('4096 KiB')).toBeInTheDocument()
    expect(screen.getByText('Fail-Closed')).toBeInTheDocument()
    expect(screen.getByText('Fail-Open')).toBeInTheDocument()
  })

  it('只读权限（仅 wasm_plugins.read）隐藏上传、编辑、删除按钮，但允许查看版本历史且不请求应用列表', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('global-header-guard')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /上传插件/ }),
    ).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删除/ })).not.toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((c) => String(c[0]).includes('/api/v1/applications')),
    ).toBe(false)

    // 可打开只读版本历史抽屉，且不显示回滚按钮
    fireEvent.click(screen.getAllByRole('button', { name: /版本历史/ })[0])
    expect(await screen.findByText('首次上线观察')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /回滚到此版本/ }),
    ).not.toBeInTheDocument()
  })

  it('上传新建抽屉：展示零权限与凭据隔离声明，拦截非法魔数文件，提交合法 .wasm Base64 与精确 DTO', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser([
        'wasm_plugins.read',
        'wasm_plugins.manage',
        'applications.read',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('global-header-guard')

    fireEvent.click(screen.getByRole('button', { name: /上传插件/ }))
    expect(
      await screen.findByText('零权限 WebAssembly 沙箱安全声明（ABI: wdsp_v1）'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Authorization、Cookie、Proxy-Authorization、DPoP/),
    ).toBeInTheDocument()

    // 1. 上传非法魔数文件应被客户端直接拦截
    const firstFileInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement
    expect(firstFileInput).not.toBeNull()
    const badFile = makeWasmFile(
      new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]),
      'evil.wasm',
    )
    fireEvent.change(firstFileInput, { target: { files: [badFile] } })
    expect(
      await screen.findAllByText(/无效的 WebAssembly 二进制文件/),
    ).not.toHaveLength(0)

    // 1b. 上传超过 4 MiB 的文件应被客户端直接拦截（不触发 POST）
    const oversizedInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement
    const hugeFile = new File(['x'], 'huge.wasm', { type: 'application/wasm' })
    Object.defineProperty(hugeFile, 'size', {
      value: WASM_PLUGIN_LIMITS.maxBinaryBytes + 1,
    })
    fireEvent.change(oversizedInput, { target: { files: [hugeFile] } })
    expect(
      await screen.findAllByText(/Wasm 二进制大小不能超过 4 MiB/),
    ).not.toHaveLength(0)

    // 2. 上传合法 Wasm 1.0 二进制并填写表单提交（rc-upload 每次变更后会重建 input）
    const validWasmBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    ])
    const validFile = makeWasmFile(validWasmBytes, 'my_rule.wasm')
    const freshFileInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement
    fireEvent.change(freshFileInput, { target: { files: [validFile] } })
    expect(await screen.findByText('my_rule.wasm')).toBeInTheDocument()
    expect(screen.getByText('WebAssembly 1.0 魔数校验通过')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('如 custom-graphql-guard'), {
      target: { value: 'custom-graphql-guard' },
    })
    fireEvent.change(
      screen.getByPlaceholderText(
        '64 位十六进制 SHA-256（留空则由服务端自动计算并固定）',
      ),
      { target: { value: SHA_1.toUpperCase() } },
    )
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明插件用途与上线原因，如：上线自定义业务签名校验插件（观察模式）',
      ),
      { target: { value: '上线 GraphQL 深度自定义检测插件' } },
    )

    fireEvent.click(screen.getByRole('button', { name: '上传并创建' }))
    expect(
      await screen.findByText(/Wasm 插件「custom-graphql-guard」已创建/),
    ).toBeInTheDocument()

    const postCall = (fetch as Mock).mock.calls.find(
      (c) => String(c[0]).endsWith('/api/v1/wasm-plugins') && c[1]?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    const body = JSON.parse(String(postCall![1]?.body))
    expect(body).toEqual({
      name: 'custom-graphql-guard',
      application_id: null,
      description: '',
      mode: 'OBSERVE',
      wasm_base64: arrayBufferToBase64(validWasmBytes),
      expected_sha256: SHA_1,
      priority: 100,
      timeout_ms: 2,
      max_memory_kb: 4096,
      max_body_bytes: 65536,
      fail_policy: 'FAIL_OPEN',
      path_prefixes: [],
      reason: '上线 GraphQL 深度自定义检测插件',
    })
  })

  it('编辑抽屉不重传文件时省略 wasm_base64 并携带 expected_version 提交 PUT；409 冲突提示刷新', async () => {
    const fetchMock = mockFetch({ putStatus: 409 })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read', 'wasm_plugins.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('global-header-guard')

    fireEvent.click(screen.getAllByRole('button', { name: /编辑/ })[0])
    expect(
      await screen.findByText('编辑 Wasm 检测插件：global-header-guard'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('强制执行 + 故障闭环（FAIL_CLOSED）提示'),
    ).toBeInTheDocument()

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次配置或模块升级原因，如：调优检测逻辑并开启强制执行',
      ),
      { target: { value: '调整护栏超时参数' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存更新' }))

    expect(
      await screen.findAllByText('插件版本已被他人更新，请刷新后重试'),
    ).not.toHaveLength(0)

    const putCall = fetchMock.mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/wasm-plugins/wp-1') &&
        c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
    expect(body.expected_version).toBe(2)
    expect(body.wasm_base64).toBeUndefined()
    expect(body.reason).toBe('调整护栏超时参数')
  })

  it('版本历史与回滚抽屉：加载不可变版本列表，回滚须填理由并提交 POST /wasm-plugins/{id}/rollback', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read', 'wasm_plugins.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('global-header-guard')

    fireEvent.click(screen.getAllByRole('button', { name: /版本与回滚/ })[0])
    expect(await screen.findByText('首次上线观察')).toBeInTheDocument()
    expect(screen.getByText('切换至强制阻断模式')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /回滚到此版本/ }))
    expect(
      await screen.findByText('确认回滚「global-header-guard」至 v1'),
    ).toBeInTheDocument()

    // 不填理由直接点确认回滚 -> 校验拦截
    fireEvent.click(screen.getByRole('button', { name: '确认回滚' }))
    expect(await screen.findByText('请填写回滚理由')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('回滚理由'), {
      target: { value: 'v2 存在误报，临时回退至 v1' },
    })
    fireEvent.click(screen.getByRole('button', { name: '确认回滚' }))

    expect(
      await screen.findByText(/已回滚至历史快照并生成新版本 v3/),
    ).toBeInTheDocument()

    const rbCall = fetchMock.mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/wasm-plugins/wp-1/rollback') &&
        c[1]?.method === 'POST',
    )
    expect(rbCall).toBeTruthy()
    expect(JSON.parse(String(rbCall![1]?.body))).toEqual({
      target_version: 1,
      expected_version: 2,
      reason: 'v2 存在误报，临时回退至 v1',
    })
  })

  it('删除插件 Popconfirm 确认后调用 DELETE /wasm-plugins/{id}', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read', 'wasm_plugins.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('payment-signature-check')

    const deleteBtns = screen.getAllByRole('button', { name: /删除/ })
    fireEvent.click(deleteBtns[1])
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    expect(
      await screen.findByText('Wasm 插件已删除；需经配置发布同步到网关节点'),
    ).toBeInTheDocument()
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          (c) =>
            String(c[0]).endsWith('/api/v1/wasm-plugins/wp-2') &&
            c[1]?.method === 'DELETE',
        ),
      ).toBe(true)
    })
  })

  it('关键词与全局作用域筛选将参数透传至 GET /wasm-plugins', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('global-header-guard')

    fireEvent.change(screen.getByPlaceholderText('按插件名称或说明搜索'), {
      target: { value: 'payment' },
    })
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some((c) =>
          String(c[0]).includes('/api/v1/wasm-plugins?keyword=payment'),
        ),
      ).toBe(true)
    })

    // 切换作用域筛选至「全局」 -> application_id=global
    const scopeCombobox = screen.getByRole('combobox', { name: '作用域筛选' })
    fireEvent.mouseDown(scopeCombobox)
    const globalOptions = await screen.findAllByText('全局')
    fireEvent.click(globalOptions[globalOptions.length - 1])
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some((c) =>
          String(c[0]).includes('application_id=global'),
        ),
      ).toBe(true)
    })
  })

  it('创建返回 400 字段级校验错误时将后端消息映射回表单字段', async () => {
    const fetchMock = mockFetch({ postStatus: 400 })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['wasm_plugins.read', 'wasm_plugins.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('global-header-guard')

    fireEvent.click(screen.getByRole('button', { name: /上传插件/ }))
    await screen.findByText('零权限 WebAssembly 沙箱安全声明（ABI: wdsp_v1）')

    const validWasmBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ])
    const fileInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement
    fireEvent.change(fileInput, {
      target: { files: [makeWasmFile(validWasmBytes, 'missing_export.wasm')] },
    })
    await screen.findByText('missing_export.wasm')

    fireEvent.change(screen.getByPlaceholderText('如 custom-graphql-guard'), {
      target: { value: 'missing-export-plugin' },
    })
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明插件用途与上线原因，如：上线自定义业务签名校验插件（观察模式）',
      ),
      { target: { value: '测试后端字段级错误映射' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '上传并创建' }))

    expect(
      await screen.findByText('Wasm 模块缺少 wdsp_on_request 导出'),
    ).toBeInTheDocument()
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
      user: makeUser(['wasm_plugins.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('边界常量、WASM 魔数校验、Base64 编码、路径校验、错误映射与 i18n 词表对齐后端契约', () => {
    expect(WASM_PLUGIN_GLOBAL_SCOPE_QUERY).toBe('global')
    expect(WASM_PLUGIN_LIMITS.maxBinaryBytes).toBe(4 * 1024 * 1024)
    expect(WASM_PLUGIN_LIMITS.minPriority).toBe(0)
    expect(WASM_PLUGIN_LIMITS.maxPriority).toBe(10000)
    expect(WASM_PLUGIN_LIMITS.minTimeoutMs).toBe(1)
    expect(WASM_PLUGIN_LIMITS.maxTimeoutMs).toBe(50)
    expect(WASM_PLUGIN_LIMITS.defaultTimeoutMs).toBe(2)
    expect(WASM_PLUGIN_LIMITS.minMaxMemoryKb).toBe(256)
    expect(WASM_PLUGIN_LIMITS.maxMaxMemoryKb).toBe(16384)
    expect(WASM_PLUGIN_LIMITS.defaultMaxMemoryKb).toBe(4096)
    expect(WASM_PLUGIN_LIMITS.minMaxBodyBytes).toBe(0)
    expect(WASM_PLUGIN_LIMITS.maxMaxBodyBytes).toBe(65536)
    expect(WASM_PLUGIN_LIMITS.defaultMaxBodyBytes).toBe(65536)
    expect(WASM_PLUGIN_LIMITS.maxPathPrefixes).toBe(32)
    expect(WASM_PLUGIN_LIMITS.maxPathLen).toBe(256)
    expect(WASM_PLUGIN_LIMITS.maxNameLen).toBe(128)
    expect(WASM_PLUGIN_LIMITS.maxReasonLen).toBe(500)

    expect(hasValidWasmMagicHeader(WASM_MAGIC_HEADER)).toBe(true)
    expect(hasValidWasmMagicHeader(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x02, 0, 0, 0]))).toBe(false)
    expect(validateWasmBinaryBuffer(new Uint8Array([]))).toContain('不能为空')
    expect(validateWasmBinaryBuffer(new Uint8Array([1, 2, 3, 4]))).toContain('魔数头')
    expect(validateWasmBinaryBuffer(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x02, 0, 0, 0]))).toContain('1.0')
    expect(validateWasmBinaryBuffer(WASM_MAGIC_HEADER)).toBeNull()
    expect(arrayBufferToBase64(WASM_MAGIC_HEADER)).toBe('AGFzbQEAAAA=')

    expect(formatShortSha256(SHA_1)).toBe('111122223333…')
    expect(formatShortSha256('')).toBe('-')
    expect(formatWasmSizeKiB(4096)).toBe('4.00 KiB')
    expect(formatWasmSizeKiB(15360)).toBe('15.0 KiB')
    expect(formatWasmSizeKiB(204800)).toBe('200 KiB')

    expect(validateWasmPluginName('valid_plugin-1.0')).toBeNull()
    expect(validateWasmPluginName('-bad')).toContain('须以字母或数字开头')
    expect(validateExpectedSha256('')).toBeNull()
    expect(validateExpectedSha256(SHA_1)).toBeNull()
    expect(validateExpectedSha256('not-hex')).toContain('64 位十六进制')

    expect(validateWasmPathPrefixes(['/api/v1/', '/graphql'])).toBeNull()
    expect(validateWasmPathPrefixes(['api/no-slash'])).toContain('必须以 / 开头')
    expect(validateWasmPathPrefixes(['/api?a=1'])).toContain('不能包含')

    expect(mapWasmPluginFieldErrorPath('wasm_base64')).toEqual(['wasm_base64'])
    expect(mapWasmPluginFieldErrorPath('path_prefixes[2]')).toEqual([
      'path_prefixes',
    ])
    expect(mapWasmPluginFieldErrorPath('unknown_field')).toBeNull()

    expect(PERMISSION_MODULE_LABELS.wasm_plugins).toBe('Wasm 检测插件')
    expect(AUDIT_MODULE_LABELS.wasm_plugins).toBe('Wasm 检测插件')
    expect(AUDIT_OBJECT_TYPE_LABELS.wasm_plugin).toBe('Wasm 检测插件')
    expect(DECISION_REASON_CODE_LABELS.WASM_PLUGIN_OBSERVED).toBe(
      'Wasm 插件观测',
    )
    expect(DECISION_REASON_CODE_LABELS.WASM_PLUGIN_BLOCK).toBe('Wasm 插件阻断')
    expect(DECISION_REASON_CODE_LABELS.WASM_PLUGIN_RATE_LIMIT).toBe(
      'Wasm 插件限速',
    )
    expect(DECISION_REASON_CODE_LABELS.WASM_PLUGIN_ERROR).toBe(
      'Wasm 插件执行异常',
    )
    expect(COMMON_DETAIL_VALUE_LABELS.event_type.WASM_PLUGIN_BLOCK).toBe(
      'Wasm 插件阻断',
    )
  })
})
