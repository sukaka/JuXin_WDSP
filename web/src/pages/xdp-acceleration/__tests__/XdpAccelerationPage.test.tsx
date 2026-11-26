import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  XDP_ACCEL_LIMITS,
  type XdpAccelConfig,
  type XdpAccelStatus,
  type XdpAccelSyncResult,
} from '../../../api/xdpAccel'
import {
  formatPacketCount,
  getXdpHeadlineStatus,
  mapXdpAccelFieldErrorPath,
  normalizeXdpInterfaces,
  validateXdpInterfaceName,
  validateXdpInterfaces,
  validateXdpSocketPath,
  XDP_ATTACH_MODE_META,
  XDP_DAEMON_STATUS_META,
  XDP_FORBIDDEN_INTERFACE_PREFIXES,
  XDP_RUNTIME_MODE_META,
} from '../../../utils/xdpAccel'
import {
  AUDIT_ACTION_LABELS,
  AUDIT_MODULE_LABELS,
  AUDIT_OBJECT_TYPE_LABELS,
  PERMISSION_MODULE_LABELS,
} from '../../../utils/i18nLabels'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import XdpAccelerationPage from '../XdpAccelerationPage'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sysops',
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

const SAMPLE_CONFIG: XdpAccelConfig = {
  enabled: true,
  socket_path: '/var/run/caddy/sidecars/xdpguard.sock',
  interfaces: ['eth0', 'ens192'],
  attach_mode: 'auto',
  sync_interval_seconds: 15,
  version: 4,
  updated_at: '2026-11-26T12:00:00Z',
}

const ATTACHED_STATUS: XdpAccelStatus = {
  available: true,
  status: 'ok',
  mode: 'xdp_native',
  kernel_attached: true,
  socket_path: '/var/run/caddy/sidecars/xdpguard.sock',
  attach_mode_requested: 'auto',
  interfaces: [
    { name: 'eth0', attached: true, mode: 'xdp_native' },
    {
      name: 'ens192',
      attached: false,
      mode: 'fallback_userspace',
      error: 'driver lacks native XDP support',
    },
  ],
  dropped_v4_packets: 125430,
  dropped_v6_packets: 842,
  passed_packets: 9876543,
  synced_v4_cidrs: 128,
  synced_v6_cidrs: 14,
  excluded_protected_count: 6,
  last_sync_at: '2026-11-26T12:05:00Z',
}

const UNAVAILABLE_STATUS: XdpAccelStatus = {
  available: false,
  status: 'unavailable',
  mode: 'fallback_userspace',
  kernel_attached: false,
  socket_path: '/var/run/caddy/sidecars/xdpguard.sock',
  attach_mode_requested: 'auto',
  interfaces: [],
  dropped_v4_packets: 0,
  dropped_v6_packets: 0,
  passed_packets: 0,
  synced_v4_cidrs: 0,
  synced_v6_cidrs: 0,
  excluded_protected_count: 0,
  last_sync_at: '',
  error:
    'dial unix /var/run/caddy/sidecars/xdpguard.sock: connect: no such file or directory',
}

const FALLBACK_ONLINE_STATUS: XdpAccelStatus = {
  available: true,
  status: 'degraded',
  mode: 'fallback_userspace',
  kernel_attached: false,
  socket_path: '/var/run/caddy/sidecars/xdpguard.sock',
  attach_mode_requested: 'auto',
  interfaces: [],
  dropped_v4_packets: 0,
  dropped_v6_packets: 0,
  passed_packets: 0,
  synced_v4_cidrs: 0,
  synced_v6_cidrs: 0,
  excluded_protected_count: 3,
  last_sync_at: '2026-11-26T12:05:00Z',
  error: 'missing CAP_BPF/CAP_NET_ADMIN in unprivileged container',
}

const SAMPLE_SYNC_RESULT: XdpAccelSyncResult = {
  synced: true,
  mode: 'xdp_native',
  kernel_attached: true,
  attached_interfaces: ['eth0'],
  synced_v4_cidrs: 132,
  synced_v6_cidrs: 15,
  excluded_protected_count: 6,
  control_plane_excluded_count: 2,
  invalid_cidrs_skipped: 0,
  last_sync_at: '2026-11-26T12:10:00Z',
}

interface MockFetchOptions {
  config?: XdpAccelConfig
  status?: XdpAccelStatus
  putResponse?: {
    config: XdpAccelConfig
    sync_warning?: string
    sync_result?: XdpAccelSyncResult
  }
  syncStatus?: number
  syncResponse?: XdpAccelSyncResult
}

function mockFetch(options: MockFetchOptions = {}): Mock {
  const cfg = options.config ?? SAMPLE_CONFIG
  const st = options.status ?? ATTACHED_STATUS
  const syncHttpStatus = options.syncStatus ?? 200

  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'

    if (url.endsWith('/api/v1/xdp-acceleration/config') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: cfg }),
      )
    }

    if (url.endsWith('/api/v1/xdp-acceleration/config') && method === 'PUT') {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      const respData = options.putResponse ?? {
        config: {
          ...cfg,
          enabled: Boolean(payload.enabled),
          socket_path: String(payload.socket_path ?? cfg.socket_path),
          interfaces: Array.isArray(payload.interfaces)
            ? (payload.interfaces as string[])
            : cfg.interfaces,
          attach_mode:
            (payload.attach_mode as XdpAccelConfig['attach_mode']) ??
            cfg.attach_mode,
          sync_interval_seconds:
            Number(payload.sync_interval_seconds) || cfg.sync_interval_seconds,
          version: cfg.version + 1,
        },
        sync_result: SAMPLE_SYNC_RESULT,
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: respData }),
      )
    }

    if (url.endsWith('/api/v1/xdp-acceleration/status') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: st }),
      )
    }

    if (url.endsWith('/api/v1/xdp-acceleration/sync') && method === 'POST') {
      if (syncHttpStatus === 503) {
        return Promise.resolve(
          jsonResponse(503, {
            code: 'SERVICE_UNAVAILABLE',
            message: 'xdpguard 守护进程不可达',
            data: null,
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: options.syncResponse ?? SAMPLE_SYNC_RESULT,
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
        <XdpAccelerationPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('xdpAccel utils & i18n labels', () => {
  it('XDP_ACCEL_LIMITS 为冻结常量并与后端上下限 1:1 对齐', () => {
    expect(Object.isFrozen(XDP_ACCEL_LIMITS)).toBe(true)
    expect(Object.isFrozen(XDP_ACCEL_LIMITS.allowedSocketPrefixes)).toBe(true)
    expect(XDP_ACCEL_LIMITS.defaultSocketPath).toBe(
      '/var/run/caddy/sidecars/xdpguard.sock',
    )
    expect(XDP_ACCEL_LIMITS.allowedSocketPrefixes).toEqual([
      '/var/run/caddy/sidecars/',
      '/run/jiuzhang/',
    ])
    expect(XDP_ACCEL_LIMITS.maxSocketPathLen).toBe(256)
    expect(XDP_ACCEL_LIMITS.maxInterfaces).toBe(16)
    expect(XDP_ACCEL_LIMITS.minSyncIntervalSec).toBe(1)
    expect(XDP_ACCEL_LIMITS.maxSyncIntervalSec).toBe(300)
    expect(XDP_ACCEL_LIMITS.defaultSyncIntervalSec).toBe(5)
    expect(XDP_ACCEL_LIMITS.maxReasonLen).toBe(500)
  })

  it('validateXdpSocketPath 与后端路径约束 1:1 对齐', () => {
    expect(
      validateXdpSocketPath('/var/run/caddy/sidecars/xdpguard.sock'),
    ).toBeNull()
    expect(validateXdpSocketPath('/run/jiuzhang/xdpguard.sock')).toBeNull()
    expect(validateXdpSocketPath('')).not.toBeNull()
    expect(validateXdpSocketPath('/tmp/xdpguard.sock')).not.toBeNull()
    expect(validateXdpSocketPath('http://127.0.0.1:9090/sync')).not.toBeNull()
    expect(
      validateXdpSocketPath('/var/run/caddy/sidecars/../etc/passwd'),
    ).not.toBeNull()
    expect(
      validateXdpSocketPath('/var/run/caddy/sidecars//xdpguard.sock'),
    ).not.toBeNull()
    expect(validateXdpSocketPath('/var/run/caddy/sidecars/')).not.toBeNull()
    expect(
      validateXdpSocketPath(`/run/jiuzhang/${'a'.repeat(250)}.sock`),
    ).not.toBeNull()
  })

  it('validateXdpInterfaceName 拒绝 lo 及全部虚拟/容器前缀并放行合法物理网卡', () => {
    for (const ok of ['eth0', 'ens192', 'enp3s0f0', 'bond0.100', 'p1p2']) {
      expect(validateXdpInterfaceName(ok), ok).toBeNull()
    }
    for (const bad of [
      '',
      'lo',
      'LO',
      'docker0',
      'DOCKER1',
      'br-a1b2c3',
      'veth1234',
      'virbr0',
      'cni0',
      'flannel.1',
      'cali8a1b2c',
      'tun0',
      'tap0',
      'wg0',
      '-eth0',
      'eth 0',
      'eth0123456789012', // 16 chars > 15
    ]) {
      expect(validateXdpInterfaceName(bad), bad).not.toBeNull()
    }
    expect(XDP_FORBIDDEN_INTERFACE_PREFIXES).toEqual([
      'docker',
      'br-',
      'veth',
      'virbr',
      'cni',
      'flannel',
      'cali',
      'tun',
      'tap',
      'wg',
    ])
  })

  it('validateXdpInterfaces、formatPacketCount、getXdpHeadlineStatus、mapXdpAccelFieldErrorPath 与 i18nLabels 完整一致', () => {
    expect(normalizeXdpInterfaces([' eth0 ', 'eth0', 'ens192', ''])).toEqual([
      'eth0',
      'ens192',
    ])
    expect(validateXdpInterfaces([], false)).toBeNull()
    expect(validateXdpInterfaces([], true)).toMatch(/至少需要指定 1 个/)
    expect(validateXdpInterfaces(['eth0', 'lo'], true)).toMatch(/环回接口/)
    expect(
      validateXdpInterfaces(
        Array.from({ length: 17 }, (_, i) => `eth${i}`),
        true,
      ),
    ).toMatch(/不能超过 16/)

    expect(formatPacketCount(null)).toBe('-')
    expect(formatPacketCount(-1)).toBe('-')
    expect(formatPacketCount(0)).toBe('0')
    expect(formatPacketCount(842)).toBe('842')
    expect(formatPacketCount(9999)).toBe('9,999')
    expect(formatPacketCount(125430)).toBe('125.4K')
    expect(formatPacketCount(9876543)).toBe('9.88M')
    expect(formatPacketCount(1500000000)).toBe('1.50B')

    expect(getXdpHeadlineStatus(ATTACHED_STATUS).label).toBe('内核态已挂载')
    expect(getXdpHeadlineStatus(FALLBACK_ONLINE_STATUS).label).toBe(
      '用户态回退',
    )
    expect(getXdpHeadlineStatus(UNAVAILABLE_STATUS).label).toBe(
      '守护进程未部署',
    )

    expect(XDP_ATTACH_MODE_META.auto.label).toContain('Native')
    expect(XDP_RUNTIME_MODE_META.fallback_userspace.label).toContain('用户态')
    expect(XDP_DAEMON_STATUS_META.invalid_socket_path.label).toContain('非法')
    expect(mapXdpAccelFieldErrorPath('interfaces[0]')).toEqual(['interfaces'])
    expect(mapXdpAccelFieldErrorPath('socket_path')).toEqual(['socket_path'])
    expect(mapXdpAccelFieldErrorPath('unknown')).toBeNull()

    expect(PERMISSION_MODULE_LABELS.xdp_acceleration).toBe('内核 XDP 加速')
    expect(AUDIT_MODULE_LABELS.xdp_acceleration).toBe('内核 XDP 加速')
    expect(AUDIT_OBJECT_TYPE_LABELS.xdp_acceleration_config).toBe(
      '内核 XDP 加速配置',
    )
    expect(AUDIT_ACTION_LABELS.SYNC).toBe('同步')
  })
})

describe('XdpAccelerationPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('已挂载内核态时完整渲染安全声明横幅、实时遥测卡片与网卡挂载表，支持刷新状态', async () => {
    const fetchMock = mockFetch({
      config: SAMPLE_CONFIG,
      status: ATTACHED_STATUS,
    })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read', 'xdp_accel.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()

    // 安全声明横幅始终可见
    expect(
      await screen.findByText('XDP 内核高速丢包安全边界与自动降级说明'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/protected_addresses、管理口、环回与链路本地地址被双重隔离永不写入 XDP 丢包表/),
    ).toBeInTheDocument()

    // 实时状态徽标、模式标签与指标卡
    expect(await screen.findByText('内核态已挂载')).toBeInTheDocument()
    expect(
      screen.getAllByText('XDP 驱动级 Native').length,
    ).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('IPv4 内核丢包数')).toBeInTheDocument()
    expect(screen.getByText('125.4K')).toBeInTheDocument()
    expect(screen.getByText('IPv6 内核丢包数')).toBeInTheDocument()
    expect(screen.getByText('842')).toBeInTheDocument()
    expect(screen.getByText('已同步黑名单前缀 (v4/v6)')).toBeInTheDocument()
    expect(screen.getByText('128 / 14')).toBeInTheDocument()
    expect(screen.getByText('受保护地址自动排除数')).toBeInTheDocument()
    expect(screen.getByText('6')).toBeInTheDocument()
    expect(screen.getByText('最近同步时间')).toBeInTheDocument()

    // 挂载网卡明细表
    const nicTableEl = screen
      .getByRole('columnheader', { name: '网卡名' })
      .closest('table') as HTMLElement
    const nicTable = within(nicTableEl)
    expect(nicTable.getByText('eth0')).toBeInTheDocument()
    expect(nicTable.getByText('ens192')).toBeInTheDocument()
    expect(
      nicTable.getByText('driver lacks native XDP support'),
    ).toBeInTheDocument()

    // 点击刷新状态应再次调用 GET /xdp-acceleration/status
    const beforeCalls = fetchMock.mock.calls.filter((c) =>
      String(c[0]).endsWith('/api/v1/xdp-acceleration/status'),
    ).length
    fireEvent.click(screen.getByRole('button', { name: /刷新状态/ }))
    await waitFor(() => {
      const afterCalls = fetchMock.mock.calls.filter((c) =>
        String(c[0]).endsWith('/api/v1/xdp-acceleration/status'),
      ).length
      expect(afterCalls).toBeGreaterThan(beforeCalls)
    })
  })

  it('守护进程未部署（available=false）时如实展示离线回退告警，绝不伪装内核挂载', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        config: { ...SAMPLE_CONFIG, enabled: false, interfaces: [] },
        status: UNAVAILABLE_STATUS,
      }),
    )
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read', 'xdp_accel.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()

    expect(
      await screen.findByText(
        'XDP 守护进程未部署或当前不可达（已自动回退至用户态防护）',
      ),
    ).toBeInTheDocument()
    expect(
      screen.getAllByText('守护进程未部署').length,
    ).toBeGreaterThanOrEqual(1)
    expect(
      screen.getByText(/connect: no such file or directory/),
    ).toBeInTheDocument()
    expect(screen.queryByText('内核态已挂载')).not.toBeInTheDocument()
    expect(
      screen.getByText('XDP 内核高速丢包安全边界与自动降级说明'),
    ).toBeInTheDocument()
  })

  it('守护进程在线但无特权降级（kernel_attached=false）时展示用户态回退提示', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        config: SAMPLE_CONFIG,
        status: FALLBACK_ONLINE_STATUS,
      }),
    )
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('用户态回退')).toBeInTheDocument()
    expect(
      screen.getByText('XDP 当前运行于用户态回退模式（未挂载内核网卡）'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/missing CAP_BPF\/CAP_NET_ADMIN/),
    ).toBeInTheDocument()
  })

  it('只读用户（仅 xdp_accel.read，无 xdp_accel.manage）可看状态与只读配置，隐藏保存与立即同步按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('内核态已挂载')).toBeInTheDocument()
    expect(screen.getByText('只读视图')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /保存配置/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /立即同步黑名单至 XDP/ }),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /刷新状态/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Unix Socket 路径')).toBeDisabled()
  })

  it('客户端表单校验拦截 lo、docker0 虚拟网卡及非法 Socket 路径，不发起 PUT 请求', async () => {
    const fetchMock = mockFetch({
      config: { ...SAMPLE_CONFIG, enabled: true, interfaces: ['eth0'] },
      status: ATTACHED_STATUS,
    })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read', 'xdp_accel.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    await screen.findByText('内核态已挂载')

    // 1. 输入非法 Socket 路径
    const socketInput = screen.getByLabelText('Unix Socket 路径')
    fireEvent.change(socketInput, { target: { value: '/tmp/evil.sock' } })
    fireEvent.blur(socketInput)
    expect(
      await screen.findByText(
        /Socket 路径必须以 \/var\/run\/caddy\/sidecars\/ 或 \/run\/jiuzhang\/ 开头/,
      ),
    ).toBeInTheDocument()

    // 2. 在物理网卡标签输入框中添加 lo
    const nicInput = screen.getByLabelText('物理业务网卡列表')
    fireEvent.change(nicInput, { target: { value: 'lo' } })
    fireEvent.keyDown(nicInput, { key: 'Enter', code: 'Enter', keyCode: 13 })
    expect(
      await screen.findByText(/禁止挂载环回接口（lo）/),
    ).toBeInTheDocument()

    // 3. 添加 docker0 也应被拒绝
    fireEvent.change(nicInput, { target: { value: 'docker0' } })
    fireEvent.keyDown(nicInput, { key: 'Enter', code: 'Enter', keyCode: 13 })
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }))

    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter(
        (c) =>
          String(c[0]).endsWith('/api/v1/xdp-acceleration/config') &&
          (c[1]?.method ?? 'GET') === 'PUT',
      )
      expect(putCalls).toHaveLength(0)
    })
  })

  it('保存配置提交规范 DTO 并展示 sync_warning；手动同步调用 POST /xdp-acceleration/sync 并处理成功与 503 失败', async () => {
    const fetchMock = mockFetch({
      config: SAMPLE_CONFIG,
      status: ATTACHED_STATUS,
      putResponse: {
        config: {
          ...SAMPLE_CONFIG,
          socket_path: '/run/jiuzhang/xdpguard.sock',
          version: 5,
        },
        sync_warning: 'daemon temporarily unreachable; will retry in 15s',
      },
    })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read', 'xdp_accel.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    await screen.findByText('内核态已挂载')

    const socketInput = screen.getByLabelText('Unix Socket 路径')
    fireEvent.change(socketInput, {
      target: { value: '/run/jiuzhang/xdpguard.sock' },
    })
    const reasonInput = screen.getByLabelText('变更原因')
    fireEvent.change(reasonInput, {
      target: { value: '切换至统一运行目录 Socket' },
    })
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }))

    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(
        (c) =>
          String(c[0]).endsWith('/api/v1/xdp-acceleration/config') &&
          (c[1]?.method ?? 'GET') === 'PUT',
      )
      expect(putCall).toBeDefined()
      const body = JSON.parse(String(putCall?.[1]?.body)) as Record<
        string,
        unknown
      >
      expect(body).toEqual({
        enabled: true,
        attach_mode: 'auto',
        interfaces: ['eth0', 'ens192'],
        sync_interval_seconds: 15,
        socket_path: '/run/jiuzhang/xdpguard.sock',
        reason: '切换至统一运行目录 Socket',
      })
    })

    expect(
      await screen.findByText('配置已持久化，实时下发至守护进程产生告警'),
    ).toBeInTheDocument()
    expect(
      screen.getAllByText(/daemon temporarily unreachable/).length,
    ).toBeGreaterThanOrEqual(1)

    // 手动触发立即同步（成功）
    fireEvent.click(
      screen.getByRole('button', { name: /立即同步黑名单至 XDP/ }),
    )
    expect(
      await screen.findByText('已成功同步全局黑名单至 XDP 内核映射表'),
    ).toBeInTheDocument()
    expect(screen.getByText(/IPv4 132 \/ IPv6 15/)).toBeInTheDocument()
    expect(screen.getByText(/控制面过滤排除：2/)).toBeInTheDocument()
  })

  it('手动同步遇到 503 时展示诚实的同步失败错误横幅', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        config: SAMPLE_CONFIG,
        status: UNAVAILABLE_STATUS,
        syncStatus: 503,
      }),
    )
    useAuthStore.setState({
      user: makeUser(['xdp_accel.read', 'xdp_accel.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    await screen.findByText(
      'XDP 守护进程未部署或当前不可达（已自动回退至用户态防护）',
    )

    fireEvent.click(
      screen.getByRole('button', { name: /立即同步黑名单至 XDP/ }),
    )
    expect(
      await screen.findByText(
        '立即同步黑名单至 XDP 失败（用户态防护仍正常生效）',
      ),
    ).toBeInTheDocument()
    expect(screen.getByText('xdpguard 守护进程不可达')).toBeInTheDocument()
  })
})
