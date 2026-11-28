import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import IpLibrariesPage from '../IpLibrariesPage'
import { setCsrfToken } from '../../../api/client'
import type {
  GeoIpStatusResponse,
  OutboundSettings,
  ThreatIntelFeedsResponse,
} from '../../../api/ipLibraries'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(roleCode: string, permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: roleCode === 'AUDIT_ADMIN' ? 'auditor' : 'secops',
    display_name: roleCode === 'AUDIT_ADMIN' ? '审计管理员' : '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: roleCode, name: roleCode }],
    permissions,
    must_change_password: false,
  }
}

const OUTBOUND_SETTINGS: OutboundSettings = {
  outbound_allowlist: '10.20.0.0/16, mirror.corp.local',
  allow_insecure_http_mirror: false,
  proxy_url: 'http://proxy.corp.local:3128',
  has_proxy_auth: true,
  http_timeout_seconds: 120,
}

const GEOIP_STATUS: GeoIpStatusResponse = {
  geo_enabled: true,
  sources: ['ip2region_v4', 'dbip_city'],
  loaded_at: '2026-11-28T06:00:00Z',
  revision: 'rev-20261128-abcdef123456',
  schedule: {
    auto_update_enabled: false,
    schedule_cron: '0 3 2 * *',
    ha_sync_enabled: true,
    maxmind_account_id: '987654',
    has_maxmind_license_key: true,
  },
  ha_nodes: [
    {
      node_id: 'node-standby-1',
      node_name: 'standby-1',
      reachable: true,
      geoip_ready: true,
      revision: 'rev-old-000000',
      consistent: false,
      updated_at: '2026-11-27T06:00:00Z',
    },
  ],
  presets: [
    {
      id: 'ip2region_v4',
      slot: 'ip2region_v4',
      name: 'ip2region IPv4 官方源（Apache-2.0）',
      license: 'Apache-2.0 OR MIT',
    },
    {
      id: 'dbip_city_lite',
      slot: 'dbip_city',
      name: 'DB-IP City Lite（CC BY 4.0）',
      license: 'CC BY 4.0',
      monthly_fallback: true,
    },
    {
      id: 'maxmind_geolite2_city',
      slot: 'dbip_city',
      name: 'MaxMind GeoLite2 City',
      license: 'MaxMind GeoLite2 EULA',
      requires_maxmind_auth: true,
    },
  ],
  slots: [
    {
      slot: 'ip2region_v4',
      display_name: 'ip2region IPv4（国内省市/运营商）',
      canonical_file: 'ip2region_v4.xdb',
      format: 'xdb',
      max_bytes: 67108864,
      enabled: true,
      source_mode: 'OFFICIAL',
      official_preset: 'ip2region_v4',
      custom_url: '',
      active_origin: 'runtime',
      active_filename: 'ip2region_v4.xdb',
      active_source_type: 'OFFLINE',
      sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      size_bytes: 11200000,
      updated_at: '2026-11-28T06:00:00Z',
      last_status: 'SUCCESS',
      last_error: '',
      backups: [
        {
          backup_id: '1700000000-abcdef123456.xdb',
          filename: 'ip2region_v4.xdb',
          sha256: '1111111111112222222222223333333333334444444444445555555555556666',
          size_bytes: 10900000,
          created_at: '2026-11-20T03:00:00Z',
        },
      ],
    },
    {
      slot: 'dbip_city',
      display_name: '全球城市库（DB-IP Lite / MaxMind GeoLite2 City）',
      canonical_file: 'city.mmdb',
      format: 'mmdb',
      max_bytes: 268435456,
      enabled: false,
      source_mode: 'OFFLINE_ONLY',
      official_preset: 'dbip_city_lite',
      custom_url: '',
      active_origin: 'builtin',
      active_filename: 'city.mmdb',
      active_source_type: 'BUILTIN',
      sha256: 'f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1',
      size_bytes: 64000000,
      updated_at: '2026-11-01T00:00:00Z',
      last_status: 'IDLE',
      last_error: '',
      backups: [],
    },
  ],
}

const THREAT_FEEDS_DATA: ThreatIntelFeedsResponse = {
  settings: {
    auto_update_enabled: false,
    circuit_threshold: 5,
  },
  summary: {
    enabled_count: 1,
    total_active_rules: 320,
    circuit_open_count: 1,
  },
  presets: [
    {
      key: 'feodo',
      name: 'abuse.ch Feodo C2 IP 清单（CC0-1.0）',
      format: 'text',
      license: 'CC0-1.0',
    },
    {
      key: 'sslbl',
      name: 'abuse.ch SSLBL 恶意 C2 IP 清单（CC0-1.0）',
      format: 'text',
      license: 'CC0-1.0',
    },
  ],
  feeds: [
    {
      id: 'feed-feodo',
      feed_key: 'feodo',
      name: 'abuse.ch Feodo C2 IP 清单',
      description: '僵尸网络控制端推荐封禁 IPv4 列表',
      is_builtin: true,
      enabled: true,
      source_mode: 'OFFICIAL',
      official_preset: 'feodo',
      custom_url: '',
      format: 'text',
      allow_cidr: false,
      ttl_days: 30,
      schedule_cron: '0 */6 * * *',
      min_entries_guard: true,
      max_drop_ratio: 0.8,
      active_rule_count: 200,
      consecutive_failures: 0,
      circuit_open: false,
      last_sync_at: '2026-11-28T05:00:00Z',
      last_status: 'GUARD_ABORTED',
      last_error: '新批次条目缩水 92%，触发骤降保护',
    },
    {
      id: 'feed-soc',
      feed_key: 'corp_soc',
      name: '企业内网 SOC 黑名单',
      description: '内部威胁情报推送源',
      is_builtin: false,
      enabled: true,
      source_mode: 'CUSTOM_URL',
      official_preset: '',
      custom_url: 'https://mirror.corp.local/soc/ips.txt',
      format: 'text',
      allow_cidr: true,
      ttl_days: 7,
      schedule_cron: '0 */2 * * *',
      min_entries_guard: true,
      max_drop_ratio: 0.8,
      active_rule_count: 120,
      consecutive_failures: 5,
      circuit_open: true,
      last_sync_at: '2026-11-28T04:00:00Z',
      last_status: 'FAILED',
      last_error: '上游连接超时',
    },
  ],
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function createFetchMock() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))

    if (url.includes('/ip-libraries/outbound-settings')) {
      if (method === 'PUT') return ok({ ...OUTBOUND_SETTINGS, has_proxy_auth: false })
      return ok(OUTBOUND_SETTINGS)
    }
    if (url.includes('/geoip/status')) return ok(GEOIP_STATUS)
    if (url.includes('/geoip/settings') && method === 'PUT') return ok(GEOIP_STATUS)
    if (url.includes('/geoip/upload') && method === 'POST') {
      return ok({
        slot: 'ip2region_v4',
        filename: 'ip2region_v4.xdb',
        previous_sha256: 'a'.repeat(64),
        new_sha256: 'b'.repeat(64),
        size_bytes: 2048,
        revision: 'rev-upload-1',
        unchanged: false,
        loaded_sources: ['ip2region_v4'],
      })
    }
    if (url.includes('/geoip/rollback') && method === 'POST') {
      return ok({
        slot: 'ip2region_v4',
        filename: 'ip2region_v4.xdb',
        previous_sha256: 'a'.repeat(64),
        new_sha256: '1'.repeat(64),
        size_bytes: 10900000,
        revision: 'rev-rollback-1',
        unchanged: false,
        loaded_sources: ['ip2region_v4'],
      })
    }
    if (url.includes('/geoip/ha-resync') && method === 'POST') {
      return ok({
        runs: [
          {
            id: 'ha-1',
            slot: 'ip2region_v4',
            trigger_type: 'HA_RESYNC',
            status: 'SUCCESS',
            source_label: 'ha_resync',
            previous_sha256: 'a'.repeat(64),
            new_sha256: 'a'.repeat(64),
            file_size_bytes: 11200000,
            ha_results: [{ node_name: 'standby-1', status: 'SUCCESS' }],
            error_message: '',
            started_at: '2026-11-28T06:30:00Z',
            finished_at: '2026-11-28T06:30:01Z',
          },
        ],
        succeeded: 1,
        skipped: 0,
        partial_ha_failed: 0,
        failed: 0,
      })
    }
    if (url.includes('/geoip/sync') && method === 'POST') {
      return ok({
        runs: [
          {
            id: 'r1',
            slot: 'ip2region_v4',
            trigger_type: 'MANUAL',
            status: 'SUCCESS',
            source_label: 'ip2region_v4',
            previous_sha256: '',
            new_sha256: 'a'.repeat(64),
            file_size_bytes: 11200000,
            ha_results: [],
            error_message: '',
            started_at: '2026-11-28T06:30:00Z',
            finished_at: '2026-11-28T06:30:02Z',
          },
        ],
        succeeded: 1,
        skipped: 0,
        partial_ha_failed: 0,
        failed: 0,
      })
    }
    if (url.includes('/geoip/runs')) {
      return ok({
        items: [
          {
            id: 'geo-run-1',
            slot: 'ip2region_v4',
            trigger_type: 'OFFLINE_UPLOAD',
            status: 'SUCCESS',
            source_label: 'ip2region_v4.xdb',
            previous_sha256: '',
            new_sha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
            file_size_bytes: 11200000,
            ha_results: [{ node_name: 'standby-1', status: 'SUCCESS' }],
            error_message: '',
            started_at: '2026-11-28T06:00:00Z',
            finished_at: '2026-11-28T06:00:03Z',
          },
        ],
        total: 1,
        page: 1,
        page_size: 10,
      })
    }
    if (url.includes('/threat-intel/feeds/feed-feodo/sync') && method === 'POST') {
      const reqBody = init?.body ? JSON.parse(String(init.body)) : {}
      const forced = Boolean(reqBody.force_ignore_guard)
      return ok({
        run: {
          id: 'ti-sync-1',
          feed_key: 'feodo',
          trigger_type: 'MANUAL',
          batch_id: forced ? 'batch-force-1' : '',
          status: forced ? 'SUCCESS' : 'GUARD_ABORTED',
          total_parsed: 15,
          added: forced ? 5 : 0,
          refreshed: forced ? 10 : 0,
          expired: forced ? 2 : 0,
          skipped_conflict: 0,
          invalid_count: 0,
          published: forced,
          error_message: forced ? '' : '新批次条目缩水 92%，触发骤降保护',
          started_at: '2026-11-28T07:00:00Z',
          finished_at: '2026-11-28T07:00:01Z',
        },
        feed: THREAT_FEEDS_DATA.feeds[0],
        guard_triggered: !forced,
        guard_reason: forced ? '' : '新批次条目缩水 92%，触发骤降保护',
        circuit_opened: false,
        changed_rules: forced ? 17 : 0,
      })
    }
    if (url.includes('/threat-intel/import') && method === 'POST') {
      return ok({
        batch_id: 'imp-20261128',
        feed: 'feodo',
        ttl_days: 30,
        total_parsed: 3,
        added: 2,
        refreshed: 0,
        expired: 1,
        skipped_conflict: 1,
        invalid: 1,
        truncated: false,
        conflicts: [{ address: '203.0.113.99', reason: '命中保护地址，禁止加入黑名单' }],
        invalid_entries: [{ line: 4, content: 'not-an-ip', error: '非法 IPv4 地址' }],
      })
    }
    if (url.includes('/threat-intel/settings') && method === 'PUT') {
      return ok({ auto_update_enabled: true, circuit_threshold: 5 })
    }
    if (url.includes('/threat-intel/feeds') && method === 'GET') {
      return ok(THREAT_FEEDS_DATA)
    }
    if (url.includes('/threat-intel/runs') && method === 'GET') {
      return ok({ items: [], total: 0, page: 1, page_size: 10 })
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/ip-libraries']}>
          <IpLibrariesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('IpLibrariesPage IP 库与威胁情报', () => {
  let fetchMock: ReturnType<typeof createFetchMock>

  beforeEach(() => {
    setCsrfToken('csrf-ui-token')
    useAuthStore.setState({
      user: makeUser('SECURITY_ADMIN', [
        'geoip.read',
        'geoip.manage',
        'threat_intel.read',
        'threat_intel.manage',
        'access_rules.import',
      ]),
      csrfToken: 'csrf-ui-token',
      initialized: true,
    })
    fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    useAuthStore.getState().reset()
  })

  it('GeoIP 页签展示引擎概览、HA 漂移告警并支持重新同步备节点与历史回滚', async () => {
    renderPage()

    expect(await screen.findByText('ip2region IPv4（国内省市/运营商）')).toBeInTheDocument()
    expect(screen.getByText(/检测到 1 个 HA 备节点 GeoIP 库版本不一致/)).toBeInTheDocument()

    // 触发 HA 重新同步
    const resyncBtns = screen.getAllByRole('button', { name: /重新同步备节点/ })
    fireEvent.click(resyncBtns[0])
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          (c) => String(c[0]).includes('/geoip/ha-resync') && c[1]?.method === 'POST',
        ),
      ).toBe(true)
    })

    // 打开回滚弹窗并提交回滚
    fireEvent.click(screen.getByRole('button', { name: /回滚历史\(1\)/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('1700000000-abcdef123456.xdb')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: /确认回滚并热加载/ }))

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes('/geoip/rollback') && c[1]?.method === 'POST',
      )
      expect(call).toBeDefined()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({
        slot: 'ip2region_v4',
        backup_id: '1700000000-abcdef123456.xdb',
      })
    })
  })

  it('GeoIP 离线上传弹窗以 multipart/form-data 提交文件与可选 SHA-256（携带 X-CSRF-Token）', async () => {
    const captured: {
      method: string
      url: string
      headers: Record<string, string>
      body: FormData | null
    }[] = []
    class MockXHR {
      status = 200
      readyState = 4
      responseText = JSON.stringify({
        code: 'SUCCESS',
        message: 'ok',
        data: {
          slot: 'ip2region_v4',
          filename: 'ip2region_v4.xdb',
          previous_sha256: 'a'.repeat(64),
          new_sha256: 'b'.repeat(64),
          size_bytes: 2048,
          revision: 'rev-upload-1',
          unchanged: false,
          loaded_sources: ['ip2region_v4'],
        },
      })
      withCredentials = false
      timeout = 0
      upload: { onprogress: ((e: ProgressEvent) => void) | null } = { onprogress: null }
      onload: (() => void) | null = null
      onerror: (() => void) | null = null
      ontimeout: (() => void) | null = null
      onabort: (() => void) | null = null
      onreadystatechange: (() => void) | null = null
      onprogress: ((e: ProgressEvent) => void) | null = null
      private req = { method: '', url: '', headers: {} as Record<string, string>, body: null as FormData | null }

      open(method: string, url: string) {
        this.req.method = method
        this.req.url = url
      }
      setRequestHeader(k: string, v: string) {
        this.req.headers[k] = v
      }
      getResponseHeader() {
        return null
      }
      abort() {}
      send(body?: Document | XMLHttpRequestBodyInit | null) {
        this.req.body = body instanceof FormData ? body : null
        captured.push(this.req)
        this.upload.onprogress?.({ loaded: 100, total: 100, lengthComputable: true } as ProgressEvent)
        queueMicrotask(() => this.onload?.())
      }
    }
    vi.stubGlobal('XMLHttpRequest', MockXHR)

    renderPage()
    await screen.findByText('ip2region IPv4（国内省市/运营商）')

    const uploadButtons = screen.getAllByRole('button', { name: /离线上传/ })
    fireEvent.click(uploadButtons[0])
    const dialog = await screen.findByRole('dialog')

    const fileInput = dialog.querySelector('input[type="file"]') as HTMLInputElement
    expect(fileInput).not.toBeNull()
    const file = new File(['xdb-payload'], 'ip2region_v4.xdb', {
      type: 'application/octet-stream',
    })
    fireEvent.change(fileInput, { target: { files: [file] } })

    const sha = 'b'.repeat(64)
    fireEvent.change(within(dialog).getByPlaceholderText(/64 位十六进制 SHA-256/), {
      target: { value: sha },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /上传并热加载/ }))

    await waitFor(() => {
      expect(captured).toHaveLength(1)
    })
    expect(captured[0].method).toBe('POST')
    expect(captured[0].url).toBe('/api/v1/geoip/upload')
    expect(captured[0].headers['X-CSRF-Token']).toBe('csrf-ui-token')
    expect(captured[0].body?.get('slot')).toBe('ip2region_v4')
    expect(captured[0].body?.get('expected_sha256')).toBe(sha)
    expect((captured[0].body?.get('file') as File)?.name).toBe('ip2region_v4.xdb')
  })

  it('GeoIP 设置抽屉严格掩码 MaxMind License Key（不回显明文且支持清除密钥）', async () => {
    renderPage()
    await screen.findByText('ip2region IPv4（国内省市/运营商）')

    fireEvent.click(screen.getByRole('button', { name: /定时与 MaxMind 设置/ }))
    const drawer = await screen.findByRole('dialog')

    // 确认已配置状态标签出现且密码框为空（绝不回显明文）
    expect(within(drawer).getByText('已配置密钥')).toBeInTheDocument()
    const keyInput = within(drawer).getByPlaceholderText(
      /已保存密钥（留空不修改，输入新密钥覆盖）/,
    ) as HTMLInputElement
    expect(keyInput.value).toBe('')

    // 勾选清除密钥后密码框禁用，保存提交 clear_maxmind_license_key=true
    fireEvent.click(within(drawer).getByLabelText('清除已保存的 MaxMind License Key'))
    await waitFor(() => {
      expect(keyInput).toBeDisabled()
    })
    fireEvent.click(within(drawer).getByRole('button', { name: /保存设置/ }))

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes('/geoip/settings') && c[1]?.method === 'PUT',
      )
      expect(call).toBeDefined()
      const payload = JSON.parse(String(call?.[1]?.body))
      expect(payload.clear_maxmind_license_key).toBe(true)
      expect(payload.maxmind_license_key).toBeUndefined()
    })
  })

  it('威胁情报页签展示熔断横幅、支持护栏中止后二次确认强制同步与离线快照导入', async () => {
    renderPage()
    await screen.findByText('ip2region IPv4（国内省市/运营商）')

    // 切换到威胁情报页签
    fireEvent.click(screen.getByRole('tab', { name: /威胁情报 IP 黑名单库/ }))
    expect(await screen.findByText('abuse.ch Feodo C2 IP 清单')).toBeInTheDocument()
    expect(screen.getByText(/共有 1 个威胁情报源处于熔断状态/)).toBeInTheDocument()

    // 护栏中止源显示强制同步按钮，二次确认后调用 force_ignore_guard: true
    fireEvent.click(screen.getByRole('button', { name: /强制同步/ }))
    const confirmModal = await screen.findByRole('dialog')
    fireEvent.click(within(confirmModal).getByRole('button', { name: /确认强制同步/ }))

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        (c) =>
          String(c[0]).includes('/threat-intel/feeds/feed-feodo/sync') &&
          c[1]?.method === 'POST' &&
          JSON.parse(String(c[1]?.body)).force_ignore_guard === true,
      )
      expect(call).toBeDefined()
    })

    // 点击普通「立即拉取」触发护栏中止时，二次确认后同样以 force_ignore_guard: true 重试
    const pullButtons = screen.getAllByRole('button', { name: /立即拉取/ })
    fireEvent.click(pullButtons[0])
    const guardModal = await screen.findByRole('dialog')
    expect(within(guardModal).getAllByText(/安全护栏已中止对账/).length).toBeGreaterThan(0)
    fireEvent.click(within(guardModal).getByRole('button', { name: /忽略保护强制同步/ }))

    await waitFor(() => {
      const forcedCalls = fetchMock.mock.calls.filter(
        (c) =>
          String(c[0]).includes('/threat-intel/feeds/feed-feodo/sync') &&
          c[1]?.method === 'POST' &&
          JSON.parse(String(c[1]?.body)).force_ignore_guard === true,
      )
      expect(forcedCalls.length).toBeGreaterThanOrEqual(2)
    })

    // 离线快照导入抽屉
    fireEvent.click(screen.getByRole('button', { name: /离线快照导入/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByPlaceholderText(/每行一个 IPv4/), {
      target: { value: '203.0.113.10\n203.0.113.99\nnot-an-ip' },
    })
    fireEvent.click(within(drawer).getByRole('button', { name: /执行对账导入/ }))

    expect(await within(drawer).findByText(/对账导入结果（批次 imp-20261128）/)).toBeInTheDocument()
    expect(within(drawer).getByText('203.0.113.99')).toBeInTheDocument()
    expect(within(drawer).getByText(/命中保护地址/)).toBeInTheDocument()
  })

  it('共用出站代理抽屉：不回显代理密码明文，支持勾选清除凭据并提交 PUT /ip-libraries/outbound-settings', async () => {
    renderPage()
    await screen.findByText('ip2region IPv4（国内省市/运营商）')

    fireEvent.click(screen.getByRole('button', { name: /出站代理与镜像白名单/ }))
    const drawer = await screen.findByRole('dialog')

    expect(await within(drawer).findByText('已保存凭据')).toBeInTheDocument()
    const authInput = within(drawer).getByPlaceholderText(
      /已配置（留空不修改，输入新值覆盖）/,
    ) as HTMLInputElement
    expect(authInput.value).toBe('')

    fireEvent.click(within(drawer).getByLabelText('清除已保存的代理认证凭据'))
    await waitFor(() => {
      expect(authInput).toBeDisabled()
    })
    fireEvent.click(within(drawer).getByRole('button', { name: /保存配置/ }))

    await waitFor(() => {
      const call = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes('/ip-libraries/outbound-settings') && c[1]?.method === 'PUT',
      )
      expect(call).toBeDefined()
      const payload = JSON.parse(String(call?.[1]?.body))
      expect(payload.clear_proxy_auth).toBe(true)
      expect(payload.proxy_auth).toBeUndefined()
    })
  })

  it('RBAC 只读用户（AUDIT_ADMIN）隐藏全部写操作与导入按钮，出站配置抽屉只读', async () => {
    useAuthStore.setState({
      user: makeUser('AUDIT_ADMIN', ['geoip.read', 'threat_intel.read']),
      csrfToken: 'csrf-audit',
      initialized: true,
    })

    renderPage()
    expect(await screen.findByText('ip2region IPv4（国内省市/运营商）')).toBeInTheDocument()

    // GeoIP 页签无写按钮
    expect(screen.queryByRole('button', { name: /离线上传/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /同步全部启用槽位/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /定时与 MaxMind 设置/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /重新同步备节点/ })).not.toBeInTheDocument()

    // 出站代理抽屉为只读且无保存按钮
    fireEvent.click(screen.getByRole('button', { name: /出站代理与镜像白名单/ }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('已保存凭据')).toBeInTheDocument()
    expect(within(drawer).queryByRole('button', { name: /保存配置/ })).not.toBeInTheDocument()
    fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }))

    // 威胁情报页签同样无新建/离线导入/强制同步/保存调度按钮
    fireEvent.click(screen.getByRole('tab', { name: /威胁情报 IP 黑名单库/ }))
    expect(await screen.findByText('abuse.ch Feodo C2 IP 清单')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /新建自定义源/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /离线快照导入/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /强制同步/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /保存调度设置/ })).not.toBeInTheDocument()
  })
})
