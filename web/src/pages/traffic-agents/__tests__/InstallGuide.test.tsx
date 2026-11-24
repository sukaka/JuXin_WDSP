import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import InstallGuidePanel, {
  buildOfflineInstallCommand,
  buildOneClickCommand,
  buildOnlineInstallCommand,
  normalizeServerAddress,
} from '../InstallGuidePanel'
import AgentDetailDrawer from '../AgentDetailDrawer'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SAMPLE_PACKAGES = {
  available: true,
  version: '2.4.0',
  built_at: '2026-11-24T05:00:00Z',
  packages: [
    {
      os: 'linux',
      distro: 'rpm',
      arch: 'amd64',
      format: 'rpm',
      filename: 'wdsp-agent-2.4.0-1.x86_64.rpm',
      size: 4_226_903,
      sha256: 'a'.repeat(64),
    },
    {
      os: 'linux',
      distro: 'deb',
      arch: 'amd64',
      format: 'deb',
      filename: 'wdsp-agent_2.4.0_amd64.deb',
      size: 4_225_126,
      sha256: 'b'.repeat(64),
    },
    {
      os: 'darwin',
      distro: 'darwin',
      arch: 'arm64',
      format: 'pkg',
      filename: 'wdsp-agent-2.4.0-darwin-arm64.pkg',
      size: 3_906_104,
      sha256: 'c'.repeat(64),
    },
    {
      os: 'windows',
      distro: 'windows',
      arch: 'amd64',
      format: 'zip',
      filename: 'wdsp-agent-2.4.0-windows-amd64.zip',
      size: 4_051_211,
      sha256: 'd'.repeat(64),
    },
  ],
}

const SAMPLE_ENDPOINT = {
  recommended_url: 'https://192.168.10.20:8443',
  saved_url: '',
  source: 'request_host',
  https_port: 8443,
  self_signed_tls: true,
  candidate_ips: ['192.168.10.20', '10.0.5.8'],
  candidate_urls: ['https://192.168.10.20:8443', 'https://10.0.5.8:8443'],
}

function renderWithQuery(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>{ui}</AntdApp>
    </QueryClientProvider>,
  )
}

function mockInstallFetch(opts?: { packages?: unknown; endpoint?: unknown }) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/traffic/agents/install-endpoint')) {
      if (method === 'PUT') {
        const body = JSON.parse(String(init?.body ?? '{}')) as { server_url?: string }
        const saved = normalizeServerAddress(body.server_url ?? '', 8443)
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              ...SAMPLE_ENDPOINT,
              recommended_url: saved,
              saved_url: saved,
              source: 'saved',
            },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: opts?.endpoint ?? SAMPLE_ENDPOINT,
        }),
      )
    }
    if (url.includes('/traffic/agents/enrollment-tokens') && method === 'POST') {
      return Promise.resolve(
        jsonResponse(201, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            id: 'tok-quick-1',
            token: 'wdt_' + '1'.repeat(64),
            expires_at: '2026-11-24T15:30:00Z',
          },
        }),
      )
    }
    return Promise.resolve(
      jsonResponse(200, {
        code: 'SUCCESS',
        message: 'ok',
        data: opts?.packages ?? SAMPLE_PACKAGES,
      }),
    )
  })
}

describe('InstallGuidePanel 与命令生成器', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('裸 IP 自动归一化为 https://<IP>:<port>', () => {
    expect(normalizeServerAddress('192.168.10.20', 8443)).toBe('https://192.168.10.20:8443')
    expect(normalizeServerAddress('192.168.10.20:9443', 8443)).toBe('https://192.168.10.20:9443')
    expect(normalizeServerAddress('fd00::1', 8443)).toBe('https://[fd00::1]:8443')
    expect(normalizeServerAddress('https://10.0.0.5:8443/', 8443)).toBe('https://10.0.0.5:8443')
  })

  it('生成单行全自动一键安装命令：Linux/macOS 自动适配 root/sudo，Windows 启用 TLS 1.2 且兼容自签证书', () => {
    const tok = 'wdt_' + 'a'.repeat(64)

    const unixCmd = buildOneClickCommand({
      target: 'unix-auto',
      serverUrl: '192.168.10.20',
      token: tok,
      insecure: true,
    })
    expect(unixCmd).not.toContain('\n')
    expect(unixCmd).toContain(`WDSP_ENROLL_TOKEN='${tok}'`)
    expect(unixCmd).toContain('Authorization: Bearer $WDSP_ENROLL_TOKEN')
    expect(unixCmd).toContain('[ "$(id -u)" -eq 0 ]')
    expect(unixCmd).toContain('sudo -E bash -s --')
    expect(unixCmd).toContain('https://192.168.10.20:8443')
    expect(unixCmd).toContain('--insecure-skip-verify')
    expect(unixCmd).not.toContain('?token=')

    const winCmd = buildOneClickCommand({
      target: 'windows-auto',
      serverUrl: '192.168.10.20',
      token: tok,
      insecure: true,
    })
    expect(winCmd).not.toContain('\n')
    expect(winCmd).toContain('SecurityProtocolType]::Tls12')
    expect(winCmd).toContain('WdspTlsBypass')
    expect(winCmd).toContain(`$env:WDSP_ENROLL_TOKEN='${tok}'`)
    expect(winCmd).toContain('https://192.168.10.20:8443/api/v1/agents/bootstrap/script/windows')
    expect(winCmd).toContain("-Server 'https://192.168.10.20:8443' -InsecureSkipVerify")
    expect(winCmd).not.toContain('?token=')
  })

  it('生成四平台指定参数在线安装命令：Token 仅经环境变量与 Header 传递，绝不放 URL Query，且安全转义单引号', () => {
    const tok = 'wdt_' + 'f'.repeat(64)
    const server = "https://wdsp.example.com:8443/path'test"

    const centosCmd = buildOnlineInstallCommand({
      platform: 'centos',
      serverUrl: server,
      token: tok,
      arch: 'amd64',
    })
    expect(centosCmd).toContain('export WDSP_ENROLL_TOKEN=')
    expect(centosCmd).toContain('Authorization: Bearer $WDSP_ENROLL_TOKEN')
    expect(centosCmd).toContain('--format rpm --arch amd64')
    expect(centosCmd).not.toContain(`?token=${tok}`)
    expect(centosCmd).toContain(`path'\\''test`)

    const debianCmd = buildOnlineInstallCommand({
      platform: 'debian',
      serverUrl: 'https://wdsp.local',
      token: tok,
      arch: 'arm64',
    })
    expect(debianCmd).toContain('--format deb --arch arm64')

    const macCmd = buildOnlineInstallCommand({
      platform: 'macos',
      serverUrl: 'https://wdsp.local',
      token: tok,
      arch: 'arm64',
      macFormat: 'pkg',
    })
    expect(macCmd).toContain('/api/v1/agents/bootstrap/script/darwin')
    expect(macCmd).toContain('--format pkg --arch arm64')

    const winCmd = buildOnlineInstallCommand({
      platform: 'windows',
      serverUrl: "https://wdsp.local/o'ne",
      token: tok,
      arch: 'amd64',
      insecure: true,
    })
    expect(winCmd).toContain('$env:WDSP_ENROLL_TOKEN =')
    expect(winCmd).toContain('SecurityProtocolType]::Tls12')
    expect(winCmd).toContain('Authorization = "Bearer $env:WDSP_ENROLL_TOKEN"')
    expect(winCmd).toContain('-InsecureSkipVerify')
    expect(winCmd).toContain(`o''ne`)
    expect(winCmd).not.toContain('?token=')
  })

  it('生成离线安装命令覆盖 rpm/dpkg/installer/PowerShell', () => {
    expect(
      buildOfflineInstallCommand({ platform: 'centos', serverUrl: 'https://x', arch: 'amd64' }),
    ).toContain('rpm -Uvh --replacepkgs')
    expect(
      buildOfflineInstallCommand({ platform: 'debian', serverUrl: 'https://x', arch: 'amd64' }),
    ).toContain('dpkg -i')
    expect(
      buildOfflineInstallCommand({
        platform: 'macos',
        serverUrl: 'https://x',
        arch: 'arm64',
        macFormat: 'pkg',
      }),
    ).toContain('installer -pkg')
    expect(
      buildOfflineInstallCommand({ platform: 'windows', serverUrl: 'https://x', arch: 'amd64' }),
    ).toContain('Expand-Archive')
  })

  it('自动回填 WDSP IP 接入地址、支持点击候选 IP 切换、一键生成令牌并保存默认对接地址', async () => {
    const fetchMock = mockInstallFetch()
    vi.stubGlobal('fetch', fetchMock)

    renderWithQuery(<InstallGuidePanel canManage />)

    // 自动加载后端探测的 WDSP IP
    await waitFor(() => {
      expect(screen.getByLabelText('管理面接入地址')).toHaveValue('https://192.168.10.20:8443')
    })

    // 点击第二个候选 IP 快捷切换
    fireEvent.click(screen.getByText('10.0.5.8'))
    expect(screen.getByLabelText('管理面接入地址')).toHaveValue('https://10.0.5.8:8443')

    // 点击“设为默认”触发 PUT /install-endpoint
    fireEvent.click(screen.getByRole('button', { name: '设为默认' }))
    await waitFor(() => {
      const putCall = (fetchMock as Mock).mock.calls.find(
        (c) => String(c[0]).includes('/install-endpoint') && (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      expect(JSON.parse(String(putCall![1]?.body))).toEqual({ server_url: 'https://10.0.5.8:8443' })
    })

    // 点击“一键生成可执行命令”自动签发令牌并嵌入命令
    fireEvent.click(screen.getByRole('button', { name: '一键生成可执行命令' }))
    await waitFor(() => {
      const cmdText = screen.getByTestId('one-click-install-cmd').textContent ?? ''
      expect(cmdText).toContain('wdt_' + '1'.repeat(64))
      expect(cmdText).toContain('https://10.0.5.8:8443')
      expect(cmdText).toContain('--insecure-skip-verify')
    })
  })

  it('高级/离线包 Tab：四平台切换展示包名、SHA-256 与下载链接', async () => {
    vi.stubGlobal('fetch', mockInstallFetch())

    renderWithQuery(<InstallGuidePanel token="wdt_demo_token" defaultMode="advanced" />)

    // 默认 CentOS (RPM)
    expect(await screen.findByText('安装包就绪')).toBeInTheDocument()
    const rpmLink = screen.getByRole('link', { name: /下载 wdsp-agent-2\.4\.0-1\.x86_64\.rpm/ })
    expect(rpmLink).toHaveAttribute('href', '/api/v1/traffic/agents/packages/linux/amd64/rpm')
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()

    // 切 Debian
    fireEvent.click(screen.getByRole('tab', { name: /Debian/ }))
    expect(
      await screen.findByRole('link', { name: /下载 wdsp-agent_2\.4\.0_amd64\.deb/ }),
    ).toHaveAttribute('href', '/api/v1/traffic/agents/packages/linux/amd64/deb')

    // 切 macOS（自动切换默认 arm64）
    fireEvent.click(screen.getByRole('tab', { name: /macOS/ }))
    expect(
      await screen.findByRole('link', { name: /下载 wdsp-agent-2\.4\.0-darwin-arm64\.pkg/ }),
    ).toHaveAttribute('href', '/api/v1/traffic/agents/packages/darwin/arm64/pkg')

    // 切 Windows
    fireEvent.click(screen.getByRole('tab', { name: /Windows/ }))
    expect(
      await screen.findByRole('link', { name: /下载 wdsp-agent-2\.4\.0-windows-amd64\.zip/ }),
    ).toHaveAttribute('href', '/api/v1/traffic/agents/packages/windows/amd64/zip')
  })

  it('服务端未挂载安装包时如实禁用在线一键命令并提示缺失状态', async () => {
    vi.stubGlobal(
      'fetch',
      mockInstallFetch({ packages: { available: false, packages: [] } }),
    )

    renderWithQuery(<InstallGuidePanel token="wdt_demo_token" defaultMode="advanced" />)
    expect(await screen.findByText('服务端未挂载对应包')).toBeInTheDocument()
    expect(screen.getByText(/当前服务端未挂载 linux\/amd64\/rpm 安装包/)).toBeInTheDocument()
  })

  it('AgentDetailDrawer 展示跨平台生效抓包后端与回退标记', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/events')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [], total: 0 } }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              agent_id: 'a3c98f51-0000-4000-8000-000000000099',
              hostname: 'win-app-01',
              ip: '10.0.2.5',
              os: 'Windows Server 2022 (Build 20348)',
              kernel: '10.0.20348',
              arch: 'amd64',
              version: '2.4.0',
              status: 'ONLINE',
              disabled: false,
              last_seen: new Date().toISOString(),
              last_metrics: {
                cpu_percent: 2.1,
                memory_mb: 64.0,
                capture_backend: 'rawsocket',
                backend_fallback_reason: 'npcap wpcap.dll not found',
              },
              config_version: 1,
              applied_config_version: 1,
              clock_offset_ms: 0,
              health_score: 100,
              health_reasons: [],
              created_at: '2026-11-24T00:00:00Z',
              interfaces: [],
              policy_binding: null,
            },
          }),
        )
      }),
    )

    renderWithQuery(
      <AgentDetailDrawer
        agentId="a3c98f51-0000-4000-8000-000000000099"
        open
        onClose={() => {}}
        canManage={false}
      />,
    )

    await waitFor(() => {
      expect(screen.getByText('IPv4 Raw Socket (Windows 回退)')).toBeInTheDocument()
      expect(screen.getByText('已自动回退')).toBeInTheDocument()
    })
  })
})
