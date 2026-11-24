import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Input,
  Radio,
  Space,
  Switch,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { ApiError } from '../../api/client'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type {
  CreateTrafficEnrollmentTokenResult,
  TrafficAgentPackageItem,
} from '../../api/trafficAgents'
import { formatBytes, formatDateTime } from '../../utils/format'

export type InstallPlatform = 'centos' | 'debian' | 'macos' | 'windows'
export type InstallArch = 'amd64' | 'arm64'
export type QuickInstallTarget = 'unix-auto' | 'windows-auto'

export interface InstallCommandOptions {
  platform: InstallPlatform
  serverUrl: string
  token?: string
  arch: InstallArch
  macFormat?: 'pkg' | 'targz'
  insecure?: boolean
  filename?: string
}

export interface OneClickCommandOptions {
  target: QuickInstallTarget
  serverUrl: string
  token?: string
  insecure?: boolean
}

/** Shell 单引号安全转义（防止特殊字符拼出命令注入） */
function quoteShellSingle(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

/** PowerShell 单引号安全转义 */
function quotePowerShellSingle(value: string): string {
  return `'${value.replace(/'/g, `''`)}'`
}

function isIPv4Literal(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host)
}

function isIPLiteral(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, '')
  return isIPv4Literal(clean) || clean.includes(':')
}

export function isLoopbackServerUrl(raw: string): boolean {
  const trimmed = raw.trim()
  if (!trimmed) return false
  try {
    const withScheme = trimmed.includes('://') ? trimmed : `https://${trimmed}`
    const u = new URL(withScheme)
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost')
  } catch {
    return false
  }
}

export function isPlainHttpNonLoopback(raw: string): boolean {
  const trimmed = raw.trim()
  if (!/^http:\/\//i.test(trimmed)) return false
  return !isLoopbackServerUrl(trimmed)
}

export function formatHttpsUrlForHost(host: string, httpsPort = 8443): string {
  const clean = host.trim().replace(/^\[|\]$/g, '')
  const hostPart = clean.includes(':') ? `[${clean}]` : clean
  if (httpsPort === 443) return `https://${hostPart}`
  return `https://${hostPart}:${httpsPort}`
}

/** 归一化接入地址：允许直接填写裸 IP（如 192.168.10.20）并自动补齐 https:// 与端口 */
export function normalizeServerAddress(raw: string, defaultHttpsPort = 8443): string {
  const trimmed = raw.trim().replace(/\/+$/, '')
  if (!trimmed) return `https://<WDSP服务器IP>:${defaultHttpsPort}`
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }
  // 裸 IPv6（无方括号、无端口）
  if (trimmed.includes(':') && !trimmed.startsWith('[') && !trimmed.includes('.')) {
    const colonCount = (trimmed.match(/:/g) ?? []).length
    if (colonCount > 1) {
      return formatHttpsUrlForHost(trimmed, defaultHttpsPort)
    }
  }
  try {
    const parsed = new URL(`https://${trimmed}`)
    if (!parsed.port && defaultHttpsPort !== 443) {
      return formatHttpsUrlForHost(parsed.hostname, defaultHttpsPort)
    }
    return `https://${parsed.host}`
  } catch {
    return `https://${trimmed}`
  }
}

/** 将浏览器当前 origin 智能转换为默认 HTTPS 地址（若当前为非回环 HTTP :8080，自动升级至 HTTPS 端口） */
function deriveBrowserDefaultUrl(httpsPort = 8443): string {
  if (typeof window === 'undefined' || !window.location?.hostname) {
    return `https://<WDSP服务器IP>:${httpsPort}`
  }
  const { protocol, hostname, origin } = window.location
  if (isLoopbackServerUrl(origin)) {
    return origin.replace(/\/+$/, '')
  }
  if (protocol === 'http:') {
    return formatHttpsUrlForHost(hostname, httpsPort)
  }
  return origin.replace(/\/+$/, '')
}

/** 构造单行全自动一键安装命令（客户端直接粘贴执行，自动识别系统/架构并经 IP 自动注册对接 WDSP） */
export function buildOneClickCommand(opts: OneClickCommandOptions): string {
  const server = normalizeServerAddress(opts.serverUrl)
  const tok = opts.token?.trim() || 'wdt_<点击上方一键生成一次性注册令牌>'

  if (opts.target === 'windows-auto') {
    const tlsSetup = opts.insecure
      ? `; if(-not('WdspTlsBypass' -as [type])){Add-Type 'using System.Net;public static class WdspTlsBypass{public static void Enable(){ServicePointManager.ServerCertificateValidationCallback=(s,c,h,e)=>true;}}'}; [WdspTlsBypass]::Enable()`
      : ''
    const insecurePs = opts.insecure ? ' -InsecureSkipVerify' : ''
    return [
      `$env:WDSP_ENROLL_TOKEN=${quotePowerShellSingle(tok)}`,
      `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12${tlsSetup}`,
      `$s=Join-Path $env:TEMP 'install-wdsp-agent.ps1'`,
      `Invoke-WebRequest -UseBasicParsing -Headers @{Authorization="Bearer $env:WDSP_ENROLL_TOKEN"} -Uri ${quotePowerShellSingle(`${server}/api/v1/agents/bootstrap/script/windows`)} -OutFile $s`,
      `& $s -Server ${quotePowerShellSingle(server)}${insecurePs}`,
      `Remove-Item -Force $s -EA SilentlyContinue`,
      `Remove-Item Env:WDSP_ENROLL_TOKEN`,
    ].join('; ')
  }

  // Linux（CentOS/RHEL/openEuler/Debian/Ubuntu）+ macOS 单行全自动命令：
  // - Token 仅存于命令级环境变量，不进 URL Query，也不在 ps 命令行暴露；
  // - 已是 root（含无 sudo 的极简容器/云主机）直接运行，普通用户自动 sudo -E；
  // - install-agent.sh 自动识别 Linux/macOS、RPM/DEB/PKG/tar.gz 与 amd64/arm64，并向 WDSP IP 注册与拉起系统服务。
  const curlInsecure = opts.insecure ? ' -k' : ''
  const scriptInsecure = opts.insecure ? ' --insecure-skip-verify' : ''
  return `WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)} bash -c 'set -o pipefail; curl -fsSL${curlInsecure} -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" "$1/api/v1/agents/bootstrap/script/linux" | ( [ "$(id -u)" -eq 0 ] && exec bash -s -- --server "$1"${scriptInsecure} || exec sudo -E bash -s -- --server "$1"${scriptInsecure} )' _ ${quoteShellSingle(server)}`
}

/** 构造按平台指定参数的在线安装命令（Token 仅通过环境变量与 Authorization Header 传递，绝不放 URL Query） */
export function buildOnlineInstallCommand(opts: InstallCommandOptions): string {
  const server = normalizeServerAddress(opts.serverUrl)
  const tok = opts.token?.trim() || 'wdt_<替换为一次性注册令牌>'
  if (opts.platform === 'windows') {
    const insecurePs = opts.insecure ? ' -InsecureSkipVerify' : ''
    const psLines = [
      `$env:WDSP_ENROLL_TOKEN = ${quotePowerShellSingle(tok)}`,
      `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
      `$s = Join-Path $env:TEMP 'install-wdsp-agent.ps1'`,
      ...(opts.insecure
        ? [
            `if (-not ('WdspTlsBypass' -as [type])) { Add-Type 'using System.Net;public static class WdspTlsBypass{public static void Enable(){ServicePointManager.ServerCertificateValidationCallback=(s,c,h,e)=>true;}}' }`,
            `[WdspTlsBypass]::Enable()`,
          ]
        : []),
      `Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "Bearer $env:WDSP_ENROLL_TOKEN" } -Uri ${quotePowerShellSingle(`${server}/api/v1/agents/bootstrap/script/windows`)} -OutFile $s`,
      `& $s -Server ${quotePowerShellSingle(server)} -Arch ${quotePowerShellSingle(opts.arch)}${insecurePs}`,
      `Remove-Item -Force $s -ErrorAction SilentlyContinue`,
      `Remove-Item Env:WDSP_ENROLL_TOKEN`,
    ]
    return psLines.join('\n')
  }

  const osPath = opts.platform === 'macos' ? 'darwin' : 'linux'
  const fmt =
    opts.platform === 'centos'
      ? 'rpm'
      : opts.platform === 'debian'
        ? 'deb'
        : opts.macFormat ?? 'pkg'
  const curlInsecure = opts.insecure ? ' -k' : ''
  const scriptInsecure = opts.insecure ? ' --insecure-skip-verify' : ''
  return [
    `export WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)}`,
    `curl -fsSL${curlInsecure} -H "Authorization: Bearer $WDSP_ENROLL_TOKEN" ${quoteShellSingle(`${server}/api/v1/agents/bootstrap/script/${osPath}`)} \\`,
    `  | sudo -E bash -s -- --server ${quoteShellSingle(server)} --format ${fmt} --arch ${opts.arch}${scriptInsecure}`,
    `unset WDSP_ENROLL_TOKEN`,
  ].join('\n')
}

/** 构造离线安装包本地部署命令 */
export function buildOfflineInstallCommand(opts: InstallCommandOptions): string {
  const server = normalizeServerAddress(opts.serverUrl)
  const tok = opts.token?.trim() || 'wdt_<替换为一次性注册令牌>'
  const insecureFlag = opts.insecure ? ' --insecure-skip-verify' : ''

  if (opts.platform === 'windows') {
    const fname = opts.filename || `wdsp-agent-windows-${opts.arch}.zip`
    const insecurePs = opts.insecure ? ' -InsecureSkipVerify' : ''
    return [
      `Expand-Archive -Path ${quotePowerShellSingle(`.\\${fname}`)} -DestinationPath .\\wdsp-agent-pkg -Force`,
      `cd .\\wdsp-agent-pkg\\*`,
      `$env:WDSP_ENROLL_TOKEN = ${quotePowerShellSingle(tok)}`,
      `.\\install-agent.ps1 -Server ${quotePowerShellSingle(server)} -LocalPackage ${quotePowerShellSingle(`..\\..\\${fname}`)}${insecurePs}`,
      `Remove-Item Env:WDSP_ENROLL_TOKEN`,
    ].join('\n')
  }

  if (opts.platform === 'centos') {
    const fname =
      opts.filename ||
      `wdsp-agent-2.4.0-1.${opts.arch === 'arm64' ? 'aarch64' : 'x86_64'}.rpm`
    return [
      `sudo rpm -Uvh --replacepkgs ${quoteShellSingle(fname)}`,
      `export WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)}`,
      `sudo -E /usr/local/bin/wdsp-agent install --server ${quoteShellSingle(server)}${insecureFlag}`,
      `unset WDSP_ENROLL_TOKEN`,
    ].join('\n')
  }

  if (opts.platform === 'debian') {
    const fname = opts.filename || `wdsp-agent_2.4.0_${opts.arch}.deb`
    return [
      `sudo dpkg -i ${quoteShellSingle(fname)}`,
      `export WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)}`,
      `sudo -E /usr/local/bin/wdsp-agent install --server ${quoteShellSingle(server)}${insecureFlag}`,
      `unset WDSP_ENROLL_TOKEN`,
    ].join('\n')
  }

  // macOS
  const macFmt = opts.macFormat ?? 'pkg'
  if (macFmt === 'pkg') {
    const fname = opts.filename || `wdsp-agent-2.4.0-darwin-${opts.arch}.pkg`
    return [
      `sudo installer -pkg ${quoteShellSingle(fname)} -target /`,
      `export WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)}`,
      `sudo -E /usr/local/bin/wdsp-agent install --server ${quoteShellSingle(server)}${insecureFlag}`,
      `unset WDSP_ENROLL_TOKEN`,
    ].join('\n')
  }
  const fname = opts.filename || `wdsp-agent-2.4.0-darwin-${opts.arch}.tar.gz`
  return [
    `tar -xzf ${quoteShellSingle(fname)}`,
    `sudo install -m 0755 wdsp-agent-*/wdsp-agent /usr/local/bin/wdsp-agent`,
    `export WDSP_ENROLL_TOKEN=${quoteShellSingle(tok)}`,
    `sudo -E /usr/local/bin/wdsp-agent install --server ${quoteShellSingle(server)}${insecureFlag}`,
    `unset WDSP_ENROLL_TOKEN`,
  ].join('\n')
}

function targetTuple(
  platform: InstallPlatform,
  arch: InstallArch,
  macFormat: 'pkg' | 'targz',
): { os: string; arch: string; format: string } {
  switch (platform) {
    case 'centos':
      return { os: 'linux', arch, format: 'rpm' }
    case 'debian':
      return { os: 'linux', arch, format: 'deb' }
    case 'macos':
      return { os: 'darwin', arch, format: macFormat }
    case 'windows':
      return { os: 'windows', arch, format: 'zip' }
  }
}

const PLATFORM_NOTES: Record<InstallPlatform, { title: string; body: string }> = {
  centos: {
    title: 'CentOS / RHEL / Rocky / AlmaLinux / openEuler 说明',
    body: '纯静态二进制（零 glibc/libpcap 依赖），自动注册 systemd 服务（低内核如 CentOS 7 自动兼容省略 CAP_BPF）。抓包优先 eBPF/TCX（内核 ≥6.6），否则自动无感回退 AF_PACKET。',
  },
  debian: {
    title: 'Debian / Ubuntu / 麒麟 / 统信 UOS 说明',
    body: '通过标准 .deb 安装至 /usr/local/bin/wdsp-agent 并注册 systemd 服务，默认以最小权限 CAP_NET_RAW/CAP_NET_ADMIN 纯旁路只读抓包。',
  },
  macos: {
    title: 'macOS 说明（LaunchDaemon + 原生只读 BPF）',
    body: '安装为系统级 LaunchDaemon（com.jiuzhang.wdsp-agent），配置目录 /Library/Application Support/WDSPAgent。通过 /dev/bpf* 以 O_RDONLY 方式纯旁路只读采集（需 root 或 access_bpf 组权限）。',
  },
  windows: {
    title: 'Windows 说明（管理员 PowerShell + Windows Service）',
    body: '请以管理员身份运行 PowerShell。服务注册为原生 WDSPAgent，凭据目录 %ProgramData%\\JiuZhang\\WDSPAgent 自动施加受限 NTFS ACL。生产环境推荐宿主机自行安装 Npcap 驱动（不随本包分发），未安装时将自动回退至 Winsock IPv4 Raw Socket（仅 IPv4、受本机防火墙影响）。',
  },
}

const CODE_BLOCK_STYLE: React.CSSProperties = {
  margin: 0,
  padding: '10px 12px',
  background: '#0f172a',
  color: '#e2e8f0',
  borderRadius: 6,
  fontSize: 12,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
}

const ENDPOINT_SOURCE_LABEL: Record<string, string> = {
  saved: '已保存的默认对接地址',
  env: '服务端环境变量配置',
  request_host: '当前控制台访问 IP 自动识别',
  configured_host_ip: '宿主机安装期 IP 自动识别',
  console_cert: '控制台证书 SAN IP 自动识别',
  host_interface: '本机网卡 IP 自动识别',
}

/** 跨平台 Agent 一键安装与离线包分发面板（自动识别 WDSP IP 并生成单行可执行安装命令） */
export default function InstallGuidePanel({
  token,
  tokenExpiresAt,
  active = true,
  canManage = false,
  defaultMode = 'quick',
  onTokenCreated,
}: {
  token?: string
  tokenExpiresAt?: string
  active?: boolean
  canManage?: boolean
  defaultMode?: 'quick' | 'advanced'
  onTokenCreated?: (created: CreateTrafficEnrollmentTokenResult) => void
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [modeTab, setModeTab] = useState<'quick' | 'advanced'>(defaultMode)
  const [quickTarget, setQuickTarget] = useState<QuickInstallTarget>('unix-auto')
  const [platform, setPlatform] = useState<InstallPlatform>('centos')
  const [arch, setArch] = useState<InstallArch>('amd64')
  const [macFormat, setMacFormat] = useState<'pkg' | 'targz'>('pkg')
  const [serverUrl, setServerUrl] = useState(() => deriveBrowserDefaultUrl(8443))
  const [insecure, setInsecure] = useState(() => {
    const def = deriveBrowserDefaultUrl(8443)
    try {
      return isIPLiteral(new URL(def).hostname)
    } catch {
      return false
    }
  })

  const [mintedToken, setMintedToken] = useState<CreateTrafficEnrollmentTokenResult | null>(null)
  const userEditedUrlRef = useRef(false)
  const userToggledInsecureRef = useRef(false)

  // 外部传入新令牌时覆盖本地临时令牌
  useEffect(() => {
    if (token) {
      setMintedToken(null)
    }
  }, [token])

  const effectiveToken = mintedToken?.token || token
  const effectiveExpiresAt = mintedToken?.expires_at || tokenExpiresAt

  const packagesQuery = useQuery({
    queryKey: ['traffic-agents', 'packages'],
    queryFn: () => trafficAgentsApi.packages(),
    enabled: active,
    staleTime: 60_000,
  })

  const endpointQuery = useQuery({
    queryKey: ['traffic-agents', 'install-endpoint'],
    queryFn: () => trafficAgentsApi.installEndpoint(),
    enabled: active,
    staleTime: 60_000,
  })

  const httpsPort = endpointQuery.data?.https_port ?? 8443

  // 后端返回自动探测的 WDSP IP 接入地址后，自动回填（不覆盖用户手工编辑）
  useEffect(() => {
    const ep = endpointQuery.data
    if (!ep) return
    if (!userEditedUrlRef.current && ep.recommended_url) {
      setServerUrl(ep.recommended_url)
    }
    if (!userToggledInsecureRef.current) {
      setInsecure(ep.self_signed_tls)
    }
  }, [endpointQuery.data])

  const quickTokenMutation = useMutation({
    mutationFn: () => {
      const now = new Date()
      const stamp = `${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`
      return trafficAgentsApi.createEnrollmentToken({
        label: `quick-install-${stamp}`,
        ttl_minutes: 60,
      })
    },
    onSuccess: (created) => {
      setMintedToken(created)
      onTokenCreated?.(created)
      message.success('已签发一次性安装令牌并嵌入下方命令')
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '生成一次性注册令牌失败')
    },
  })

  const saveEndpointMutation = useMutation({
    mutationFn: (urlToSave: string) => trafficAgentsApi.saveInstallEndpoint(urlToSave),
    onSuccess: (updated) => {
      queryClient.setQueryData(['traffic-agents', 'install-endpoint'], updated)
      if (updated.recommended_url) {
        setServerUrl(updated.recommended_url)
      }
      message.success(
        updated.saved_url
          ? `已将 ${updated.saved_url} 设为默认 WDSP 对接地址`
          : '已恢复自动识别 WDSP 对接地址',
      )
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '保存默认对接地址失败')
    },
  })

  const normalizedUrl = useMemo(
    () => normalizeServerAddress(serverUrl, httpsPort),
    [serverUrl, httpsPort],
  )

  const target = targetTuple(platform, arch, macFormat)
  const matchedPkg: TrafficAgentPackageItem | undefined = useMemo(() => {
    const list = packagesQuery.data?.packages ?? []
    return list.find(
      (p) => p.os === target.os && p.arch === target.arch && p.format === target.format,
    )
  }, [packagesQuery.data, target.os, target.arch, target.format])

  const hasUnixPackages = useMemo(() => {
    const list = packagesQuery.data?.packages ?? []
    return list.some((p) => p.os === 'linux' || p.os === 'darwin')
  }, [packagesQuery.data])

  const hasWindowsPackages = useMemo(() => {
    const list = packagesQuery.data?.packages ?? []
    return list.some((p) => p.os === 'windows')
  }, [packagesQuery.data])

  const quickPackagesReady = Boolean(
    packagesQuery.data?.available &&
      (quickTarget === 'windows-auto' ? hasWindowsPackages : hasUnixPackages),
  )

  const oneClickCmd = useMemo(
    () =>
      buildOneClickCommand({
        target: quickTarget,
        serverUrl: normalizedUrl,
        token: effectiveToken,
        insecure,
      }),
    [quickTarget, normalizedUrl, effectiveToken, insecure],
  )

  const onlineCmd = useMemo(
    () =>
      buildOnlineInstallCommand({
        platform,
        serverUrl: normalizedUrl,
        token: effectiveToken,
        arch,
        macFormat,
        insecure,
      }),
    [platform, normalizedUrl, effectiveToken, arch, macFormat, insecure],
  )

  const offlineCmd = useMemo(
    () =>
      buildOfflineInstallCommand({
        platform,
        serverUrl: normalizedUrl,
        token: effectiveToken,
        arch,
        macFormat,
        insecure,
        filename: matchedPkg?.filename,
      }),
    [platform, normalizedUrl, effectiveToken, arch, macFormat, insecure, matchedPkg?.filename],
  )

  const copyCommand = async (cmd: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(cmd)
        message.success('已复制安装命令，请在目标客户端终端粘贴执行')
        return
      }
    } catch {
      // 回落到下方提示
    }
    message.info('请直接选中上方代码块复制命令')
  }

  const note = PLATFORM_NOTES[platform]
  const packagesAvailable = Boolean(packagesQuery.data?.available && matchedPkg)
  const candidateIPs = endpointQuery.data?.candidate_ips ?? []
  const endpointSource = endpointQuery.data?.source
  const showLoopbackWarn = isLoopbackServerUrl(serverUrl)
  const showPlainHttpWarn = isPlainHttpNonLoopback(serverUrl)

  const quickInstallContent = (
    <Space direction="vertical" size={12} style={{ display: 'flex' }}>
      <Space wrap align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
        <Radio.Group
          value={quickTarget}
          onChange={(e) => setQuickTarget(e.target.value as QuickInstallTarget)}
          optionType="button"
          buttonStyle="solid"
          size="small"
          options={[
            { label: 'Linux / macOS（自动识别 CentOS / Debian / Ubuntu / macOS）', value: 'unix-auto' },
            { label: 'Windows（管理员 PowerShell）', value: 'windows-auto' },
          ]}
        />
        <Tag color={quickPackagesReady ? 'green' : 'orange'}>
          {quickPackagesReady ? '安装包就绪' : '服务端未挂载安装包'}
        </Tag>
      </Space>

      {!effectiveToken ? (
        <Alert
          type="info"
          showIcon
          message="需要一次性注册令牌即可直接运行"
          description={
            canManage ? (
              <Space wrap size={8} style={{ marginTop: 4 }}>
                <span>点击右侧按钮自动签发一次性令牌，命令将直接填入令牌与 WDSP IP，复制到客户端终端执行即可完成安装并自动上线。</span>
                <Button
                  type="primary"
                  size="small"
                  loading={quickTokenMutation.isPending}
                  onClick={() => quickTokenMutation.mutate()}
                >
                  一键生成可执行命令
                </Button>
              </Space>
            ) : (
              '当前账号仅具查看权限（需 traffic.agents.manage 权限签发一次性注册令牌）。'
            )
          }
        />
      ) : (
        <Space wrap align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
          <Space size={8} wrap>
            <Tag color="success">一次性令牌已嵌入，复制即可直接执行</Tag>
            {effectiveExpiresAt ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                有效期至 {formatDateTime(effectiveExpiresAt)}（单次注册后自动失效）
              </Typography.Text>
            ) : null}
          </Space>
          {canManage ? (
            <Button
              size="small"
              loading={quickTokenMutation.isPending}
              onClick={() => quickTokenMutation.mutate()}
            >
              重新生成令牌（部署下一台）
            </Button>
          ) : null}
        </Space>
      )}

      {quickPackagesReady ? (
        <div>
          <Space style={{ marginBottom: 6, justifyContent: 'space-between', width: '100%' }}>
            <Typography.Text strong>
              {quickTarget === 'windows-auto'
                ? '在客户端“以管理员身份运行”PowerShell 粘贴执行：'
                : '在目标客户端终端（CentOS / Debian / Ubuntu / macOS，amd64 / arm64）直接粘贴执行：'}
            </Typography.Text>
            <Button
              type="primary"
              size="small"
              disabled={!effectiveToken}
              onClick={() => void copyCommand(oneClickCmd)}
            >
              一键复制命令
            </Button>
          </Space>
          <pre data-testid="one-click-install-cmd" style={CODE_BLOCK_STYLE}>
            {oneClickCmd}
          </pre>
          <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block', marginTop: 6 }}>
            执行后将自动识别系统与 CPU 架构、从 {normalizedUrl} 拉取对应安装包并校验 SHA-256、完成机器身份证书注册、拉起原生系统服务并自动上报心跳至 WDSP 平台。
          </Typography.Text>
        </div>
      ) : (
        <Alert
          type="warning"
          showIcon
          message="当前服务端尚未挂载跨平台 Agent 安装包"
          description="请先在构建机执行 packaging/wdsp-agent/build-packages.sh 生成全平台安装包并挂载至 TRAFFIC_AGENT_PACKAGES_DIR（默认 /app/runtime/agent-packages），或切换至“按平台指定 / 离线包下载”标签。"
        />
      )}
    </Space>
  )

  const advancedInstallContent = (
    <Space direction="vertical" size={12} style={{ display: 'flex' }}>
      <Tabs
        size="small"
        activeKey={platform}
        onChange={(k) => {
          const next = k as InstallPlatform
          setPlatform(next)
          if (next === 'macos') {
            setArch('arm64')
          } else if (arch === 'arm64' && next === 'windows') {
            setArch('amd64')
          }
        }}
        items={[
          { key: 'centos', label: 'CentOS / RHEL (RPM)' },
          { key: 'debian', label: 'Debian / Ubuntu (DEB)' },
          { key: 'macos', label: 'macOS (PKG / tar.gz)' },
          { key: 'windows', label: 'Windows (ZIP / PowerShell)' },
        ]}
      />

      <Space wrap size={12} align="center">
        <Space size={6}>
          <Typography.Text type="secondary">CPU 架构：</Typography.Text>
          <Radio.Group
            size="small"
            value={arch}
            onChange={(e) => setArch(e.target.value as InstallArch)}
            optionType="button"
            options={[
              { label: 'amd64 (x86_64)', value: 'amd64' },
              { label: 'arm64', value: 'arm64' },
            ]}
          />
        </Space>
        {platform === 'macos' ? (
          <Space size={6}>
            <Typography.Text type="secondary">格式：</Typography.Text>
            <Radio.Group
              size="small"
              value={macFormat}
              onChange={(e) => setMacFormat(e.target.value as 'pkg' | 'targz')}
              optionType="button"
              options={[
                { label: '.pkg', value: 'pkg' },
                { label: '.tar.gz', value: 'targz' },
              ]}
            />
          </Space>
        ) : null}
      </Space>

      <Alert type="info" showIcon message={note.title} description={note.body} />

      <div>
        <Space style={{ marginBottom: 6, justifyContent: 'space-between', width: '100%' }}>
          <Space size={8}>
            <Typography.Text strong>指定平台在线安装命令</Typography.Text>
            <Tag color={packagesAvailable ? 'green' : 'orange'}>
              {packagesAvailable ? '安装包就绪' : '服务端未挂载对应包'}
            </Tag>
          </Space>
          {packagesAvailable ? (
            <Typography.Text copyable={{ text: onlineCmd }} style={{ fontSize: 12 }}>
              复制命令
            </Typography.Text>
          ) : null}
        </Space>
        {packagesAvailable ? (
          <pre style={CODE_BLOCK_STYLE}>{onlineCmd}</pre>
        ) : (
          <Alert
            type="warning"
            showIcon
            message={`当前服务端未挂载 ${target.os}/${target.arch}/${target.format} 安装包`}
            description="请先运行 packaging/wdsp-agent/build-packages.sh 生成全平台安装包并挂载至服务端 TRAFFIC_AGENT_PACKAGES_DIR（默认 /app/runtime/agent-packages），或使用下方离线方式手动部署。"
          />
        )}
      </div>

      <div>
        <Space style={{ marginBottom: 6, justifyContent: 'space-between', width: '100%' }}>
          <Typography.Text strong>离线包下载与手动安装</Typography.Text>
          <Space size={8}>
            {matchedPkg ? (
              <Button
                type="primary"
                size="small"
                href={trafficAgentsApi.packageDownloadUrl(
                  matchedPkg.os,
                  matchedPkg.arch,
                  matchedPkg.format,
                )}
                download={matchedPkg.filename}
              >
                下载 {matchedPkg.filename}
              </Button>
            ) : null}
            <Typography.Text copyable={{ text: offlineCmd }} style={{ fontSize: 12 }}>
              复制离线命令
            </Typography.Text>
          </Space>
        </Space>

        {matchedPkg ? (
          <Descriptions size="small" bordered column={2} style={{ marginBottom: 8 }}>
            <Descriptions.Item label="包版本">
              {packagesQuery.data?.version || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="大小">{formatBytes(matchedPkg.size)}</Descriptions.Item>
            <Descriptions.Item label="SHA-256" span={2}>
              <Typography.Text
                copyable={{ text: matchedPkg.sha256 }}
                style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}
              >
                {matchedPkg.sha256}
              </Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        ) : null}

        <pre style={CODE_BLOCK_STYLE}>{offlineCmd}</pre>
      </div>
    </Space>
  )

  return (
    <Space direction="vertical" size={12} style={{ display: 'flex' }}>
      {/* WDSP 对接 IP / 地址配置区（自动识别并支持一键切换宿主 IP 或保存默认地址） */}
      <div
        style={{
          padding: '10px 12px',
          background: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: 6,
        }}
      >
        <Space direction="vertical" size={8} style={{ display: 'flex' }}>
          <Space wrap size={8} align="center" style={{ justifyContent: 'space-between', width: '100%' }}>
            <Space wrap size={6} align="center">
              <Typography.Text strong>WDSP 对接地址（IP）：</Typography.Text>
              <Input
                aria-label="管理面接入地址"
                value={serverUrl}
                onChange={(e) => {
                  userEditedUrlRef.current = true
                  setServerUrl(e.target.value)
                }}
                placeholder={`https://<WDSP服务器IP>:${httpsPort}`}
                style={{ width: 270 }}
                size="small"
              />
              {canManage ? (
                <Tooltip title="保存后，后续每次生成一键安装命令都将默认使用此 WDSP 地址">
                  <Button
                    size="small"
                    loading={saveEndpointMutation.isPending}
                    onClick={() => saveEndpointMutation.mutate(serverUrl)}
                  >
                    设为默认
                  </Button>
                </Tooltip>
              ) : null}
              {endpointSource && ENDPOINT_SOURCE_LABEL[endpointSource] ? (
                <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                  {ENDPOINT_SOURCE_LABEL[endpointSource]}
                </Tag>
              ) : null}
            </Space>
            <Space size={6}>
              <Switch
                size="small"
                checked={insecure}
                onChange={(checked) => {
                  userToggledInsecureRef.current = true
                  setInsecure(checked)
                }}
                aria-label="跳过自签证书校验"
              />
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                兼容自签 HTTPS 证书
              </Typography.Text>
            </Space>
          </Space>

          {candidateIPs.length > 0 ? (
            <Space wrap size={6} align="center">
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                检测到本机 IP（点击切换）：
              </Typography.Text>
              {candidateIPs.map((ip) => {
                const urlForIP = formatHttpsUrlForHost(ip, httpsPort)
                const selected = normalizedUrl === urlForIP
                return (
                  <Tag
                    key={ip}
                    color={selected ? 'processing' : 'default'}
                    style={{ cursor: 'pointer', marginInlineEnd: 0 }}
                    onClick={() => {
                      userEditedUrlRef.current = true
                      setServerUrl(urlForIP)
                      if (!userToggledInsecureRef.current) {
                        setInsecure(true)
                      }
                    }}
                  >
                    {ip}
                  </Tag>
                )
              })}
            </Space>
          ) : null}
        </Space>
      </div>

      {showLoopbackWarn ? (
        <Alert
          type="warning"
          showIcon
          message="当前地址为本机回环地址（localhost / 127.0.0.1），远程客户端无法连通"
          description="请点击上方检测到的 WDSP 局域网 IP，或直接输入客户端可访问的 WDSP 服务器 IP（如 192.168.10.20）。"
        />
      ) : null}

      {showPlainHttpWarn ? (
        <Alert
          type="error"
          showIcon
          message="非本机地址必须使用 HTTPS（Agent 禁止经明文 HTTP 传输凭据）"
          action={
            <Button
              size="small"
              type="primary"
              onClick={() => {
                try {
                  const u = new URL(serverUrl.trim())
                  userEditedUrlRef.current = true
                  setServerUrl(formatHttpsUrlForHost(u.hostname, httpsPort))
                } catch {
                  // ignore
                }
              }}
            >
              自动切换为 HTTPS (:{httpsPort})
            </Button>
          }
        />
      ) : null}

      <Tabs
        activeKey={modeTab}
        onChange={(k) => setModeTab(k as 'quick' | 'advanced')}
        items={[
          { key: 'quick', label: '一键部署命令（推荐）', children: quickInstallContent },
          { key: 'advanced', label: '按平台指定 / 离线包下载', children: advancedInstallContent },
        ]}
      />
    </Space>
  )
}
