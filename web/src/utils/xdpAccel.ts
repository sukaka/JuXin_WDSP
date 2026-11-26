import { XDP_ACCEL_LIMITS, type XdpAccelStatus } from '../api/xdpAccel'

/**
 * eBPF/XDP 内核级高速丢包加速（WDSP Phase 9D-2）
 * 中文枚举标签、前后端 1:1 校验器、计数格式化与后端字段错误路径映射。
 */

export interface XdpLabelMeta {
  color: string
  label: string
}

/** XDP 期望挂载模式：auto / native / generic */
export const XDP_ATTACH_MODE_META: Record<string, XdpLabelMeta> = {
  auto: { color: 'blue', label: '自动优先 Native 回退 Generic' },
  native: { color: 'green', label: '驱动级 Native' },
  generic: { color: 'cyan', label: '通用内核 Generic' },
}

/** XDP 实际运行时模式：xdp_native / xdp_generic / fallback_userspace */
export const XDP_RUNTIME_MODE_META: Record<string, XdpLabelMeta> = {
  xdp_native: { color: 'green', label: 'XDP 驱动级 Native' },
  xdp_generic: { color: 'cyan', label: 'XDP 通用内核 Generic' },
  fallback_userspace: { color: 'orange', label: '用户态回退防护' },
}

/** xdpguard 守护进程探测状态：ok / degraded / unavailable / invalid_socket_path */
export const XDP_DAEMON_STATUS_META: Record<string, XdpLabelMeta> = {
  ok: { color: 'green', label: '运行正常' },
  degraded: { color: 'orange', label: '降级运行' },
  unavailable: { color: 'red', label: '守护进程未部署' },
  invalid_socket_path: { color: 'red', label: 'Socket 路径非法' },
}

export interface XdpHeadlineStatusMeta {
  badgeStatus: 'success' | 'warning' | 'error'
  color: string
  label: '内核态已挂载' | '用户态回退' | '守护进程未部署'
}

/** 将实时状态归约为顶部状态徽标（绝不伪装内核挂载状态） */
export function getXdpHeadlineStatus(
  status?: XdpAccelStatus | null,
): XdpHeadlineStatusMeta {
  if (!status || !status.available) {
    return {
      badgeStatus: 'error',
      color: 'red',
      label: '守护进程未部署',
    }
  }
  if (status.kernel_attached) {
    return {
      badgeStatus: 'success',
      color: 'green',
      label: '内核态已挂载',
    }
  }
  return {
    badgeStatus: 'warning',
    color: 'orange',
    label: '用户态回退',
  }
}

/** Linux 物理网卡名称正则（IFNAMSIZ-1，1..15 字符） */
export const XDP_INTERFACE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$/

/** 禁止挂载的虚拟/容器/隧道网口前缀（不区分大小写，与后端/守护进程 1:1 对齐） */
export const XDP_FORBIDDEN_INTERFACE_PREFIXES = Object.freeze([
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
] as const)

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\r\n\u0000-\u001f\u007f]/
const URI_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/

/**
 * 校验 xdpguard Unix Domain Socket 路径（与后端 1:1 对齐）：
 * 仅允许 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 前缀下的规范文件路径，
 * 拒绝 ..、//、尾随 /、空白、反斜杠、控制字符与任何网络 URI Scheme。
 */
export function validateXdpSocketPath(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) {
    return '请填写本地 Unix Socket 路径'
  }
  if (v.length > XDP_ACCEL_LIMITS.maxSocketPathLen) {
    return `Socket 路径长度不能超过 ${XDP_ACCEL_LIMITS.maxSocketPathLen} 字符`
  }
  if (CONTROL_CHAR_RE.test(v) || /\s/.test(v) || v.includes('\\')) {
    return 'Socket 路径不能包含空白、反斜杠或控制字符'
  }
  if (v.includes('://') || URI_SCHEME_RE.test(v)) {
    return '仅支持本地 Unix Socket 绝对路径，禁止 HTTP/TCP 等网络地址'
  }
  if (v.includes('..')) {
    return 'Socket 路径不能包含上级目录穿越片段（..）'
  }
  if (v.includes('//') || v.endsWith('/')) {
    return 'Socket 路径须为规范的文件路径，不能包含重复斜杠或以 / 结尾'
  }
  const matchedPrefix = XDP_ACCEL_LIMITS.allowedSocketPrefixes.find((prefix) =>
    v.startsWith(prefix),
  )
  if (!matchedPrefix || v.length <= matchedPrefix.length) {
    return 'Socket 路径必须以 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 开头并指定文件名'
  }
  const restSegments = v.slice(matchedPrefix.length).split('/')
  if (restSegments.some((seg) => !seg || seg === '.' || seg === '..')) {
    return 'Socket 路径包含非法目录片段'
  }
  return null
}

/**
 * 校验单个物理业务网卡名称（与后端及 xdpguard 1:1 对齐）：
 * 正则 ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$，不区分大小写拒绝 lo 及虚拟/容器前缀。
 */
export function validateXdpInterfaceName(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) {
    return '网卡名称不能为空'
  }
  if (!XDP_INTERFACE_NAME_RE.test(v)) {
    return `网卡名称「${v}」不合法：须以字母或数字开头，长度 1~15 字符，仅允许字母、数字、点、下划线和短横线`
  }
  const lower = v.toLowerCase()
  if (lower === 'lo') {
    return '禁止挂载环回接口（lo），避免影响本机通信'
  }
  const matchedPrefix = XDP_FORBIDDEN_INTERFACE_PREFIXES.find((prefix) =>
    lower.startsWith(prefix),
  )
  if (matchedPrefix) {
    return `禁止挂载虚拟或容器网口（${v}），仅允许选择物理业务网卡`
  }
  return null
}

/** 规范化并去重物理网卡列表 */
export function normalizeXdpInterfaces(items?: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of items ?? []) {
    const trimmed = raw.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    out.push(trimmed)
  }
  return out
}

/** 校验物理业务网卡列表（含启用态非空与上限 16 个校验） */
export function validateXdpInterfaces(
  items?: string[],
  enabled = false,
): string | null {
  const list = normalizeXdpInterfaces(items)
  if (enabled && list.length === 0) {
    return '启用 XDP 内核加速时至少需要指定 1 个物理业务网卡'
  }
  if (list.length > XDP_ACCEL_LIMITS.maxInterfaces) {
    return `物理业务网卡数量不能超过 ${XDP_ACCEL_LIMITS.maxInterfaces} 个`
  }
  for (const iface of list) {
    const err = validateXdpInterfaceName(iface)
    if (err) return err
  }
  return null
}

/** 格式化内核丢包/放行数据包计数（大数自动缩放 K/M/B，小数保留精确千分位） */
export function formatPacketCount(value?: number | null): string {
  if (
    value === null ||
    value === undefined ||
    !Number.isFinite(value) ||
    value < 0
  ) {
    return '-'
  }
  const whole = Math.floor(value)
  if (whole >= 1_000_000_000) {
    return `${(whole / 1_000_000_000).toFixed(2)}B`
  }
  if (whole >= 1_000_000) {
    return `${(whole / 1_000_000).toFixed(2)}M`
  }
  if (whole >= 10_000) {
    return `${(whole / 1_000).toFixed(1)}K`
  }
  return whole.toLocaleString('en-US')
}

/** 后端字段级校验错误路径 → Antd Form 字段路径 */
export function mapXdpAccelFieldErrorPath(
  field: string,
): (string | number)[] | null {
  const trimmed = field.trim()
  switch (trimmed) {
    case 'enabled':
    case 'socket_path':
    case 'interfaces':
    case 'attach_mode':
    case 'sync_interval_seconds':
    case 'reason':
      return [trimmed]
    default:
      break
  }
  if (/^interfaces\[\d+\]$/.test(trimmed)) {
    return ['interfaces']
  }
  return null
}
