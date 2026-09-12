/**
 * Bot 挑战策略（WDSP P1-02 B4）状态中文映射与表单字段错误路径映射。
 * 配色对齐 utils/stage3 PROTECTION_MODE_META：OFF 灰 / OBSERVE 蓝 / PROTECT 绿。
 * 词表与 server/internal/botpolicy（policy.go / validate.go / handler.go）一一对应。
 */

/** 策略模式：OFF 关闭 / OBSERVE 观察 / PROTECT 强制挑战 */
export const BOT_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制挑战' },
}

/** 状态摘要：草稿 vs 发布批次 vs 节点有效版本（server StatusSummary.state） */
export const BOT_STATE_META: Record<string, { color: string; label: string }> = {
  NOT_CONFIGURED: { color: 'default', label: '未配置' },
  DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
  PUBLISHED: { color: 'green', label: '已发布' },
}

/** 预检单项状态 */
export const BOT_CHECK_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  PASS: { color: 'success', label: '通过' },
  FAIL: { color: 'error', label: '未通过' },
  WARN: { color: 'warning', label: '警告' },
  SKIP: { color: 'default', label: '跳过' },
}

/** 预检检查项名称（handler.go Preflight 检查序） */
export const BOT_CHECK_NAME_LABELS: Record<string, string> = {
  structure: '结构校验',
  route_conflicts: '保留路由冲突',
  shared_state: '共享状态存储（Valkey）',
  signing_key: '签名密钥就绪',
  node_capability: '节点状态与能力',
}

/** 预检冲突类型（handler.go RouteConflict.type） */
export const BOT_CONFLICT_TYPE_LABELS: Record<string, string> = {
  l7_deny_rule: 'L7 拒绝规则',
  l7_allow_rule: 'L7 放行规则',
  reserved_path_asset: '既有应用路径',
  path_route: '路径转发',
  protected_address_scope: '保护地址范围',
}

/** 保留路由状态机（route_reservation.state） */
export const BOT_RESERVATION_META: Record<
  string,
  { color: string; label: string }
> = {
  ENABLED: { color: 'green', label: '已启用（保留路由已注册）' },
  RESERVED_TOMBSTONE: { color: 'orange', label: '墓碑保留（关闭后保留 404 墓碑）' },
  RELEASED: { color: 'default', label: '已解除（不抢占业务路径）' },
}

/** 节点同步结果（gatewayconfig NodeSync 词表；空=从未同步） */
export const BOT_NODE_SYNC_META: Record<
  string,
  { color: string; label: string }
> = {
  SUCCESS: { color: 'success', label: '同步成功' },
  FAILED: { color: 'error', label: '同步失败' },
  HASH_MISMATCH: { color: 'error', label: '哈希不一致' },
}

/** 信号组（B0 冻结；client_claim 为可伪造弱信号声明组） */
export const BOT_GROUP_LABELS: Record<string, string> = {
  request_behavior: '请求行为组',
  access_sequence: '访问序列组',
  client_claim: '客户端声明组（可伪造弱信号）',
}

/** 信号指标规格（B0 冻结白名单；group 由指标推导，不接受请求侧覆盖） */
export interface BotMetricSpec {
  group: 'request_behavior' | 'access_sequence' | 'client_claim'
  label: string
  description: string
  /** 参数键白名单（全部必填）；空数组 = 不接受参数 */
  params: { key: string; label: string; options?: string[]; placeholder?: string }[]
  /** 阈值语义：ratio_gte 占比≥触发 / ratio_lte 占比≤触发 / count_gte 计数≥触发 / none 命中即触发（threshold 恒 0） */
  threshold: 'ratio_gte' | 'ratio_lte' | 'count_gte' | 'none'
  defaultThreshold: number
}

export const BOT_METRIC_SPECS: Record<string, BotMetricSpec> = {
  status_family_ratio: {
    group: 'request_behavior',
    label: '状态码族占比',
    description: '窗口内某状态码族请求占比，≥ 阈值触发',
    params: [
      { key: 'family', label: '状态码族', options: ['2xx', '3xx', '4xx', '5xx'] },
    ],
    threshold: 'ratio_gte',
    defaultThreshold: 0.5,
  },
  method_ratio: {
    group: 'request_behavior',
    label: '方法占比',
    description: '窗口内某 HTTP 方法请求占比，≥ 阈值触发',
    params: [
      {
        key: 'method',
        label: 'HTTP 方法',
        options: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
      },
    ],
    threshold: 'ratio_gte',
    defaultThreshold: 0.5,
  },
  uri_concentration: {
    group: 'request_behavior',
    label: 'URI 集中度',
    description: '窗口内最热 URI 请求占比（无参数），≥ 阈值触发',
    params: [],
    threshold: 'ratio_gte',
    defaultThreshold: 0.8,
  },
  known_uri_ratio: {
    group: 'access_sequence',
    label: '已知 URI 占比',
    description: '窗口内已知 URI 请求占比，≤ 阈值触发（低比例 = 枚举探测）',
    params: [],
    threshold: 'ratio_lte',
    defaultThreshold: 0.2,
  },
  method_enumeration_size: {
    group: 'access_sequence',
    label: '方法枚举数',
    description: '窗口内 distinct HTTP 方法数（无参数），≥ 阈值触发',
    params: [],
    threshold: 'count_gte',
    defaultThreshold: 4,
  },
  ua_class_match: {
    group: 'client_claim',
    label: 'UA 分类命中',
    description: 'UA 分类命中即触发（可伪造弱信号，不能单独构成挑战依据）',
    params: [
      {
        key: 'class',
        label: 'UA 分类',
        options: ['BOT', 'APPLICATION', 'SERVICE', 'AGENT', 'UNKNOWN'],
      },
    ],
    threshold: 'none',
    defaultThreshold: 0,
  },
  tls_client_hint: {
    group: 'client_claim',
    label: 'TLS 轻量特征比对',
    description:
      'TLS 版本/密码套件轻量特征精确比对（非 JA3/JA4 指纹；可伪造弱信号）',
    params: [
      { key: 'field', label: '特征字段', options: ['version', 'cipher_suite'] },
      { key: 'equals', label: '比对值', placeholder: '如 TLS1.3' },
    ],
    threshold: 'none',
    defaultThreshold: 0,
  },
}

export const BOT_METRIC_OPTIONS = Object.entries(BOT_METRIC_SPECS).map(
  ([value, spec]) => ({
    value,
    label: `${spec.label}（${BOT_GROUP_LABELS[spec.group] ?? spec.group}）`,
  }),
)

/**
 * 后端字段级错误路径 → 表单字段路径
 * （selectors[0].path_exact → ['selectors',0,'path']；challenge.difficulty → ['difficulty'] 等）。
 */
export function mapBotFieldErrorPath(
  field: string,
): (string | number)[] | null {
  if (field === 'mode' || field === 'reason') return [field]
  if (field.startsWith('challenge.')) {
    const sub = field.slice('challenge.'.length)
    switch (sub) {
      case 'nonce_ttl_seconds':
      case 'clearance_ttl_seconds':
      case 'difficulty':
      case 'max_attempts':
      case 'key_ref':
        return [sub]
      default:
        return null
    }
  }
  if (field === 'route_reservation.state' || field === 'route_reservation.namespace') {
    return ['reservation_state']
  }
  if (field === 'signal_rules.min_independent_groups') {
    return ['min_independent_groups']
  }
  if (field === 'selectors' || field === 'signal_rules.rules') return null
  let m = /^selectors\[(\d+)\](?:\.(.+))?$/.exec(field)
  if (m) {
    const idx = Number(m[1])
    const sub = m[2]
    if (!sub || sub === 'path_exact' || sub === 'path_prefix') {
      return ['selectors', idx, 'path']
    }
    return null
  }
  m = /^signal_rules\.rules\[(\d+)\](?:\.(.+))?$/.exec(field)
  if (m) {
    const idx = Number(m[1])
    const sub = m[2]
    if (!sub || sub === 'group') return ['rules', idx, sub === 'group' ? 'metric' : 'id']
    switch (sub) {
      case 'id':
      case 'metric':
      case 'window_seconds':
      case 'weight':
      case 'threshold':
        return ['rules', idx, sub]
      default:
        break
    }
    if (sub.startsWith('params')) {
      // params / params.family / params.method / params.class / params.field / params.equals
      const key = sub.split('.')[1]
      switch (key) {
        case 'family':
          return ['rules', idx, 'family']
        case 'method':
          return ['rules', idx, 'method']
        case 'class':
          return ['rules', idx, 'class']
        case 'field':
          return ['rules', idx, 'tls_field']
        case 'equals':
          return ['rules', idx, 'tls_equals']
        default:
          return ['rules', idx, 'metric']
      }
    }
    return null
  }
  return null
}
