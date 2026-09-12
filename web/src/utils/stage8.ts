/* ==================== 阶段8 / WDSP：API 动态防护 展示元数据 ==================== */

import type { TreeDataNode } from 'antd'

/** 目录树扁平项（/api-security/endpoints/directory-tree 返回项） */
export interface DirectoryFlatItem {
  directory_path: string
  endpoint_count: number
}

/**
 * 把目录扁平列表组装成 antd Tree 层级数据：
 * - 按 `/` 切段逐级建树，节点 key 用全路径（如 /test、/test/php）
 * - 计数写在叶子（精确匹配）节点标题「段名 (计数)」；中间节点若无独立计数仅显示段名
 * - 空目录 '' 与 '/' 归到根节点（key 为 '/'）
 */
export function buildDirectoryTree(flat: DirectoryFlatItem[]): TreeDataNode[] {
  interface MutableNode {
    key: string
    title: string
    children?: MutableNode[]
  }
  const byPath = new Map<string, MutableNode>()

  const ensure = (fullPath: string, segment: string): MutableNode => {
    let node = byPath.get(fullPath)
    if (!node) {
      node = { key: fullPath, title: segment }
      byPath.set(fullPath, node)
    }
    return node
  }

  for (const { directory_path: dir, endpoint_count: count } of flat) {
    const segments = dir.split('/').filter(Boolean)
    if (segments.length === 0) {
      const root = ensure('/', '/')
      root.title = `/ (${count})`
      continue
    }
    let fullPath = ''
    let parent: MutableNode | undefined
    segments.forEach((segment, index) => {
      fullPath += `/${segment}`
      const node = ensure(fullPath, segment)
      if (index === segments.length - 1) {
        node.title = `${segment} (${count})`
      }
      if (parent) {
        parent.children = parent.children ?? []
        if (!parent.children.includes(node)) {
          parent.children.push(node)
        }
      }
      parent = node
    })
  }

  // 顶层节点：根 '/' 或单段路径（如 /api）
  const roots: MutableNode[] = []
  for (const node of byPath.values()) {
    const depth = node.key === '/' ? 0 : node.key.split('/').filter(Boolean).length
    if (depth <= 1) {
      roots.push(node)
    }
  }

  // 按全路径排序，保证渲染顺序稳定
  const sortRecursive = (nodes: MutableNode[]): void => {
    nodes.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    for (const n of nodes) {
      if (n.children) sortRecursive(n.children)
    }
  }
  sortRecursive(roots)

  return roots
}

/** API 接口资产状态（与 server/internal/apiassets 状态枚举一致） */
export const API_ENDPOINT_STATUS_META: Record<string, { color: string; label: string }> = {
  DISCOVERED: { color: 'blue', label: '已发现' },
  CONFIRMED: { color: 'green', label: '已确认' },
  IGNORED: { color: 'default', label: '已忽略' },
  DEPRECATED: { color: 'orange', label: '已废弃' },
}

/** API 接口学习状态（与 server/internal/apiassets 学习状态枚举一致） */
export const API_LEARNING_STATUS_META: Record<string, { color: string; label: string }> = {
  NOT_STARTED: { color: 'default', label: '未开始' },
  LEARNING: { color: 'processing', label: '学习中' },
  PAUSED: { color: 'gold', label: '已暂停' },
  LEARNED: { color: 'green', label: '已完成' },
}

/** API 模型版本状态（与 server/internal/apimodels 状态枚举一致） */
export const API_MODEL_VERSION_STATUS_META: Record<string, { color: string; label: string }> = {
  CANDIDATE: { color: 'blue', label: '候选' },
  IN_REVIEW: { color: 'purple', label: '评审中' },
  FORMAL: { color: 'green', label: '正式' },
  REJECTED: { color: 'red', label: '已拒绝' },
  SUPERSEDED: { color: 'default', label: '已被取代' },
  ARCHIVED: { color: 'default', label: '已归档' },
}

/** 敏感字段数据类型 */
export const API_SENSITIVE_TYPE_META: Record<string, { color: string; label: string }> = {
  phone: { color: 'volcano', label: '手机号' },
  id_card: { color: 'magenta', label: '身份证号' },
  bank_card: { color: 'red', label: '银行卡号' },
  email: { color: 'orange', label: '邮箱' },
  credential: { color: 'magenta', label: '凭据口令' },
  token: { color: 'volcano', label: '令牌密钥' },
  name: { color: 'gold', label: '姓名' },
  address: { color: 'gold', label: '住址' },
}

/** 风险发现严重级别 */
export const API_FINDING_SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: 'magenta', label: '严重' },
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
  LOW: { color: 'blue', label: '低' },
  INFO: { color: 'default', label: '信息' },
  NONE: { color: 'default', label: '无' },
}

/** 风险发现类型 */
export const API_FINDING_TYPE_META: Record<string, { color: string; label: string }> = {
  SHADOW: { color: 'volcano', label: '影子 API' },
  ZOMBIE: { color: 'magenta', label: '僵尸 API' },
  DEPRECATED: { color: 'orange', label: '已下线 API' },
  BOLA: { color: 'red', label: '对象级越权' },
  BFLA: { color: 'red', label: '功能级越权' },
  SCHEMA_DEVIATION: { color: 'orange', label: '模型偏离' },
  SENSITIVE_LEAK: { color: 'magenta', label: '敏感数据泄露' },
  MASS_ASSIGNMENT: { color: 'red', label: '批量赋值' },
  BEHAVIOR_ANOMALY: { color: 'volcano', label: '行为异常' },
}

/**
 * 风险发现处置状态（七态状态机，与 server 端 risk.go / 迁移 000042 词表一致）；
 * 未命中时 StatusTag 原样展示后端返回值。
 */
export const API_FINDING_STATUS_META: Record<string, { color: string; label: string }> = {
  NEW: { color: 'red', label: '待确认' },
  CONFIRMED: { color: 'blue', label: '已确认' },
  IN_PROGRESS: { color: 'processing', label: '处理中' },
  RESOLVED: { color: 'green', label: '已解决' },
  FALSE_POSITIVE: { color: 'default', label: '误报' },
  IGNORED: { color: 'default', label: '已忽略' },
  ARCHIVED: { color: 'default', label: '已归档' },
}

/** Schema 违例类型 */
export const API_VIOLATION_TYPE_META: Record<string, { color: string; label: string }> = {
  undefined_field: { color: 'orange', label: '未定义字段' },
  type_mismatch: { color: 'red', label: '类型不匹配' },
  missing_field: { color: 'gold', label: '缺失字段' },
  constraint_violation: { color: 'volcano', label: '约束违例' },
}

/** 规范对比差异类型 */
export const API_SPEC_DIFF_TYPE_META: Record<string, { color: string; label: string }> = {
  MISSING_IN_RUNTIME: { color: 'volcano', label: '运行时缺失' },
  MISSING_IN_SPEC: { color: 'orange', label: '规范缺失' },
  CHANGED: { color: 'gold', label: '定义变更' },
}

/** API 防护模式 */
export const API_PROTECTION_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'gold', label: '观察' },
  PROTECT: { color: 'green', label: '防护' },
}

/** 三微模型成熟度阶段（与 server 端模型成熟度状态机一致）：配色按成熟度递进京蓝→金→绿 */
export const MODEL_MATURITY_STAGE_META: Record<string, { color: string; label: string }> = {
  LEARNING: { color: 'geekblue', label: '学习中' },
  CANDIDATE: { color: 'gold', label: '候选' },
  CONFIRMED: { color: 'green', label: '已确认' },
  ENFORCING: { color: '#237804', label: '已生效' },
}

/** 运行时处置动作（final_action / action_taken，与 server/internal/apiruntime 一致） */
export const API_ACTION_META: Record<string, { color: string; label: string }> = {
  ALLOW: { color: 'green', label: '放行' },
  BLOCK: { color: 'red', label: '阻断' },
  TEMP_BLOCK: { color: 'red', label: '临时封禁' },
  LOG: { color: 'default', label: '仅记录' },
  OBSERVE: { color: 'gold', label: '仅观察' },
}

/** 产品形态（apisecurity 策略接口 edition 字段；ENTERPRISE/STANDARD 为兼容值） */
export const API_POLICY_EDITION_META: Record<string, { color: string; label: string }> = {
  waf: { color: 'blue', label: 'WAF 版' },
  wdsp: { color: 'purple', label: 'Web 动态防护版' },
  api: { color: 'geekblue', label: 'API 安全版' },
  ENTERPRISE: { color: 'purple', label: '企业版' },
  STANDARD: { color: 'blue', label: '标准版' },
}

/** 认证类型（身份画像 auth_type，与 server/internal/apiassets 词表一致） */
export const API_AUTH_TYPE_META: Record<string, { color: string; label: string }> = {
  bearer_or_basic: { color: 'blue', label: '令牌/基本认证' },
  api_key: { color: 'geekblue', label: 'API Key' },
  cookie_session: { color: 'purple', label: 'Cookie 会话' },
}

/** 运行时检测器（details.detector，与 server 端 dsctx.DetectorMatch 一致） */
export const API_DETECTOR_META: Record<string, { color: string; label: string }> = {
  waf: { color: 'red', label: 'WAF 检测' },
  api_schema: { color: 'orange', label: '模型校验' },
  sensitive: { color: 'magenta', label: '敏感数据' },
  sensitive_data: { color: 'magenta', label: '敏感数据' },
  identity: { color: 'blue', label: '身份检测' },
  authentication: { color: 'geekblue', label: '认证检测' },
  lifecycle: { color: 'gold', label: '生命周期' },
  scanner: { color: 'volcano', label: '扫描器' },
  llm: { color: 'purple', label: 'LLM 检测' },
}

/** 风险主体类型（finding.subject_type，与 server/internal/apiruntime 一致） */
export const API_SUBJECT_TYPE_META: Record<string, { color: string; label: string }> = {
  IDENTITY: { color: 'blue', label: '认证身份' },
  IP: { color: 'geekblue', label: 'IP 主体' },
}

/** 参数语义类型（与 server/internal/apimodels 语义推断词表一致） */
export const API_SEMANTIC_TYPE_META: Record<string, { color: string; label: string }> = {
  id: { color: 'blue', label: 'ID' },
  uuid: { color: 'blue', label: 'UUID' },
  email: { color: 'orange', label: '邮箱' },
  phone: { color: 'volcano', label: '手机号' },
  token: { color: 'magenta', label: '令牌' },
  secret: { color: 'magenta', label: '口令' },
  money: { color: 'gold', label: '金额' },
}

/** 接口协议类型（api_endpoints.protocol_type，与网关分类器打标词表一致——任务书 §9 十三值
 *  另含历史值 REST/GRPC/WEBSOCKET；协议名为专有名词保持英文） */
export const API_PROTOCOL_META: Record<string, { color: string; label: string }> = {
  REST_JSON: { color: 'blue', label: 'REST/JSON' },
  REST_XML: { color: 'geekblue', label: 'REST/XML' },
  FORM_API: { color: 'gold', label: 'Form 表单' },
  SOAP: { color: 'volcano', label: 'SOAP' },
  GRAPHQL: { color: 'purple', label: 'GraphQL' },
  JSON_RPC: { color: 'magenta', label: 'JSON-RPC' },
  XML_RPC: { color: 'orange', label: 'XML-RPC' },
  WEBHOOK: { color: 'lime', label: 'Webhook' },
  FILE_UPLOAD: { color: 'green', label: '文件上传' },
  FILE_DOWNLOAD: { color: 'cyan', label: '文件下载' },
  WEBSOCKET_HANDSHAKE: { color: 'cyan', label: 'WebSocket 握手' },
  SERVER_SENT_EVENTS: { color: 'geekblue', label: 'SSE' },
  UNKNOWN_HTTP_API: { color: 'default', label: '未知 HTTP API' },
  // 历史值（存量数据与旧版网关仍可能上报）
  REST: { color: 'blue', label: 'REST' },
  GRPC: { color: 'geekblue', label: 'gRPC' },
  WEBSOCKET: { color: 'cyan', label: 'WebSocket' },
}

/** 参数方向（api_parameter_models.direction，与 server 端词表一致） */
export const API_PARAM_DIRECTION_META: Record<string, { color: string; label: string }> = {
  REQUEST: { color: 'blue', label: '请求' },
  RESPONSE: { color: 'purple', label: '响应' },
}

/** 参数位置（api_parameter_models.location，与 server 端词表一致） */
export const API_PARAM_LOCATION_META: Record<string, { color: string; label: string }> = {
  QUERY: { color: 'geekblue', label: '查询参数' },
  HEADER: { color: 'gold', label: '请求头' },
  BODY: { color: 'volcano', label: '请求体' },
  PATH: { color: 'green', label: '路径参数' },
  COOKIE: { color: 'cyan', label: 'Cookie' },
}

/** 参数基础类型（模型扁平 Schema 类型词表） */
export const API_BASE_TYPE_META: Record<string, { color: string; label: string }> = {
  string: { color: 'blue', label: '字符串' },
  number: { color: 'geekblue', label: '数字' },
  integer: { color: 'geekblue', label: '整数' },
  bool: { color: 'gold', label: '布尔' },
  boolean: { color: 'gold', label: '布尔' },
  array: { color: 'orange', label: '数组' },
  object: { color: 'purple', label: '对象' },
}

/** 常见国家/地区码（ISO 3166-1 alpha-2）；未覆盖的码原样展示 */
export const API_COUNTRY_META: Record<string, { color: string; label: string }> = {
  CN: { color: 'default', label: '中国' },
  HK: { color: 'default', label: '中国香港' },
  MO: { color: 'default', label: '中国澳门' },
  TW: { color: 'default', label: '中国台湾' },
  US: { color: 'default', label: '美国' },
  JP: { color: 'default', label: '日本' },
  KR: { color: 'default', label: '韩国' },
  SG: { color: 'default', label: '新加坡' },
  MY: { color: 'default', label: '马来西亚' },
  TH: { color: 'default', label: '泰国' },
  VN: { color: 'default', label: '越南' },
  ID: { color: 'default', label: '印度尼西亚' },
  IN: { color: 'default', label: '印度' },
  RU: { color: 'default', label: '俄罗斯' },
  DE: { color: 'default', label: '德国' },
  FR: { color: 'default', label: '法国' },
  GB: { color: 'default', label: '英国' },
  NL: { color: 'default', label: '荷兰' },
  CA: { color: 'default', label: '加拿大' },
  AU: { color: 'default', label: '澳大利亚' },
  BR: { color: 'default', label: '巴西' },
}
