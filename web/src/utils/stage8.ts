/* ==================== 阶段8 / WDSP：API 动态防护 展示元数据 ==================== */

import type { TreeDataNode } from 'antd'
import { CRS_RULE_NAMES_ZH, ruleMessageZh } from './crsRuleNames'

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
  ZOMBIE: { color: 'purple', label: '僵尸接口' },
}

/** API 暴露面（后端词表 INTERNAL/PARTNER/PUBLIC/UNKNOWN 不变，仅界面中文化） */
export const API_EXPOSURE_META: Record<string, { color: string; label: string }> = {
  INTERNAL: { color: 'blue', label: '内网' },
  PARTNER: { color: 'purple', label: '合作方' },
  PUBLIC: { color: 'volcano', label: '外网' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 分类来源（后端词表 AUTO/MANUAL/CONFIG/TRAFFIC_OBSERVED 不变，仅界面中文化） */
export const API_CLASSIFICATION_SOURCE_META: Record<string, { color: string; label: string }> = {
  AUTO: { color: 'cyan', label: '自动识别' },
  MANUAL: { color: 'purple', label: '人工标记' },
  CONFIG: { color: 'geekblue', label: '配置判定' },
  TRAFFIC_OBSERVED: { color: 'blue', label: '流量观测' },
}

/** 暴露面中文展示（大小写/空白归一，未知值原样返回，不伪造映射） */
export function apiExposureLabel(value: string): string {
  const key = value.trim().toUpperCase()
  return API_EXPOSURE_META[key]?.label ?? value
}

/** 分类来源中文展示（大小写/空白归一，未知值原样返回） */
export function apiClassificationSourceLabel(value: string): string {
  const key = value.trim().toUpperCase()
  return API_CLASSIFICATION_SOURCE_META[key]?.label ?? value
}

/** 暴露面评估置信度（api_exposure_assessments.confidence 词表，与 server/internal/apiexposure 一致） */
export const EXPOSURE_CONFIDENCE_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'green', label: '高' },
}

/** 暴露面评估置信度中文展示（大小写/空白归一，未知值原样返回，不伪造映射） */
export function exposureConfidenceLabel(value: string): string {
  const key = value.trim().toUpperCase()
  return EXPOSURE_CONFIDENCE_META[key]?.label ?? value
}

/** 资产价值评分理由展示：把英文词表键转换为中文，保留冒号后的中文事实说明 */
export function apiAssetValueReasonLabel(reason: string): string {
  return reason
    .replace(/^exposure=([A-Za-z_]+)/, (_, raw: string) => `暴露面=${apiExposureLabel(raw)}`)
    .replace(/^exposure(?=\s)/, '暴露面')
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
  password: { color: 'red', label: '密码口令' },
  token: { color: 'volcano', label: '令牌密钥' },
  jwt: { color: 'purple', label: 'JWT 令牌' },
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

/** 风险/弱点/扫描发现严重级别筛选下拉选项（排除 NONE；后端仅接受 CRITICAL/HIGH/MEDIUM/LOW/INFO） */
export const API_FINDING_SEVERITY_FILTER_OPTIONS = Object.entries(API_FINDING_SEVERITY_META)
  .filter(([value]) => value !== 'NONE')
  .map(([value, meta]) => ({ value, label: meta.label }))

/** 风险发现类型（覆盖网关全量检测器、API 准入、授权决策、流程防护、文件安全、LLM/MCP、gRPC/GraphQL 与 WAF 规则） */
export const API_FINDING_TYPE_META: Record<string, { color: string; label: string }> = {
  // 生命周期与 API 准入
  SHADOW: { color: 'volcano', label: '影子 API' },
  ZOMBIE: { color: 'magenta', label: '僵尸 API' },
  DEPRECATED: { color: 'orange', label: '已下线 API' },
  ADMISSION_UNCONFIRMED: { color: 'volcano', label: '未确认 API 准入命中' },
  ADMISSION_UNKNOWN_ENDPOINT: { color: 'volcano', label: '未发现 API 准入命中' },
  ADMISSION_UNCONFIRMED_ENDPOINT: { color: 'volcano', label: '未确认 API 准入命中' },
  // 越权与授权（BOLA / BFLA / 字段权限 / 多租户）
  BOLA: { color: 'red', label: '对象级越权' },
  BFLA: { color: 'red', label: '功能级越权' },
  BOLA_UNAUTHENTICATED_OBJECT_ACCESS: { color: 'red', label: '未认证对象越权访问' },
  MASS_ASSIGNMENT: { color: 'red', label: '批量赋值' },
  AUTHZ_BFLA_ANONYMOUS: { color: 'red', label: '匿名功能级越权' },
  AUTHZ_BFLA_ROLE_MISMATCH: { color: 'red', label: '角色功能级越权' },
  AUTHZ_FORBIDDEN_FIELD: { color: 'red', label: '请求含禁止字段（批量赋值）' },
  AUTHZ_SERVER_GENERATED_WRITE: { color: 'red', label: '篡改服务端生成字段' },
  AUTHZ_READONLY_WRITE: { color: 'red', label: '写入只读或管理员字段' },
  AUTHZ_RESPONSE_FORBIDDEN_FIELD: { color: 'volcano', label: '响应含禁止字段（过度暴露）' },
  AUTHZ_RESPONSE_SENSITIVE_FIELD: { color: 'magenta', label: '响应含已确认敏感字段' },
  AUTHZ_WATERMARK_REGRESSION: { color: 'red', label: '授权快照水位回退' },
  AUTHZ_BOLA_001: { color: 'red', label: '对象级越权（BOLA）' },
  AUTHZ_BOLA_002: { color: 'orange', label: '对象授权证据不足' },
  AUTHZ_BFLA_001: { color: 'red', label: '功能级越权（BFLA）' },
  AUTHZ_TENANT_001: { color: 'red', label: '跨租户越权访问' },
  AUTHZ_TENANT_002: { color: 'orange', label: '租户授权上下文异常' },
  AUTHZ_IDENTITY_001: { color: 'orange', label: '缺少可信身份（授权未知）' },
  AUTHZ_ROLE_001: { color: 'orange', label: '缺少可信角色（授权未知）' },
  AUTHZ_POLICY_001: { color: 'orange', label: '授权策略基线冲突' },
  AUTHZ_POLICY_002: { color: 'orange', label: '授权快照已过期' },
  AUTHZ_CLOCK_001: { color: 'orange', label: '授权节点时钟漂移' },
  AUTHZ_LEASE_001: { color: 'volcano', label: '授权租约过期（严格拒绝）' },
  AUTHZ_LEASE_002: { color: 'orange', label: '授权租约过期（降级观察）' },
  AUTHZ_CONFLICT_001: { color: 'orange', label: '对象授权关系冲突' },
  AUTHZ_RELATION_001: { color: 'orange', label: '缺少对象归属关系' },
  AUTHZ_OBJECT_001: { color: 'orange', label: '对象标识缺失或非法' },
  AUTHZ_OBJECT_002: { color: 'orange', label: '对象标识不唯一' },
  AUTHZ_OBJECT_003: { color: 'orange', label: '对象签名密钥缺失' },
  // 请求/响应模型与参数约束
  SCHEMA_DEVIATION: { color: 'orange', label: '模型偏离' },
  SCHEMA_TYPE_MISMATCH: { color: 'red', label: '参数类型不匹配' },
  SCHEMA_EXTRA_FIELD: { color: 'orange', label: '未定义多余字段' },
  SCHEMA_UNDEFINED_FIELD: { color: 'orange', label: '未定义请求字段' },
  SCHEMA_MISSING_FIELD: { color: 'gold', label: '必填字段缺失' },
  SCHEMA_PARAM_REQUIRED: { color: 'gold', label: '必填参数缺失' },
  SCHEMA_PARAM_TYPE: { color: 'red', label: '参数类型不匹配' },
  SCHEMA_PARAM_LENGTH: { color: 'volcano', label: '参数长度超限' },
  SCHEMA_PARAM_RANGE: { color: 'volcano', label: '参数数值越界' },
  SCHEMA_PARAM_ENUM: { color: 'volcano', label: '参数不在枚举范围' },
  SCHEMA_PARAM_REGEX: { color: 'volcano', label: '参数格式不匹配' },
  SCHEMA_PARAM_NULLABLE: { color: 'orange', label: '参数不允许为空' },
  SCHEMA_PARAM_EMPTY: { color: 'orange', label: '参数不允许空值' },
  SCHEMA_PARAM_CONSTRAINT_INVALID: { color: 'orange', label: '参数约束不可执行' },
  SCHEMA_RELATION_REQUIRES: { color: 'purple', label: '关联必填参数缺失' },
  SCHEMA_RELATION_MUTEX: { color: 'purple', label: '互斥参数同时出现' },
  SCHEMA_RELATION_COOCCURS: { color: 'purple', label: '共现参数关系偏离' },
  SCHEMA_RELATION_EQUALS: { color: 'purple', label: '参数相等约束违例' },
  SCHEMA_RELATION_NOT_EQUALS: { color: 'purple', label: '参数不等约束违例' },
  SCHEMA_RELATION_GREATER_THAN: { color: 'purple', label: '参数大于约束违例' },
  SCHEMA_RELATION_LESS_THAN: { color: 'purple', label: '参数小于约束违例' },
  SCHEMA_RELATION_TIME_BEFORE: { color: 'purple', label: '时间先后约束违例（早于）' },
  SCHEMA_RELATION_TIME_AFTER: { color: 'purple', label: '时间先后约束违例（晚于）' },
  SCHEMA_RELATION_COUNT_MATCHES: { color: 'purple', label: '数组数量约束违例' },
  SCHEMA_RELATION_SUM_MATCHES: { color: 'purple', label: '参数求和约束违例' },
  RESPONSE_SCHEMA_NEW_STATUS: { color: 'orange', label: '响应出现未学习状态码' },
  RESPONSE_SCHEMA_NEW_FIELD: { color: 'orange', label: '响应出现未学习字段' },
  RESPONSE_SCHEMA_MISSING_FIELD: { color: 'gold', label: '响应缺少基线字段' },
  // 敏感数据、响应与服务端泄露
  SENSITIVE_LEAK: { color: 'magenta', label: '敏感数据泄露' },
  SENSITIVE_IN_QUERY: { color: 'red', label: 'URL 查询含敏感字段' },
  SENSITIVE_VALUE_IN_QUERY: { color: 'red', label: 'URL 查询含敏感数据' },
  SENSITIVE_FIELD: { color: 'magenta', label: '请求含敏感字段名' },
  SENSITIVE_VALUE: { color: 'magenta', label: '请求含敏感数据值' },
  SENSITIVE_RESPONSE_FIELD: { color: 'magenta', label: '响应含敏感字段名' },
  SENSITIVE_RESPONSE_VALUE: { color: 'magenta', label: '响应包含敏感数据' },
  SENSITIVE_RESPONSE_BODY_UNCHECKED: { color: 'orange', label: '响应敏感检测未完成' },
  SERVER_VERSION_DISCLOSURE: { color: 'orange', label: '服务端版本信息泄露' },
  SERVER_ERROR_DISCLOSURE: { color: 'volcano', label: '服务端错误详情泄露' },
  RESPONSE_MASK_FAILED: { color: 'red', label: '响应脱敏失败' },
  RESPONSE_MASK_SKIPPED: { color: 'orange', label: '响应脱敏已跳过' },
  RESPONSE_MASK_APPLIED: { color: 'cyan', label: '已执行响应脱敏' },
  RESPONSE_MASK_PLAN: { color: 'cyan', label: '已生成响应脱敏计划' },
  RESPONSE_FAIL_CLOSED: { color: 'red', label: '响应安全抑制（故障关闭）' },
  RESPONSE_ERROR_SIGNATURE: { color: 'orange', label: '响应异常错误特征' },
  REQUEST_BODY_PRESERVE_SKIPPED: { color: 'volcano', label: '请求体超限跳过检测' },
  REQUEST_BODY_TOO_LARGE_FAIL_CLOSED: { color: 'red', label: '请求体超限触发保护' },
  // 行为、频率、配额与业务流程
  BEHAVIOR_ANOMALY: { color: 'volcano', label: '行为异常' },
  BEHAVIOR_RATE_SPIKE: { color: 'volcano', label: '访问速率突增' },
  SHARED_DEVICE_ACCOUNTS: { color: 'orange', label: '同设备多账号' },
  RATELIMIT_API_WRITE_RATE: { color: 'volcano', label: 'API 写入频率超限' },
  RATELIMIT_CREDENTIAL_RATE: { color: 'volcano', label: '单凭据请求速率超限' },
  RATELIMIT_TENANT_RATE: { color: 'volcano', label: '租户请求速率超限' },
  RATELIMIT_ACTION_RATE: { color: 'volcano', label: '操作请求速率超限' },
  RATELIMIT_GROUP_RATE: { color: 'volcano', label: '接口分组速率超限' },
  RATELIMIT_API_HOURLY_QUOTA: { color: 'volcano', label: 'API 每小时配额超限' },
  RATELIMIT_API_DAILY_QUOTA: { color: 'volcano', label: 'API 每日配额超限' },
  RATELIMIT_OBJECT_RATE: { color: 'volcano', label: '单对象访问频率超限' },
  RATELIMIT_PAGE_SIZE_EXCEEDED: { color: 'orange', label: '分页拉取大小超限' },
  RATELIMIT_BATCH_SIZE_EXCEEDED: { color: 'orange', label: '批量请求数量超限' },
  FLOW_ANONYMOUS_LATE_ENTRY: { color: 'red', label: '匿名进入非首步流程' },
  FLOW_STEP_SKIP: { color: 'red', label: '业务流程跳步执行' },
  FLOW_OUT_OF_ORDER: { color: 'volcano', label: '业务流程顺序异常' },
  FLOW_DUPLICATE_SUBMIT: { color: 'orange', label: '业务请求短时重复提交' },
  FLOW_ILLEGAL_STATE_TRANSITION: { color: 'red', label: '对象状态非法流转' },
  FLOW_RAPID_BATCH: { color: 'volcano', label: '业务流程高频批量调用' },
  FLOW_POST_CANCEL_OPERATION: { color: 'red', label: '取消后继续操作流程' },
  FLOWGUARD_VIOLATION: { color: 'red', label: '强流程状态违例' },
  FLOWGUARD_UNKNOWN: { color: 'orange', label: '强流程评估未知' },
  FLOWGUARD_STEP_CONFIRMED: { color: 'green', label: '强流程步骤已确认' },
  FLOWGUARD_COMMIT_REJECTED: { color: 'volcano', label: '强流程令牌过期拒提交' },
  FLOWGUARD_STEP_ACCEPTED_202: { color: 'blue', label: '强流程异步受理待完成' },
  FLOWGUARD_STEP_UNKNOWN: { color: 'orange', label: '强流程结果未知待对账' },
  // 认证、凭据与机器身份
  WEAK_AUTH: { color: 'orange', label: '弱认证风险' },
  AUTH_UNAUTHENTICATED_API: { color: 'orange', label: '未携带认证凭据' },
  AUTH_WEAK_CREDENTIAL: { color: 'orange', label: '弱认证凭据' },
  AUTH_MALFORMED_CREDENTIAL: { color: 'orange', label: '认证头格式异常' },
  AUTH_JWT_MALFORMED_HEADER: { color: 'volcano', label: 'JWT 头部格式异常' },
  AUTH_JWT_ALG_NONE: { color: 'red', label: 'JWT 空算法（alg=none）' },
  AUTH_JWT_KID_TRAVERSAL: { color: 'red', label: 'JWT kid 路径遍历风险' },
  AUTH_JWT_EMPTY_SIGNATURE: { color: 'red', label: 'JWT 缺少签名段' },
  AUTH_JWT_EXPIRED: { color: 'orange', label: 'JWT 令牌已过期' },
  AUTH_CREDENTIAL_IN_URL: { color: 'red', label: 'URL 明文传递凭据' },
  CREDENTIAL_URL_PASSWORD: { color: 'red', label: 'URL 明文传递密码' },
  AUTH_CREDENTIAL_CROSS_APP: { color: 'volcano', label: '凭据跨应用复用' },
  AUTH_CREDENTIAL_DEVICE_SPREAD: { color: 'orange', label: '凭据多设备扩散' },
  AUTH_CREDENTIAL_REVOKED: { color: 'red', label: '已吊销凭据复用' },
  AUTH_CREDENTIAL_IP_SPREAD: { color: 'volcano', label: '凭据多来源 IP 使用' },
  AUTH_CREDENTIAL_CONCURRENCY: { color: 'volcano', label: '凭据异常并发使用' },
  AUTH_CREDENTIAL_UNUSUAL_HOUR: { color: 'orange', label: '凭据非常规时段活跃' },
  AUTH_CREDENTIAL_UA_CHANGE: { color: 'orange', label: '凭据客户端类型变更' },
  AUTH_ENV_ANOMALY_STACK: { color: 'red', label: '凭据多项环境异常叠加' },
  CREDENTIAL_COOKIE_SENSITIVE: { color: 'volcano', label: 'Cookie 携带敏感凭据' },
  IDENTITY_TOKEN_PRESENT: { color: 'blue', label: '携带认证请求头' },
  IDENTITY_COOKIE_PRESENT: { color: 'blue', label: '携带 Cookie 会话头' },
  IDENTITY_HMAC_SIGNATURE_PRESENT: { color: 'blue', label: '携带 HMAC 签名凭据' },
  MACHINEID_FAILED: { color: 'red', label: '机器身份验证失败' },
  MACHINEID_DEPENDENCY_UNAVAILABLE: { color: 'orange', label: '机器身份校验依赖不可用' },
  MACHINEID_BODY_UNAVAILABLE: { color: 'orange', label: '机器身份内容摘要不可用' },
  ID_COVERAGE_V1: { color: 'default', label: '机器身份校验覆盖观测' },
  // 文件安全
  FILE_DOUBLE_EXTENSION: { color: 'red', label: '文件双扩展名风险' },
  FILE_COMPLIANCE_VIOLATION: { color: 'volcano', label: '文件合规违规' },
  FILE_SENSITIVE_CONTENT: { color: 'magenta', label: '文件含敏感内容' },
  FILE_SENSITIVE_CONTENT_NOT_INSPECTED: { color: 'orange', label: '文件敏感检测未完成' },
  FILE_CONTENT_TYPE_MISMATCH: { color: 'volcano', label: '文件签名与声明类型不符' },
  FILE_CONTENT_UNRECOGNIZED: { color: 'orange', label: '文件签名无法识别' },
  FILE_CONTENT_NOT_INSPECTED: { color: 'default', label: '文件内容签名未检测' },
  FILE_BULK_DOWNLOAD: { color: 'red', label: '同身份文件批量下载' },
  FILE_DOWNLOAD_BLOCK_UNAVAILABLE: { color: 'orange', label: '文件下载阻断未生效' },
  FILE_WATERMARK_APPLIED: { color: 'cyan', label: '已添加文件水印' },
  FILE_SIGNATURE_EMBEDDED: { color: 'cyan', label: '已嵌入文件签名' },
  // 扫描器、WebShell、镜像、资源与报文解析
  SCANNER_PRESENCE_ONLY: { color: 'cyan', label: '主动扫描流量标记' },
  SCANNER_SIGNATURE_VALID: { color: 'cyan', label: '已验签主动扫描流量' },
  SCANNER_SIGNATURE_FORGED: { color: 'red', label: '伪造扫描器签名' },
  WEBSHELL_C2_SUSPECTED: { color: 'red', label: '疑似 WebShell/远控通信' },
  RESOURCE_OBJECT_ENUMERATION: { color: 'volcano', label: '对象资源枚举探测' },
  MIRROR_CAPTURE: { color: 'default', label: '镜像流量旁路观测' },
  WAF_DOWNSTREAM_INTERCEPT: { color: 'red', label: 'WAF 下游阻断' },
  PARSER_DUPLICATE_JSON_KEY: { color: 'orange', label: 'JSON 重复键解析异常' },
  PARSER_DUPLICATE_QUERY_PARAM: { color: 'orange', label: '查询参数重复解析异常' },
  PARSER_DUPLICATE_HEADER: { color: 'orange', label: '请求头重复解析异常' },
  PARSER_DUPLICATE_FORM_PARAM: { color: 'orange', label: '表单参数重复解析异常' },
  PARSER_FIELD_COUNT_CAPPED: { color: 'orange', label: '请求字段数量超解析上限' },
  // gRPC 与 GraphQL
  GRPC_OBSERVED: { color: 'default', label: 'gRPC 报文帧观测' },
  GRPC_MALFORMED_FRAME: { color: 'volcano', label: 'gRPC 异常报文帧' },
  GRPC_UNEXPECTED_COMPRESSION: { color: 'volcano', label: 'gRPC 未允许压缩帧' },
  GRPC_DECODE_ERROR: { color: 'orange', label: 'gRPC 消息解码失败' },
  GRPC_SENSITIVE_FIELD: { color: 'magenta', label: 'gRPC 消息含敏感字段' },
  GRPC_COVERAGE_V1: { color: 'default', label: 'gRPC 一元调用覆盖观测' },
  GRPC_NO_UNARY_MESSAGE: { color: 'default', label: 'gRPC 请求无消息帧' },
  GRPC_READ_ERROR: { color: 'orange', label: 'gRPC 报文帧读取失败' },
  GRPC_STREAMING_OBSERVED: { color: 'orange', label: 'gRPC 流式调用检测降级' },
  GRPC_UNSUPPORTED_ENCODING: { color: 'volcano', label: 'gRPC 不支持的压缩编码' },
  GRPC_COMPRESSION_BUDGET_EXCEEDED: { color: 'red', label: 'gRPC 解压预算超限' },
  GRPC_FIELD_VIOLATION: { color: 'red', label: 'gRPC 消息结构违规' },
  GRPC_ENUM_OUT_OF_RANGE: { color: 'red', label: 'gRPC 枚举值越界' },
  GRPC_FIELD_VIOLATION_SUMMARY: { color: 'orange', label: 'gRPC 结构违例已截断' },
  GRPCGUARD_MALFORMED_FRAME: { color: 'red', label: 'gRPC 报文帧畸形' },
  GRPCGUARD_BUDGET_EXCEEDED: { color: 'red', label: 'gRPC 报文帧预算超限' },
  GQL_ADMISSION: { color: 'volcano', label: 'GraphQL 准入拒绝' },
  GQL_COST_V1: { color: 'red', label: 'GraphQL 单请求复杂度超限' },
  GQL_WINDOW: { color: 'red', label: 'GraphQL 时间窗预算超限' },
  GQL_TRUSTED_DOC: { color: 'green', label: 'GraphQL 可信文档直通' },
  // LLM 与 MCP
  LLM_PROMPT_INJECTION: { color: 'red', label: 'LLM 提示词注入' },
  LLM_UNAUTHORIZED_MODEL: { color: 'orange', label: 'LLM 未授权模型调用' },
  LLM_INPUT_CONTENT_VIOLATION: { color: 'volcano', label: 'LLM 输入内容违规' },
  LLM_TOPIC_VIOLATION: { color: 'volcano', label: 'LLM 提示词命中禁止主题' },
  LLM_PII_DETECTED: { color: 'magenta', label: 'LLM 提示词含敏感信息' },
  LLM_PROMPT_SIZE_EXCEEDED: { color: 'orange', label: 'LLM 提示词长度超限' },
  LLM_OUTPUT_TOKEN_BUDGET_EXCEEDED: { color: 'volcano', label: 'LLM 输出 Token 超预算' },
  LLM_OUTPUT_CONTENT_VIOLATION: { color: 'volcano', label: 'LLM 输出内容违规' },
  LLM_OUTPUT_PII_DETECTED: { color: 'magenta', label: 'LLM 输出含敏感信息' },
  LLM_OUTPUT_NOT_INSPECTED: { color: 'default', label: 'LLM 输出未完整检测' },
  LLM_OUTPUT_PARTIALLY_INSPECTED: { color: 'default', label: 'LLM 输出部分检测' },
  LLM_MCP_UNKNOWN_METHOD: { color: 'cyan', label: 'MCP 未知扩展方法' },
  LLM_MCP_SENSITIVE_ARG: { color: 'magenta', label: 'MCP 参数含敏感信息' },
  MCP_SUBJECT_UNTRUSTED: { color: 'red', label: 'MCP 调用主体未通过可信认证' },
  MCP_TOOL_NOT_IN_CATALOG: { color: 'red', label: 'MCP 调用未审核目录外工具' },
  MCP_CALLER_NOT_AUTHORIZED: { color: 'red', label: 'MCP 调用方无工具授权' },
  MCP_JSON_DUPLICATE_KEY: { color: 'red', label: 'MCP 参数含 JSON 重复键' },
  MCP_ARG_SCHEMA_VIOLATION: { color: 'red', label: 'MCP 工具参数 Schema 违规' },
  MCP_ARG_SCOPE_VIOLATION: { color: 'red', label: 'MCP 工具参数越出允许范围' },
  MCP_CALL_BUDGET_EXCEEDED: { color: 'volcano', label: 'MCP 工具调用频率超限' },
  MCP_HIGH_RISK_DENIED: { color: 'red', label: 'MCP 高风险工具默认拒绝' },
  MCP_UNSUPPORTED_SHAPE: { color: 'orange', label: 'MCP 不支持的批处理格式' },
  MCP_BUDGET_EXCEEDED: { color: 'volcano', label: 'MCP 消息结构超预算' },
  MCP_RESULT_SCHEMA_VIOLATION: { color: 'red', label: 'MCP 工具返回 Schema 违规' },
  MCP_RESULT_SENSITIVE_VALUE: { color: 'magenta', label: 'MCP 工具返回含敏感数据' },
  MCP_RESULT_BLOCKED_MIDSTREAM: { color: 'red', label: 'MCP 流式返回中途阻断' },
  MCP_COVERAGE_V1: { color: 'default', label: 'MCP 工具调用覆盖观测' },
  MCPGUARD_DEPENDENCY_UNAVAILABLE: { color: 'orange', label: 'MCP 防护依赖不可用' },
}

const FINDING_TYPE_PREFIX_FALLBACKS: { prefix: string; color: string; label: string }[] = [
  { prefix: 'RESPONSE_SCHEMA_', color: 'orange', label: '响应模型偏离' },
  { prefix: 'RESPONSE_', color: 'orange', label: '响应安全异常' },
  { prefix: 'REQUEST_', color: 'volcano', label: '请求安全异常' },
  { prefix: 'SCHEMA_', color: 'orange', label: '请求模型偏离' },
  { prefix: 'PARSER_', color: 'orange', label: '报文解析异常' },
  { prefix: 'RATELIMIT_', color: 'volcano', label: '频率限速触发' },
  { prefix: 'SENSITIVE_', color: 'magenta', label: '敏感数据风险' },
  { prefix: 'SERVER_', color: 'orange', label: '服务端信息泄露' },
  { prefix: 'ADMISSION_', color: 'volcano', label: 'API 准入告警' },
  { prefix: 'LIFECYCLE_', color: 'orange', label: 'API 生命周期风险' },
  { prefix: 'AUTHZ_', color: 'red', label: '授权安全异常' },
  { prefix: 'AUTH_', color: 'red', label: '认证凭据异常' },
  { prefix: 'CREDENTIAL_', color: 'red', label: '凭据安全风险' },
  { prefix: 'JWT_', color: 'red', label: 'JWT 认证异常' },
  { prefix: 'MACHINEID_', color: 'geekblue', label: '机器身份异常' },
  { prefix: 'IDENTITY_', color: 'blue', label: '身份信号异常' },
  { prefix: 'BOLA_', color: 'red', label: '对象级越权风险' },
  { prefix: 'BFLA_', color: 'red', label: '功能级越权风险' },
  { prefix: 'FLOWGUARD_', color: 'purple', label: '强流程防护异常' },
  { prefix: 'FLOW_', color: 'purple', label: '业务流程异常' },
  { prefix: 'LLM_', color: 'purple', label: 'LLM 安全告警' },
  { prefix: 'MCPGUARD_', color: 'cyan', label: 'MCP 安全防护告警' },
  { prefix: 'MCP_', color: 'cyan', label: 'MCP 工具安全告警' },
  { prefix: 'FILE_', color: 'volcano', label: '文件安全告警' },
  { prefix: 'GRPCGUARD_', color: 'geekblue', label: 'gRPC 安全防护告警' },
  { prefix: 'GRPC_', color: 'geekblue', label: 'gRPC 协议异常' },
  { prefix: 'GRAPHQL_', color: 'purple', label: 'GraphQL 安全告警' },
  { prefix: 'GQL_', color: 'purple', label: 'GraphQL 安全告警' },
  { prefix: 'RESOURCE_', color: 'volcano', label: '资源访问异常' },
  { prefix: 'SCANNER_', color: 'cyan', label: '扫描器异常' },
  { prefix: 'BEHAVIOR_', color: 'volcano', label: '异常行为检测' },
  { prefix: 'WEBSHELL_', color: 'red', label: 'WebShell 通信风险' },
  { prefix: 'MIRROR_', color: 'default', label: '镜像旁路观测' },
  { prefix: 'WAF_', color: 'red', label: 'WAF 安全检测' },
]

/** WAF 规则 ID 号段 → 中文风险分类（覆盖 Coraza 核心、OWASP CRS 4.x、扩展规则包与九章内置规则） */
const WAF_RULE_ID_CATEGORY_RANGES: Array<{ min: number; max: number; color: string; label: string }> = [
  { min: 200000, max: 200999, color: 'orange', label: 'WAF 报文解析异常' },
  { min: 911000, max: 911999, color: 'orange', label: 'WAF HTTP 方法限制' },
  { min: 913000, max: 913999, color: 'cyan', label: 'WAF 扫描器检测' },
  { min: 920000, max: 920999, color: 'orange', label: 'WAF 协议合规' },
  { min: 921000, max: 921999, color: 'red', label: 'WAF 协议攻击' },
  { min: 922000, max: 922999, color: 'volcano', label: 'WAF Multipart 攻击' },
  { min: 930000, max: 930999, color: 'red', label: 'WAF 本地文件包含' },
  { min: 931000, max: 931999, color: 'red', label: 'WAF 远程文件包含' },
  { min: 932000, max: 932999, color: 'red', label: 'WAF 命令执行' },
  { min: 933000, max: 933999, color: 'red', label: 'WAF PHP 注入' },
  { min: 934000, max: 934999, color: 'red', label: 'WAF 通用应用攻击' },
  { min: 941000, max: 941999, color: 'red', label: 'WAF XSS 攻击' },
  { min: 942000, max: 942999, color: 'red', label: 'WAF SQL 注入' },
  { min: 943000, max: 943999, color: 'volcano', label: 'WAF 会话固定' },
  { min: 944000, max: 944999, color: 'red', label: 'WAF Java 攻击' },
  { min: 949000, max: 949999, color: 'red', label: 'WAF 入站异常阻断' },
  { min: 950000, max: 954999, color: 'magenta', label: 'WAF 数据泄露' },
  { min: 955000, max: 955999, color: 'red', label: 'WAF WebShell 检测' },
  { min: 956000, max: 956999, color: 'magenta', label: 'WAF 数据泄露' },
  { min: 959000, max: 959999, color: 'red', label: 'WAF 出站异常阻断' },
  { min: 980000, max: 980999, color: 'orange', label: 'WAF 关联评分' },
  { min: 1000000, max: 1000099, color: 'red', label: 'WAF 高危 CVE 防护' },
  { min: 1000100, max: 1000199, color: 'red', label: 'WAF WebShell 检测' },
  { min: 1000200, max: 1000299, color: 'cyan', label: 'WAF 扫描器指纹' },
  { min: 1000300, max: 1000399, color: 'volcano', label: 'WAF 云原生滥用' },
  { min: 1000400, max: 1000499, color: 'volcano', label: 'WAF API 滥用防护' },
  { min: 1000500, max: 1000599, color: 'orange', label: 'WAF 敏感路径暴露' },
  { min: 1000600, max: 1000699, color: 'red', label: 'WAF 反序列化/RCE' },
  { min: 1000700, max: 1000799, color: 'orange', label: 'WAF 自动化异常' },
  { min: 1000800, max: 1000999, color: 'red', label: 'WAF 漏洞利用防护' },
  { min: 1001000, max: 1001099, color: 'red', label: 'WAF WebShell 混淆' },
  { min: 1001100, max: 1001299, color: 'red', label: 'WAF 攻击变种检测' },
  { min: 1001300, max: 1001499, color: 'red', label: 'WAF WebShell 检测' },
  { min: 1001500, max: 1001599, color: 'red', label: 'WAF SSRF 防护' },
  { min: 1001600, max: 1001699, color: 'red', label: 'WAF XXE/文件包含' },
  { min: 1001700, max: 1001799, color: 'red', label: 'WAF 注入变种检测' },
  { min: 1001800, max: 1001899, color: 'red', label: 'WAF 模板注入' },
  { min: 1001900, max: 1001999, color: 'volcano', label: 'WAF 未授权探测' },
  { min: 1002000, max: 1003999, color: 'cyan', label: 'WAF 扩展爬虫指纹' },
  { min: 1010000, max: 1010199, color: 'cyan', label: 'WAF AI 爬虫管控' },
  { min: 1010200, max: 1010299, color: 'orange', label: 'WAF 伪造爬虫检测' },
  { min: 9000000, max: 9000999, color: 'red', label: 'WAF 九章内置规则' },
]

function getWafNumericFindingTypeMeta(ruleId: number): { color: string; label: string } {
  for (const range of WAF_RULE_ID_CATEGORY_RANGES) {
    if (ruleId >= range.min && ruleId <= range.max) {
      return { color: range.color, label: `${range.label}（${ruleId}）` }
    }
  }
  return { color: 'red', label: `WAF 规则命中（${ruleId}）` }
}

/** 查询风险发现类型展示元数据（支持精确命中、WAF_<规则号> 分类与动态前缀兜底，未知原样返回） */
export function getApiFindingTypeMeta(type: string): { color: string; label: string } {
  if (!type) return { color: 'default', label: '-' }
  const direct = API_FINDING_TYPE_META[type]
  if (direct) return direct
  const upper = type.trim().toUpperCase()
  if (API_FINDING_TYPE_META[upper]) return API_FINDING_TYPE_META[upper]
  const normalized = upper.replace(/[.\-\s]+/g, '_')
  if (API_FINDING_TYPE_META[normalized]) return API_FINDING_TYPE_META[normalized]
  const wafMatch = /^WAF_(\d+)$/.exec(normalized)
  if (wafMatch) {
    return getWafNumericFindingTypeMeta(Number(wafMatch[1]))
  }
  for (const rule of FINDING_TYPE_PREFIX_FALLBACKS) {
    if (normalized.startsWith(rule.prefix)) {
      return { color: rule.color, label: rule.label }
    }
  }
  return { color: 'default', label: type }
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

/** Schema 违例类型（覆盖通用违例码与网关 schema.* 规则 ID） */
export const API_VIOLATION_TYPE_META: Record<string, { color: string; label: string }> = {
  undefined_field: { color: 'orange', label: '未定义字段' },
  type_mismatch: { color: 'red', label: '类型不匹配' },
  missing_field: { color: 'gold', label: '缺失字段' },
  constraint_violation: { color: 'volcano', label: '约束违例' },
  'schema.extra_field': { color: 'orange', label: '多余未定义字段' },
  'schema.undefined_field': { color: 'orange', label: '未定义字段' },
  'schema.type_mismatch': { color: 'red', label: '字段类型不匹配' },
  'schema.param_type': { color: 'red', label: '参数类型不匹配' },
  'schema.missing_field': { color: 'gold', label: '缺失必填字段' },
  'schema.param_required': { color: 'gold', label: '必填参数缺失' },
  'schema.param_length': { color: 'volcano', label: '参数长度超限' },
  'schema.param_range': { color: 'volcano', label: '参数数值越界' },
  'schema.param_enum': { color: 'volcano', label: '参数不在枚举范围' },
  'schema.param_regex': { color: 'volcano', label: '参数格式不匹配' },
  'schema.param_nullable': { color: 'orange', label: '参数不允许为空' },
  'schema.param_empty': { color: 'orange', label: '参数不允许空值' },
  'schema.param_constraint_invalid': { color: 'volcano', label: '参数约束校验失败' },
  'schema.relation_requires': { color: 'purple', label: '关联必填依赖缺失' },
  'schema.relation_mutex': { color: 'purple', label: '互斥参数同时出现' },
  'schema.relation_cooccurs': { color: 'purple', label: '共现参数不完整' },
  'schema.relation_equals': { color: 'purple', label: '参数相等约束违例' },
  'schema.relation_not_equals': { color: 'purple', label: '参数不等约束违例' },
  'schema.relation_greater_than': { color: 'purple', label: '参数大于约束违例' },
  'schema.relation_less_than': { color: 'purple', label: '参数小于约束违例' },
  'schema.relation_time_after': { color: 'purple', label: '时间先后约束违例（晚于）' },
  'schema.relation_time_before': { color: 'purple', label: '时间先后约束违例（早于）' },
  'schema.relation_sum_matches': { color: 'purple', label: '参数求和校验违例' },
  'schema.relation_count_matches': { color: 'purple', label: '参数数量校验违例' },
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
  RATE_LIMIT: { color: 'orange', label: '限速' },
  MASK_RESPONSE: { color: 'cyan', label: '响应脱敏' },
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
  WAF: { color: 'red', label: 'WAF 检测' },
  admission: { color: 'volcano', label: 'API 准入检测' },
  api_authz: { color: 'red', label: 'API 授权检测' },
  api_flow: { color: 'purple', label: '业务流程检测' },
  flowguard: { color: 'purple', label: '强流程防护' },
  api_parser: { color: 'orange', label: '报文解析检测' },
  api_ratelimit: { color: 'gold', label: 'API 频率限制' },
  api_request: { color: 'blue', label: 'API 请求检测' },
  api_response: { color: 'cyan', label: 'API 响应检测' },
  api_schema: { color: 'orange', label: '模型校验' },
  behavior: { color: 'volcano', label: '行为异常检测' },
  credential_transport: { color: 'red', label: '凭据传输检测' },
  file: { color: 'volcano', label: '文件安全检测' },
  graphql: { color: 'purple', label: 'GraphQL 检测' },
  'graphql.cost_v1': { color: 'purple', label: 'GraphQL 复杂度检测' },
  graphql_coverage: { color: 'purple', label: 'GraphQL 覆盖检测' },
  grpc: { color: 'geekblue', label: 'gRPC 检测' },
  grpcguard: { color: 'geekblue', label: 'gRPC 安全防护' },
  mcpguard: { color: 'cyan', label: 'MCP 工具调用防护' },
  pipeline: { color: 'blue', label: '防护管线' },
  resource_access: { color: 'volcano', label: '资源访问检测' },
  server_disclosure: { color: 'orange', label: '服务端信息泄露' },
  temp_block: { color: 'red', label: '临时封禁' },
  webshell: { color: 'red', label: 'WebShell 检测' },
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
  captcha: { color: 'cyan', label: '验证码' },
  username: { color: 'geekblue', label: '用户名' },
  id_card: { color: 'magenta', label: '身份证号' },
  bank_card: { color: 'red', label: '银行卡号' },
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
  UNKNOWN: { color: 'default', label: '未知' },
}

/**
 * 网关检测器/风险发现英文消息 → 中文展示映射（键统一小写，仅做界面展示，不改后端落库值）。
 * 覆盖 gateway/dynamic_security/detectors 与 pipeline 产出的英文 Message，兼顾存量历史 finding 标题。
 */
export const API_FINDING_TITLE_LABELS: Record<string, string> = {
  // 生命周期与准入
  'endpoint not in known baseline (shadow candidate)': '接口不在已知基线中（影子 API 候选）',
  'deprecated api still called': '已下线接口仍被调用',
  'endpoint not in admission baseline (never discovered)': '接口不在准入基线中（从未发现的影子 API）',
  'endpoint in baseline but not confirmed for admission': '接口已发现但尚未确认准入',
  // 认证与凭据
  'api request without credential': 'API 请求未携带认证凭据',
  'x-api-key too short': 'X-API-Key 长度过短',
  'malformed authorization header': 'Authorization 请求头格式异常',
  'weak credential': '检测到弱凭据',
  'jwt header not decodable': 'JWT 头部无法解码',
  'jwt header json invalid': 'JWT 头部 JSON 格式无效',
  'jwt alg none or empty': 'JWT 算法为 none 或为空',
  'jwt kid looks like path traversal': 'JWT kid 参数疑似路径遍历',
  'jwt empty signature segment': 'JWT 缺少签名段',
  'jwt exp in the past (unverified claims)': 'JWT 声明已过期（未验签）',
  'hmac signature credential present': '检测到 HMAC 签名凭据',
  'revoked credential in use': '已吊销凭据仍在使用',
  'credential exposed in url query': '凭据通过 URL 查询参数明文暴露',
  'credential-shaped value in url query': 'URL 查询参数中疑似包含凭据值',
  'sensitive cookie name observed': 'Cookie 中检测到敏感凭据字段',
  'credential used across multiple applications': '同一凭据跨多个应用复用',
  'credential used from multiple user-agent families in window': '同一凭据短时间内跨多类客户端使用',
  'credential used from multiple source ips': '同一凭据从多个来源 IP 访问',
  'credential used by concurrent requests': '同一凭据存在异常并发请求',
  'credential active in unusual hour vs own baseline': '凭据在非常规时段活跃',
  'credential user-agent family changed': '凭据客户端类型发生变更',
  'multiple environment anomalies for same credential': '同一凭据触发多项环境异常',
  'multiple verified principals used the same passive device fingerprint': '多个已认证账号共用同一设备指纹（疑似群控）',
  // 越权与字段权限
  'object access without credential': '未携带认证凭据访问对象资源',
  'many distinct object identifiers accessed in a short window': '短时间内高频访问大量不同对象标识（疑似枚举）',
  'sequential access across distinct object identifiers': '按顺序遍历访问多个不同对象标识（疑似对象枚举）',
  'anonymous access to endpoint with confirmed role baseline': '匿名访问已确认角色基线的接口',
  'request role has no allowed baseline for endpoint+method': '当前请求角色无该接口调用基线权限',
  'forbidden field present in request body (mass assignment)': '请求体包含禁止写入字段（疑似批量赋值）',
  'server-generated field provided by client': '客户端传入了服务端生成字段',
  'read-only field written in request body': '请求体尝试写入只读字段',
  'admin-only field written by non-designated role': '非指定角色尝试写入管理员专用字段',
  'forbidden field present in response body (excessive data exposure)': '响应体包含禁止返回字段（疑似过度数据暴露）',
  'confirmed-sensitive field present in response body': '响应体包含已确认的敏感字段',
  'incoming authz snapshot watermark below applied, config load rejected': '下发授权快照水位低于当前已生效水位，配置加载已拒绝',
  // Schema / 参数关系 / 响应偏离 / 敏感数据
  'undefined field vs formal model': '请求包含正式模型未定义的字段',
  'required parameter missing': '缺少必填参数',
  'parameter constraint violated': '参数值违反模型约束',
  'parameter constraint cannot be executed (observed only)': '参数约束暂无法执行校验（仅观察）',
  'credential header present (redacted)': '检测到认证请求头（已脱敏）',
  'cookie header present (redacted)': '检测到 Cookie 请求头（已脱敏）',
  'required companion parameter missing (requires relation)': '缺少关联必填参数（REQUIRES 依赖关系违例）',
  'mutually exclusive parameters co-occur (mutex relation)': '互斥参数同时出现（MUTEX 互斥关系违例）',
  'co-occurrence relation deviated (observe only)': '参数共现关系偏离基线（仅观察）',
  'equal-value relation violated (equals relation)': '参数相等关系约束违例',
  'distinct-value relation violated (not_equals relation)': '参数不等关系约束违例',
  'numeric order relation violated (greater_than relation)': '参数大于关系约束违例',
  'numeric order relation violated (less_than relation)': '参数小于关系约束违例',
  'time order relation violated (time_before relation)': '时间先后关系约束违例（早于）',
  'time order relation violated (time_after relation)': '时间先后关系约束违例（晚于）',
  'array count relation violated (count_matches relation)': '数组数量关系约束违例',
  'array sum relation violated (sum_matches relation)': '参数求和关系约束违例',
  'response status not covered by learned response schema baseline': '响应状态码未覆盖在已学习响应基线中',
  'response field not present in learned response schema baseline': '响应体出现未学习的新字段',
  'learned baseline field missing from response': '响应体缺少已学习基线中的字段',
  'sensitive field in url query': 'URL 查询参数包含敏感字段',
  'sensitive value in url query': 'URL 查询参数中检测到敏感数据值',
  'sensitive field name observed': '检测到敏感字段名',
  'sensitive value observed': '请求中检测到敏感数据值',
  'sensitive field name observed in response body': '响应体检测到敏感字段名',
  'sensitive value observed in response body': '响应体检测到敏感数据值',
  'response body value inspection incomplete': '响应体敏感值检测未完全覆盖',
  'response error signature observed': '响应中检测到异常错误特征',
  'response transform plan generated': '已生成响应脱敏转换计划',
  'response suppressed: cannot process safely under fail-closed policy': '响应已抑制：严格防护策略下无法安全处理',
  'partial content (206/content-range) suppressed under fail-closed policy to prevent response control bypass': '分段响应（206/Content-Range）已在严格防护策略下抑制，防止绕过响应控制',
  'response mask skipped: partial content (206/content-range), original delivered': '已跳过响应脱敏：分段响应（206/Content-Range）按原样放行',
  'response mask transform failed, suppressed by fail-closed policy': '响应脱敏转换失败，已在严格防护策略下抑制响应',
  'response mask transform failed, original delivered (fail-open)': '响应脱敏转换失败，已按原样放行',
  'response fields masked': '响应体敏感字段已完成脱敏',
  'server implementation header observed': '响应头暴露服务端实现信息',
  'server error details observed in response': '响应体暴露服务端错误详情',
  // 频率 / 配额 / 行为 / 业务流程
  'request rate spike vs baseline': '请求速率较基线显著突增',
  'api write rate exceeded': 'API 写入频率超限',
  'credential request rate exceeded': '单凭据请求速率超限',
  'tenant request rate exceeded': '租户请求速率超限',
  'action request rate exceeded': '操作请求速率超限',
  'group request rate exceeded': '接口分组请求速率超限',
  'api hourly quota exceeded': 'API 每小时配额超限',
  'api daily quota exceeded': 'API 每日配额超限',
  'per-object access rate exceeded': '单对象访问频率超限',
  'pagination size exceeded': '分页拉取大小超限',
  'batch size exceeded': '批量请求数量超限',
  'anonymous principal reached non-first flow step': '匿名主体访问非首步业务流程节点',
  'flow step reached without observed predecessors': '跳过前置步骤直接访问业务流程节点',
  'flow step sequence regression': '业务流程步骤顺序回退异常',
  'duplicate submit within short window': '短时间内重复提交业务请求',
  'object state transition violates declared flow': '对象状态流转违反已声明的业务流程',
  'flow step call rate exceeds baseline within short window': '流程步骤调用速率超出短窗基线',
  'flow call rate exceeds baseline within short window': '业务流程调用速率超出短窗基线',
  'flow step executed after cancellation': '取消操作后仍继续执行流程步骤',
  'strong flow step violates reservation state': '强流程步骤违反预留状态约束',
  'strong flow evaluation unknown (fail-open, disclosed)': '强流程评估结果未知（已放行并披露）',
  'strong flow step confirmed by success rule': '强流程步骤已按成功规则确认',
  'strong flow commit rejected (stale fencing token, newer state preserved)': '强流程提交被拒绝（令牌已过期，已保留最新状态）',
  'strong flow step accepted (202 pending completion, not auto-confirmed)': '强流程步骤已受理（202 待完成，未自动确认）',
  'strong flow step outcome unknown (f04: not auto-released, pending reconciliation)': '强流程步骤结果未知（未自动释放，待对账）',
  'strong flow response-phase action rejected (fencing)': '强流程响应阶段动作被拒绝（令牌校验未通过）',
  // 文件 / 扫描 / WebShell / WAF / 镜像
  'double file extension observed (inner extension may disguise real type)': '检测到文件双扩展名（内层扩展名可能伪装真实类型）',
  'file signature is not recognized': '无法识别文件内容签名',
  'file signature differs from declared type': '文件实际签名与声明类型不一致',
  'file content signature was not inspected': '未检测文件内容签名',
  'sensitive value observed in file text': '上传文件文本中检测到敏感数据',
  'file text was not fully inspected for sensitive values': '文件文本敏感数据检测未完全覆盖',
  'file compliance download block not enforced: response already streamed (fail-open)': '文件合规下载阻断未生效：响应已开始流式输出（已放行）',
  'inline html watermark applied': '已为内联 HTML 页面添加水印',
  'download file watermark applied': '已为下载文件添加水印',
  'download file signature embedded': '已为下载文件嵌入防篡改签名',
  'api scan header observed (no verification key configured, presence only)': '检测到主动扫描标记头（未配置验签密钥，仅作存在标记）',
  'api scan traffic identified (signature verified)': '识别到已验签的主动扫描流量',
  'scan header present with invalid signature (forgery suspect)': '扫描标记头签名无效（疑似伪造扫描流量）',
  'encrypted webshell c&c session suspected (behavioral multi-signal heuristic)': '疑似加密 WebShell/远控通信会话',
  'request blocked by downstream waf (coraza interruption)': '请求已被下游 WAF 引擎阻断',
  'request passively reconstructed from mirrored traffic (span/tap); detect-only, enforcement not possible': '旁路镜像流量（SPAN/TAP）被动还原请求：仅检测观测，无法阻断',
  'failed to parse request body.': '请求体解析失败',
  'multipart request body failed strict validation.': 'Multipart 请求体严格校验失败',
  // LLM / MCP / gRPC / GraphQL / 管线
  'prompt injection pattern observed': '检测到 LLM 提示词注入特征',
  'llm model not in allowed list': '调用了未在允许列表中的 LLM 模型',
  'llm prompt matches a blocked topic': 'LLM 提示词命中禁止主题',
  'llm prompt contains a sensitive data pattern': 'LLM 提示词包含敏感数据特征',
  'llm prompt exceeds the configured size budget': 'LLM 提示词超出长度预算上限',
  'llm prompt matches a harmful content rule': 'LLM 提示词命中违规内容规则',
  'llm requested output token limit exceeds the application budget': 'LLM 请求的输出 Token 上限超出应用预算',
  'llm output matches a harmful content rule': 'LLM 输出命中违规内容规则',
  'llm output contains a sensitive data pattern': 'LLM 输出包含敏感数据特征',
  'llm output content was not available for complete inspection': 'LLM 输出内容未能完整检测',
  'llm output inspection reached the text budget': 'LLM 输出检测达到文本长度上限',
  'mcp json-rpc method not in known vocabulary': 'MCP JSON-RPC 方法不在已知词表中',
  'sensitive value observed in mcp tool call arguments': 'MCP 工具调用参数中检测到敏感数据',
  'mcp tool call budget exceeded': 'MCP 工具调用配额超限',
  'mcp candidate coverage': 'MCP 候选流量覆盖观测',
  'mcp batch shape (removed in frozen protocol revision): pass through in observe mode': '检测到已废弃的 MCP 批处理格式（观察模式放行）',
  'mcp protect binding endpoint not covered by jwt trust chain (fail-open, disclosed)': 'MCP 防护绑定接口未纳入 JWT 信任链覆盖（已放行并披露）',
  'mcp sse result check degraded to passthrough (budget)': 'MCP SSE 返回结果检测超预算降级为透传',
  'mcp tool result blocked midstream (event withheld, connection closed, forwarded bytes disclosed honestly)': 'MCP 工具流式返回结果已中途阻断（当前事件已拦截并关闭连接）',
  'grpc frames observed': '观测到 gRPC 报文帧',
  'grpc malformed frame': 'gRPC 报文帧格式异常',
  'grpc frame budget exceeded': 'gRPC 报文帧超出预算上限',
  'grpc compression budget exceeded': 'gRPC 压缩报文解压超出预算上限',
  'grpc compressed frame observed while compression not allowed': '未允许压缩时检测到 gRPC 压缩帧',
  'grpc message decode failed': 'gRPC 消息解码失败',
  'grpc sensitive field value observed': 'gRPC 消息中检测到敏感字段值',
  'grpc unary coverage': 'gRPC 一元调用覆盖观测',
  'grpc request carries no message frame': 'gRPC 请求未携带消息帧',
  'grpc message decode failed (not a violation, fail-open)': 'gRPC 消息解码失败（不计违规，已放行）',
  'grpc compressed message stream corrupt (not a violation, fail-open)': 'gRPC 压缩消息流损坏（不计违规，已放行）',
  'grpc frame source read error (fail-open)': 'gRPC 帧源读取失败（已放行）',
  'grpc gzip stream corrupt (not a violation, fail-open)': 'gRPC gzip 流损坏（不计违规，已放行）',
  'grpc streaming call detected: deep inspection degraded (not covered, not passed)': '检测到 gRPC 流式调用：深度检测已降级',
  'grpc encoding not implemented': '暂不支持的 gRPC 编码格式',
  'grpc message structure violation': 'gRPC 消息结构违反约束',
  'grpc structure violations truncated': 'gRPC 结构违例明细已截断',
  'machine identity dependency unavailable (fail-open observe / 503 protect, not a proof failure)': '机器身份校验依赖不可用（观察模式放行 / 防护模式返回 503）',
  'machine identity content-digest not evaluated (body unreadable/over budget, not invalid)': '机器身份内容摘要未评估（请求体不可读或超限）',
  'machine identity coverage': '机器身份校验覆盖观测',
  'api request body exceeds preserve limit or read failed: metadata-only inspection performed': 'API 请求体超出缓存上限或读取失败（仅执行元数据检测）',
  'api request phase skipped: request body exceeds preserve limit or read failed (fail-open)': '已跳过 API 请求检测阶段：请求体超出缓存上限或读取失败（已放行）',
  'request body exceeds inspection limit under fail-closed or body-dependent protect policy': '请求体超出检测上限（防护策略触发保护）',
  'graphql request body exceeds inspection limit': 'GraphQL 请求体超出检测上限',
  'trusted graphql document (digest allowlisted), cost check bypassed': '受信任的 GraphQL 文档（摘要白名单已跳过复杂度检查）',
}

const PARSER_LOCATION_ZH: Record<string, string> = {
  query: '查询',
  body: '请求体',
  json: 'JSON ',
  header: '请求头',
  cookie: 'Cookie ',
  form: '表单',
}

const GQL_ADMISSION_KIND_ZH: Record<string, string> = {
  DOC_TOO_LARGE: '文档体积超限',
  TOO_DEEP: '查询嵌套过深',
  TOO_MANY_NODES: '节点数量超限',
  TOO_MANY_ALIASES: '别名数量超限',
  FRAGMENT_CYCLE: '片段循环引用',
  SYNTAX: '语法错误',
  NO_OPERATION: '缺少操作定义',
  MULTIPLE_OPERATIONS: '多操作未指定操作名',
  OPERATION_NOT_FOUND: '指定操作不存在',
}

const GQL_BUDGET_REASON_ZH: Record<string, string> = {
  GQL_COST_EXCEEDED: '单请求复杂度超限',
  GQL_WINDOW_EXCEEDED: '时间窗预算超限',
}

const FILE_COMPLIANCE_MATCH_ZH: Record<string, string> = {
  EXT: '扩展名',
  MIME: 'MIME 类型',
  FILENAME_REGEX: '文件名正则',
}

const CORAZA_CORE_RULE_TITLES_ZH: Record<number, string> = {
  200002: '请求体解析失败',
  200003: 'Multipart 请求体严格校验失败',
  980170: '异常评分汇总记录',
}

/** formatApiFindingTitle 可选上下文（提供 findingType/ruleId/detector/detail 以精确翻译 WAF 规则与空消息兜底） */
export interface ApiFindingTitleContext {
  findingType?: string | null
  ruleId?: string | number | null
  detector?: string | null
  detail?: unknown
}

function extractNumericWafRuleId(trimmedTitle: string, context?: ApiFindingTitleContext): number | null {
  const fromSlug = (raw?: string | null): number | null => {
    if (!raw) return null
    const m = /^WAF_(\d+)$/i.exec(raw.trim())
    return m ? Number(m[1]) : null
  }
  const byType = fromSlug(context?.findingType)
  if (byType) return byType

  const byTitleSlug = fromSlug(trimmedTitle)
  if (byTitleSlug) return byTitleSlug

  if (context?.ruleId !== undefined && context?.ruleId !== null && context?.ruleId !== '') {
    const rawId = String(context.ruleId).trim()
    const isWaf =
      !context.detector ||
      context.detector.trim().toLowerCase() === 'waf' ||
      Boolean(context.findingType && /^WAF_/i.test(context.findingType.trim()))
    if (isWaf && /^\d+$/.test(rawId)) {
      const n = Number(rawId)
      if (n > 0) return n
    }
  }

  if (context?.detail && typeof context.detail === 'object' && !Array.isArray(context.detail)) {
    const rec = context.detail as Record<string, unknown>
    const det = typeof rec.detector === 'string' ? rec.detector.trim().toLowerCase() : ''
    const rid = rec.rule_id !== undefined && rec.rule_id !== null ? String(rec.rule_id).trim() : ''
    if (det === 'waf' && /^\d+$/.test(rid)) {
      const n = Number(rid)
      if (n > 0) return n
    }
  }
  return null
}

function hasCjkText(s: string): boolean {
  return /[\u2E80-\u9FFF\uF900-\uFAFF]/.test(s)
}

/**
 * 将网关检测器/WAF 规则产出的英文风险标题/检测消息格式化为中文展示文案；
 * 已经是中文或未命中映射的文案原样返回，不伪造语义。
 */
export function formatApiFindingTitle(title?: string | null, context?: ApiFindingTitleContext): string {
  if (!title) return ''
  const trimmed = title.trim()
  if (!trimmed) return ''
  const exact = API_FINDING_TITLE_LABELS[trimmed.toLowerCase()]
  if (exact) return exact

  // 动态模板：schema.go `type mismatch for %s`
  const typeMismatch = /^type mismatch for (.+)$/i.exec(trimmed)
  if (typeMismatch) {
    return `参数 ${typeMismatch[1]} 类型不匹配`
  }

  // 动态模板：filecomp.go `file compliance rule matched (%s %q)`
  const fileCompliance = /^file compliance rule matched\s*\((\S+)\s+"([^"]*)"\)$/i.exec(trimmed)
  if (fileCompliance) {
    const matchKind = FILE_COMPLIANCE_MATCH_ZH[fileCompliance[1].toUpperCase()] ?? fileCompliance[1]
    return `命中文件合规规则（${matchKind} "${fileCompliance[2]}"）`
  }

  // 动态模板：graphql.go `graphql admission rejected: %s`
  const gqlReject = /^graphql admission rejected:\s*(.+)$/i.exec(trimmed)
  if (gqlReject) {
    const rawKind = gqlReject[1].trim()
    const kindZh = GQL_ADMISSION_KIND_ZH[rawKind] ?? rawKind
    return `GraphQL 准入拒绝：${kindZh}`
  }

  // 动态模板：graphql.go `graphql budget exceeded: %s (cost=%d budget=%d)`
  const gqlBudget = /^graphql budget exceeded:\s*(.+?)\s*\(cost=(\d+)\s+budget=(\d+)\)$/i.exec(trimmed)
  if (gqlBudget) {
    const rawReason = gqlBudget[1].trim()
    const reasonZh = GQL_BUDGET_REASON_ZH[rawReason] ?? rawReason
    return `GraphQL 复杂度预算超限：${reasonZh}（实际 ${gqlBudget[2]}，上限 ${gqlBudget[3]}）`
  }

  // 动态模板：parserambiguity.go `%s %s: duplicate %s parameter %q (x%d)`
  const dupParam = /^([A-Z0-9-]+)\s+[^:]+:\s*duplicate\s+(\S+)\s+parameter\s+"([^"]+)"\s+\(x(\d+)\)$/i.exec(trimmed)
  if (dupParam) {
    const loc = PARSER_LOCATION_ZH[dupParam[2].toLowerCase()] ?? `${dupParam[2]} `
    return `检测到重复的${loc}参数「${dupParam[3]}」（共 ${dupParam[4]} 次，规则 ${dupParam[1]}）`
  }

  // 动态模板：parserambiguity.go `PARSER-FIELD-CAP-001 %s: field count cap reached (%s), excess fields not parsed`
  const fieldCap = /^PARSER-FIELD-CAP-001\s+[^:]+:\s*field count cap reached\s*\(([^)]+)\),\s*excess fields not parsed$/i.exec(trimmed)
  if (fieldCap) {
    return `请求字段数量达到解析上限（${fieldCap[1]}），超出字段未解析`
  }

  // CRS 980170 异常评分汇总英文长日志
  if (/^Anomaly Scores:/i.test(trimmed)) {
    return '异常评分汇总记录'
  }

  // WAF 规则消息（按 WAF_<rule_id> / detail.rule_id / CRS 逐条词表及爬虫模板翻译）
  const wafRuleId = extractNumericWafRuleId(trimmed, context)
  if (wafRuleId !== null) {
    const coreTitle = CORAZA_CORE_RULE_TITLES_ZH[wafRuleId]
    if (coreTitle) return coreTitle
    const isSlugTitle = /^WAF_\d+$/i.test(trimmed)
    if (isSlugTitle) {
      return CRS_RULE_NAMES_ZH[wafRuleId] ?? getWafNumericFindingTypeMeta(wafRuleId).label
    }
    const localized = ruleMessageZh({ rule_id: wafRuleId, message: trimmed })
    if (localized && hasCjkText(localized)) {
      return localized
    }
  } else if (!hasCjkText(trimmed)) {
    // 无 rule_id 时仍尝试翻译模板型 WAF 规则消息（扫描器爬虫/AI 爬虫/搜索引擎爬虫声称）
    const templateLocalized = ruleMessageZh({ rule_id: 0, message: trimmed })
    if (templateLocalized && hasCjkText(templateLocalized)) {
      return templateLocalized
    }
  }

  // 兜底：部分检测器（如 authzdecide / mcpguard / machineid）不传 Message 时，
  // 服务端以 finding_type 作为标题落库（如 AUTHZ_BOLA_001、MCP_TOOL_NOT_IN_CATALOG、MACHINEID_FAILED）
  if (/^[A-Za-z][A-Za-z0-9._-]{1,63}$/.test(trimmed)) {
    const normalized = trimmed.toUpperCase().replace(/[.-]+/g, '_')
    const exactTypeMeta = API_FINDING_TYPE_META[normalized]
    if (exactTypeMeta) {
      return exactTypeMeta.label
    }
  }

  return trimmed
}
