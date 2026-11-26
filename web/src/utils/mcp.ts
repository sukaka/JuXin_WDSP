/* ==================== NG-MCP G1：MCP 目录词表与纯函数（docs/nextgen/NG-MCP-g1-toolcall.md §1.3） ==================== */

/** 工具审核状态机（导入与语义变更恒落 PENDING_REVIEW——旧审批不继承） */
export const MCP_REVIEW_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING_REVIEW: { color: 'gold', label: '待审核' },
  APPROVED: { color: 'green', label: '已通过' },
  REJECTED: { color: 'red', label: '已拒绝' },
}

/** 工具风险等级（导入缺省 HIGH——未定级按高风险对待） */
export const MCP_RISK_LEVEL_META: Record<string, { color: string; label: string }> = {
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
  LOW: { color: 'green', label: '低' },
}

/** 数据分级（导入缺省 UNKNOWN） */
export const MCP_DATA_CLASSIFICATION_META: Record<string, { color: string; label: string }> = {
  PUBLIC: { color: 'green', label: '公开' },
  INTERNAL: { color: 'blue', label: '内部' },
  CONFIDENTIAL: { color: 'red', label: '机密' },
  UNKNOWN: { color: 'default', label: '未分级' },
}

/** 目录启停（DISABLED 不下发） */
export const MCP_CATALOG_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '启用' },
  DISABLED: { color: 'default', label: '停用' },
}

/** 绑定模式（OBSERVE 只记录 / PROTECT 协议化执行 JSON-RPC 错误对象） */
export const MCP_BINDING_MODE_META: Record<string, { color: string; label: string }> = {
  OBSERVE: { color: 'default', label: '观察' },
  PROTECT: { color: 'red', label: '实断' },
}

/** 工具定义钉扎执行策略（Phase 9C-1 Rug Pull 漂移检测） */
export const MCP_PIN_ENFORCEMENT_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察' },
  PROTECT: { color: 'red', label: '强制阻断' },
}

/** 响应侧间接提示词/隐写防护模式（Phase 9C-1） */
export const MCP_RESPONSE_GUARD_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察' },
  SANITIZE: { color: 'gold', label: '净化隐写' },
  PROTECT: { color: 'red', label: '强制阻断' },
}

/** OAuth 2.1 受保护资源元数据 URL 校验（可选；非空须为 https:// 且不含空白/引号/反斜杠/控制字符/内嵌凭据，上限 512） */
export function validateOAuthResourceMetadataUrl(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) return null
  if (v.length > 512) {
    return 'OAuth 资源元数据地址不能超过 512 字符'
  }
  // eslint-disable-next-line no-control-regex
  if (/[\r\n\u0000-\u001f\u007f\s"\\]/.test(v)) {
    return 'OAuth 资源元数据地址不能包含空白、引号、反斜杠或控制字符'
  }
  if (v.includes('#')) {
    return 'OAuth 资源元数据地址不能包含片段标识（#）'
  }
  if (!v.toLowerCase().startsWith('https://')) {
    return 'OAuth 资源元数据地址必须以 https:// 开头'
  }
  try {
    const parsed = new URL(v)
    if (
      parsed.protocol !== 'https:' ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.hash
    ) {
      return 'OAuth 资源元数据地址须为合法的 https:// URL（不含内嵌凭据或片段标识）'
    }
  } catch {
    return 'OAuth 资源元数据地址须为合法的 https:// URL（不含内嵌凭据或片段标识）'
  }
  return null
}

/** 审核语义固定说明（导入/再导入状态机 + 发布通道口径；M02 红线不美化） */
export const MCP_REVIEW_NOTE =
  '导入与再导入后，新工具与语义变更行恒落「待审核」——同名变更重算 tool_hash，旧审批不继承；发布通道只下发「已通过」工具行（待审核/已拒绝不出现在快照，网关侧同一不可调用语义）。'

/** 覆盖范围提示（NG-T-M05 断言形态：stdio/出网未覆盖明示，不冒充已保护） */
export const MCP_COVERAGE_NOTE =
  '覆盖范围：仅经反代的远程 HTTP MCP（Streamable HTTP）在覆盖内；未经反代的 MCP（stdio/本地进程）与工具进程出网不在覆盖内。'

/** tool_hash/catalog_hash 短显（"mcp-…-sha256:v1:" 前缀剥离 + 前 12 位 hex，全文入 title/copyable） */
export function shortMcpHash(value?: string | null): string {
  if (!value) return '-'
  const hex = value.includes(':') ? value.slice(value.lastIndexOf(':') + 1) : value
  return hex.length > 12 ? `${hex.slice(0, 12)}…` : hex
}

/** JSON 文本域解析（空=undefined 不发送；非法 JSON 返回错误消息，合法返回解析值） */
export function parseJsonText(text: string): { value?: Record<string, unknown>; error?: string } {
  const raw = text.trim()
  if (raw === '') return {}
  try {
    const parsed = JSON.parse(raw) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { error: '须为 JSON 对象' }
    }
    return { value: parsed as Record<string, unknown> }
  } catch {
    return { error: '非法 JSON，请检查后重试' }
  }
}

/** arg_constraints 文本域解析（每行一条 JSON 对象或整体 JSON 数组；空=undefined） */
export function parseArgConstraintsText(text: string): { value?: { field: string; kind: string; allow: string[] }[]; error?: string } {
  const raw = text.trim()
  if (raw === '') return {}
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return { error: '须为 JSON 数组' }
    for (const [i, item] of parsed.entries()) {
      const it = item as Record<string, unknown>
      if (typeof it !== 'object' || it === null) return { error: `第 ${i + 1} 项须为对象` }
      if (typeof it.field !== 'string' || it.field.trim() === '') return { error: `第 ${i + 1} 项参数字段名必填` }
      if (it.kind !== 'path_prefix' && it.kind !== 'domain_suffix') return { error: `第 ${i + 1} 项约束类型非法（仅支持路径前缀或域名后缀）` }
      if (!Array.isArray(it.allow) || it.allow.length === 0 || it.allow.some((a) => typeof a !== 'string' || a === '')) {
        return { error: `第 ${i + 1} 项允许列表须为非空字符串数组` }
      }
    }
    return { value: parsed as { field: string; kind: string; allow: string[] }[] }
  } catch {
    return { error: '非法 JSON，请检查后重试' }
  }
}

/** 允许维度计数展示（空=该维度不约束） */
export function allowedCountText(values?: string[]): string {
  return values && values.length > 0 ? `${values.length} 项` : '不约束'
}
