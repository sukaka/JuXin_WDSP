import { request } from './client'

/* ==================== NG-MCP G1：MCP 工具目录与绑定（/api-security/mcp） ====================
 * 逐键对齐 OpenAPI ApiMcp*（server/openapi/fragments/07-api-security.yaml）。
 * 设计契约：docs/nextgen/NG-MCP-g1-toolcall.md §1.3（目录/工具/绑定模型）/§1.14（端点语义）。
 * 权限：api_spec.read（读）/ api_spec.manage（写，HIGH 审计）。
 * 红线：导入与语义变更恒落 PENDING_REVIEW（旧审批不继承——审批绑定 tool_hash 不是名字）；
 * 发布通道只下发 APPROVED 工具行。
 */

/** 参数范围约束（G1 两种确定性形态） */
export interface McpArgConstraint {
  /** 参数字段点路径（如 path/url，≤128） */
  field: string
  kind: 'path_prefix' | 'domain_suffix' | string
  /** 允许前缀/后缀集合（非空） */
  allow: string[]
}

/** MCP 目录工具行（tool_hash 审批绑定不可变摘要；发布只下发 APPROVED） */
export interface McpTool {
  id: string
  catalog_id: string
  tool_name: string
  tool_version: string
  /** 规范化描述全文 sha256（hex） */
  description_digest: string
  /** 描述截断预览（仅管理面展示，永不为证据） */
  description_preview?: string
  input_schema?: Record<string, unknown> | null
  output_schema?: Record<string, unknown> | null
  input_schema_digest?: string
  output_schema_digest?: string
  /** 五元组（名称/版本/规范化描述全文/双 schema）域分隔 sha256：mcp-tool-sha256:v1:<64hex> */
  tool_hash: string
  capability_tags?: string[]
  /** LOW|MEDIUM|HIGH（导入缺省 HIGH——未定级按高风险对待） */
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | string
  /** PUBLIC|INTERNAL|CONFIDENTIAL|UNKNOWN（导入缺省 UNKNOWN） */
  data_classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'UNKNOWN' | string
  /** 空=该维度不约束，非空逐维 AND */
  allowed_principals?: string[]
  allowed_roles?: string[]
  allowed_tenants?: string[]
  /** G1 语义=默认拒绝同 HIGH（数据前向兼容字段） */
  approval_required: boolean
  /** 0=不限 */
  max_calls_per_minute: number
  arg_constraints?: McpArgConstraint[]
  /** 导入与语义变更恒落 PENDING_REVIEW */
  review_status: 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED' | string
  reviewed_by?: string
  reviewed_at?: string | null
  created_at: string
  updated_at: string
}

/** MCP 工具目录（服务身份维度；发布通道只下发 ENABLED 目录的 APPROVED 工具行） */
export interface McpToolCatalog {
  id: string
  /** 目录名（全局唯一，≤128） */
  name: string
  /** 服务身份（如 mcp://pay.example.com，≤256） */
  service_identity: string
  /** MCP 协议版本（缺省 2025-11-25） */
  protocol_version: string
  /** 来源（G1 仅显式导入 MANUAL_IMPORT） */
  source: string
  /** ENABLED|DISABLED（DISABLED 不下发） */
  status: 'ENABLED' | 'DISABLED' | string
  /** 发布集摘要（mcp-catalog-sha256:v1:<64hex>；APPROVED 工具 tool_hash 排序拼接 sha256） */
  catalog_hash: string
  /** 乐观锁版本（写操作携带比对） */
  version: number
  created_by?: string
  created_at: string
  updated_at: string
}

/** 目录列表行（含审核统计） */
export interface McpToolCatalogSummary extends McpToolCatalog {
  tool_count: number
  approved_count: number
  pending_count: number
  rejected_count: number
}

/** 目录详情响应（目录 + 工具行） */
export interface McpToolCatalogDetail {
  catalog: McpToolCatalog
  tools: McpTool[]
}

/** 工具导入载荷（工具集整体提交——整体替换语义；空数组=空目录合法） */
export interface McpToolInput {
  tool_name: string
  tool_version?: string
  /** 规范化描述全文（入 tool_hash，≤65536） */
  description?: string
  /** 再导入未重填描述时为 true，保留存量 description_digest/preview（不重置审核态） */
  preserve_description?: boolean
  input_schema?: Record<string, unknown> | null
  output_schema?: Record<string, unknown> | null
  capability_tags?: string[]
  risk_level?: string
  data_classification?: string
  allowed_principals?: string[]
  allowed_roles?: string[]
  allowed_tenants?: string[]
  approval_required?: boolean
  max_calls_per_minute?: number
  arg_constraints?: McpArgConstraint[]
}

/** 目录导入/再导入载荷（version 为 PUT 乐观锁必填，POST 忽略） */
export interface McpToolCatalogInput {
  name: string
  service_identity: string
  protocol_version?: string
  tools: McpToolInput[]
  version?: number
}

/** 工具审核载荷（action 必填；定级/允许维度/预算可选更新） */
export interface McpToolReviewInput {
  action: 'APPROVED' | 'REJECTED' | string
  risk_level?: string
  data_classification?: string
  allowed_principals?: string[]
  allowed_roles?: string[]
  allowed_tenants?: string[]
  approval_required?: boolean
  max_calls_per_minute?: number
}

/** MCP 目录 per-app 绑定（绑定驱动识别；空绑定=网关 MCP 管控零行为） */
export interface McpBinding {
  id: string
  application_id: string
  /** MCP 端点精确路径（/ 开头，大小写敏感，≤1024） */
  endpoint_path: string
  catalog_id: string
  /** 目录名（JOIN 带出） */
  catalog_name: string
  /** OBSERVE 只记录 / PROTECT 协议化执行（JSON-RPC 错误对象） */
  mode: 'OBSERVE' | 'PROTECT' | string
  /** 乐观锁版本 */
  version: number
  created_by?: string
  created_at: string
  updated_at: string
}

export interface McpBindingInput {
  application_id: string
  endpoint_path: string
  catalog_id: string
  mode?: string
}

/** 绑定更新载荷（绑定身份维度（应用/endpoint_path）不可改——改即删建；version 乐观锁必填） */
export interface McpBindingUpdateInput {
  catalog_id: string
  mode?: string
  version: number
}

export const mcpApi = {
  /* ---------- 工具目录 ---------- */
  /** 显式导入目录（工具集整体提交——新工具与语义变更行恒落 PENDING_REVIEW；同名 409） */
  createCatalog: (body: McpToolCatalogInput) =>
    request<McpToolCatalogDetail>('/api-security/mcp/tool-catalogs', { method: 'POST', body }),
  /** 目录列表（含 catalog_hash 与审核统计；不分页） */
  listCatalogs: async () => {
    const data = await request<{ items: McpToolCatalogSummary[]; total: number }>('/api-security/mcp/tool-catalogs')
    return { ...data, items: data.items ?? [] }
  },
  getCatalog: (id: string) =>
    request<McpToolCatalogDetail>(`/api-security/mcp/tool-catalogs/${id}`),
  /** 整体再导入（乐观锁 version 不匹配 409；语义相等行保留审核态，变更/新增行重置 PENDING_REVIEW——旧审批不继承） */
  updateCatalog: (id: string, body: McpToolCatalogInput) =>
    request<McpToolCatalogDetail>(`/api-security/mcp/tool-catalogs/${id}`, { method: 'PUT', body }),
  /** 删除目录（FK 级联删工具行；被绑定引用 409——先解绑再删除） */
  deleteCatalog: (id: string) =>
    request<{ status: string }>(`/api-security/mcp/tool-catalogs/${id}`, { method: 'DELETE' }),
  /** 审核工具行（action=APPROVED/REJECTED + 可选定级更新；审核人/时间落列） */
  reviewTool: (catalogId: string, toolId: string, body: McpToolReviewInput) =>
    request<McpTool>(`/api-security/mcp/tool-catalogs/${catalogId}/tools/${toolId}/review`, { method: 'POST', body }),

  /* ---------- 绑定 ---------- */
  /** 绑定列表（application_id 可选过滤；不分页） */
  listBindings: async (params?: { application_id?: string }) => {
    const data = await request<{ items: McpBinding[]; total: number }>('/api-security/mcp/bindings', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 创建绑定（同（应用,endpoint_path）恰一条——重复 409；变更触发整站发布链热生效） */
  createBinding: (body: McpBindingInput) =>
    request<McpBinding>('/api-security/mcp/bindings', { method: 'POST', body }),
  /** 更新 mode/catalog_id（version 乐观锁，不匹配 409） */
  updateBinding: (id: string, body: McpBindingUpdateInput) =>
    request<McpBinding>(`/api-security/mcp/bindings/${id}`, { method: 'PUT', body }),
  /** 解绑（解绑后该端点 MCP 工具调用评估零行为） */
  deleteBinding: (id: string) =>
    request<{ status: string }>(`/api-security/mcp/bindings/${id}`, { method: 'DELETE' }),
}
