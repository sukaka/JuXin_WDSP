import { request } from './client'
import type { PageResult } from '../types'

/* ==================== NG-FLOW 强流程（/api-security/strong-flows） ====================
 * 逐键对齐 OpenAPI ApiSecStrongFlow*（server/openapi/fragments/07-api-security.yaml）。
 * 设计契约：docs/nextgen/NG-FLOW-strong-flow.md §1.1（定义/步骤）/§1.2（实例五态）/§1.5（恢复）。
 * 权限：api_flow.read（查询）/ api_flow.manage（写与激活停用/恢复）；
 * 实例详情证据明细档（fencing_token/reason_code/request_id）仅 api_authorization.evidence_read
 * 带出（无权限键缺席，非无数据）。
 */

/** 成功判定式（§1.4 三形态可组合与；白名单键，至少一形态——HTTP 2xx 不是通用成功证据） */
export interface StrongFlowSuccessRule {
  /** 形态一：响应状态码集合（100~599） */
  status_codes?: number[]
  /** 形态二：body JSONPath 子集等值（仅点路径 $.a.b 形态） */
  body_jsonpath_equals?: { path: string; value: unknown }
  /** 形态三：GraphQL errors 为空 */
  graphql_errors_empty?: boolean
}

/** 强流程步骤（§1.1 冻结形状） */
export interface StrongFlowStep {
  /** 步骤键（定义内唯一，≤128） */
  step_key: string
  /** 端点键（activate 核对须属绑定前缀下本应用已 CONFIRMED 端点） */
  endpoint_key: string
  /** 流程内单调序号（定义内唯一；首步唯一最小） */
  sequence: number
  /** 成功判定式（必填——无配置步骤恒 UNKNOWN） */
  success_rule: StrongFlowSuccessRule | null
  /** 步骤超时秒数（15~600，词表外 400 不夹紧猜义） */
  timeout_seconds: number
  retry_semantics: 'IDEMPOTENT' | 'NOT_RETRYABLE' | 'REQUIRES_REVIEW' | string
  /** 并行组（同组步骤 sequence 相邻连续；空=串行） */
  parallel_group?: string
  /** 步骤预留租约秒数（15~300） */
  lease_seconds: number
  /** 异步受理（202=已受理待完成，不自动完成） */
  allows_202?: boolean
}

export type StrongFlowDefinitionStatus = 'DRAFT' | 'ACTIVE' | 'RETIRED'
export type StrongFlowMode = 'OBSERVE' | 'PROTECT'

/** 强流程定义（版本化：编辑产新草稿 version+1、激活即冻结、RETIRED 单向终态） */
export interface StrongFlowDefinition {
  id: string
  application_id: string
  name: string
  /** 版本（单调递增；同名草稿 max+1） */
  version: number
  status: StrongFlowDefinitionStatus | string
  /** 端点组前缀（/ 开头纯字面） */
  binding_path_prefix: string
  /** 实例引用来源（query:<参数名> / path:<段序>） */
  instance_key_param: string
  /** 模式（缺省 OBSERVE；UNKNOWN 任何形态恒不阻断） */
  mode: StrongFlowMode | string
  created_by_name?: string
  created_at: string
  activated_at?: string | null
}

/** 定义详情（含步骤，sequence 升序） */
export interface StrongFlowDefinitionDetail extends StrongFlowDefinition {
  steps?: StrongFlowStep[]
}

/** 定义新建/编辑载荷（编辑为整体替换语义：steps 全量给出；PUT 仅 DRAFT） */
export interface StrongFlowDefinitionInput {
  application_id: string
  name: string
  binding_path_prefix: string
  instance_key_param: string
  mode?: StrongFlowMode | string
  steps: StrongFlowStep[]
}

export type StrongFlowInstanceStatus =
  'ACTIVE' | 'CONFIRMED' | 'INDETERMINATE' | 'CANCELLED' | 'FAILED'

/** 强流程实例（definition_version 创建时冻结——NG-T-F06 不换图） */
export interface StrongFlowInstance {
  id: string
  application_id: string
  definition_id: string
  /** 定义名称（LEFT JOIN 带出） */
  definition_name?: string
  /** 实例创建时冻结的定义版本 */
  definition_version: number
  /** 实例键（sfref: 前缀域隔离 HMAC 脱敏形态） */
  instance_key: string
  /** 可信租户引用（脱敏形态） */
  tenant_ref: string
  /** 可信主体引用（脱敏形态） */
  principal_ref: string
  status: StrongFlowInstanceStatus | string
  /** 乐观锁版本（resolve expected_version 比对） */
  version: number
  created_at: string
  updated_at: string
  terminated_at?: string | null
}

/** 步骤轨迹条目（摘要档四字段随读权限可见；明细档三键仅 evidence_read 带出，缺席=无权限） */
export interface StrongFlowStepEvent {
  /** 步骤键（实例级事件为空串） */
  step_key: string
  /** RESERVE/COMMIT/RELEASE/EXPIRE/INSTANCE_NEW/INSTANCE_CONFIRMED/INSTANCE_INDETERMINATE/INSTANCE_CANCELLED/INSTANCE_FAILED/RESOLVE（管理面专属） */
  action: string
  result: 'OK' | 'CONFLICT' | 'REJECTED' | 'UNKNOWN' | string
  occurred_at: string
  /** 预留 fencing 序号（明细档） */
  fencing_token?: number
  /** 原因码（FLOW-RESERVE-001/FENCE-001/UNKNOWN-001/FLOW-RESOLVE-001 等；明细档） */
  reason_code?: string
  /** 关联请求 ID（明细档） */
  request_id?: string
}

/** 实例详情（实例行 + 步骤轨迹全链 + 状态语义字段） */
export interface StrongFlowInstanceDetail extends StrongFlowInstance {
  /** 状态语义词表：IN_PROGRESS/SUCCEEDED/UNKNOWN_NOT_CONFIRMED/CANCELLED/FAILED（INDETERMINATE 不得映射为成功态） */
  status_semantics: string
  /** 状态语义中文文案（INDETERMINATE 固定「未知，不显示安全通过」逐字不美化，§9.4 红线） */
  status_message: string
  steps: StrongFlowStepEvent[]
}

/** 管理恢复载荷（reason 必填 ≤512；expected_version 乐观锁；终态实例 409 拒重复） */
export interface StrongFlowResolveInput {
  /** CONFIRM_SUCCEEDED→CONFIRMED / CONFIRM_NOT_EXECUTED→FAILED / KEEP_UNKNOWN 不推进 */
  action: 'CONFIRM_SUCCEEDED' | 'CONFIRM_NOT_EXECUTED' | 'KEEP_UNKNOWN' | string
  reason: string
  expected_version: number
}

export const strongFlowApi = {
  /* ---------- 定义（api_flow.read/manage） ---------- */
  listDefinitions: async (params: {
    application_id?: string
    status?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<StrongFlowDefinition>>(
      '/api-security/strong-flows/definitions',
      {
        query: { ...params },
      },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 新建（同应用同名不存在 → version=1 DRAFT；已存在 → version=max+1 新草稿） */
  createDefinition: (body: StrongFlowDefinitionInput) =>
    request<StrongFlowDefinitionDetail>(
      '/api-security/strong-flows/definitions',
      { method: 'POST', body },
    ),
  getDefinition: (id: string) =>
    request<StrongFlowDefinitionDetail>(
      `/api-security/strong-flows/definitions/${id}`,
    ),
  /** 仅 DRAFT 原地编辑（激活即冻结——ACTIVE/RETIRED 409） */
  updateDefinition: (id: string, body: StrongFlowDefinitionInput) =>
    request<StrongFlowDefinitionDetail>(
      `/api-security/strong-flows/definitions/${id}`,
      { method: 'PUT', body },
    ),
  /** 激活即冻结（activate 前全量校验+端点归属核对；同事务 RETIRED 同名义旧 ACTIVE） */
  activateDefinition: (id: string) =>
    request<StrongFlowDefinition>(
      `/api-security/strong-flows/definitions/${id}/activate`,
      { method: 'POST' },
    ),
  /** 停用（RETIRED 单向终态，重复 409） */
  retireDefinition: (id: string) =>
    request<{ id: string; status: string }>(
      `/api-security/strong-flows/definitions/${id}/retire`,
      { method: 'POST' },
    ),

  /* ---------- 实例（列表/详情 read；恢复 manage） ---------- */
  listInstances: async (params: {
    application_id?: string
    status?: string
    /** RFC3339（created_at 下界） */
    created_since?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<StrongFlowInstance>>(
      '/api-security/strong-flows/instances',
      {
        query: { ...params },
      },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 详情（步骤轨迹全链+状态语义；证据明细档按 evidence_read 服务端裁剪） */
  getInstance: (id: string) =>
    request<StrongFlowInstanceDetail>(
      `/api-security/strong-flows/instances/${id}`,
    ),
  /** 管理恢复（响应为恢复后的实例详情） */
  resolveInstance: (id: string, body: StrongFlowResolveInput) =>
    request<StrongFlowInstanceDetail>(
      `/api-security/strong-flows/instances/${id}/resolve`,
      { method: 'POST', body },
    ),
}
