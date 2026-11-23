import { request } from './client'

/* ==================== WDSP 流量采集 Agent 管理（契约 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md §4） ==================== */

/** Agent 状态（服务端按 §5 规则派生：DISABLED/OFFLINE 优先，否则取心跳上报状态） */
export type TrafficAgentStatus =
  'ONLINE' | 'OFFLINE' | 'DEGRADED' | 'ERROR' | 'DISABLED'

/** 心跳携带的 metrics 快照（契约 §3.2；全部字段由 Agent 上报，可能缺省） */
export interface TrafficAgentMetrics {
  cpu_percent?: number
  memory_mb?: number
  capture_pps?: number
  capture_bps?: number
  forward_pps?: number
  forward_bps?: number
  drop_pps?: number
  queue_depth?: number
  buffer_bytes?: number
  packets_received?: number
  packets_processed?: number
  packets_forwarded?: number
  packets_dropped?: number
  kernel_drops?: number
  current_mbps?: number
  raw_frames_received?: number
  raw_bytes_received?: number
  /** Phase 4 §3：背压降级帽（当前生效等级上限，如 "L1"；未降级不上报） */
  backpressure_cap?: string
  /** Phase 4 §3：背压累计降级次数（omitempty，未降级不上报） */
  backpressure_events?: number
}

/** Agent 列表项（GET /traffic/agents） */
export interface TrafficAgentItem {
  agent_id: string
  hostname: string
  ip: string
  os: string
  kernel: string
  arch: string
  version: string
  status: TrafficAgentStatus
  disabled: boolean
  last_seen: string | null
  last_metrics: TrafficAgentMetrics | null
  config_version: number
  applied_config_version: number
  /** Phase 2：最近心跳时钟偏移（毫秒，正=Agent 时钟偏慢）；未上报为 null */
  clock_offset_ms: number | null
  /** Phase 2：健康分 0-100（查询时计算，PHASE2 契约 §4 公式） */
  health_score: number
  /** Phase 2：健康扣分原因码数组（恒为数组，满分时为 []） */
  health_reasons: string[]
  created_at: string
}

/** Agent 网卡（注册时上报，契约 §3.1） */
export interface TrafficAgentInterface {
  name: string
  mac: string
  ipv4: string
  ipv6: string
  mtu: number
  speed_mbps: number
}

/** 当前策略绑定（详情接口返回，无绑定时为 null） */
export interface TrafficPolicyBinding {
  policy_id: string
  policy_name: string
  policy_version: number
  bound_by?: string
  bound_at?: string
}

/** Agent 详情（GET /traffic/agents/{agent_id}） */
export interface TrafficAgentDetail extends TrafficAgentItem {
  interfaces: TrafficAgentInterface[]
  policy_binding: TrafficPolicyBinding | null
  /** v2 契约 §3 能力协商生效集（注册/心跳声明 ∩ 服务端支持集；不含 2 = 旧 Agent
   * 仅支持 v1 事件——页面按此显示「需升级」，不假报 v2 能力已启用） */
  http_event_schemas?: number[]
}

/** 流量事件（GET /traffic/agents/{agent_id}/events；字段同契约 §3.4 上报结构） */
export interface TrafficK8sMetadata {
  cluster: string
  namespace: string
  pod: string
  workload?: string
  service?: string
  side: 'src' | 'dst'
}

export interface TrafficFlowEvent {
  id?: number
  agent_id?: string
  event_type: 'request' | 'flow_end' | string
  flow_id: string
  /** 管理端事件列表返回 RFC3339 字符串 ts；兼容保留 Unix 秒 number 与 timestamp */
  ts?: string | number
  timestamp?: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  direction: 'ingress' | 'egress' | string
  bytes_in: number
  bytes_out: number
  packets_in?: number
  packets_out?: number
  tls_visibility: 'PLAINTEXT' | 'ENCRYPTED' | 'UNKNOWN' | string
  http_method?: string
  http_host?: string
  http_uri?: string
  http_status?: number
  k8s?: TrafficK8sMetadata
}

/** HTTP 事件 Header 值（v1 行 string map、v2 行数组 map——同列双形态按 schema_version
 * 区分解读，v2 契约 §6；数组形态保序保留重复值，禁止隐式逗号合并） */
export type TrafficHttpHeaders = Record<string, string | string[]>

/** Body 采集质量（v2 契约 §2.1；original_total_size 未知为 null——不得按 0 展示） */
export interface TrafficHttpBodyQuality {
  captured_bytes: number
  original_total_size: number | null
  truncated: boolean
  skipped_reason: string
}

/** gRPC 元数据子对象（v2 契约 §2.2；grpc_status null=流未结束/不可见，HTTP 200 ≠ RPC 成功） */
export interface TrafficGrpcMeta {
  service: string
  method: string
  grpc_status: number | null
  stream_state: 'OPEN' | 'CLOSED' | 'CANCELLED' | 'UNKNOWN' | string
}

/** HTTP 事件请求/响应消息（Phase 3 契约 §3；仅 PLAINTEXT 流且采集等级 ≥L1 含 headers/body，列表端点可省略） */
export interface TrafficHttpMessage {
  headers?: TrafficHttpHeaders | null
  /** 脱敏后的最终值（Agent 侧离主机前完成，服务端/前端不再二次脱敏）；未采集为 null */
  body?: string | null
  body_truncated?: boolean
  original_body_size?: number
  /** 未采集原因码（content_type/encoding，§4）；空串表示已采集 */
  body_skipped_reason?: string
  /** v2：trailers 数组形态（null=来源不可见，空对象=确认无 trailer） */
  trailers?: TrafficHttpHeaders | null
  /** v2：完整 body 质量对象（含 captured_bytes 与"未知长度"语义；v1 行为 null） */
  body_quality?: TrafficHttpBodyQuality | null
}

/** HTTP 事件请求消息（Phase 3 契约 §3） */
export interface TrafficHttpRequestMessage extends TrafficHttpMessage {
  method: string
  scheme: string
  host: string
  uri: string
}

/** HTTP 事件响应消息（Phase 3 契约 §3；响应未捕获/超时整条为 null） */
export interface TrafficHttpResponseMessage extends TrafficHttpMessage {
  status: number
}

/** HTTP 事件（GET /traffic/agents/{agent_id}/http-events；Phase 3 契约 §3 记录结构 + 服务端 id，ts 倒序） */
export interface TrafficHttpEvent {
  id: number
  flow_id: string
  /** Unix 秒浮点（毫秒精度，§3） */
  request_ts: number
  /** 响应未捕获时为 null（§3） */
  response_ts: number | null
  latency_ms: number | null
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  direction: 'ingress' | 'egress' | string
  tls_visibility: 'PLAINTEXT' | 'ENCRYPTED' | 'UNKNOWN' | string
  request: TrafficHttpRequestMessage
  response: TrafficHttpResponseMessage | null
  k8s?: TrafficK8sMetadata
  /* ---- v2 增量（v2 契约 §2/§6；v1 存量行为库默认值/null，不回填伪造） ---- */
  /** 事件 schema 版本（1=v1 旧采集，2=v2） */
  schema_version?: number
  /** v2 幂等去重键（重试/补传不变）；v1 行为 null（无去重能力） */
  event_id?: string | null
  source_type?: 'PASSIVE_HTTP1' | 'NGINX_MIRROR' | 'ENVOY_TAP' | string
  source_instance?: string
  source_epoch?: number
  source_capabilities_version?: string
  /** 适配器观测协议（UNKNOWN=无法确认，不从 User-Agent 推断） */
  observed_http_version?: string
  /** 可确认的原协议；null=不可确认（与原协议分开记录，不互相回填） */
  original_http_version?: string | null
  /** 请求/响应关联状态；v1 行为 null */
  association_state?: 'COMPLETE' | 'REQUEST_ONLY' | 'PARTIAL' | 'UNCORRELATED' | string | null
  association_reason?: string
  capture_stream_id?: string | null
  application_binding_id?: string | null
  binding_version?: number | null
  /** gRPC 元数据（null=非 gRPC 流量；仅详情端点带出） */
  grpc?: TrafficGrpcMeta | null
  /** 来源采集时间（Unix 秒浮点）；与 ingestion_ts 差值为采集→入库延迟（缓存补传可辨） */
  collection_ts?: number | null
  /** 服务端接收时间（Unix 秒浮点）；均不混入业务延迟（业务延迟仅 latency_ms） */
  ingestion_ts?: number | null
}

/** HTTP 资产来源关系（GET /traffic/agents/{agent_id}/http-asset-sources，v2 契约 §5；
 * 事件入库 ≠ 资产关联成功——配额拒绝/未绑定/关联失败均可查询） */
export interface TrafficHttpAssetSource {
  id: number
  agent_id: string
  endpoint_id: string | null
  host: string
  method: string
  path_template: string
  source_type: string
  source_instance: string
  source_epoch: number
  application_binding_id: string | null
  binding_version: number | null
  /** LINKED=关联成功 / UNASSIGNED=未绑定待确认 / QUOTA_REJECTED=授权配额拒绝 / FAILED=关联失败 */
  association_state: 'LINKED' | 'UNASSIGNED' | 'QUOTA_REJECTED' | 'FAILED' | string
  last_error: string
  first_seen_at: string
  last_seen_at: string
}

/** HTTP 事件分页查询参数（Phase 3 契约 §6：page/page_size/host/method） */
export interface TrafficHttpEventsParams extends TrafficPageParams {
  host?: string
  method?: string
}

export type TrafficEnrollmentTokenStatus =
  | 'ACTIVE'
  | 'USED'
  | 'REVOKED'
  | 'EXPIRED'

/** 注册令牌列表项（GET /traffic/agents/enrollment-tokens；不含明文 token） */
export interface TrafficEnrollmentTokenItem {
  id: string
  label: string
  status: TrafficEnrollmentTokenStatus | string
  expires_at: string
  used_at?: string | null
  used_by_agent_id?: string | null
  revoked_at?: string | null
  created_by?: string
  created_at?: string
}

/** 创建注册令牌响应（token 明文仅此一次返回） */
export interface CreateTrafficEnrollmentTokenResult {
  id: string
  token: string
  expires_at: string
}

/** Agent 汇总（GET /traffic/agents/summary） */
export interface TrafficAgentSummary {
  total: number
  online: number
  offline: number
  degraded: number
  disabled: number
}

/** 采集策略（config 结构见契约 §3.3） */
export interface TrafficPolicy {
  id: string
  name: string
  version: number
  config: Record<string, unknown>
  created_at?: string
  updated_at?: string
}

/** 策略历史版本（Phase 2，GET /traffic/policies/{id}/versions 列表项） */
export interface TrafficPolicyVersion {
  version: number
  config: Record<string, unknown>
  created_by: string
  created_at: string
  /** 是否为当前生效版本（当前版本不可作为回滚目标） */
  current: boolean
}

export interface TrafficAgentListParams {
  status?: string
  q?: string
  page: number
  page_size: number
}

export interface TrafficPageParams {
  page: number
  page_size: number
}

export interface CreateTrafficPolicyBody {
  name: string
  config: Record<string, unknown>
}

/** 定向采集匹配条件（Phase 4 契约 §2.2：全部可选，多字段 AND，至少一个字段） */
export interface TrafficCaptureOverrideMatch {
  /** 单个 IP 或 CIDR（v4/v6） */
  dst_ip?: string
  /** 1-65535 */
  dst_port?: number
  /** 精确匹配（大小写不敏感） */
  host?: string
  /** URI 前缀（以 / 开头，≤512 字节） */
  uri_prefix?: string
}

/** 定向采集规则（Phase 4 契约 §2.1/§2.3；active 为服务端派生：未过期） */
export interface TrafficCaptureOverride {
  id: string
  agent_id: string
  match: TrafficCaptureOverrideMatch
  capture_level: 'L0' | 'L1' | 'L2' | 'L3' | string
  note: string
  created_by: string
  created_at: string
  expires_at: string
  active: boolean
}

/** 新增定向采集规则入参（ttl_minutes 1-1440，缺省 30） */
export interface CreateCaptureOverrideBody {
  match: TrafficCaptureOverrideMatch
  capture_level: string
  ttl_minutes: number
  note?: string
}

interface ItemsPage<T> {
  items: T[] | null
  total: number
}

/** WDSP 流量采集 Agent 管理接口封装；读权限 traffic.agents.view，写权限 traffic.agents.manage。
 * 写操作按契约返回 204 No Content（无信封），由 client.request 的空 body 2xx 分支统一按成功处理 */
export const trafficAgentsApi = {
  /** POST /traffic/agents/enrollment-tokens：创建一次性注册令牌（ttl_minutes 5–10080，token 仅此一次返回明文） */
  createEnrollmentToken: (body: { label: string; ttl_minutes: number }) =>
    request<CreateTrafficEnrollmentTokenResult>(
      '/traffic/agents/enrollment-tokens',
      {
        method: 'POST',
        body,
      },
    ),
  /** GET /traffic/agents/enrollment-tokens：令牌列表（不含明文，含 ACTIVE/USED/REVOKED/EXPIRED 派生状态） */
  enrollmentTokens: async () => {
    const data = await request<ItemsPage<TrafficEnrollmentTokenItem>>(
      '/traffic/agents/enrollment-tokens',
    )
    return { ...data, items: data.items ?? [] }
  },
  /** POST /traffic/agents/enrollment-tokens/{id}/revoke：撤销令牌（204） */
  revokeEnrollmentToken: (id: string) =>
    request<null>(
      `/traffic/agents/enrollment-tokens/${encodeURIComponent(id)}/revoke`,
      {
        method: 'POST',
      },
    ),
  /** GET /traffic/agents/summary：总数/在线/离线/降级/禁用汇总 */
  summary: () => request<TrafficAgentSummary>('/traffic/agents/summary'),
  /** GET /traffic/agents：Agent 分页列表（status/q 筛选） */
  agents: async (params: TrafficAgentListParams) => {
    const data = await request<ItemsPage<TrafficAgentItem>>('/traffic/agents', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** GET /traffic/agents/{agent_id}：详情（含网卡与策略绑定） */
  agent: async (agentId: string) => {
    const data = await request<TrafficAgentDetail>(
      `/traffic/agents/${encodeURIComponent(agentId)}`,
    )
    return { ...data, interfaces: data.interfaces ?? [] }
  },
  /** POST /traffic/agents/{agent_id}/disable：禁用（Agent 停止抓包、保留心跳，204） */
  disableAgent: (agentId: string) =>
    request<null>(`/traffic/agents/${encodeURIComponent(agentId)}/disable`, {
      method: 'POST',
    }),
  /** POST /traffic/agents/{agent_id}/enable：启用（204） */
  enableAgent: (agentId: string) =>
    request<null>(`/traffic/agents/${encodeURIComponent(agentId)}/enable`, {
      method: 'POST',
    }),
  /** DELETE /traffic/agents/{agent_id}：删除（吊销 credential、删除绑定与网卡、保留审计，204） */
  deleteAgent: (agentId: string) =>
    request<null>(`/traffic/agents/${encodeURIComponent(agentId)}`, {
      method: 'DELETE',
    }),
  /** GET /traffic/agents/{agent_id}/events：流量事件分页（按 ts 倒序） */
  agentEvents: async (agentId: string, params: TrafficPageParams) => {
    const data = await request<ItemsPage<TrafficFlowEvent>>(
      `/traffic/agents/${encodeURIComponent(agentId)}/events`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** GET /traffic/agents/{agent_id}/http-events：HTTP 事件分页（ts 倒序，host/method 过滤，Phase 3 契约 §6） */
  agentHttpEvents: async (agentId: string, params: TrafficHttpEventsParams) => {
    const data = await request<ItemsPage<TrafficHttpEvent>>(
      `/traffic/agents/${encodeURIComponent(agentId)}/http-events`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** GET /traffic/agents/{agent_id}/http-events/{id}：单条全量（含 headers/body，Phase 3 契约 §6） */
  agentHttpEvent: (agentId: string, id: number) =>
    request<TrafficHttpEvent>(
      `/traffic/agents/${encodeURIComponent(agentId)}/http-events/${encodeURIComponent(String(id))}`,
    ),
  /** GET /traffic/agents/{agent_id}/http-asset-sources：资产来源关系分页（state 精确过滤，
   * last_seen_at 倒序，v2 契约 §5——配额拒绝/未绑定/关联失败均可查询） */
  agentHttpAssetSources: async (
    agentId: string,
    params: TrafficPageParams & { state?: string },
  ) => {
    const data = await request<ItemsPage<TrafficHttpAssetSource>>(
      `/traffic/agents/${encodeURIComponent(agentId)}/http-asset-sources`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** GET /traffic/policies：采集策略列表 */
  policies: async (params?: Partial<TrafficPageParams>) => {
    const data = await request<ItemsPage<TrafficPolicy>>('/traffic/policies', {
      query: { page: params?.page ?? 1, page_size: params?.page_size ?? 100 },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** POST /traffic/policies：创建策略 */
  createPolicy: (body: CreateTrafficPolicyBody) =>
    request<TrafficPolicy>('/traffic/policies', { method: 'POST', body }),
  /** GET /traffic/policies/{id}：策略详情 */
  policy: (id: string) =>
    request<TrafficPolicy>(`/traffic/policies/${encodeURIComponent(id)}`),
  /** PUT /traffic/policies/{id}：修改策略（修改后 version+1） */
  updatePolicy: (id: string, body: CreateTrafficPolicyBody) =>
    request<TrafficPolicy>(`/traffic/policies/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body,
    }),
  /** DELETE /traffic/policies/{id}：删除策略（204） */
  deletePolicy: (id: string) =>
    request<null>(`/traffic/policies/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  /** GET /traffic/policies/{id}/versions：策略历史版本列表（Phase 2，version 倒序，current 标记当前版本） */
  policyVersions: async (id: string) => {
    const data = await request<ItemsPage<TrafficPolicyVersion>>(
      `/traffic/policies/${encodeURIComponent(id)}/versions`,
    )
    return { ...data, items: data.items ?? [] }
  },
  /** POST /traffic/policies/{id}/rollback：回滚到历史版本（以历史 config 生成新版本 version+1，200 返回新策略） */
  rollbackPolicy: (id: string, version: number) =>
    request<TrafficPolicy>(
      `/traffic/policies/${encodeURIComponent(id)}/rollback`,
      {
        method: 'POST',
        body: { version },
      },
    ),
  /** POST /traffic/agents/{agent_id}/policy：绑定策略（每 Agent 同时仅一条生效绑定，重复绑定即换绑，204） */
  bindPolicy: (agentId: string, policyId: string) =>
    request<null>(`/traffic/agents/${encodeURIComponent(agentId)}/policy`, {
      method: 'POST',
      body: { policy_id: policyId },
    }),
  /** DELETE /traffic/agents/{agent_id}/policy：解绑策略（204） */
  unbindPolicy: (agentId: string) =>
    request<null>(`/traffic/agents/${encodeURIComponent(agentId)}/policy`, {
      method: 'DELETE',
    }),
  /** GET /traffic/agents/{agent_id}/overrides：定向采集规则列表（含已过期，active 派生，Phase 4 契约 §2.3） */
  agentOverrides: async (agentId: string) => {
    const data = await request<ItemsPage<TrafficCaptureOverride>>(
      `/traffic/agents/${encodeURIComponent(agentId)}/overrides`,
    )
    return { ...data, items: data.items ?? [] }
  },
  /** POST /traffic/agents/{agent_id}/overrides：新增定向采集规则（201，创建后 config_version+1 即时下发） */
  createOverride: (agentId: string, body: CreateCaptureOverrideBody) =>
    request<TrafficCaptureOverride>(
      `/traffic/agents/${encodeURIComponent(agentId)}/overrides`,
      {
        method: 'POST',
        body,
      },
    ),
  /** DELETE /traffic/agents/{agent_id}/overrides/{override_id}：删除定向采集规则（204） */
  deleteOverride: (agentId: string, overrideId: string) =>
    request<null>(
      `/traffic/agents/${encodeURIComponent(agentId)}/overrides/${encodeURIComponent(overrideId)}`,
      { method: 'DELETE' },
    ),
}
