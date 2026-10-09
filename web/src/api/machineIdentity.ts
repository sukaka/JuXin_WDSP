import { request } from './client'

/* ==================== NG-ID G1：机器身份与绑定（/api-security/machine-identities*） ====================
 * 逐键对齐 OpenAPI ApiMachineIdentity*（server/openapi/fragments/07-api-security.yaml）。
 * 设计契约：docs/nextgen/NG-ID-g1-machine-identity.md §1.2（四表模型）/§1.3（公钥静态导入）/
 * §1.6（轮换重叠窗口/撤销水位单调）/§1.7（bot_challenge_exempt 三重豁免）。
 * 权限：jwt_trust.read（读）/ jwt_trust.manage（写，HIGH 审计）。
 */

/** 机器身份（发布通道只下发 ENABLED 身份） */
export interface MachineIdentity {
  id: string
  /** 身份名（全局唯一，≤128，同名 409） */
  identity_name: string
  /** 租户范围（null=跨租户共享身份） */
  tenant_id?: string | null
  /** 绑定 JWT VerifiedPrincipalID 指纹值（声明即强制一致） */
  principal_binding?: string | null
  /** ENABLED|DISABLED（DISABLED 不下发不参与验证） */
  status: 'ENABLED' | 'DISABLED' | string
  /** Bot 精确豁免前提之一（缺省 false） */
  bot_challenge_exempt: boolean
  /** 乐观锁版本（写操作携带比对） */
  version: number
  created_by?: string
  created_at: string
  updated_at: string
}

/** 身份列表行（含键状态摘要） */
export interface MachineIdentitySummary extends MachineIdentity {
  key_count: number
  active_keys: number
  retired_keys: number
  revoked_keys: number
}

/** 机器身份公钥（ACTIVE/RETIRED/REVOKED 状态机 + 重叠窗口 + revoked_seq 水位溯源） */
export interface MachineIdentityKey {
  id: string
  identity_id: string
  /** 键标识（身份内唯一；签名 keyid 登记册精确查找） */
  kid: string
  /** 算法词表：ed25519|ecdsa-p256-sha256|rsa-pss-sha512（hmac-sha256/rsa-v1_5-sha256 排除） */
  alg: 'ed25519' | 'ecdsa-p256-sha256' | 'rsa-pss-sha512' | string
  /** 公钥 PEM（公钥非秘密，明文存储合法） */
  public_key_pem: string
  /** 公钥指纹（sha256 前 16 hex，管理面现算） */
  key_fingerprint: string
  /** ACTIVE 可签发可验证 / RETIRED 重叠窗口内仅验证 / REVOKED 立即拒验 */
  status: 'ACTIVE' | 'RETIRED' | 'REVOKED' | string
  not_before?: string | null
  not_after?: string | null
  /** RETIRED 重叠窗口终点（窗口外旧键拒验） */
  retire_overlap_until?: string | null
  /** 撤销时水位值（溯源；未撤销为 null） */
  revoked_seq?: number | null
  created_by?: string
  created_at: string
  updated_at: string
}

/** 身份创建/更新载荷（version 为 PUT 乐观锁必填，POST 忽略） */
export interface MachineIdentityInput {
  identity_name: string
  tenant_id?: string | null
  principal_binding?: string | null
  status?: string
  bot_challenge_exempt?: boolean
  version?: number
}

/** 公钥导入/轮换载荷（overlap_hours 仅 rotate 消费：缺省 24、上限 168） */
export interface MachineIdentityKeyInput {
  kid: string
  /** 声明算法（与 PEM 实际键型一致性核对——不符 400） */
  alg: string
  /** 公钥 PEM（PKIX PUBLIC KEY 或 RSA PUBLIC KEY 块，恰一个公钥块，≤8192） */
  public_key_pem: string
  not_before?: string | null
  not_after?: string | null
  overlap_hours?: number | null
}

export interface MachineIdentityDetail {
  identity: MachineIdentity
  keys: MachineIdentityKey[]
}

/** 身份列表响应（撤销水位随列表带出——machine_identity_revocation_watermark 单行 seq） */
export interface MachineIdentityListResult {
  items: MachineIdentitySummary[]
  total: number
  revocation_watermark?: number
}

/** 轮换结果（同一事务原子：新键 ACTIVE+旧键 RETIRED+重叠窗口） */
export interface MachineIdentityRotateResult {
  key: MachineIdentityKey
  retired_key: MachineIdentityKey
}

/** 机器身份 per-app 绑定（绑定驱动识别；绑定不引用身份——登记册全局生效） */
export interface MachineIdentityBinding {
  id: string
  application_id: string
  /** 精确路径（与 path_prefix 二选一，缺省一侧为空串） */
  path_exact: string
  /** 路径前缀（jwt selector 同形：/ 开头、≤512、不含 query/fragment） */
  path_prefix: string
  /** OBSERVE 只记录 / PROTECT 验签失败与违规模态协议化执行 */
  mode: 'OBSERVE' | 'PROTECT' | string
  /** true=绑定命中且未签名请求拒绝 401；false=未签名按普通流量继续既有防护 */
  proof_required: boolean
  /** 乐观锁版本 */
  version: number
  created_by?: string
  created_at: string
  updated_at: string
}

export interface MachineIdentityBindingInput {
  application_id: string
  /** 与 path_prefix 必须且仅须提供一个 */
  path_exact?: string
  path_prefix?: string
  mode?: string
  proof_required?: boolean
}

/** 绑定更新载荷（身份维度（应用/路径）不可改——改即删建；version 乐观锁必填） */
export interface MachineIdentityBindingUpdateInput {
  mode?: string
  proof_required?: boolean
  version: number
}

export const machineIdentityApi = {
  /* ---------- 身份与键 ---------- */
  /** 创建机器身份（同名 409；变更触发整站发布链热生效） */
  createIdentity: (body: MachineIdentityInput) =>
    request<{ identity: MachineIdentity }>('/api-security/machine-identities', { method: 'POST', body }),
  /** 身份列表（含键状态摘要与撤销水位 revocation_watermark；不分页） */
  listIdentities: async () => {
    const data = await request<MachineIdentityListResult>('/api-security/machine-identities')
    return { ...data, items: data.items ?? [] }
  },
  getIdentity: (id: string) =>
    request<MachineIdentityDetail>(`/api-security/machine-identities/${id}`),
  /** 更新范围/状态/exempt/绑定主体（version 乐观锁必填——不匹配/同名 409） */
  updateIdentity: (id: string, body: MachineIdentityInput) =>
    request<{ identity: MachineIdentity }>(`/api-security/machine-identities/${id}`, { method: 'PUT', body }),
  /** 删除身份（键 FK 级联；存在任一机器身份绑定时 409——先解绑再删除） */
  deleteIdentity: (id: string) =>
    request<{ status: string }>(`/api-security/machine-identities/${id}`, { method: 'DELETE' }),

  /** 导入公钥（唯一来源=管理面静态离线导入；声明 alg 与 PEM 键型不一致 400；kid 重复 409；落库即 ACTIVE） */
  importKey: (identityId: string, body: MachineIdentityKeyInput) =>
    request<MachineIdentityKey>(`/api-security/machine-identities/${identityId}/keys`, { method: 'POST', body }),
  /** 轮换（原子=新键 ACTIVE+旧键 RETIRED+重叠窗口终点；仅 ACTIVE 键可轮换 409） */
  rotateKey: (identityId: string, keyId: string, body: MachineIdentityKeyInput) =>
    request<MachineIdentityRotateResult>(`/api-security/machine-identities/${identityId}/keys/${keyId}/rotate`, { method: 'POST', body }),
  /** 撤销（即时生效；撤销事实与水位 seq+1 同事务；已 REVOKED 重复撤销 409；普通回滚不复活已撤销密钥） */
  revokeKey: (identityId: string, keyId: string) =>
    request<MachineIdentityKey>(`/api-security/machine-identities/${identityId}/keys/${keyId}/revoke`, { method: 'POST' }),

  /* ---------- 绑定 ---------- */
  /** 绑定列表（application_id 可选过滤；不分页） */
  listBindings: async (params?: { application_id?: string }) => {
    const data = await request<{ items: MachineIdentityBinding[]; total: number }>('/api-security/machine-identity-bindings', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 创建绑定（path_exact|path_prefix 二选一；同（应用,path）恰一条重复 409） */
  createBinding: (body: MachineIdentityBindingInput) =>
    request<MachineIdentityBinding>('/api-security/machine-identity-bindings', { method: 'POST', body }),
  /** 更新 mode/proof_required（version 乐观锁，不匹配 409） */
  updateBinding: (id: string, body: MachineIdentityBindingUpdateInput) =>
    request<MachineIdentityBinding>(`/api-security/machine-identity-bindings/${id}`, { method: 'PUT', body }),
  /** 解绑（解绑后该端点机器身份签名评估零行为） */
  deleteBinding: (id: string) =>
    request<{ status: string }>(`/api-security/machine-identity-bindings/${id}`, { method: 'DELETE' }),
}
