/* API 授权实体层展示元数据（与 server/internal/apiauthz 枚举一致） */

/** 角色基线来源（api_role_baselines.source） */
export const API_AUTHZ_SOURCE_META: Record<string, { color: string; label: string }> = {
  MANUAL: { color: 'blue', label: '人工登记' },
  SPEC: { color: 'purple', label: '规格导入' },
  OBSERVED: { color: 'geekblue', label: '观测学习' },
  IMPORTED: { color: 'gold', label: '批量导入' },
}

/** 字段方向（api_field_permissions.direction） */
export const API_FIELD_DIRECTION_META: Record<string, { color: string; label: string }> = {
  REQUEST: { color: 'blue', label: '请求侧' },
  RESPONSE: { color: 'purple', label: '响应侧' },
}

/** 字段属性七值（api_field_permissions.attribute） */
export const API_FIELD_ATTRIBUTE_META: Record<string, { color: string; label: string }> = {
  READABLE: { color: 'green', label: '可读' },
  WRITABLE: { color: 'blue', label: '可写' },
  READ_ONLY: { color: 'gold', label: '只读' },
  ADMIN_WRITABLE: { color: 'purple', label: '仅管理员可写' },
  SERVER_GENERATED: { color: 'geekblue', label: '服务端生成' },
  SENSITIVE: { color: 'volcano', label: '敏感' },
  FORBIDDEN: { color: 'red', label: '禁止' },
}

/** BOLA 五档评估结论（色阶：绿=确认允许，金/橙=倾向，红=高置信越权，灰=证据不足） */
export const API_BOLA_VERDICT_META: Record<string, { color: string; label: string }> = {
  POLICY_CONFIRMED: { color: 'green', label: '策略确认·允许' },
  LIKELY: { color: 'gold', label: '倾向允许' },
  POSSIBLE: { color: 'orange', label: '倾向可疑' },
  HIGH_CONFIDENCE: { color: 'red', label: '高置信·越权' },
  INSUFFICIENT_EVIDENCE: { color: 'default', label: '证据不足' },
}

/** HTTP 方法选项（与服务端白名单一致） */
export const API_AUTHZ_METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))
